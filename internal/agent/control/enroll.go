// Package control implements the Agent-side control channel client (P08):
// enrollment over HTTP (enroll.go) and the signed session over a bounded
// WebSocket (session.go).
//
// The client consumes only the frozen contracts and the P07 localstate
// journal; it owns no data-plane logic. All secrets (token, node key) are
// handled secret-safe: never logged, never rendered into errors, and the
// token input is consumed exactly once.
package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// EnrollOptions configures the enrollment client.
type EnrollOptions struct {
	// Endpoint is the controller base URL (http:// or https://).
	Endpoint string
	// NodeID is the agent's node identity (store-form string).
	NodeID string
	// Token is the one-time enrollment token (from TTY or a 0600 file).
	// It is never logged and never persisted.
	Token string
	// ControllerPublicKey is the PINNED controller signing key (from the
	// deployment profile). Challenge/result signatures are verified against
	// it; a wrong pin fails closed before the token is used.
	ControllerPublicKey ed25519.PublicKey
	// ControllerKeyID optionally pins the controller key id; when non-empty
	// it must match the challenge's key id.
	ControllerKeyID string
	// KeyDir is where the node identity key lives (created 0600).
	KeyDir string
	// HTTPClient overrides the default client (tests, TLS config).
	HTTPClient *http.Client
}

// Enroll runs the frozen enrollment transcript against the controller and
// returns the agent node key. It is idempotent on response loss: a retry with
// the same key converges on the same binding. The token is used in memory
// only.
func Enroll(ctx context.Context, store *localstate.Store, opts EnrollOptions) (*security.NodeKey, error) {
	if opts.Endpoint == "" {
		return nil, errors.New("control: enroll requires controller endpoint")
	}
	if opts.NodeID == "" {
		return nil, errors.New("control: enroll requires node id")
	}
	if opts.Token == "" {
		return nil, errors.New("control: enroll requires a token")
	}
	if len(opts.ControllerPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("control: enroll requires a pinned controller public key")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}

	key, err := security.LoadOrCreateNodeKey(opts.KeyDir, 1)
	if err != nil {
		return nil, err
	}

	// 1. Fetch the signed challenge.
	chalBytes, err := fetchChallenge(ctx, opts.HTTPClient, opts.Endpoint, opts.NodeID)
	if err != nil {
		return nil, err
	}
	chal, err := protocol.ParseEnrollChallenge(chalBytes, opts.ControllerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("control: verify enrollment challenge: %w", err)
	}
	if opts.ControllerKeyID != "" && chal.ControllerKeyID != opts.ControllerKeyID {
		return nil, fmt.Errorf("control: challenge key id %q does not match pinned key id %q", chal.ControllerKeyID, opts.ControllerKeyID)
	}

	// 2. Build and sign the possession proof.
	var agentNonce [protocol.EnrollNonceSize]byte
	if _, err := rand.Read(agentNonce[:]); err != nil {
		return nil, fmt.Errorf("control: agent nonce: %w", err)
	}
	req := protocol.EnrollRequest{
		ChallengeHash:          sha256.Sum256(chalBytes[:len(chalBytes)-64]), // canonical challenge
		AgentNonce:             agentNonce,
		AgentPublicKey:         [32]byte(key.PublicKey()),
		AgentCredentialVersion: key.CredentialVersion(),
		Token:                  opts.Token,
		CapabilityHash:         sha256.Sum256([]byte("capabilities-v1")),
	}
	sig, err := key.Sign(req.SigningBytes())
	if err != nil {
		return nil, err
	}
	rawReq := append(req.Canonical(), sig...)

	// 3. Submit and verify the result.
	resBytes, err := submitRequest(ctx, opts.HTTPClient, opts.Endpoint, rawReq)
	if err != nil {
		return nil, err
	}
	res, err := protocol.ParseEnrollResult(resBytes, opts.ControllerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("control: verify enrollment result: %w", err)
	}
	if res.AgentCredentialVersion != key.CredentialVersion() {
		return nil, fmt.Errorf("control: result credential version %d does not match key version %d", res.AgentCredentialVersion, key.CredentialVersion())
	}
	// The result must bind the node and the presented key hash.
	pubHash := sha256.Sum256(key.PublicKey())
	if !bytes.Equal(res.AgentPublicKeyHash[:], pubHash[:]) {
		return nil, errors.New("control: enrollment result binds a different key")
	}
	if !strings.EqualFold(strings.TrimRight(string(res.NodeID[:]), "\x00"), opts.NodeID) {
		return nil, errors.New("control: enrollment result binds a different node")
	}

	// Persist the pinned controller identity so sessions can verify
	// controller-signed messages (the pin is the session trust anchor).
	pin := localstate.ControllerPin{
		InstanceID:   hex.EncodeToString(res.ControllerInstanceID[:]),
		KeyID:        res.ControllerKeyID,
		PublicKeyRaw: append([]byte(nil), opts.ControllerPublicKey...),
		Generation:   1, // P14 rotation raises generations
	}
	if err := store.SaveControllerPin(pin); err != nil {
		return nil, fmt.Errorf("control: persist controller pin: %w", err)
	}
	return key, nil
}

// fetchChallenge POSTs the node id and returns the raw signed challenge.
func fetchChallenge(ctx context.Context, client *http.Client, endpoint, nodeID string) ([]byte, error) {
	u, err := url.Parse(strings.TrimRight(endpoint, "/") + "/agent/v1/enroll/challenge")
	if err != nil {
		return nil, fmt.Errorf("control: challenge url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(nodeID))
	if err != nil {
		return nil, fmt.Errorf("control: challenge request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control: challenge request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("control: challenge rejected (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4096))
}

// submitRequest POSTs the raw EnrollRequest and returns the raw EnrollResult.
func submitRequest(ctx context.Context, client *http.Client, endpoint string, rawReq []byte) ([]byte, error) {
	u, err := url.Parse(strings.TrimRight(endpoint, "/") + "/agent/v1/enroll/request")
	if err != nil {
		return nil, fmt.Errorf("control: enroll url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(rawReq))
	if err != nil {
		return nil, fmt.Errorf("control: enroll request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control: enroll request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("control: enrollment rejected (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4096))
}
