// Package security provides the P08-owned cryptographic and challenge
// primitives for the control plane: the Agent node identity key (nodekey.go),
// the enrollment challenge manager plus the signed session handshake
// transcript (challenge.go), and the Controller signing keyring (keyring.go).
//
// All secrets are handled secret-safe: key files are written atomically with
// mode 0600 (DPAPI-protected on Windows) and secret material is never
// rendered into error strings or logs.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security/framecrypto"
)

// Challenge errors — stable sentinels so callers fail closed on unknown,
// expired, replayed, or cross-node challenges.
var (
	// ErrChallengeUnknown reports a challenge hash the manager never issued
	// (or evicted) — a cross-controller replay or a foreign challenge.
	ErrChallengeUnknown = errors.New("security: unknown enrollment challenge")
	// ErrChallengeExpired reports a challenge past its expiry.
	ErrChallengeExpired = errors.New("security: enrollment challenge expired")
	// ErrChallengeReplayed reports a challenge consumed more than once.
	ErrChallengeReplayed = errors.New("security: enrollment challenge replay")
	// ErrChallengeNodeMismatch reports a challenge issued for a different node.
	ErrChallengeNodeMismatch = errors.New("security: enrollment challenge node mismatch")
	// ErrChallengeCacheFull reports the bounded challenge cache at capacity
	// with no expired entries to evict (resource bound).
	ErrChallengeCacheFull = errors.New("security: enrollment challenge cache full")
)

// challengeEntry is one outstanding issued challenge in the bounded replay
// cache. nodeID is the store-form (unpadded) node identifier; the wire field
// is the same bytes zero-padded to 16.
type challengeEntry struct {
	nodeID   string
	instance [16]byte
	expiry   time.Time
	used     bool
}

// ChallengeManager issues signed EnrollChallenges and validates/consumes them
// with a bounded, expiring replay cache (v0.8 §6.2: nonce replay protection;
// the cache is bounded so the controller never grows without limit).
type ChallengeManager struct {
	mu    sync.Mutex
	ttl   time.Duration
	max   int
	now   func() time.Time
	cache map[[32]byte]challengeEntry
}

// NewChallengeManager builds a manager issuing challenges valid for ttl and
// holding at most max outstanding entries. max <= 0 is treated as unbounded
// (used only by tests that need explicit eviction control).
func NewChallengeManager(ttl time.Duration, max int) *ChallengeManager {
	return &ChallengeManager{
		ttl:   ttl,
		max:   max,
		now:   time.Now,
		cache: make(map[[32]byte]challengeEntry),
	}
}

// SetClock overrides the wall clock (deterministic tests).
func (m *ChallengeManager) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// nodeIDBytes normalizes a node identifier to the frozen 16-byte transcript
// width: values longer than 16 bytes are rejected (the wire format cannot
// carry them); shorter values are zero-padded deterministically so Issue and
// ValidateAndConsume always compare the same canonical form.
func nodeIDBytes(nodeID string) ([16]byte, error) {
	var out [16]byte
	if len(nodeID) > 16 {
		return out, errors.New("security: node id exceeds 16 bytes")
	}
	copy(out[:], nodeID)
	return out, nil
}

// Signer signs a domain-separated message (implemented by Keyring and by raw
// ed25519 keys via SignerFunc).
type Signer interface {
	Sign(msg []byte) ([]byte, error)
}

// SignerFunc adapts a signing function to the Signer interface.
type SignerFunc func(msg []byte) ([]byte, error)

// Sign implements Signer.
func (f SignerFunc) Sign(msg []byte) ([]byte, error) { return f(msg) }

// Issue creates, caches, and signs a fresh EnrollChallenge for nodeID with a
// random server nonce. It returns the challenge and its raw signed bytes
// (canonical fields || signature), ready for the wire. The challenge binds
// controller identity, key ID, node, protocol versions, and an absolute
// expiry.
func (m *ChallengeManager) Issue(signer Signer, instance [16]byte, keyID, nodeID string) (protocol.EnrollChallenge, []byte, error) {
	node, err := nodeIDBytes(nodeID)
	if err != nil {
		return protocol.EnrollChallenge{}, nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.max > 0 {
		// Evict expired entries; if still full, fail closed (resource bound).
		now := m.now()
		for h, e := range m.cache {
			if !e.expiry.After(now) {
				delete(m.cache, h)
			}
		}
		if len(m.cache) >= m.max {
			return protocol.EnrollChallenge{}, nil, ErrChallengeCacheFull
		}
	}

	var nonce [protocol.EnrollNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return protocol.EnrollChallenge{}, nil, err
	}
	ch := protocol.EnrollChallenge{
		ControllerInstanceID: instance,
		ControllerKeyID:      keyID,
		NodeID:               node,
		ServerNonce:          nonce,
		ProtocolVersions:     protocol.EnrollVersion,
		ExpiryUnix:           uint64(m.now().Add(m.ttl).Unix()),
	}
	hash := sha256.Sum256(ch.Canonical())
	m.cache[hash] = challengeEntry{
		nodeID:   nodeID,
		instance: instance,
		expiry:   m.now().Add(m.ttl),
	}
	sig, err := signer.Sign(ch.SigningBytes())
	if err != nil {
		delete(m.cache, hash)
		return protocol.EnrollChallenge{}, nil, err
	}
	raw := append(ch.Canonical(), sig...)
	return ch, raw, nil
}

// ValidateAndConsume checks an EnrollRequest's challenge hash: it must be a
// known, unexpired, unconsumed challenge. On success the challenge is consumed
// (nonce replay protection) and the node id the challenge was issued for is
// returned — the caller binds the request to that node (the EnrollRequest
// carries no node id of its own; the challenge is the node identity). Failed
// attempts never consume the challenge.
func (m *ChallengeManager) ValidateAndConsume(hash [32]byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, ok := m.cache[hash]
	if !ok {
		return "", ErrChallengeUnknown
	}
	if !entry.expiry.After(m.now()) {
		delete(m.cache, hash)
		return "", ErrChallengeExpired
	}
	if entry.used {
		return "", ErrChallengeReplayed
	}
	entry.used = true
	m.cache[hash] = entry
	return entry.nodeID, nil
}

// Size returns the number of cached challenges (tests + observability).
func (m *ChallengeManager) Size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cache)
}

// ---------------------------------------------------------------------------
// Session handshake transcript
//
// The control session is established by a mutual challenge over the bounded
// WebSocket before any envelope traffic (P08-owned wire element, additive to
// the frozen contracts which do not define session establishment; v0.8 §6.3
// requires a handshake whose final message the Agent persists before socket
// activation). All three messages are canonical length-prefixed field lists
// signed with Ed25519 over a domain-separated input, mirroring the frozen
// enrollment transcript encoding (docs/protocol.md §4).
// ---------------------------------------------------------------------------

// SessionDomain separates the session handshake signature inputs.
const SessionDomain = "AntiNAT-Session-v1"

// Session message size bounds (pre-filter, mirrors enrollment codec style).
// Each bound = 4-byte length prefix per field + field caps + 64-byte sig.
const (
	SessionNonceSize  = 32
	SessionIDMax      = 255
	SessionIDSize     = 16
	SessionHelloMax   = 7*4 + SessionIDSize + SessionIDSize + 4 + 32 + SessionNonceSize + 8 + 1 + 64
	SessionWelcomeMax = 8*4 + SessionIDSize + SessionIDMax + SessionIDSize + SessionNonceSize + SessionNonceSize + 8 + SessionIDMax + 8 + 64
	SessionFinalMax   = 5*4 + SessionIDSize + SessionIDSize + SessionNonceSize + 8 + SessionIDMax + 64
)

// SessionHello is the Agent→Controller session request (signed by the Agent
// node key). It carries the agent public key (the controller stores only its
// hash, so the hello is the key-presentation step), the highest accepted
// epoch (rollback detection), and a fresh nonce.
type SessionHello struct {
	ControllerInstanceID [16]byte
	NodeID               [16]byte
	AgentCredentialVer   uint32
	AgentPublicKey       [32]byte
	AgentNonce           [SessionNonceSize]byte
	AgentMaxEpoch        uint64
	ProtocolVersions     string
}

// NodeIDString returns the store-form (NUL-trimmed) node id.
func (h SessionHello) NodeIDString() string {
	return strings.TrimRight(string(h.NodeID[:]), "\x00")
}

// PublicKey returns the presented agent public key.
func (h SessionHello) PublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(append([]byte(nil), h.AgentPublicKey[:]...))
}

// SessionWelcome is the Controller→Agent grant (signed by the Controller
// signing key): the echoed agent nonce, a fresh server nonce, the granted
// connection epoch, and the session id.
type SessionWelcome struct {
	ControllerInstanceID [16]byte
	ControllerKeyID      string
	NodeID               [16]byte
	AgentNonce           [SessionNonceSize]byte
	ServerNonce          [SessionNonceSize]byte
	ConnectionEpoch      uint64
	SessionID            string
	ExpiryUnix           uint64
}

// SessionFinal is the Agent→Controller handshake final (signed by the Agent
// key): the echoed server nonce plus the accepted epoch/session. The Agent
// persists the epoch/session BEFORE sending this message and enabling the
// socket (v0.8 §6.3).
type SessionFinal struct {
	ControllerInstanceID [16]byte
	NodeID               [16]byte
	ServerNonce          [SessionNonceSize]byte
	ConnectionEpoch      uint64
	SessionID            string
}

func sessionEncode(fields ...[]byte) []byte {
	out := make([]byte, 0, 128)
	for _, f := range fields {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		out = append(out, l[:]...)
		out = append(out, f...)
	}
	return out
}

func sessionU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func sessionU64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func sessionSign(priv ed25519.PrivateKey, domain string, fields []byte) ([]byte, error) {
	return framecrypto.Sign(priv, append([]byte(domain), fields...))
}

func sessionVerify(pub ed25519.PublicKey, domain string, fields, sig []byte) bool {
	return framecrypto.Verify(pub, append([]byte(domain), fields...), sig)
}

// Canonical renders the length-prefixed field list.
func (h SessionHello) Canonical() []byte {
	return sessionEncode(
		h.ControllerInstanceID[:], h.NodeID[:], sessionU32(h.AgentCredentialVer),
		h.AgentPublicKey[:], h.AgentNonce[:], sessionU64(h.AgentMaxEpoch),
		[]byte(h.ProtocolVersions),
	)
}

// Sign returns the domain-separated Ed25519 signature of the hello.
func (h SessionHello) Sign(priv ed25519.PrivateKey) ([]byte, error) {
	return sessionSign(priv, SessionDomain, h.Canonical())
}

// ParseSessionHello decodes a SessionHello and verifies its signature against
// the public key PRESENTED INSIDE the message (the controller then checks
// that key against the stored credential hash). It validates every fixed
// width before any copy.
func ParseSessionHello(raw []byte) (SessionHello, error) {
	var h SessionHello
	if len(raw) > SessionHelloMax {
		return h, errors.New("security: session hello too large")
	}
	fields, sig, err := splitFields(raw)
	if err != nil {
		return h, err
	}
	parts, err := readFields(fields, 7)
	if err != nil {
		return h, err
	}
	if len(parts[0]) != 16 || len(parts[1]) != 16 || len(parts[2]) != 4 ||
		len(parts[3]) != 32 || len(parts[4]) != SessionNonceSize || len(parts[5]) != 8 {
		return h, errors.New("security: session hello malformed")
	}
	copy(h.ControllerInstanceID[:], parts[0])
	copy(h.NodeID[:], parts[1])
	h.AgentCredentialVer = binary.BigEndian.Uint32(parts[2])
	copy(h.AgentPublicKey[:], parts[3])
	copy(h.AgentNonce[:], parts[4])
	h.AgentMaxEpoch = binary.BigEndian.Uint64(parts[5])
	h.ProtocolVersions = string(parts[6])
	if h.AgentCredentialVer == 0 {
		return h, errors.New("security: session hello zero credential version")
	}
	if !sessionVerify(h.PublicKey(), SessionDomain, h.Canonical(), sig) {
		return h, errors.New("security: session hello signature invalid")
	}
	return h, nil
}

// Canonical renders the length-prefixed field list.
func (w SessionWelcome) Canonical() []byte {
	return sessionEncode(
		w.ControllerInstanceID[:], []byte(w.ControllerKeyID), w.NodeID[:],
		w.AgentNonce[:], w.ServerNonce[:], sessionU64(w.ConnectionEpoch),
		[]byte(w.SessionID), sessionU64(w.ExpiryUnix),
	)
}

// Sign returns the domain-separated Ed25519 signature of the welcome.
func (w SessionWelcome) Sign(priv ed25519.PrivateKey) ([]byte, error) {
	return sessionSign(priv, SessionDomain, w.Canonical())
}

// ParseSessionWelcome decodes and verifies a SessionWelcome against the
// pinned Controller public key.
func ParseSessionWelcome(raw []byte, controllerPub ed25519.PublicKey) (SessionWelcome, error) {
	var w SessionWelcome
	if len(raw) > SessionWelcomeMax {
		return w, errors.New("security: session welcome too large")
	}
	fields, sig, err := splitFields(raw)
	if err != nil {
		return w, err
	}
	parts, err := readFields(fields, 8)
	if err != nil {
		return w, err
	}
	if len(parts[0]) != 16 || len(parts[2]) != 16 || len(parts[3]) != SessionNonceSize ||
		len(parts[4]) != SessionNonceSize || len(parts[5]) != 8 || len(parts[7]) != 8 {
		return w, errors.New("security: session welcome malformed")
	}
	copy(w.ControllerInstanceID[:], parts[0])
	w.ControllerKeyID = string(parts[1])
	copy(w.NodeID[:], parts[2])
	copy(w.AgentNonce[:], parts[3])
	copy(w.ServerNonce[:], parts[4])
	w.ConnectionEpoch = binary.BigEndian.Uint64(parts[5])
	w.SessionID = string(parts[6])
	w.ExpiryUnix = binary.BigEndian.Uint64(parts[7])
	if w.ControllerKeyID == "" || w.SessionID == "" {
		return w, errors.New("security: session welcome empty key/session id")
	}
	if !sessionVerify(controllerPub, SessionDomain, w.Canonical(), sig) {
		return w, errors.New("security: session welcome signature invalid")
	}
	return w, nil
}

// Canonical renders the length-prefixed field list.
func (f SessionFinal) Canonical() []byte {
	return sessionEncode(
		f.ControllerInstanceID[:], f.NodeID[:], f.ServerNonce[:],
		sessionU64(f.ConnectionEpoch), []byte(f.SessionID),
	)
}

// Sign returns the domain-separated Ed25519 signature of the final.
func (f SessionFinal) Sign(priv ed25519.PrivateKey) ([]byte, error) {
	return sessionSign(priv, SessionDomain, f.Canonical())
}

// ParseSessionFinal decodes and verifies a SessionFinal against the Agent
// public key.
func ParseSessionFinal(raw []byte, agentPub ed25519.PublicKey) (SessionFinal, error) {
	var f SessionFinal
	if len(raw) > SessionFinalMax {
		return f, errors.New("security: session final too large")
	}
	fields, sig, err := splitFields(raw)
	if err != nil {
		return f, err
	}
	parts, err := readFields(fields, 5)
	if err != nil {
		return f, err
	}
	if len(parts[0]) != 16 || len(parts[1]) != 16 || len(parts[2]) != SessionNonceSize || len(parts[3]) != 8 {
		return f, errors.New("security: session final malformed")
	}
	copy(f.ControllerInstanceID[:], parts[0])
	copy(f.NodeID[:], parts[1])
	copy(f.ServerNonce[:], parts[2])
	f.ConnectionEpoch = binary.BigEndian.Uint64(parts[3])
	f.SessionID = string(parts[4])
	if f.SessionID == "" {
		return f, errors.New("security: session final empty session id")
	}
	if !sessionVerify(agentPub, SessionDomain, f.Canonical(), sig) {
		return f, errors.New("security: session final signature invalid")
	}
	return f, nil
}

// splitFields separates the canonical field bytes from the trailing
// 64-byte signature.
func splitFields(raw []byte) (fields, sig []byte, err error) {
	if len(raw) < 64 {
		return nil, nil, errors.New("security: message shorter than signature")
	}
	sig = raw[len(raw)-64:]
	fields = raw[:len(raw)-64]
	if len(fields) == 0 {
		return nil, nil, errors.New("security: empty message fields")
	}
	return fields, sig, nil
}

// MessageID deterministically derives a 16-byte message id from an operation
// id and message type. The controller outbox and the agent journal store
// SEMANTIC payloads only; the envelope message id must be reproducible on
// reconnect so the same operation/message id is re-enveloped and the receiver
// dedups redelivery (v0.8 §6.1, protocol.md §3.5).
func MessageID(operationID, messageType string) [16]byte {
	h := sha256.Sum256([]byte("antinat-msgid-v1\x00" + operationID + "\x00" + messageType))
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

// readFields parses count length-prefixed fields with full bounds checks and
// rejects trailing bytes.
func readFields(b []byte, count int) ([][]byte, error) {
	parts := make([][]byte, 0, count)
	idx := 0
	for i := 0; i < count; i++ {
		if len(b)-idx < 4 {
			return nil, errors.New("security: truncated length prefix")
		}
		l := binary.BigEndian.Uint32(b[idx : idx+4])
		idx += 4
		if uint64(l) > uint64(len(b)-idx) {
			return nil, errors.New("security: field length exceeds message")
		}
		parts = append(parts, b[idx:idx+int(l)])
		idx += int(l)
	}
	if idx != len(b) {
		return nil, errors.New("security: trailing bytes after fields")
	}
	return parts, nil
}
