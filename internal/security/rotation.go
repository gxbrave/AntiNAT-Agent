// P14 Story 4: keyring rotation certificate (v0.8 §8.3).
//
// The Controller key-rotation certificate is signed by the OLD key and binds
// the old/new key IDs, public keys, generation, not-before window and the
// overlap deadline. An Agent accepts a new pin only for a valid certificate
// from its currently pinned key that carries a HIGHER generation (anti-
// downgrade). The wire form is JSON; the signature covers the canonical
// concatenation of the binding fields so a re-encode always verifies.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gxbrave/AntiNAT-Agent/internal/security/framecrypto"
)

// RotationDomain is the domain separator for rotation certificate signing.
const RotationDomain = "AntiNAT-Rotate-v1"

// RotateVersion marks the canonical certificate encoding.
const RotateVersion = 1

// RotationCertificate binds one key generation to its successor (signed by the
// old key). The overlap deadline is the instant after which a normal retire
// may proceed without every offline Agent's ACK; force-retire bypasses it and
// then requires manual re-pin/re-enroll.
type RotationCertificate struct {
	Version             uint16 `json:"version"`
	Scope               string `json:"scope"` // 'controller' | 'agent' | 'master' | 'hook' | 'probe'
	OldKeyID            string `json:"old_key_id"`
	OldGeneration       uint64 `json:"old_generation"`
	OldPublicKeyHex     string `json:"old_public_key"`
	NewKeyID            string `json:"new_key_id"`
	NewGeneration       uint64 `json:"new_generation"`
	NewPublicKeyHex     string `json:"new_public_key"`
	NotBeforeUnix       int64  `json:"not_before_unix"`
	OverlapDeadlineUnix int64  `json:"overlap_deadline_unix"`
	SignatureHex        string `json:"signature"`
}

// ErrRotationInvalid is the fail-closed certificate error.
var ErrRotationInvalid = errors.New("security: invalid rotation certificate")

// NewRotationCertificate assembles (unsigned) a rotation binding from the old
// and new keys. The old key's ID/generation are embedded and the certificate
// is signed by the old private key in Sign.
func NewRotationCertificate(scope string, oldPub ed25519.PublicKey, oldGeneration uint64, oldKeyID string, newPub ed25519.PublicKey, newGeneration uint64, newKeyID string, notBeforeUnix, overlapDeadlineUnix int64) RotationCertificate {
	return RotationCertificate{
		Version:             RotateVersion,
		Scope:               scope,
		OldKeyID:            oldKeyID,
		OldGeneration:       oldGeneration,
		OldPublicKeyHex:     hex.EncodeToString(oldPub),
		NewKeyID:            newKeyID,
		NewGeneration:       newGeneration,
		NewPublicKeyHex:     hex.EncodeToString(newPub),
		NotBeforeUnix:       notBeforeUnix,
		OverlapDeadlineUnix: overlapDeadlineUnix,
	}
}

// PublicKeys returns the decoded public keys.
func (c RotationCertificate) PublicKeys() (ed25519.PublicKey, ed25519.PublicKey, error) {
	oldRaw, err := hex.DecodeString(c.OldPublicKeyHex)
	if err != nil || len(oldRaw) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: old public key", ErrRotationInvalid)
	}
	newRaw, err := hex.DecodeString(c.NewPublicKeyHex)
	if err != nil || len(newRaw) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: new public key", ErrRotationInvalid)
	}
	return ed25519.PublicKey(oldRaw), ed25519.PublicKey(newRaw), nil
}

// canonicalFields renders the exact signed byte string. Signature and JSON
// wrappers are excluded; re-encoding must be deterministic.
func (c RotationCertificate) canonicalFields() []byte {
	var buf []byte
	appendField := func(s string) {
		var l [2]byte
		l[0] = byte(len(s) >> 8)
		l[1] = byte(len(s))
		buf = append(buf, l[:]...)
		buf = append(buf, s...)
	}
	appendU64 := func(v uint64) {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(v >> (8 * (7 - i)))
		}
		buf = append(buf, b[:]...)
	}
	appendU16 := func(v uint16) {
		buf = append(buf, byte(v>>8), byte(v))
	}
	appendU16(c.Version)
	appendField(c.Scope)
	appendField(c.OldKeyID)
	appendU64(c.OldGeneration)
	appendField(c.OldPublicKeyHex)
	appendField(c.NewKeyID)
	appendU64(c.NewGeneration)
	appendField(c.NewPublicKeyHex)
	appendU64(uint64(c.NotBeforeUnix))
	appendU64(uint64(c.OverlapDeadlineUnix))
	return buf
}

// sign computes the domain-separated signature over the canonical fields.
func (c *RotationCertificate) sign(oldKey ed25519.PrivateKey) error {
	fields := c.canonicalFields()
	sig, err := framecrypto.Sign(oldKey, append([]byte(RotationDomain), fields...))
	if err != nil {
		return err
	}
	c.SignatureHex = hex.EncodeToString(sig)
	return nil
}

// SignRotationCertificate signs the certificate with the old (current) key.
// It is the public signer used by the controller lifecycle orchestrator.
func SignRotationCertificate(c *RotationCertificate, oldKey ed25519.PrivateKey) error {
	return c.sign(oldKey)
}

// MarshalJSON renders the signed certificate.
func (c RotationCertificate) Encode() (string, error) {
	if c.SignatureHex == "" {
		return "", fmt.Errorf("%w: unsigned certificate", ErrRotationInvalid)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Decode parses a rotation certificate. It verifies the signature against the
// pinned (old) public key and enforces the generation strictly increases.
func DecodeRotationCertificate(raw []byte, pinnedPub ed25519.PublicKey) (RotationCertificate, error) {
	var c RotationCertificate
	if len(raw) == 0 || len(raw) > 1<<16 {
		return c, fmt.Errorf("%w: bad length", ErrRotationInvalid)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("%w: json: %v", ErrRotationInvalid, err)
	}
	if c.Version != RotateVersion {
		return c, fmt.Errorf("%w: unsupported version %d", ErrRotationInvalid, c.Version)
	}
	// Controller rotation certificates have one protocol scope. Accepting a
	// blank or foreign scope would let a valid old-key signature be replayed in
	// another key domain.
	if c.Scope != "controller" {
		return c, fmt.Errorf("%w: unsupported rotation scope %q", ErrRotationInvalid, c.Scope)
	}
	if c.NewGeneration <= c.OldGeneration {
		return c, fmt.Errorf("%w: generation does not increase (%d -> %d)", ErrRotationInvalid, c.OldGeneration, c.NewGeneration)
	}
	// The window is structurally required, but the decoder deliberately does
	// not compare NotBefore with wall clock: a future not-before is a legitimate
	// overlap schedule and runtime clock policy is outside this certificate
	// parser's contract.
	if c.NotBeforeUnix == 0 || c.OverlapDeadlineUnix == 0 || c.NotBeforeUnix > c.OverlapDeadlineUnix {
		return c, fmt.Errorf("%w: malformed rotation validity window", ErrRotationInvalid)
	}
	oldPub, newPub, err := c.PublicKeys()
	if err != nil {
		return c, err
	}
	if !bytesEqual(oldPub, pinnedPub) {
		return c, fmt.Errorf("%w: certificate is not bound to the currently pinned key", ErrRotationInvalid)
	}
	if c.OldKeyID != KeyIDOf(pinnedPub) {
		return c, fmt.Errorf("%w: old key id does not match the pinned public key", ErrRotationInvalid)
	}
	if len(c.SignatureHex) == 0 || c.NewKeyID == "" || c.OldKeyID == "" {
		return c, fmt.Errorf("%w: incomplete certificate", ErrRotationInvalid)
	}
	sig, err := hex.DecodeString(c.SignatureHex)
	if err != nil {
		return c, fmt.Errorf("%w: signature hex", ErrRotationInvalid)
	}
	fields := c.canonicalFields()
	if !framecrypto.Verify(oldPub, append([]byte(RotationDomain), fields...), sig) {
		return c, fmt.Errorf("%w: signature does not verify against the pinned key", ErrRotationInvalid)
	}
	if rotationKeyID(newPub) != c.NewKeyID {
		return c, fmt.Errorf("%w: new key id does not match new public key", ErrRotationInvalid)
	}
	return c, nil
}

// GenerateNewKeyringKey returns a fresh Ed25519 signing key (the successor).
func GenerateNewKeyringKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func rotationKeyID(pub ed25519.PublicKey) string {
	return KeyIDOf(pub)
}

// KeyIDOf returns the deterministic 8-byte hex key id for a public key,
// matching Keyring.KeyID and the rotation certificate binding.
func KeyIDOf(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
