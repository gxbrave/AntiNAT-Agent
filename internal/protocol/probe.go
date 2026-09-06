// Probe wire frames and operation state machine (docs/protocol.md §7).
//
// Two-phase arm + provider-hidden challenge, same-path Agent signature, and
// signed control receipt. The arm never contains the challenge; the provider
// introduces the challenge only at WAN ingress. Invalid ingress exposes one
// generic rejection with zero authenticated material (anti-oracle).
//
// All frames are fixed binary (never JSON). Length-prefixed fields use a
// 1-byte length prefix (fields are <= 255 bytes). All multi-byte integers
// are big-endian.
package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/security/framecrypto"
)

// Probe frame constants frozen by docs/protocol.md §7.
const (
	ProbeMagicArm     = "ARM1"
	ProbeMagicArmed   = "RDY1"
	ProbeMagicWAN     = "WAN1"
	ProbeMagicACK     = "ACK1"
	ProbeMagicReceipt = "RCT1"

	ProbeIDLen         = 16
	ProbeProviderIDLen = 16
	ProbeActivationLen = 16
	ProbeNonceLen      = 32
	ProbeOpaqueLen     = 16
	ProbeDigestLen     = sha256.Size
	ProbeEndpointMax   = 255

	ProbeReplayWindow = 5 * time.Minute
	ProbeTTLMax       = 24 * time.Hour

	// ProbeOpMax bounds the number of concurrently armed probe operations
	// the ProbeAgent keeps in memory. Frozen docs/protocol.md §7.6 requires
	// probe state to be bounded and expirable; arming beyond this cap fails
	// with ErrProbeStateFull (an implementation resource bound, not a wire
	// constant).
	ProbeOpMax = 1024
)

// Probe frame maximum: magic + digest + ids + activation + 1-byte endpoint
// length + endpoint + opaque + challenge + signature.
const (
	probeFrameMax = 4 + 32 + 16 + 16 + 16 + 1 + ProbeEndpointMax + 16 + 32 + ed25519.SignatureSize
)

// Stable probe rejection reasons.
var (
	ErrProbeMalformed  = errors.New("protocol: malformed probe frame")
	ErrProbeSignature  = errors.New("protocol: probe frame signature verification failed")
	ErrProbeReplay     = errors.New("protocol: probe ID is in the replay cache")
	ErrProbeIDConflict = errors.New("protocol: probe ID already armed with different material")
	ErrProbeStateFull  = errors.New("protocol: probe state capacity exhausted")
	ErrProbeChallenge  = errors.New("protocol: probe arm must never contain the provider challenge")
	ErrProbeEndpoint   = errors.New("protocol: probe endpoint is not a concrete IPv4:port")
)

// ---------------------------------------------------------------------------
// ProbeArm (ARM1, Controller -> Agent, signed by Controller at the envelope
// layer)
// ---------------------------------------------------------------------------

// ProbeArm is the arm command delivered inside a signed control envelope.
// It never carries the provider challenge or any per-probe secret.
type ProbeArm struct {
	ProbeID           [ProbeIDLen]byte
	ProviderID        [ProbeProviderIDLen]byte
	ProviderPublicKey [ed25519.PublicKeySize]byte
	ExpectedSourceIP  [4]byte
	Activation        [ProbeActivationLen]byte
	Endpoint          string
	TTLMS             uint64
	ExpiryOpaque      [ProbeOpaqueLen]byte
}

// Canonical renders the exact signed bytes (the magic carries the domain).
func (arm ProbeArm) Canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString(ProbeMagicArm)
	buf.Write(arm.ProbeID[:])
	buf.Write(arm.ProviderID[:])
	buf.Write(arm.ProviderPublicKey[:])
	buf.Write(arm.ExpectedSourceIP[:])
	buf.Write(arm.Activation[:])
	buf.WriteByte(byte(len(arm.Endpoint)))
	buf.WriteString(arm.Endpoint)
	var ttl [8]byte
	binary.BigEndian.PutUint64(ttl[:], arm.TTLMS)
	buf.Write(ttl[:])
	buf.Write(arm.ExpiryOpaque[:])
	return buf.Bytes()
}

// Digest is the sha256 of the canonical arm, the binding key for every
// downstream frame.
func (arm ProbeArm) Digest() [ProbeDigestLen]byte {
	return sha256.Sum256(arm.Canonical())
}

// ProviderKey returns the provider public key pinned by the arm.
func (arm ProbeArm) ProviderKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), arm.ProviderPublicKey[:]...)
}

// Validate enforces the frozen arm invariants.
func (arm ProbeArm) Validate() error {
	if arm.ProviderID == ([ProbeProviderIDLen]byte{}) || arm.ProbeID == ([ProbeIDLen]byte{}) {
		return ErrProbeMalformed
	}
	if arm.TTLMS == 0 || arm.TTLMS > uint64(ProbeTTLMax/time.Millisecond) {
		return ErrProbeMalformed
	}
	if len(arm.Endpoint) == 0 || len(arm.Endpoint) > ProbeEndpointMax {
		return ErrProbeMalformed
	}
	if err := ValidateProbeEndpoint(arm.Endpoint); err != nil {
		return err
	}
	return nil
}

// ParseProbeArm decodes and validates an ARM1 frame. The Controller signature
// is checked at the enclosing control-envelope layer, not here.
func ParseProbeArm(raw []byte) (ProbeArm, error) {
	var arm ProbeArm
	const fixed = 4 + ProbeIDLen + ProbeProviderIDLen + ed25519.PublicKeySize + 4 + ProbeActivationLen + 1
	if len(raw) < fixed || len(raw) > probeFrameMax || !bytes.Equal(raw[:4], []byte(ProbeMagicArm)) {
		return arm, ErrProbeMalformed
	}
	endpointLen := int(raw[fixed-1])
	expected := fixed + endpointLen + 8 + ProbeOpaqueLen
	if endpointLen == 0 || len(raw) != expected {
		return arm, ErrProbeMalformed
	}
	copy(arm.ProbeID[:], raw[4:4+ProbeIDLen])
	copy(arm.ProviderID[:], raw[4+ProbeIDLen:4+ProbeIDLen+ProbeProviderIDLen])
	copy(arm.ProviderPublicKey[:], raw[4+ProbeIDLen+ProbeProviderIDLen:4+ProbeIDLen+ProbeProviderIDLen+ed25519.PublicKeySize])
	copy(arm.ExpectedSourceIP[:], raw[4+ProbeIDLen+ProbeProviderIDLen+ed25519.PublicKeySize:4+ProbeIDLen+ProbeProviderIDLen+ed25519.PublicKeySize+4])
	copy(arm.Activation[:], raw[4+ProbeIDLen+ProbeProviderIDLen+ed25519.PublicKeySize+4:4+ProbeIDLen+ProbeProviderIDLen+ed25519.PublicKeySize+4+ProbeActivationLen])
	arm.Endpoint = string(raw[fixed : fixed+endpointLen])
	arm.TTLMS = binary.BigEndian.Uint64(raw[fixed+endpointLen : fixed+endpointLen+8])
	copy(arm.ExpiryOpaque[:], raw[fixed+endpointLen+8:])
	if err := arm.Validate(); err != nil {
		return arm, err
	}
	return arm, nil
}

// ---------------------------------------------------------------------------
// ProbeArmed (RDY1, Agent -> Controller, signed by node key)
// ---------------------------------------------------------------------------

// ProbeArmed is the durable armed response binding the arm digest.
type ProbeArmed struct {
	ArmDigest [ProbeDigestLen]byte
	Signature []byte
}

// SigningBytes is RDY1 || arm_digest.
func (a ProbeArmed) SigningBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(ProbeMagicArmed)
	buf.Write(a.ArmDigest[:])
	return buf.Bytes()
}

// ParseProbeArmed decodes and verifies an RDY1 frame against the node key and
// the expected arm digest.
func ParseProbeArmed(raw []byte, nodePub ed25519.PublicKey, wantDigest [ProbeDigestLen]byte) (ProbeArmed, error) {
	var a ProbeArmed
	const fixed = 4 + ProbeDigestLen
	if len(raw) != fixed+ed25519.SignatureSize || !bytes.Equal(raw[:4], []byte(ProbeMagicArmed)) {
		return a, ErrProbeMalformed
	}
	copy(a.ArmDigest[:], raw[4:fixed])
	a.Signature = append([]byte(nil), raw[fixed:]...)
	if a.ArmDigest != wantDigest {
		return a, ErrProbeMalformed
	}
	if !framecrypto.Verify(nodePub, a.SigningBytes(), a.Signature) {
		return a, ErrProbeSignature
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// ProviderFrame (WAN1, Provider -> Agent, signed by the arm's provider key)
// ---------------------------------------------------------------------------

// ProviderFrame introduces the challenge at WAN ingress.
type ProviderFrame struct {
	ArmDigest    [ProbeDigestLen]byte
	ProbeID      [ProbeIDLen]byte
	ProviderID   [ProbeProviderIDLen]byte
	Activation   [ProbeActivationLen]byte
	Endpoint     string
	ExpiryOpaque [ProbeOpaqueLen]byte
	Challenge    [ProbeNonceLen]byte
	Signature    []byte
}

// Canonical renders the exact signed bytes before the signature.
func (f ProviderFrame) Canonical() []byte {
	var buf bytes.Buffer
	buf.WriteString(ProbeMagicWAN)
	buf.Write(f.ArmDigest[:])
	buf.Write(f.ProbeID[:])
	buf.Write(f.ProviderID[:])
	buf.Write(f.Activation[:])
	buf.WriteByte(byte(len(f.Endpoint)))
	buf.WriteString(f.Endpoint)
	buf.Write(f.ExpiryOpaque[:])
	buf.Write(f.Challenge[:])
	return buf.Bytes()
}

// SigningBytes is the canonical WAN frame (magic included).
func (f ProviderFrame) SigningBytes() []byte {
	return f.Canonical()
}

// ChallengeHash is the sha256 of the introduced challenge.
func (f ProviderFrame) ChallengeHash() [ProbeDigestLen]byte {
	return sha256.Sum256(f.Challenge[:])
}

// ParseProviderFrame decodes a WAN1 frame. The signature is NOT checked here;
// it is checked against the arm's provider key by the agent state machine.
func ParseProviderFrame(raw []byte) (ProviderFrame, error) {
	var f ProviderFrame
	const fixed = 4 + ProbeDigestLen + ProbeIDLen + ProbeProviderIDLen + ProbeActivationLen + 1
	if len(raw) < fixed || len(raw) > probeFrameMax || !bytes.Equal(raw[:4], []byte(ProbeMagicWAN)) {
		return f, ErrProbeMalformed
	}
	endpointLen := int(raw[fixed-1])
	const trailer = ProbeOpaqueLen + ProbeNonceLen + ed25519.SignatureSize
	expected := fixed + endpointLen + trailer
	if endpointLen == 0 || len(raw) != expected {
		return f, ErrProbeMalformed
	}
	copy(f.ArmDigest[:], raw[4:4+ProbeDigestLen])
	copy(f.ProbeID[:], raw[4+ProbeDigestLen:4+ProbeDigestLen+ProbeIDLen])
	copy(f.ProviderID[:], raw[4+ProbeDigestLen+ProbeIDLen:4+ProbeDigestLen+ProbeIDLen+ProbeProviderIDLen])
	copy(f.Activation[:], raw[4+ProbeDigestLen+ProbeIDLen+ProbeProviderIDLen:4+ProbeDigestLen+ProbeIDLen+ProbeProviderIDLen+ProbeActivationLen])
	f.Endpoint = string(raw[fixed : fixed+endpointLen])
	if err := ValidateProbeEndpoint(f.Endpoint); err != nil {
		return f, err
	}
	trailerStart := fixed + endpointLen
	copy(f.ExpiryOpaque[:], raw[trailerStart:trailerStart+ProbeOpaqueLen])
	copy(f.Challenge[:], raw[trailerStart+ProbeOpaqueLen:trailerStart+ProbeOpaqueLen+ProbeNonceLen])
	f.Signature = append([]byte(nil), raw[trailerStart+ProbeOpaqueLen+ProbeNonceLen:]...)
	return f, nil
}

// ---------------------------------------------------------------------------
// ProbeACK (ACK1, Agent -> Provider, same path, signed by node key)
// ---------------------------------------------------------------------------

// ProbeACK proves the WAN ingress/return path.
type ProbeACK struct {
	ArmDigest     [ProbeDigestLen]byte
	ChallengeHash [ProbeDigestLen]byte
	Signature     []byte
}

// SigningBytes is ACK1 || arm_digest || challenge_hash.
func (a ProbeACK) SigningBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(ProbeMagicACK)
	buf.Write(a.ArmDigest[:])
	buf.Write(a.ChallengeHash[:])
	return buf.Bytes()
}

// ParseProbeACK decodes and verifies an ACK1 frame against the node key.
func ParseProbeACK(raw []byte, nodePub ed25519.PublicKey) (ProbeACK, error) {
	var a ProbeACK
	const fixed = 4 + ProbeDigestLen + ProbeDigestLen
	if len(raw) != fixed+ed25519.SignatureSize || !bytes.Equal(raw[:4], []byte(ProbeMagicACK)) {
		return a, ErrProbeMalformed
	}
	copy(a.ArmDigest[:], raw[4:4+ProbeDigestLen])
	copy(a.ChallengeHash[:], raw[4+ProbeDigestLen:fixed])
	a.Signature = append([]byte(nil), raw[fixed:]...)
	if !framecrypto.Verify(nodePub, a.SigningBytes(), a.Signature) {
		return a, ErrProbeSignature
	}
	return a, nil
}

// ---------------------------------------------------------------------------
// ProbeReceipt (RCT1, Agent -> Controller control channel, signed by node key)
// ---------------------------------------------------------------------------

// ProbeReceipt is the signed control receipt for a provider frame.
type ProbeReceipt struct {
	ArmDigest     [ProbeDigestLen]byte
	ChallengeHash [ProbeDigestLen]byte
	ProviderID    [ProbeProviderIDLen]byte
	Signature     []byte
}

// SigningBytes is RCT1 || arm_digest || challenge_hash || provider_id.
func (r ProbeReceipt) SigningBytes() []byte {
	var buf bytes.Buffer
	buf.WriteString(ProbeMagicReceipt)
	buf.Write(r.ArmDigest[:])
	buf.Write(r.ChallengeHash[:])
	buf.Write(r.ProviderID[:])
	return buf.Bytes()
}

// ParseProbeReceipt decodes and verifies an RCT1 frame against the node key.
func ParseProbeReceipt(raw []byte, nodePub ed25519.PublicKey) (ProbeReceipt, error) {
	var r ProbeReceipt
	const fixed = 4 + ProbeDigestLen + ProbeDigestLen + ProbeProviderIDLen
	if len(raw) != fixed+ed25519.SignatureSize || !bytes.Equal(raw[:4], []byte(ProbeMagicReceipt)) {
		return r, ErrProbeMalformed
	}
	copy(r.ArmDigest[:], raw[4:4+ProbeDigestLen])
	copy(r.ChallengeHash[:], raw[4+ProbeDigestLen:4+2*ProbeDigestLen])
	copy(r.ProviderID[:], raw[4+2*ProbeDigestLen:fixed])
	r.Signature = append([]byte(nil), raw[fixed:]...)
	if !framecrypto.Verify(nodePub, r.SigningBytes(), r.Signature) {
		return r, ErrProbeSignature
	}
	return r, nil
}

// ---------------------------------------------------------------------------
// ProbeAgent state machine: arm -> provider ingress -> same-path ACK +
// control receipt, consumed exactly once, replay-cached, anti-oracle.
// ---------------------------------------------------------------------------

// armedProbeState is one armed, outstanding probe operation.
type armedProbeState struct {
	arm      ProbeArm
	digest   [ProbeDigestLen]byte
	deadline time.Time
	used     bool
}

// ProbeAgent tracks armed probe operations and the bounded replay cache. The
// durable persistence of an armed operation (bbolt) is owned by a later
// plan; this type is the in-memory state machine over the frozen semantics.
type ProbeAgent struct {
	nodeKey ed25519.PrivateKey
	ops     map[[ProbeIDLen]byte]*armedProbeState
	replay  map[[ProbeIDLen]byte]time.Time
}

// NewProbeAgent creates an empty probe state machine for a node key.
func NewProbeAgent(nodeKey ed25519.PrivateKey) *ProbeAgent {
	return &ProbeAgent{
		nodeKey: nodeKey,
		ops:     map[[ProbeIDLen]byte]*armedProbeState{},
		replay:  map[[ProbeIDLen]byte]time.Time{},
	}
}

// sweep evicts operations whose deadline has passed and replay entries whose
// window has elapsed, keeping both maps bounded and expirable (§7.6). The
// expiry predicates match the readers exactly: an operation dies strictly
// after its deadline, a replay entry dies at-or-after its window end.
func (s *ProbeAgent) sweep(now time.Time) {
	for id, op := range s.ops {
		if now.After(op.deadline) {
			delete(s.ops, id)
		}
	}
	for id, expire := range s.replay {
		if !now.Before(expire) {
			delete(s.replay, id)
		}
	}
}

// ArmProbe validates and persists an arm, returning the signed armed
// response. Re-arm of the same probe ID with identical material is
// idempotent; different material is an ID conflict; a consumed ID within the
// replay window is a replay rejection.
func (s *ProbeAgent) ArmProbe(arm ProbeArm, now time.Time) (ProbeArmed, error) {
	if err := arm.Validate(); err != nil {
		return ProbeArmed{}, err
	}
	digest := arm.Digest()
	// Bounded/expirable state (docs/protocol.md §7.6): evict expired
	// operations and expired replay entries before any read or insert, so
	// the maps never retain state past its deadline and capacity below is
	// measured against live operations only.
	s.sweep(now)
	// Replay/conflict resolution before any state is written.
	if expire, ok := s.replay[arm.ProbeID]; ok {
		if now.Before(expire) {
			if old, ok := s.ops[arm.ProbeID]; ok && old.digest == digest {
				return ProbeArmed{}, ErrProbeReplay
			}
			return ProbeArmed{}, ErrProbeIDConflict
		}
		delete(s.replay, arm.ProbeID)
	}
	if old, ok := s.ops[arm.ProbeID]; ok {
		if old.digest != digest {
			return ProbeArmed{}, ErrProbeIDConflict
		}
		return s.signArmed(digest), nil
	}
	if len(s.ops) >= ProbeOpMax {
		return ProbeArmed{}, ErrProbeStateFull
	}
	s.ops[arm.ProbeID] = &armedProbeState{
		arm:      arm,
		digest:   digest,
		deadline: now.Add(time.Duration(arm.TTLMS) * time.Millisecond),
	}
	return s.signArmed(digest), nil
}

func (s *ProbeAgent) signArmed(digest [ProbeDigestLen]byte) ProbeArmed {
	armed := ProbeArmed{ArmDigest: digest}
	sig, err := framecrypto.Sign(s.nodeKey, armed.SigningBytes())
	if err != nil {
		// A node key of the wrong size is a programming error; fail closed by
		// returning an empty signature that never verifies.
		return ProbeArmed{ArmDigest: digest}
	}
	armed.Signature = sig
	return armed
}

// HandleProbeIngress consumes a provider frame against the armed operation.
// Every failure mode returns false with zero authenticated material; success
// consumes the operation exactly once and records the replay entry.
func (s *ProbeAgent) HandleProbeIngress(frame ProviderFrame, sourceIP [4]byte, now time.Time) (accepted bool) {
	op, ok := s.ops[frame.ProbeID]
	if !ok || op.used || now.After(op.deadline) {
		return false
	}
	arm := op.arm
	if sourceIP != arm.ExpectedSourceIP ||
		frame.ArmDigest != op.digest ||
		frame.ProviderID != arm.ProviderID ||
		frame.Activation != arm.Activation ||
		frame.Endpoint != arm.Endpoint ||
		frame.ExpiryOpaque != arm.ExpiryOpaque ||
		!framecrypto.Verify(arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
		return false
	}
	op.used = true
	s.replay[frame.ProbeID] = now.Add(ProbeReplayWindow)
	return true
}

// VerifyProbeJoin is the Controller-side join: the provider result, the
// Agent same-path ACK, and the Agent control receipt must all bind to the
// same operation, challenge hash, and provider.
func VerifyProbeJoin(arm ProbeArm, frame ProviderFrame, ack ProbeACK, receipt ProbeReceipt, nodePub ed25519.PublicKey) bool {
	if err := arm.Validate(); err != nil {
		return false
	}
	digest := arm.Digest()
	if frame.ArmDigest != digest || ack.ArmDigest != digest || receipt.ArmDigest != digest {
		return false
	}
	if frame.ProbeID != arm.ProbeID || frame.ProviderID != arm.ProviderID ||
		frame.Activation != arm.Activation || frame.Endpoint != arm.Endpoint ||
		frame.ExpiryOpaque != arm.ExpiryOpaque {
		return false
	}
	if receipt.ProviderID != arm.ProviderID {
		return false
	}
	if !framecrypto.Verify(arm.ProviderKey(), frame.SigningBytes(), frame.Signature) {
		return false
	}
	ch := frame.ChallengeHash()
	if ack.ChallengeHash != ch || receipt.ChallengeHash != ch {
		return false
	}
	if !framecrypto.Verify(nodePub, ack.SigningBytes(), ack.Signature) ||
		!framecrypto.Verify(nodePub, receipt.SigningBytes(), receipt.Signature) {
		return false
	}
	return true
}

// ValidateProbeEndpoint enforces the frozen endpoint rule: a concrete global
// IPv4 literal with a valid port. Hostnames, IPv6, private (RFC 1918),
// CGNAT, loopback, link-local (unicast and multicast), multicast, reserved,
// benchmark, and unspecified addresses are rejected. IANA documentation
// ranges (TEST-NET) are global unicast and remain valid.
func ValidateProbeEndpoint(endpoint string) error {
	if endpoint == "" || len(endpoint) > ProbeEndpointMax {
		return ErrProbeEndpoint
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return ErrProbeEndpoint
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return ErrProbeEndpoint
	}
	if !IsGlobalEndpoint(ip) {
		return ErrProbeEndpoint
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return ErrProbeEndpoint
	}
	return nil
}
