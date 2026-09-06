package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// Story 1 RED: probe wire frames (ARM1/RDY1/WAN1/ACK1/RCT1) must be parsed
// with bounded lengths, correct signature verification, and the frozen
// endpoint rules; the agent state machine must enforce anti-oracle, replay,
// conflict, and TTL semantics.

func probeTestKeys() (controller, agent, provider ed25519.PrivateKey) {
	controller = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	agent = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	provider = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32))
	return controller, agent, provider
}

func probeTestArm() ProbeArm {
	_, _, provider := probeTestKeys()
	var arm ProbeArm
	copy(arm.ProbeID[:], bytes.Repeat([]byte{0x01}, 16))
	copy(arm.ProviderID[:], bytes.Repeat([]byte{0x02}, 16))
	copy(arm.ProviderPublicKey[:], provider.Public().(ed25519.PublicKey))
	copy(arm.ExpectedSourceIP[:], []byte{198, 51, 100, 7})
	copy(arm.Activation[:], bytes.Repeat([]byte{0x03}, 16))
	arm.Endpoint = "198.51.100.7:4444"
	arm.TTLMS = 30000
	copy(arm.ExpiryOpaque[:], bytes.Repeat([]byte{0x04}, 16))
	return arm
}

func TestProbeArmValidRoundTrip(t *testing.T) {
	arm := probeTestArm()
	raw := arm.Canonical()
	got, err := ParseProbeArm(raw)
	if err != nil {
		t.Fatalf("valid arm rejected: %v", err)
	}
	if got.Endpoint != arm.Endpoint || got.TTLMS != arm.TTLMS {
		t.Fatalf("decoded arm mismatch: %+v", got)
	}
	if got.Digest() != arm.Digest() {
		t.Fatal("digest mismatch")
	}
	// Anti-oracle: the canonical arm must not contain challenge material.
	if bytes.Contains(got.Canonical(), []byte("challenge")) {
		t.Fatal("arm must never carry the provider challenge")
	}
}

// TestProbeArmRejectsBadEndpoint pins the frozen endpoint rules: hostnames,
// IPv6, private, loopback, link-local, multicast, and unspecified endpoints
// are all rejected; documentation (TEST-NET) ranges remain valid.
func TestProbeArmRejectsBadEndpoint(t *testing.T) {
	good := probeTestArm()
	cases := []struct {
		endpoint string
		reject   bool
	}{
		{"198.51.100.7:4444", false},
		{"203.0.113.9:4444", false},
		{"192.0.2.1:80", false},
		{"example.com:4444", true},
		{"[2001:db8::1]:4444", true},
		{"10.0.0.5:4444", true},
		{"172.16.0.5:4444", true},
		{"192.168.1.5:4444", true},
		{"127.0.0.1:4444", true},
		{"169.254.1.1:4444", true},
		{"224.0.0.1:4444", true},
		{"0.0.0.0:4444", true},
		{"198.51.100.7:0", true},
		{"198.51.100.7:65536", true},
		{"198.51.100.7", true},
		{"", true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.endpoint, func(t *testing.T) {
			arm := good
			arm.Endpoint = tc.endpoint
			_, err := ParseProbeArm(arm.Canonical())
			if tc.reject && err == nil {
				t.Fatalf("endpoint %q accepted", tc.endpoint)
			}
			if !tc.reject && err != nil {
				t.Fatalf("endpoint %q rejected: %v", tc.endpoint, err)
			}
		})
	}
}

func TestProbeArmRejectsBadTTL(t *testing.T) {
	arm := probeTestArm()
	arm.TTLMS = 0
	if _, err := ParseProbeArm(arm.Canonical()); err == nil {
		t.Fatal("zero TTL accepted")
	}
	arm.TTLMS = uint64(24*time.Hour/time.Millisecond) + 1
	if _, err := ParseProbeArm(arm.Canonical()); err == nil {
		t.Fatal("over-cap TTL accepted")
	}
}

// TestProbeArmedVerify pins the signed armed response binding the arm digest.
func TestProbeArmedVerify(t *testing.T) {
	_, agent, _ := probeTestKeys()
	arm := probeTestArm()
	digest := arm.Digest()
	sig, err := signProbeForTest(ProbeMagicArmed, digest[:], agent)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(append([]byte(nil), ProbeMagicArmed...), digest[:]...)
	raw = append(raw, sig...)
	got, err := ParseProbeArmed(raw, agent.Public().(ed25519.PublicKey), digest)
	if err != nil {
		t.Fatalf("valid armed rejected: %v", err)
	}
	if got.ArmDigest != digest {
		t.Fatal("arm digest mismatch")
	}
	// Wrong digest binding must fail.
	if _, err := ParseProbeArmed(raw, agent.Public().(ed25519.PublicKey), sha256.Sum256([]byte("other"))); err == nil {
		t.Fatal("armed accepted with wrong expected digest")
	}
}

func TestProviderFrameAndJoin(t *testing.T) {
	_, agent, provider := probeTestKeys()
	arm := probeTestArm()
	digest := arm.Digest()
	var challenge [ProbeNonceLen]byte
	copy(challenge[:], bytes.Repeat([]byte{0x09}, 32))

	// Build a WAN1 frame signed by the provider.
	wan := ProviderFrame{
		ArmDigest:    digest,
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	canonical := wan.Canonical()
	wanSig, err := signProbeForTest(ProbeMagicWAN, canonical[4:], provider)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(append([]byte(nil), canonical...), wanSig...)
	parsed, err := ParseProviderFrame(raw)
	if err != nil {
		t.Fatalf("valid wan1 rejected: %v", err)
	}
	if parsed.Challenge != challenge || parsed.Endpoint != arm.Endpoint {
		t.Fatal("wan1 field mismatch")
	}

	// Signed ACK and receipt by the node key.
	chHash := parsed.ChallengeHash()
	ackSig, _ := signProbeForTest(ProbeMagicACK, append(append([]byte(nil), digest[:]...), chHash[:]...), agent)
	ackRaw := append(append(append([]byte(nil), ProbeMagicACK...), digest[:]...), chHash[:]...)
	ackRaw = append(ackRaw, ackSig...)
	gotACK, err := ParseProbeACK(ackRaw, agent.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("valid ack rejected: %v", err)
	}

	rcptSig, _ := signProbeForTest(ProbeMagicReceipt, append(append(append([]byte(nil), digest[:]...), chHash[:]...), arm.ProviderID[:]...), agent)
	rcptRaw := append(append(append(append([]byte(nil), ProbeMagicReceipt...), digest[:]...), chHash[:]...), arm.ProviderID[:]...)
	rcptRaw = append(rcptRaw, rcptSig...)
	gotReceipt, err := ParseProbeReceipt(rcptRaw, agent.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	if !VerifyProbeJoin(arm, parsed, gotACK, gotReceipt, agent.Public().(ed25519.PublicKey)) {
		t.Fatal("probe join failed for a valid transcript")
	}
}

// TestProbeAgentStateMachine pins replay, conflict, anti-oracle, and TTL.
func TestProbeAgentStateMachine(t *testing.T) {
	_, agent, provider := probeTestKeys()
	state := NewProbeAgent(agent)
	now := time.Unix(2_000_000_000, 0)
	arm := probeTestArm()

	armed, err := state.ArmProbe(arm, now)
	if err != nil {
		t.Fatalf("armProbe: %v", err)
	}
	armDigest := arm.Digest()
	if !bytes.Equal(armed.ArmDigest[:], armDigest[:]) {
		t.Fatal("armed response binds the wrong digest")
	}

	// Re-arm with identical material is idempotent (same digest) — allowed by
	// the frozen state machine (returns the same armed response).
	if _, err := state.ArmProbe(arm, now); err != nil {
		t.Fatalf("re-arm with identical material rejected: %v", err)
	}

	// Build a provider frame matching the arm, signed by the provider key.
	var challenge [ProbeNonceLen]byte
	copy(challenge[:], bytes.Repeat([]byte{0x09}, 32))
	wan := ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	wanCanonical := wan.Canonical()
	wanSig, err := signProbeForTest(ProbeMagicWAN, wanCanonical[4:], provider)
	if err != nil {
		t.Fatal(err)
	}
	wanRaw := append(append([]byte(nil), wanCanonical...), wanSig...)
	parsed, err := ParseProviderFrame(wanRaw)
	if err != nil {
		t.Fatal(err)
	}

	src := arm.ExpectedSourceIP
	if !state.HandleProbeIngress(parsed, src, now) {
		t.Fatal("valid ingress rejected")
	}
	// Consumed exactly once: replay rejected.
	if state.HandleProbeIngress(parsed, src, now) {
		t.Fatal("replayed ingress accepted after consumption")
	}
	// Re-arm after consumption with same material: replay rejection.
	if _, err := state.ArmProbe(arm, now); err != ErrProbeReplay {
		t.Fatalf("re-arm after consumption: got %v, want ErrProbeReplay", err)
	}
	// Re-arm with different material: ID conflict.
	conflict := arm
	conflict.Endpoint = "203.0.113.9:4444"
	if _, err := state.ArmProbe(conflict, now); err != ErrProbeIDConflict {
		t.Fatalf("conflicting re-arm: got %v, want ErrProbeIDConflict", err)
	}
}

// TestProbeAgentStateMachineTTLAndWrongSource pins TTL expiry and wrong-source
// rejection (generic failure, no authenticated material).
func TestProbeAgentStateMachineTTLAndWrongSource(t *testing.T) {
	_, agent, provider := probeTestKeys()
	state := NewProbeAgent(agent)
	now := time.Unix(2_000_000_000, 0)
	arm := probeTestArm()
	if _, err := state.ArmProbe(arm, now); err != nil {
		t.Fatal(err)
	}

	buildWAN := func(arm ProbeArm, challenge [ProbeNonceLen]byte) ProviderFrame {
		wan := ProviderFrame{
			ArmDigest:    arm.Digest(),
			ProbeID:      arm.ProbeID,
			ProviderID:   arm.ProviderID,
			Activation:   arm.Activation,
			Endpoint:     arm.Endpoint,
			ExpiryOpaque: arm.ExpiryOpaque,
			Challenge:    challenge,
		}
		canonical := wan.Canonical()
		sig, _ := signProbeForTest(ProbeMagicWAN, canonical[4:], provider)
		raw := append(append([]byte(nil), canonical...), sig...)
		parsed, _ := ParseProviderFrame(raw)
		return parsed
	}

	var probeChallenge [ProbeNonceLen]byte
	copy(probeChallenge[:], bytes.Repeat([]byte{0x09}, 32))
	wan := buildWAN(arm, probeChallenge)
	// Wrong source: rejected generically.
	if state.HandleProbeIngress(wan, [4]byte{8, 8, 8, 8}, now) {
		t.Fatal("ingress accepted from wrong source")
	}
	// Expired TTL: rejected.
	late := now.Add(time.Duration(arm.TTLMS)*time.Millisecond + time.Second)
	if state.HandleProbeIngress(wan, arm.ExpectedSourceIP, late) {
		t.Fatal("ingress accepted after TTL expiry")
	}
}

// TestProbeAgentStateCapacityBounded pins frozen docs/protocol.md §7.6:
// armed probe operations are bounded, and arming beyond the cap fails with
// ErrProbeStateFull instead of growing the state map without bound.
func TestProbeAgentStateCapacityBounded(t *testing.T) {
	_, agent, _ := probeTestKeys()
	state := NewProbeAgent(agent)
	now := time.Unix(2_000_000_000, 0)
	for i := 0; i < ProbeOpMax; i++ {
		arm := probeTestArm()
		copy(arm.ProbeID[:], []byte{byte(i / 256), byte(i % 256)})
		if _, err := state.ArmProbe(arm, now); err != nil {
			t.Fatalf("arm %d: %v", i, err)
		}
	}
	// A distinct probe beyond the cap must fail closed with ErrProbeStateFull.
	extra := probeTestArm()
	copy(extra.ProbeID[:], []byte{0xff, 0xfe})
	if _, err := state.ArmProbe(extra, now); err != ErrProbeStateFull {
		t.Fatalf("arm beyond cap: got %v, want ErrProbeStateFull", err)
	}
	// Re-arming an existing ID while full stays idempotent.
	existing := probeTestArm()
	copy(existing.ProbeID[:], []byte{0, 0})
	if _, err := state.ArmProbe(existing, now); err != nil {
		t.Fatalf("re-arm of existing ID while full: %v", err)
	}
	// A conflicting re-arm while full still reports the ID conflict.
	conflict := existing
	conflict.Endpoint = "203.0.113.9:4444"
	if _, err := state.ArmProbe(conflict, now); err != ErrProbeIDConflict {
		t.Fatalf("conflicting re-arm while full: got %v, want ErrProbeIDConflict", err)
	}
}

// TestProbeAgentStateEvictsExpiredOnArm pins the §7.6 expirability rule:
// when the armed-operation map is full, an ArmProbe that arrives after every
// resident operation has passed its deadline must succeed — expired state is
// evicted rather than kept forever.
func TestProbeAgentStateEvictsExpiredOnArm(t *testing.T) {
	_, agent, _ := probeTestKeys()
	state := NewProbeAgent(agent)
	now := time.Unix(2_000_000_000, 0)
	for i := 0; i < ProbeOpMax; i++ {
		arm := probeTestArm()
		copy(arm.ProbeID[:], []byte{byte(i / 256), byte(i % 256)})
		arm.TTLMS = 1 // 1ms: expires almost immediately
		if _, err := state.ArmProbe(arm, now); err != nil {
			t.Fatalf("arm %d: %v", i, err)
		}
	}
	// Every resident operation is now past its deadline.
	late := now.Add(2 * time.Millisecond)
	fresh := probeTestArm()
	copy(fresh.ProbeID[:], []byte{0xff, 0xfe})
	if _, err := state.ArmProbe(fresh, late); err != nil {
		t.Fatalf("arm after resident expiry: got %v, want success (expired state evicted)", err)
	}
}

// TestProbeAgentStateReArmExpiredIsFresh pins that an arm whose operation
// deadline has passed is fully evicted: re-arming the same probe ID with
// different material afterwards is a fresh arm, not an ID conflict.
func TestProbeAgentStateReArmExpiredIsFresh(t *testing.T) {
	_, agent, _ := probeTestKeys()
	state := NewProbeAgent(agent)
	now := time.Unix(2_000_000_000, 0)
	arm := probeTestArm()
	arm.TTLMS = 1
	if _, err := state.ArmProbe(arm, now); err != nil {
		t.Fatal(err)
	}
	// Different material on the same ID once the old operation expired.
	rearm := arm
	rearm.Endpoint = "203.0.113.9:4444"
	if _, err := state.ArmProbe(rearm, now.Add(2*time.Millisecond)); err != nil {
		t.Fatalf("re-arm of expired operation with different material: got %v, want fresh arm", err)
	}
}

// TestProbeAgentStateReplayEntryExpires pins that both the armed operation and
// the replay cache entry are swept against the wall clock: after the operation
// TTL and the replay window have both passed, re-arming the consumed ID with
// different material is a fresh arm, not an ID conflict against lingering
// state.
func TestProbeAgentStateReplayEntryExpires(t *testing.T) {
	_, agent, provider := probeTestKeys()
	state := NewProbeAgent(agent)
	now := time.Unix(2_000_000_000, 0)
	arm := probeTestArm()
	if _, err := state.ArmProbe(arm, now); err != nil {
		t.Fatal(err)
	}
	// Consume the operation so a replay entry is recorded.
	var challenge [ProbeNonceLen]byte
	copy(challenge[:], bytes.Repeat([]byte{0x09}, 32))
	wan := ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
		Challenge:    challenge,
	}
	canonical := wan.Canonical()
	sig, err := signProbeForTest(ProbeMagicWAN, canonical[4:], provider)
	if err != nil {
		t.Fatal(err)
	}
	wanRaw := append(append([]byte(nil), canonical...), sig...)
	parsed, err := ParseProviderFrame(wanRaw)
	if err != nil {
		t.Fatal(err)
	}
	if !state.HandleProbeIngress(parsed, arm.ExpectedSourceIP, now) {
		t.Fatal("valid ingress rejected")
	}
	// Past the replay window (5m) and the operation TTL (30s).
	late := now.Add(ProbeReplayWindow + time.Minute)
	rearm := arm
	rearm.Endpoint = "203.0.113.9:4444"
	if _, err := state.ArmProbe(rearm, late); err != nil {
		t.Fatalf("re-arm after replay+op expiry with different material: got %v, want fresh arm", err)
	}
}

// signProbeForTest signs magic || payload for probe frames (test helper).
func signProbeForTest(magic string, payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("bad key size")
	}
	msg := append([]byte(nil), magic...)
	msg = append(msg, payload...)
	return ed25519.Sign(priv, msg), nil
}
