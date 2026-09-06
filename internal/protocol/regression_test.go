package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// Story 6 RED: enrollment messages whose fields are wire-declared shorter
// than their fixed width must be rejected as ErrEnrollMalformed, never panic
// (fixed-width big-endian reads must be length-checked first).

// signEnrollFields signs domain || canonical and appends the signature.
func signEnrollFields(domain string, canonical []byte, priv ed25519.PrivateKey) []byte {
	msg := append([]byte(nil), domain...)
	msg = append(msg, canonical...)
	return append(append([]byte(nil), canonical...), ed25519.Sign(priv, msg)...)
}

func TestEnrollmentShortFieldNoPanic(t *testing.T) {
	controller, agent := enrollTestKeys()
	controllerPub := controller.Public().(ed25519.PublicKey)
	ch := sha256.Sum256([]byte("server-issued-challenge"))

	// Challenge whose final expiry field is wire-declared as 3 bytes.
	{
		c := enrollTestChallenge()
		canonical := enrollEncode(
			c.ControllerInstanceID[:],
			[]byte(c.ControllerKeyID),
			c.NodeID[:],
			c.ServerNonce[:],
			[]byte(c.ProtocolVersions),
			[]byte{0x01, 0x02, 0x03}, // short expiry (declared 3, not 8)
		)
		raw := signEnrollFields(enrollTestDomain, canonical, controller)
		if _, err := ParseEnrollChallenge(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("challenge with short expiry: got %v, want ErrEnrollMalformed", err)
		}
	}

	// Request whose credential-version field is wire-declared as 2 bytes.
	{
		r := enrollTestRequest(ch)
		canonical := enrollEncode(
			r.ChallengeHash[:],
			r.AgentNonce[:],
			r.AgentPublicKey[:],
			[]byte{0x00, 0x01}, // short credential version (declared 2, not 4)
			[]byte(r.Token),
			r.CapabilityHash[:],
		)
		raw := signEnrollFields(enrollTestDomain, canonical, agent)
		if _, err := ParseEnrollRequest(raw, ch); err != ErrEnrollMalformed {
			t.Fatalf("request with short credential version: got %v, want ErrEnrollMalformed", err)
		}
	}

	// Result whose credential-version field is wire-declared as 1 byte.
	{
		r := enrollTestResult()
		canonical := enrollEncode(
			r.ControllerInstanceID[:],
			[]byte(r.ControllerKeyID),
			r.NodeID[:],
			r.AgentPublicKeyHash[:],
			[]byte{0x01}, // short credential version
			r.EnrollmentResultID[:],
			enrollU64(r.ExpiryUnix),
		)
		raw := signEnrollFields(enrollTestDomain, canonical, controller)
		if _, err := ParseEnrollResult(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("result with short credential version: got %v, want ErrEnrollMalformed", err)
		}
	}

	// Result whose expiry field is wire-declared as 4 bytes.
	{
		r := enrollTestResult()
		canonical := enrollEncode(
			r.ControllerInstanceID[:],
			[]byte(r.ControllerKeyID),
			r.NodeID[:],
			r.AgentPublicKeyHash[:],
			enrollU32(r.AgentCredentialVersion),
			r.EnrollmentResultID[:],
			[]byte{0x01, 0x02, 0x03, 0x04}, // short expiry
		)
		raw := signEnrollFields(enrollTestDomain, canonical, controller)
		if _, err := ParseEnrollResult(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("result with short expiry: got %v, want ErrEnrollMalformed", err)
		}
	}
}

// TestEnvelopeShortFieldNoPanic pins the envelope path: a header whose last
// fixed-size field is short must be rejected at the header stage, never
// panic.
func TestEnvelopeShortFieldNoPanic(t *testing.T) {
	priv, peer := testKeys()
	h := testHeader()
	h.ProtocolDomain = ProtocolDomain
	payload := []byte(`{}`)
	h.PayloadLength = uint64(len(payload))
	h.PayloadSHA256 = sha256.Sum256(payload)

	// Build a header whose final field (payload_sha256) is declared 8 bytes.
	truncated := encodeHeaderForTest(h, map[int][]byte{14: bytes.Repeat([]byte{0x01}, 8)})
	frame := craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(truncated)), uint32(len(payload)), truncated, payload)
	_, stage, err := ParseEnvelope(frame, peer)
	if err == nil || stage != StageHeader {
		t.Fatalf("envelope with short payload_sha256: err=%v stage=%v, want StageHeader error", err, stage)
	}
}

// TestProbeShortFieldNoPanic pins the probe path: truncated final fields are
// rejected as malformed, never panic.
func TestProbeShortFieldNoPanic(t *testing.T) {
	arm := probeTestArm()
	raw := arm.Canonical()
	// Truncate inside the TTL (8-byte) field.
	if len(raw) < 8 {
		t.Fatal("arm canonical too short")
	}
	short := raw[:len(raw)-4]
	if _, err := ParseProbeArm(short); err != ErrProbeMalformed {
		t.Fatalf("arm with short ttl: got %v, want ErrProbeMalformed", err)
	}

	_, _, provider := probeTestKeys()
	wan := ProviderFrame{
		ArmDigest:    arm.Digest(),
		ProbeID:      arm.ProbeID,
		ProviderID:   arm.ProviderID,
		Activation:   arm.Activation,
		Endpoint:     arm.Endpoint,
		ExpiryOpaque: arm.ExpiryOpaque,
	}
	var challenge [ProbeNonceLen]byte
	copy(challenge[:], bytes.Repeat([]byte{0x09}, 32))
	wan.Challenge = challenge
	canonical := wan.Canonical()
	sig, _ := signProbeForTest(ProbeMagicWAN, canonical[4:], provider)
	full := append(append([]byte(nil), canonical...), sig...)
	// Cut the last signature byte: length mismatch must be malformed.
	if _, err := ParseProviderFrame(full[:len(full)-1]); err != ErrProbeMalformed {
		t.Fatalf("wan1 with truncated signature: got %v, want ErrProbeMalformed", err)
	}
}
