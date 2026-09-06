package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// Story 6 regression: parsing the worst-case legal frame must not allocate
// unboundedly; repeated parses stay within a small constant allocation
// budget (no per-call heap growth proportional to input).

func TestEnvelopeBoundedAllocation(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	// Worst-case legal payload (maxPayloadBytes) and a large valid header.
	payload := bytes.Repeat([]byte{0x61}, MaxPayloadBytes)
	h := testHeader()
	h.ProtocolDomain = ProtocolDomain
	h.SessionID = string(bytes.Repeat([]byte("s"), 255))
	h.ControllerKeyID = string(bytes.Repeat([]byte("k"), 255))
	h.MessageType = string(bytes.Repeat([]byte("m"), 255))
	h.PayloadLength = uint64(len(payload))
	h.PayloadSHA256 = sha256.Sum256(payload)
	frame, err := BuildEnvelope(priv, h, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	peer := priv.Public().(ed25519.PublicKey)

	allocs := testing.AllocsPerRun(20, func() {
		env, stage, perr := ParseEnvelope(frame, peer)
		if perr != nil || stage != StageOK {
			t.Fatalf("parse: %v", perr)
		}
		if len(env.Payload) != MaxPayloadBytes {
			t.Fatalf("payload length %d", len(env.Payload))
		}
	})
	// The parser must not allocate proportionally to the 64 KiB payload on
	// every call (it borrows the input slice).
	if allocs > 8 {
		t.Fatalf("ParseEnvelope allocates %.1f objects per call on max-size frames", allocs)
	}
}

// TestStrictJSONBoundedAllocation pins the strict decoder on a large valid
// object: allocations are per-token, not per-byte of the value.
func TestStrictJSONBoundedAllocation(t *testing.T) {
	payload := []byte(`{"a":1,"b":"` + string(bytes.Repeat([]byte("x"), 4096)) + `"}`)
	allocs := testing.AllocsPerRun(20, func() {
		if err := ValidateStrictJSON(payload, nil); err != nil {
			t.Fatalf("validate: %v", err)
		}
	})
	// A 4 KiB string is a single token; per-byte allocation would exceed this
	// bound by orders of magnitude.
	if allocs > 60 {
		t.Fatalf("ValidateStrictJSON allocates %.1f objects per call on a 4 KiB value", allocs)
	}
}
