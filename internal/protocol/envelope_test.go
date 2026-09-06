package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// Story 1 RED: every malformed length/domain/hash/signature vector must fail
// before any payload decode, at the exact frozen rejection stage.

// testHeader builds a canonical protected header used to craft frames.
func testHeader() ProtectedHeader {
	var h ProtectedHeader
	copy(h.ControllerInstanceID[:], bytes.Repeat([]byte{0x11}, 16))
	copy(h.NodeID[:], bytes.Repeat([]byte{0x22}, 16))
	h.ControllerKeyID = "controller-key-1"
	h.AgentCredentialVer = 1
	h.ConnectionEpoch = 1
	h.SessionID = "session-1"
	h.Direction = DirectionC2A
	h.Sequence = 1
	copy(h.MessageID[:], bytes.Repeat([]byte{0x33}, 16))
	h.MessageType = "desired"
	h.SchemaVersion = 1
	return h
}

// testKeys returns the deterministic TEST-ONLY fixture keys used by the frozen
// vectors (seeds 0x11/0x22), never real credentials.
func testKeys() (priv ed25519.PrivateKey, peer ed25519.PublicKey) {
	priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	peer = priv.Public().(ed25519.PublicKey)
	return priv, peer
}

// craftEnvelope assembles and signs a frame from explicit parts so tests can
// mutate each region independently.
func craftEnvelope(priv ed25519.PrivateKey, magic []byte, wireVer byte, headerLen, payloadLen uint32, header, payload []byte) []byte {
	frame := make([]byte, 0, 13+len(header)+len(payload)+ed25519.SignatureSize)
	frame = append(frame, magic...)
	frame = append(frame, wireVer)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], headerLen)
	frame = append(frame, l[:]...)
	binary.BigEndian.PutUint32(l[:], payloadLen)
	frame = append(frame, l[:]...)
	frame = append(frame, header...)
	frame = append(frame, payload...)
	if len(priv) == ed25519.PrivateKeySize {
		sig := ed25519.Sign(priv, signatureInputForTest(header, payload))
		frame = append(frame, sig...)
	}
	return frame
}

// signatureInputForTest mirrors the frozen signature input
// domain || protected_header_bytes || payload_sha256.
func signatureInputForTest(header, payload []byte) []byte {
	sum := sha256.Sum256(payload)
	out := append([]byte(nil), ProtocolDomain...)
	out = append(out, header...)
	return append(out, sum[:]...)
}

// encodeHeaderForTest renders the canonical 14-field length-prefixed header,
// with optional per-field content overrides (field is 1-indexed) for crafting
// malformed headers.
func encodeHeaderForTest(h ProtectedHeader, overrides ...map[int][]byte) []byte {
	content := func(idx int, def []byte) []byte {
		for _, ov := range overrides {
			if b, ok := ov[idx]; ok {
				return b
			}
		}
		return def
	}
	var buf bytes.Buffer
	put := func(b []byte) {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		buf.Write(l[:])
		buf.Write(b)
	}
	u32 := func(v uint32) []byte {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		return b[:]
	}
	u64 := func(v uint64) []byte {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		return b[:]
	}
	put(content(1, []byte(h.ProtocolDomain)))
	put(content(2, h.ControllerInstanceID[:]))
	put(content(3, h.NodeID[:]))
	put(content(4, []byte(h.ControllerKeyID)))
	put(content(5, u32(h.AgentCredentialVer)))
	put(content(6, u64(h.ConnectionEpoch)))
	put(content(7, []byte(h.SessionID)))
	put(content(8, []byte{h.Direction}))
	put(content(9, u64(h.Sequence)))
	put(content(10, h.MessageID[:]))
	put(content(11, []byte(h.MessageType)))
	put(content(12, u32(h.SchemaVersion)))
	put(content(13, u64(h.PayloadLength)))
	put(content(14, h.PayloadSHA256[:]))
	return buf.Bytes()
}

// validFrame builds a fully valid, correctly signed frame for baseline tests.
func validFrame(t *testing.T) (frame []byte, priv ed25519.PrivateKey, peer ed25519.PublicKey, h ProtectedHeader) {
	t.Helper()
	priv, peer = testKeys()
	h = testHeader()
	payload := []byte(`{"a":1}`)
	h.PayloadLength = uint64(len(payload))
	h.PayloadSHA256 = sha256.Sum256(payload)
	h.ProtocolDomain = ProtocolDomain
	header := encodeHeaderForTest(h)
	frame = craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(header)), uint32(len(payload)), header, payload)
	return frame, priv, peer, h
}

func TestEnvelopeValidRoundTrip(t *testing.T) {
	frame, _, peer, wantH := validFrame(t)
	env, stage, err := ParseEnvelope(frame, peer)
	if err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	if stage != StageOK {
		t.Fatalf("valid frame stopped at stage %v", stage)
	}
	if env.Header.ProtocolDomain != wantH.ProtocolDomain ||
		env.Header.ControllerKeyID != wantH.ControllerKeyID ||
		env.Header.MessageType != wantH.MessageType ||
		env.Header.Sequence != wantH.Sequence {
		t.Fatalf("decoded header mismatch: %+v", env.Header)
	}
	if !bytes.Equal(env.Payload, []byte(`{"a":1}`)) {
		t.Fatalf("payload mismatch: %q", env.Payload)
	}
	if env.HeaderLen == 0 || env.PayloadLen == 0 {
		t.Fatalf("length fields not populated")
	}
}

// TestEnvelopeMalformedVectorsFailsBeforePayloadDecode pins Story 1: each
// malformed length/domain/hash/signature vector is rejected at the exact
// frozen stage, never after a payload decode.
func TestEnvelopeMalformedVectorsFailsBeforePayloadDecode(t *testing.T) {
	priv, peer := testKeys()
	h := testHeader()
	payload := []byte(`{"a":1}`)
	h.PayloadLength = uint64(len(payload))
	h.PayloadSHA256 = sha256.Sum256(payload)
	h.ProtocolDomain = ProtocolDomain
	header := encodeHeaderForTest(h)

	type tc struct {
		name  string
		frame []byte
		stage Stage
	}
	cases := []tc{
		{"truncated-short", []byte("ANAT\x01\x00\x00\x00\x10\x00\x00\x00\x01"), StageFraming},
		{"bad-magic", craftEnvelope(priv, []byte("XXXX"), WireVersion, uint32(len(header)), uint32(len(payload)), header, payload), StageFraming},
		{"bad-wire-version", craftEnvelope(priv, []byte(EnvelopeMagic), 9, uint32(len(header)), uint32(len(payload)), header, payload), StageFraming},
		{"header-len-zero", craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, 0, uint32(len(payload)), header, payload), StageFraming},
		{"header-len-over-cap", craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, MaxHeaderBytes+1, uint32(len(payload)), header, payload), StageFraming},
		{"payload-len-over-cap", craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(header)), MaxPayloadBytes+1, header, payload), StageFraming},
		{"declared-length-mismatch", craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(header))+1, uint32(len(payload)), header, payload), StageFraming},
		{"header-truncated-field", craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, 4, uint32(len(payload)), header[:4], payload), StageHeader},
		{"payload-truncated", craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(header)), uint32(len(payload))+1, header, payload), StageFraming},
		{"bad-domain", func() []byte {
			h2 := h
			h2.ProtocolDomain = "AntiNAT-Control-v2"
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(encodeHeaderForTest(h2))), uint32(len(payload)), encodeHeaderForTest(h2), payload)
		}(), StageConsistency},
		{"payload-length-header-mismatch", func() []byte {
			h2 := h
			h2.PayloadLength = uint64(len(payload)) + 1
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(encodeHeaderForTest(h2))), uint32(len(payload)), encodeHeaderForTest(h2), payload)
		}(), StageConsistency},
		{"payload-hash-mismatch", func() []byte {
			h2 := h
			h2.PayloadSHA256 = sha256.Sum256([]byte("different"))
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(encodeHeaderForTest(h2))), uint32(len(payload)), encodeHeaderForTest(h2), payload)
		}(), StageConsistency},
		{"invalid-direction", func() []byte {
			h2 := h
			h2.Direction = 0x07
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(encodeHeaderForTest(h2))), uint32(len(payload)), encodeHeaderForTest(h2), payload)
		}(), StageConsistency},
		{"zero-credential-version", func() []byte {
			h2 := h
			h2.AgentCredentialVer = 0
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(encodeHeaderForTest(h2))), uint32(len(payload)), encodeHeaderForTest(h2), payload)
		}(), StageConsistency},
		{"instance-id-short", func() []byte {
			bad := encodeHeaderForTest(h, map[int][]byte{2: []byte("short")})
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(bad)), uint32(len(payload)), bad, payload)
		}(), StageHeader},
		{"trailing-header-bytes", func() []byte {
			bad := append(append([]byte(nil), header...), 0xde, 0xad)
			return craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(bad)), uint32(len(payload)), bad, payload)
		}(), StageHeader},
		{"tampered-header-signature", func() []byte {
			// Correct frame with a byte of the (non-semantically-checked)
			// message_type content flipped AFTER signing: the header still
			// parses and stays consistent, so only the signature can fail.
			f := craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(header)), uint32(len(payload)), header, payload)
			msgIdx := bytes.Index(header, []byte("desired"))
			if msgIdx < 0 {
				t.Fatalf("message_type not found in test header")
			}
			f[13+msgIdx] ^= 0x01
			return f
		}(), StageSignature},
		{"wrong-peer-key", func() []byte {
			// Sign with a different key than the verifier's pinned peer.
			wrongPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
			return craftEnvelope(wrongPriv, []byte(EnvelopeMagic), WireVersion, uint32(len(header)), uint32(len(payload)), header, payload)
		}(), StageSignature},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			env, stage, err := ParseEnvelope(tc.frame, peer)
			if err == nil {
				t.Fatalf("malformed frame parsed successfully")
			}
			if stage != tc.stage {
				t.Fatalf("rejected at stage %v, want %v (err=%v)", stage, tc.stage, err)
			}
			if stage == StagePayloadJSON || stage == StageOK {
				t.Fatalf("malformed frame reached payload stage")
			}
			if len(env.Payload) != 0 {
				t.Fatalf("payload exposed before validation")
			}
		})
	}
}

// TestEnvelopeHeaderStringFieldBounds pins the frozen §3.2 1..255 bound on
// the variable-length protected-header string fields (controller_key_id,
// session_id, message_type): empty and over-cap values are rejected at
// StageHeader, before any consistency/signature stage.
func TestEnvelopeHeaderStringFieldBounds(t *testing.T) {
	priv, peer := testKeys()
	payload := []byte(`{"a":1}`)
	h := testHeader()
	h.PayloadLength = uint64(len(payload))
	h.PayloadSHA256 = sha256.Sum256(payload)
	h.ProtocolDomain = ProtocolDomain

	cases := []struct {
		name  string
		field int
		value []byte
	}{
		{"controller-key-id-empty", 4, nil},
		{"controller-key-id-over-cap", 4, bytes.Repeat([]byte{'k'}, 256)},
		{"session-id-empty", 7, nil},
		{"session-id-over-cap", 7, bytes.Repeat([]byte{'s'}, 256)},
		{"message-type-empty", 11, nil},
		{"message-type-over-cap", 11, bytes.Repeat([]byte{'m'}, 256)},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			header := encodeHeaderForTest(h, map[int][]byte{tc.field: tc.value})
			frame := craftEnvelope(priv, []byte(EnvelopeMagic), WireVersion, uint32(len(header)), uint32(len(payload)), header, payload)
			_, stage, err := ParseEnvelope(frame, peer)
			if err == nil {
				t.Fatalf("frame with %s accepted", tc.name)
			}
			if stage != StageHeader {
				t.Fatalf("frame with %s rejected at stage %v, want StageHeader (err=%v)", tc.name, stage, err)
			}
		})
	}
}

// TestEnvelopeEncodeRejectsInvalidStringFields pins the encoder counterpart:
// BuildEnvelope refuses to emit a protected header whose variable-length
// string fields violate the frozen 1..255 bound.
func TestEnvelopeEncodeRejectsInvalidStringFields(t *testing.T) {
	priv, _ := testKeys()
	h := testHeader()
	h.ProtocolDomain = ProtocolDomain

	over := func(n int) string { return string(bytes.Repeat([]byte{'x'}, n)) }
	cases := []struct {
		name   string
		mutate func(*ProtectedHeader)
	}{
		{"controller-key-id-empty", func(h *ProtectedHeader) { h.ControllerKeyID = "" }},
		{"controller-key-id-over-cap", func(h *ProtectedHeader) { h.ControllerKeyID = over(256) }},
		{"session-id-empty", func(h *ProtectedHeader) { h.SessionID = "" }},
		{"session-id-over-cap", func(h *ProtectedHeader) { h.SessionID = over(256) }},
		{"message-type-empty", func(h *ProtectedHeader) { h.MessageType = "" }},
		{"message-type-over-cap", func(h *ProtectedHeader) { h.MessageType = over(256) }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hh := h
			tc.mutate(&hh)
			if _, err := BuildEnvelope(priv, hh, nil); err == nil {
				t.Fatalf("BuildEnvelope accepted %s", tc.name)
			}
		})
	}
}

// TestEnvelopeEncodeRejectsOverCap pins the bounded encoder: an oversized
// payload or header must fail rather than emit an invalid frame.
func TestEnvelopeEncodeRejectsOverCap(t *testing.T) {
	priv, _ := testKeys()
	h := testHeader()
	h.ProtocolDomain = ProtocolDomain

	payload := make([]byte, MaxPayloadBytes+1)
	if _, err := BuildEnvelope(priv, h, payload); err == nil {
		t.Fatal("BuildEnvelope accepted payload over maxPayloadBytes")
	}

	h2 := h
	h2.SessionID = string(bytes.Repeat([]byte("x"), MaxHeaderBytes+1))
	if _, err := BuildEnvelope(priv, h2, nil); err == nil {
		t.Fatal("BuildEnvelope accepted header over maxHeaderBytes")
	}

	if _, err := BuildEnvelope(ed25519.PrivateKey{}, h, []byte(`{}`)); err == nil {
		t.Fatal("BuildEnvelope accepted an invalid private key")
	}
}
