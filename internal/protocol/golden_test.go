package protocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Golden verification over the FROZEN byte vectors under
// internal/protocol/testdata/** (pinned in test/contracts/manifest.json).
// Every parser here must accept exactly the valid vectors and reject exactly
// the invalid vectors at the frozen rejection stage.

// ---------------------------------------------------------------------------
// fixture helpers
// ---------------------------------------------------------------------------

func walkFrozenJSON(t *testing.T, dir string) []string {
	t.Helper()
	var files []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	for i := 0; i < len(files); i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j] < files[i] {
				files[i], files[j] = files[j], files[i]
			}
		}
	}
	if len(files) == 0 {
		t.Fatalf("no fixtures found under %s", dir)
	}
	return files
}

func loadFrozenJSON(t *testing.T, path string, out any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
}

func testdataRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "testdata")
}

// ---------------------------------------------------------------------------
// control-envelope golden vectors
// ---------------------------------------------------------------------------

type goldenEnvelopeFixture struct {
	Schema      string `json:"schema"`
	VectorID    string `json:"vector_id"`
	Expect      string `json:"expect"`
	RejectStage string `json:"reject_stage,omitempty"`
	FrameHex    string `json:"frame_hex"`
	Verifier    string `json:"verifier"`
	PubKeyHex   string `json:"public_key_hex,omitempty"`
	Header      struct {
		ProtocolDomain     string `json:"protocol_domain"`
		ControllerKeyID    string `json:"controller_key_id"`
		AgentCredentialVer uint32 `json:"agent_credential_version"`
		ConnectionEpoch    uint64 `json:"connection_epoch"`
		SessionID          string `json:"session_id"`
		Direction          string `json:"direction"`
		Sequence           uint64 `json:"sequence"`
		MessageType        string `json:"message_type"`
		SchemaVersion      uint32 `json:"schema_version"`
		PayloadLength      uint64 `json:"payload_length"`
		PayloadSHA256      string `json:"payload_sha256"`
	} `json:"header"`
	PayloadHex  string `json:"payload_hex,omitempty"`
	PayloadJSON string `json:"payload_json,omitempty"`
}

func TestGoldenControlEnvelope(t *testing.T) {
	dir := filepath.Join(testdataRoot(t), "control-envelope")
	for _, path := range walkFrozenJSON(t, dir) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx goldenEnvelopeFixture
			loadFrozenJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/control-envelope/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			frame, err := hex.DecodeString(fx.FrameHex)
			if err != nil {
				t.Fatalf("frame_hex: %v", err)
			}
			peer, err := hex.DecodeString(fx.PubKeyHex)
			if err != nil || len(peer) != ed25519.PublicKeySize {
				t.Fatalf("public_key_hex must be a 32-byte key")
			}
			env, stage, perr := ParseEnvelope(frame, peer)
			switch fx.Expect {
			case "valid":
				if perr != nil {
					t.Fatalf("valid vector rejected: %v", perr)
				}
				if stage != StageOK {
					t.Fatalf("valid vector stopped at stage %v", stage)
				}
				h := env.Header
				if h.ProtocolDomain != fx.Header.ProtocolDomain {
					t.Errorf("protocol_domain=%q want %q", h.ProtocolDomain, fx.Header.ProtocolDomain)
				}
				if h.ControllerKeyID != fx.Header.ControllerKeyID {
					t.Errorf("controller_key_id=%q want %q", h.ControllerKeyID, fx.Header.ControllerKeyID)
				}
				if h.AgentCredentialVer != fx.Header.AgentCredentialVer {
					t.Errorf("agent_credential_version=%d want %d", h.AgentCredentialVer, fx.Header.AgentCredentialVer)
				}
				if h.ConnectionEpoch != fx.Header.ConnectionEpoch {
					t.Errorf("connection_epoch=%d want %d", h.ConnectionEpoch, fx.Header.ConnectionEpoch)
				}
				if h.SessionID != fx.Header.SessionID {
					t.Errorf("session_id=%q want %q", h.SessionID, fx.Header.SessionID)
				}
				if h.Sequence != fx.Header.Sequence {
					t.Errorf("sequence=%d want %d", h.Sequence, fx.Header.Sequence)
				}
				if h.MessageType != fx.Header.MessageType {
					t.Errorf("message_type=%q want %q", h.MessageType, fx.Header.MessageType)
				}
				if h.SchemaVersion != fx.Header.SchemaVersion {
					t.Errorf("schema_version=%d want %d", h.SchemaVersion, fx.Header.SchemaVersion)
				}
				wantDir, derr := goldenDirection(fx.Verifier)
				if derr != nil {
					t.Fatal(derr)
				}
				if h.Direction != wantDir {
					t.Errorf("direction=%x want %x for verifier %s", h.Direction, wantDir, fx.Verifier)
				}
				if fx.Header.PayloadLength != 0 && h.PayloadLength != fx.Header.PayloadLength {
					t.Errorf("payload_length=%d want %d", h.PayloadLength, fx.Header.PayloadLength)
				}
				if fx.Header.PayloadSHA256 != "" {
					want, _ := hex.DecodeString(fx.Header.PayloadSHA256)
					if !bytes.Equal(h.PayloadSHA256[:], want) {
						t.Errorf("payload_sha256 mismatch")
					}
				}
				if fx.PayloadHex != "" {
					want, _ := hex.DecodeString(fx.PayloadHex)
					if !bytes.Equal(env.Payload, want) {
						t.Errorf("payload mismatch: got %x want %x", env.Payload, want)
					}
				}
				if fx.PayloadJSON != "" {
					if err := ValidateStrictJSON(env.Payload, nil); err != nil {
						t.Fatalf("payload strict JSON validation failed: %v", err)
					}
				}
			case "invalid":
				if perr == nil {
					t.Fatalf("invalid vector parsed successfully")
				}
				want, serr := goldenStageFromString(fx.RejectStage)
				if serr != nil {
					t.Fatalf("fixture reject_stage: %v", serr)
				}
				if stage != want {
					t.Fatalf("invalid vector failed at stage %v, want %v (err=%v)", stage, want, perr)
				}
				if stage == StagePayloadJSON || stage == StageOK {
					t.Fatalf("invalid vector reached payload stage")
				}
			default:
				t.Fatalf("fixture expect must be valid or invalid, got %q", fx.Expect)
			}
		})
	}
}

func goldenDirection(verifier string) (byte, error) {
	switch verifier {
	case "agent":
		return DirectionC2A, nil
	case "controller":
		return DirectionA2C, nil
	}
	return 0, errors.New("unknown verifier " + verifier)
}

func goldenStageFromString(s string) (Stage, error) {
	switch s {
	case "framing":
		return StageFraming, nil
	case "header":
		return StageHeader, nil
	case "consistency":
		return StageConsistency, nil
	case "signature":
		return StageSignature, nil
	case "payload_json":
		return StagePayloadJSON, nil
	}
	return StageOK, errors.New("unknown reject_stage " + s)
}

// TestGoldenControlEnvelopeBitFlip mutates every bit of every valid control
// envelope vector and asserts rejection at a pre-payload stage — never a
// successful parse and never a payload decode.
func TestGoldenControlEnvelopeBitFlip(t *testing.T) {
	dir := filepath.Join(testdataRoot(t), "control-envelope")
	for _, path := range walkFrozenJSON(t, dir) {
		var fx goldenEnvelopeFixture
		loadFrozenJSON(t, path, &fx)
		if fx.Expect != "valid" {
			continue
		}
		frame, err := hex.DecodeString(fx.FrameHex)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		peer, _ := hex.DecodeString(fx.PubKeyHex)
		for i := 0; i < len(frame); i++ {
			for bit := uint(0); bit < 8; bit++ {
				mutated := append([]byte(nil), frame...)
				mutated[i] ^= 1 << bit
				_, stage, perr := ParseEnvelope(mutated, peer)
				if perr == nil {
					t.Fatalf("%s: bit flip at byte %d bit %d parsed successfully", path, i, bit)
				}
				if stage == StagePayloadJSON || stage == StageOK {
					t.Fatalf("%s: bit flip at byte %d bit %d reached payload stage %v", path, i, bit, stage)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// enrollment golden vectors
// ---------------------------------------------------------------------------

type goldenEnrollmentFixture struct {
	Schema                 string `json:"schema"`
	VectorID               string `json:"vector_id"`
	Kind                   string `json:"kind"`
	Expect                 string `json:"expect"`
	RejectReason           string `json:"reject_reason,omitempty"`
	MsgHex                 string `json:"message_hex"`
	ChallengeHash          string `json:"challenge_hash,omitempty"`
	PubKeyHex              string `json:"public_key_hex,omitempty"`
	ControllerKeyID        string `json:"controller_key_id,omitempty"`
	ProtocolVersions       string `json:"protocol_versions,omitempty"`
	AgentCredentialVersion uint32 `json:"agent_credential_version,omitempty"`
}

func TestGoldenEnrollment(t *testing.T) {
	dir := filepath.Join(testdataRoot(t), "enrollment")
	for _, path := range walkFrozenJSON(t, dir) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx goldenEnrollmentFixture
			loadFrozenJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/enrollment/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			raw, err := hex.DecodeString(fx.MsgHex)
			if err != nil {
				t.Fatalf("message_hex: %v", err)
			}
			switch fx.Expect {
			case "valid":
				goldenEnrollValid(t, fx, raw)
			case "invalid":
				goldenEnrollInvalid(t, fx, raw)
			default:
				t.Fatalf("fixture expect must be valid or invalid, got %q", fx.Expect)
			}
		})
	}
}

func goldenEnrollValid(t *testing.T, fx goldenEnrollmentFixture, raw []byte) {
	t.Helper()
	switch fx.Kind {
	case "challenge":
		pub, err := hex.DecodeString(fx.PubKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("public_key_hex must be a 32-byte key")
		}
		c, err := ParseEnrollChallenge(raw, pub)
		if err != nil {
			t.Fatalf("valid challenge rejected: %v", err)
		}
		if fx.ControllerKeyID != "" && c.ControllerKeyID != fx.ControllerKeyID {
			t.Errorf("controller_key_id=%q want %q", c.ControllerKeyID, fx.ControllerKeyID)
		}
		if fx.ProtocolVersions != "" && c.ProtocolVersions != fx.ProtocolVersions {
			t.Errorf("protocol_versions=%q want %q", c.ProtocolVersions, fx.ProtocolVersions)
		}
	case "request":
		ch, err := hex.DecodeString(fx.ChallengeHash)
		if err != nil || len(ch) != EnrollHashSize {
			t.Fatalf("challenge_hash must be 32-byte hex")
		}
		var want [EnrollHashSize]byte
		copy(want[:], ch)
		r, err := ParseEnrollRequest(raw, want)
		if err != nil {
			t.Fatalf("valid request rejected: %v", err)
		}
		if fx.AgentCredentialVersion != 0 && r.AgentCredentialVersion != fx.AgentCredentialVersion {
			t.Errorf("agent_credential_version=%d want %d", r.AgentCredentialVersion, fx.AgentCredentialVersion)
		}
	case "result":
		pub, err := hex.DecodeString(fx.PubKeyHex)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Fatalf("public_key_hex must be a 32-byte key")
		}
		r, err := ParseEnrollResult(raw, pub)
		if err != nil {
			t.Fatalf("valid result rejected: %v", err)
		}
		if fx.ControllerKeyID != "" && r.ControllerKeyID != fx.ControllerKeyID {
			t.Errorf("controller_key_id=%q want %q", r.ControllerKeyID, fx.ControllerKeyID)
		}
	default:
		t.Fatalf("unknown enrollment kind %q", fx.Kind)
	}
}

func goldenEnrollInvalid(t *testing.T, fx goldenEnrollmentFixture, raw []byte) {
	t.Helper()
	var err error
	switch fx.Kind {
	case "challenge":
		pub, derr := hex.DecodeString(fx.PubKeyHex)
		if derr != nil {
			t.Fatalf("public_key_hex: %v", derr)
		}
		_, err = ParseEnrollChallenge(raw, pub)
	case "request":
		ch, derr := hex.DecodeString(fx.ChallengeHash)
		if derr != nil {
			t.Fatalf("challenge_hash: %v", derr)
		}
		var want [EnrollHashSize]byte
		copy(want[:], ch)
		_, err = ParseEnrollRequest(raw, want)
	case "result":
		pub, derr := hex.DecodeString(fx.PubKeyHex)
		if derr != nil {
			t.Fatalf("public_key_hex: %v", derr)
		}
		_, err = ParseEnrollResult(raw, pub)
	default:
		t.Fatalf("unknown enrollment kind %q", fx.Kind)
	}
	if err == nil {
		t.Fatalf("invalid %s vector parsed successfully", fx.Kind)
	}
	if fx.RejectReason != "" && !goldenEnrollRejectMatches(err, fx.RejectReason) {
		t.Fatalf("invalid vector rejected with %v, want reason %q", err, fx.RejectReason)
	}
}

func goldenEnrollRejectMatches(err error, reason string) bool {
	switch reason {
	case "malformed":
		return err == ErrEnrollMalformed
	case "domain":
		return err == ErrEnrollDomain
	case "challenge":
		return err == ErrEnrollChallenge
	case "signature":
		return err == ErrEnrollSignature
	}
	return true
}

// TestGoldenEnrollmentBitFlip mutates every bit of every valid enrollment
// vector and asserts rejection (signed messages must never be accepted after
// any single-bit mutation).
func TestGoldenEnrollmentBitFlip(t *testing.T) {
	dir := filepath.Join(testdataRoot(t), "enrollment")
	for _, path := range walkFrozenJSON(t, dir) {
		var fx goldenEnrollmentFixture
		loadFrozenJSON(t, path, &fx)
		if fx.Expect != "valid" {
			continue
		}
		raw, err := hex.DecodeString(fx.MsgHex)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		for i := 0; i < len(raw); i++ {
			for bit := uint(0); bit < 8; bit++ {
				mutated := append([]byte(nil), raw...)
				mutated[i] ^= 1 << bit
				var verr error
				switch fx.Kind {
				case "challenge":
					pub, _ := hex.DecodeString(fx.PubKeyHex)
					_, verr = ParseEnrollChallenge(mutated, pub)
				case "request":
					ch, _ := hex.DecodeString(fx.ChallengeHash)
					var want [EnrollHashSize]byte
					copy(want[:], ch)
					_, verr = ParseEnrollRequest(mutated, want)
				case "result":
					pub, _ := hex.DecodeString(fx.PubKeyHex)
					_, verr = ParseEnrollResult(mutated, pub)
				}
				if verr == nil {
					t.Fatalf("%s: bit flip at byte %d bit %d parsed successfully", path, i, bit)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// probe-frame golden vectors
// ---------------------------------------------------------------------------

type goldenProbeFixture struct {
	Schema       string `json:"schema"`
	VectorID     string `json:"vector_id"`
	Kind         string `json:"kind"`
	Expect       string `json:"expect"`
	RejectReason string `json:"reject_reason,omitempty"`

	FrameHex         string `json:"frame_hex,omitempty"`
	ProbeIDHex       string `json:"probe_id_hex,omitempty"`
	ProviderIDHex    string `json:"provider_id_hex,omitempty"`
	ActivationHex    string `json:"activation_hex,omitempty"`
	ExpectedSourceIP string `json:"expected_source_ip,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`
	TTLMS            uint64 `json:"ttl_ms,omitempty"`
	ExpiryOpaqueHex  string `json:"expiry_opaque_hex,omitempty"`
	ChallengeHex     string `json:"challenge_hex,omitempty"`
	ChallengeHashHex string `json:"challenge_hash_hex,omitempty"`
	ArmDigestHex     string `json:"arm_digest_hex,omitempty"`
	NodePubHex       string `json:"node_public_key_hex,omitempty"`
	ProviderPubHex   string `json:"provider_public_key_hex,omitempty"`

	ArmHex     string `json:"arm_hex,omitempty"`
	WAN1Hex    string `json:"wan1_hex,omitempty"`
	ACKHex     string `json:"ack_hex,omitempty"`
	ReceiptHex string `json:"receipt_hex,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	Operation  string `json:"operation,omitempty"`
}

func TestGoldenProbe(t *testing.T) {
	dir := filepath.Join(testdataRoot(t), "probe-frame")
	for _, path := range walkFrozenJSON(t, dir) {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			var fx goldenProbeFixture
			loadFrozenJSON(t, path, &fx)
			if fx.Schema != "antinat.contracts/probe-frame/v1" {
				t.Fatalf("unexpected schema %q", fx.Schema)
			}
			switch fx.Kind {
			case "arm":
				goldenProbeArm(t, fx)
			case "armed":
				goldenProbeArmed(t, fx)
			case "wan1":
				goldenProbeWAN1(t, fx)
			case "ack":
				goldenProbeACK(t, fx)
			case "receipt":
				goldenProbeReceipt(t, fx)
			case "operation":
				goldenProbeOperation(t, fx)
			default:
				t.Fatalf("unknown probe fixture kind %q", fx.Kind)
			}
		})
	}
}

func goldenHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func goldenProbeArm(t *testing.T, fx goldenProbeFixture) {
	t.Helper()
	raw := goldenHex(t, fx.FrameHex)
	arm, err := ParseProbeArm(raw)
	if fx.Expect == "invalid" {
		if err == nil {
			t.Fatalf("invalid arm parsed successfully")
		}
		if fx.RejectReason != "" && !goldenProbeRejectMatches(err, fx.RejectReason) {
			t.Fatalf("arm rejected with %v, want %q", err, fx.RejectReason)
		}
		return
	}
	if err != nil {
		t.Fatalf("valid arm rejected: %v", err)
	}
	if fx.ProbeIDHex != "" && !bytes.Equal(arm.ProbeID[:], goldenHex(t, fx.ProbeIDHex)) {
		t.Errorf("probe_id mismatch")
	}
	if fx.ProviderIDHex != "" && !bytes.Equal(arm.ProviderID[:], goldenHex(t, fx.ProviderIDHex)) {
		t.Errorf("provider_id mismatch")
	}
	if fx.Endpoint != "" && arm.Endpoint != fx.Endpoint {
		t.Errorf("endpoint=%q want %q", arm.Endpoint, fx.Endpoint)
	}
	if fx.TTLMS != 0 && arm.TTLMS != fx.TTLMS {
		t.Errorf("ttl_ms=%d want %d", arm.TTLMS, fx.TTLMS)
	}
	if bytes.Contains(arm.Canonical(), []byte("challenge")) {
		t.Fatalf("arm must not contain challenge material")
	}
}

func goldenProbeArmed(t *testing.T, fx goldenProbeFixture) {
	t.Helper()
	raw := goldenHex(t, fx.FrameHex)
	nodePub := goldenHex(t, fx.NodePubHex)
	if len(nodePub) != ed25519.PublicKeySize {
		t.Fatalf("node_public_key_hex must be a 32-byte key")
	}
	digest := goldenHex(t, fx.ArmDigestHex)
	if len(digest) != ProbeDigestLen {
		t.Fatalf("arm_digest_hex must be 32-byte hex")
	}
	var want [ProbeDigestLen]byte
	copy(want[:], digest)
	_, err := ParseProbeArmed(raw, nodePub, want)
	if fx.Expect == "valid" && err != nil {
		t.Fatalf("valid armed rejected: %v", err)
	}
	if fx.Expect == "invalid" && err == nil {
		t.Fatalf("invalid armed parsed successfully")
	}
}

func goldenProbeWAN1(t *testing.T, fx goldenProbeFixture) {
	t.Helper()
	raw := goldenHex(t, fx.FrameHex)
	f, err := ParseProviderFrame(raw)
	if err != nil {
		if fx.Expect == "invalid" && fx.RejectReason == "malformed" {
			return
		}
		if fx.Expect == "valid" {
			t.Fatalf("valid wan1 rejected: %v", err)
		}
		t.Fatalf("wan1 rejected with %v (fixture expect=%s reason=%s)", err, fx.Expect, fx.RejectReason)
	}
	if fx.Expect == "invalid" && fx.RejectReason == "signature" {
		providerPub := goldenHex(t, fx.ProviderPubHex)
		if ed25519.Verify(providerPub, f.SigningBytes(), f.Signature) {
			t.Fatalf("wan1 signature unexpectedly verifies for a signature-reject vector")
		}
		return
	}
	if fx.Expect == "invalid" {
		t.Fatalf("invalid wan1 parsed successfully")
	}
	if fx.ChallengeHex != "" && !bytes.Equal(f.Challenge[:], goldenHex(t, fx.ChallengeHex)) {
		t.Errorf("challenge mismatch")
	}
	if fx.Endpoint != "" && f.Endpoint != fx.Endpoint {
		t.Errorf("endpoint=%q want %q", f.Endpoint, fx.Endpoint)
	}
	providerPub := goldenHex(t, fx.ProviderPubHex)
	if !ed25519.Verify(providerPub, f.SigningBytes(), f.Signature) {
		t.Fatalf("wan1 signature does not verify against provider key")
	}
}

func goldenProbeACK(t *testing.T, fx goldenProbeFixture) {
	t.Helper()
	raw := goldenHex(t, fx.FrameHex)
	nodePub := goldenHex(t, fx.NodePubHex)
	ack, err := ParseProbeACK(raw, nodePub)
	if fx.Expect == "invalid" {
		if err == nil {
			t.Fatalf("invalid ack parsed successfully")
		}
		return
	}
	if err != nil {
		t.Fatalf("valid ack rejected: %v", err)
	}
	if fx.ChallengeHashHex != "" && !bytes.Equal(ack.ChallengeHash[:], goldenHex(t, fx.ChallengeHashHex)) {
		t.Errorf("challenge_hash mismatch")
	}
}

func goldenProbeReceipt(t *testing.T, fx goldenProbeFixture) {
	t.Helper()
	raw := goldenHex(t, fx.FrameHex)
	nodePub := goldenHex(t, fx.NodePubHex)
	receipt, err := ParseProbeReceipt(raw, nodePub)
	if fx.Expect == "invalid" {
		if err == nil {
			t.Fatalf("invalid receipt parsed successfully")
		}
		return
	}
	if err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	if fx.ProviderIDHex != "" && !bytes.Equal(receipt.ProviderID[:], goldenHex(t, fx.ProviderIDHex)) {
		t.Errorf("provider_id mismatch")
	}
}

func goldenProbeRejectMatches(err error, reason string) bool {
	switch reason {
	case "malformed":
		return err == ErrProbeMalformed
	case "endpoint":
		return err == ErrProbeEndpoint
	case "signature":
		return err == ErrProbeSignature
	}
	return true
}

func goldenProbeOperation(t *testing.T, fx goldenProbeFixture) {
	t.Helper()
	arm, err := ParseProbeArm(goldenHex(t, fx.ArmHex))
	if err != nil {
		t.Fatalf("parse arm: %v", err)
	}
	if bytes.Contains(arm.Canonical(), []byte("challenge")) {
		t.Fatalf("arm must not contain challenge material")
	}
	wan1, err := ParseProviderFrame(goldenHex(t, fx.WAN1Hex))
	if err != nil {
		t.Fatalf("parse wan1: %v", err)
	}
	now := time.Unix(2_000_000_000, 0)
	agentKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	state := NewProbeAgent(agentKey)
	armed, err := state.ArmProbe(arm, now)
	if err != nil {
		t.Fatalf("armProbe: %v", err)
	}
	if !ed25519.Verify(agentKey.Public().(ed25519.PublicKey), armed.SigningBytes(), armed.Signature) {
		t.Fatalf("armed response signature invalid")
	}
	srcIP := goldenParseIPv4(t, fx.SourceIP)
	switch fx.Operation {
	case "ingress-ok":
		if !state.HandleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("valid ingress rejected")
		}
		if state.HandleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("replayed ingress accepted after consumption")
		}
		nodePub := agentKey.Public().(ed25519.PublicKey)
		ack, aerr := ParseProbeACK(goldenHex(t, fx.ACKHex), nodePub)
		if aerr != nil {
			t.Fatalf("parse ack: %v", aerr)
		}
		receipt, rerr := ParseProbeReceipt(goldenHex(t, fx.ReceiptHex), nodePub)
		if rerr != nil {
			t.Fatalf("parse receipt: %v", rerr)
		}
		if !VerifyProbeJoin(arm, wan1, ack, receipt, nodePub) {
			t.Fatalf("probe join failed for valid transcript")
		}
	case "ingress-wrong-source":
		if state.HandleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("ingress accepted from wrong source")
		}
	case "ingress-wrong-activation":
		wan1.Activation[0] ^= 0xff
		if state.HandleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("ingress accepted with wrong activation")
		}
	case "ingress-wrong-provider":
		wan1.ProviderID[0] ^= 0xff
		if state.HandleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("ingress accepted with wrong provider")
		}
	case "ingress-expired":
		late := now.Add(time.Duration(arm.TTLMS)*time.Millisecond + time.Second)
		if state.HandleProbeIngress(wan1, srcIP, late) {
			t.Fatalf("ingress accepted after TTL expiry")
		}
	case "replay":
		if !state.HandleProbeIngress(wan1, srcIP, now) {
			t.Fatalf("initial ingress rejected")
		}
		if _, err := state.ArmProbe(arm, now); err != ErrProbeReplay {
			t.Fatalf("re-arm after consumption: got %v, want ErrProbeReplay", err)
		}
		conflict := arm
		conflict.Endpoint = "203.0.113.9:4444"
		if _, err := state.ArmProbe(conflict, now); err != ErrProbeIDConflict {
			t.Fatalf("conflicting re-arm: got %v, want ErrProbeIDConflict", err)
		}
	default:
		t.Fatalf("unknown operation %q", fx.Operation)
	}
}

func goldenParseIPv4(t *testing.T, s string) [4]byte {
	t.Helper()
	var out [4]byte
	ip := net.ParseIP(s).To4()
	if ip == nil {
		t.Fatalf("invalid source_ip %q", s)
	}
	copy(out[:], ip)
	return out
}
