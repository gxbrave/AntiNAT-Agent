package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// Story 1 RED: malformed enrollment transcripts (length, version, token,
// challenge binding, signature) must fail at the frozen reject reason.

const (
	enrollTestDomain  = "AntiNAT-Enroll-v1"
	enrollTestVersion = "1"
)

func enrollTestKeys() (controller ed25519.PrivateKey, agent ed25519.PrivateKey) {
	controller = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
	agent = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	return controller, agent
}

func enrollTestChallenge() EnrollChallenge {
	var c EnrollChallenge
	copy(c.ControllerInstanceID[:], bytes.Repeat([]byte{0x11}, 16))
	c.ControllerKeyID = "controller-key-1"
	copy(c.NodeID[:], bytes.Repeat([]byte{0x22}, 16))
	copy(c.ServerNonce[:], bytes.Repeat([]byte{0x33}, 32))
	c.ProtocolVersions = enrollTestVersion
	c.ExpiryUnix = 2_000_000_000
	return c
}

func enrollTestRequest(challengeHash [32]byte) EnrollRequest {
	var r EnrollRequest
	r.ChallengeHash = challengeHash
	copy(r.AgentNonce[:], bytes.Repeat([]byte{0x44}, 32))
	copy(r.AgentPublicKey[:], ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32)).Public().(ed25519.PublicKey))
	r.AgentCredentialVersion = 1
	r.Token = "enrollment-token"
	copy(r.CapabilityHash[:], bytes.Repeat([]byte{0x55}, 32))
	return r
}

func enrollTestResult() EnrollResult {
	var r EnrollResult
	copy(r.ControllerInstanceID[:], bytes.Repeat([]byte{0x11}, 16))
	r.ControllerKeyID = "controller-key-1"
	copy(r.NodeID[:], bytes.Repeat([]byte{0x22}, 16))
	copy(r.AgentPublicKeyHash[:], bytes.Repeat([]byte{0x66}, 32))
	r.AgentCredentialVersion = 1
	copy(r.EnrollmentResultID[:], bytes.Repeat([]byte{0x77}, 16))
	r.ExpiryUnix = 2_000_000_000
	return r
}

// signEnrollForTest signs the canonical enrollment fields and appends the
// signature, mirroring the frozen transcript layout.
func signEnrollForTest(domain string, canonical []byte, priv ed25519.PrivateKey) []byte {
	msg := append([]byte(nil), domain...)
	msg = append(msg, canonical...)
	return append(append([]byte(nil), canonical...), ed25519.Sign(priv, msg)...)
}

// TestEnrollFrozenFieldCapsAccepted pins the frozen §4 field bounds on the
// size pre-filter: a contractually valid transcript at the maximum field
// sizes (controller_key_id 1..255, token 1..256) must parse, not be rejected
// as malformed by an undercounted Enroll*Max constant.
func TestEnrollFrozenFieldCapsAccepted(t *testing.T) {
	controller, agent := enrollTestKeys()
	controllerPub := controller.Public().(ed25519.PublicKey)
	ch := sha256.Sum256([]byte("server-issued-challenge"))

	// EnrollChallenge with the maximum 255-byte controller_key_id.
	{
		c := enrollTestChallenge()
		c.ControllerKeyID = string(bytes.Repeat([]byte{'a'}, 255))
		raw := signEnrollForTest(enrollTestDomain, c.Canonical(), controller)
		got, err := ParseEnrollChallenge(raw, controllerPub)
		if err != nil {
			t.Fatalf("valid 255-byte controller_key_id challenge rejected: %v", err)
		}
		if len(got.ControllerKeyID) != 255 {
			t.Fatalf("controller_key_id length %d, want 255", len(got.ControllerKeyID))
		}
	}

	// EnrollRequest with the maximum 256-byte token.
	{
		r := enrollTestRequest(ch)
		r.Token = string(bytes.Repeat([]byte{'b'}, MaxTokenBytes))
		raw := signEnrollForTest(enrollTestDomain, r.Canonical(), agent)
		got, err := ParseEnrollRequest(raw, ch)
		if err != nil {
			t.Fatalf("valid 256-byte token request rejected: %v", err)
		}
		if len(got.Token) != MaxTokenBytes {
			t.Fatalf("token length %d, want %d", len(got.Token), MaxTokenBytes)
		}
	}

	// EnrollResult with the maximum 255-byte controller_key_id.
	{
		r := enrollTestResult()
		r.ControllerKeyID = string(bytes.Repeat([]byte{'c'}, 255))
		raw := signEnrollForTest(enrollTestDomain, r.Canonical(), controller)
		got, err := ParseEnrollResult(raw, controllerPub)
		if err != nil {
			t.Fatalf("valid 255-byte controller_key_id result rejected: %v", err)
		}
		if len(got.ControllerKeyID) != 255 {
			t.Fatalf("controller_key_id length %d, want 255", len(got.ControllerKeyID))
		}
	}
}

// TestEnrollOverCapTokenRejected pins the upper bound: a token beyond the
// frozen 1..256 field cap is rejected as malformed.
func TestEnrollOverCapTokenRejected(t *testing.T) {
	_, agent := enrollTestKeys()
	ch := sha256.Sum256([]byte("server-issued-challenge"))
	r := enrollTestRequest(ch)
	r.Token = string(bytes.Repeat([]byte{'d'}, MaxTokenBytes+1))
	raw := signEnrollForTest(enrollTestDomain, r.Canonical(), agent)
	if _, err := ParseEnrollRequest(raw, ch); err != ErrEnrollMalformed {
		t.Fatalf("over-cap token: got %v, want ErrEnrollMalformed", err)
	}
}

// TestEnrollControllerKeyIDBounds pins the frozen §4.1/4.3 controller_key_id
// bound (utf8 1..255) on both ParseEnrollChallenge and ParseEnrollResult:
// empty is rejected as malformed (finding R1-F6), the 1-byte minimum is
// accepted, and a 256-byte key_id is rejected by the Enroll*Max pre-filter.
// The 255-byte maximum is pinned by TestEnrollFrozenFieldCapsAccepted.
func TestEnrollControllerKeyIDBounds(t *testing.T) {
	controller, _ := enrollTestKeys()
	controllerPub := controller.Public().(ed25519.PublicKey)

	// Empty controller_key_id must be rejected as malformed.
	{
		c := enrollTestChallenge()
		c.ControllerKeyID = ""
		raw := signEnrollForTest(enrollTestDomain, c.Canonical(), controller)
		if _, err := ParseEnrollChallenge(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("challenge empty controller_key_id: got %v, want ErrEnrollMalformed", err)
		}
	}
	{
		r := enrollTestResult()
		r.ControllerKeyID = ""
		raw := signEnrollForTest(enrollTestDomain, r.Canonical(), controller)
		if _, err := ParseEnrollResult(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("result empty controller_key_id: got %v, want ErrEnrollMalformed", err)
		}
	}

	// Minimum 1-byte controller_key_id must be accepted.
	{
		c := enrollTestChallenge()
		c.ControllerKeyID = "k"
		raw := signEnrollForTest(enrollTestDomain, c.Canonical(), controller)
		got, err := ParseEnrollChallenge(raw, controllerPub)
		if err != nil {
			t.Fatalf("valid 1-byte controller_key_id challenge rejected: %v", err)
		}
		if len(got.ControllerKeyID) != 1 {
			t.Fatalf("controller_key_id length %d, want 1", len(got.ControllerKeyID))
		}
	}
	{
		r := enrollTestResult()
		r.ControllerKeyID = "k"
		raw := signEnrollForTest(enrollTestDomain, r.Canonical(), controller)
		got, err := ParseEnrollResult(raw, controllerPub)
		if err != nil {
			t.Fatalf("valid 1-byte controller_key_id result rejected: %v", err)
		}
		if len(got.ControllerKeyID) != 1 {
			t.Fatalf("controller_key_id length %d, want 1", len(got.ControllerKeyID))
		}
	}

	// 256-byte controller_key_id is rejected by the Enroll*Max pre-filter.
	{
		c := enrollTestChallenge()
		c.ControllerKeyID = string(bytes.Repeat([]byte{'x'}, 256))
		raw := signEnrollForTest(enrollTestDomain, c.Canonical(), controller)
		if _, err := ParseEnrollChallenge(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("challenge 256-byte controller_key_id: got %v, want ErrEnrollMalformed", err)
		}
	}
	{
		r := enrollTestResult()
		r.ControllerKeyID = string(bytes.Repeat([]byte{'x'}, 256))
		raw := signEnrollForTest(enrollTestDomain, r.Canonical(), controller)
		if _, err := ParseEnrollResult(raw, controllerPub); err != ErrEnrollMalformed {
			t.Fatalf("result 256-byte controller_key_id: got %v, want ErrEnrollMalformed", err)
		}
	}
}

func TestEnrollChallengeValidRoundTrip(t *testing.T) {
	controller, _ := enrollTestKeys()
	c := enrollTestChallenge()
	raw := signEnrollForTest(enrollTestDomain, c.Canonical(), controller)
	got, err := ParseEnrollChallenge(raw, controller.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("valid challenge rejected: %v", err)
	}
	if got.ControllerKeyID != c.ControllerKeyID || got.ProtocolVersions != c.ProtocolVersions || got.ExpiryUnix != c.ExpiryUnix {
		t.Fatalf("decoded challenge mismatch: %+v", got)
	}
}

func TestEnrollRequestValidRoundTrip(t *testing.T) {
	_, agent := enrollTestKeys()
	ch := sha256.Sum256([]byte("server-issued-challenge"))
	r := enrollTestRequest(ch)
	raw := signEnrollForTest(enrollTestDomain, r.Canonical(), agent)
	got, err := ParseEnrollRequest(raw, ch)
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if got.AgentCredentialVersion != 1 || got.Token != "enrollment-token" {
		t.Fatalf("decoded request mismatch: %+v", got)
	}
}

func TestEnrollResultValidRoundTrip(t *testing.T) {
	controller, _ := enrollTestKeys()
	r := enrollTestResult()
	raw := signEnrollForTest(enrollTestDomain, r.Canonical(), controller)
	got, err := ParseEnrollResult(raw, controller.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	if got.ControllerKeyID != r.ControllerKeyID || got.AgentCredentialVersion != 1 {
		t.Fatalf("decoded result mismatch: %+v", got)
	}
}

// TestEnrollmentMalformedVectorsFail pins the Story 1 RED set for the
// enrollment transcript.
func TestEnrollmentMalformedVectorsFail(t *testing.T) {
	controller, agent := enrollTestKeys()
	controllerPub := controller.Public().(ed25519.PublicKey)
	agentPub := agent.Public().(ed25519.PublicKey)
	ch := sha256.Sum256([]byte("server-issued-challenge"))

	validChallenge := signEnrollForTest(enrollTestDomain, enrollTestChallenge().Canonical(), controller)
	validRequest := signEnrollForTest(enrollTestDomain, enrollTestRequest(ch).Canonical(), agent)
	validResult := signEnrollForTest(enrollTestDomain, enrollTestResult().Canonical(), controller)

	cases := []struct {
		name       string
		raw        []byte
		parse      func([]byte) error
		wantReason error
	}{
		{"challenge-truncated", validChallenge[:len(validChallenge)-10], func(b []byte) error {
			_, err := ParseEnrollChallenge(b, controllerPub)
			return err
		}, ErrEnrollMalformed},
		{"challenge-unsupported-version", func() []byte {
			c := enrollTestChallenge()
			c.ProtocolVersions = "2"
			return signEnrollForTest(enrollTestDomain, c.Canonical(), controller)
		}(), func(b []byte) error {
			_, err := ParseEnrollChallenge(b, controllerPub)
			return err
		}, ErrEnrollMalformed},
		{"challenge-wrong-key", validChallenge, func(b []byte) error {
			_, err := ParseEnrollChallenge(b, agentPub)
			return err
		}, ErrEnrollSignature},
		{"request-empty-token", func() []byte {
			r := enrollTestRequest(ch)
			r.Token = ""
			return signEnrollForTest(enrollTestDomain, r.Canonical(), agent)
		}(), func(b []byte) error {
			_, err := ParseEnrollRequest(b, ch)
			return err
		}, ErrEnrollMalformed},
		{"request-wrong-challenge-hash", func() []byte {
			other := sha256.Sum256([]byte("different-challenge"))
			return signEnrollForTest(enrollTestDomain, enrollTestRequest(other).Canonical(), agent)
		}(), func(b []byte) error {
			_, err := ParseEnrollRequest(b, ch)
			return err
		}, ErrEnrollChallenge},
		{"request-wrong-key", validRequest, func(b []byte) error {
			other := sha256.Sum256([]byte("other"))
			_, err := ParseEnrollRequest(b, other)
			return err
		}, ErrEnrollChallenge},
		{"request-signed-by-controller", signEnrollForTest(enrollTestDomain, enrollTestRequest(ch).Canonical(), controller), func(b []byte) error {
			_, err := ParseEnrollRequest(b, ch)
			return err
		}, ErrEnrollSignature},
		{"result-zero-credential-version", func() []byte {
			r := enrollTestResult()
			r.AgentCredentialVersion = 0
			return signEnrollForTest(enrollTestDomain, r.Canonical(), controller)
		}(), func(b []byte) error {
			_, err := ParseEnrollResult(b, controllerPub)
			return err
		}, ErrEnrollMalformed},
		{"result-wrong-key", validResult, func(b []byte) error {
			_, err := ParseEnrollResult(b, agentPub)
			return err
		}, ErrEnrollSignature},
		{"result-truncated", validResult[:20], func(b []byte) error {
			_, err := ParseEnrollResult(b, controllerPub)
			return err
		}, ErrEnrollMalformed},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.parse(tc.raw)
			if err == nil {
				t.Fatalf("malformed enrollment vector parsed successfully")
			}
			if tc.wantReason != nil && err != tc.wantReason {
				t.Fatalf("rejected with %v, want %v", err, tc.wantReason)
			}
		})
	}
}
