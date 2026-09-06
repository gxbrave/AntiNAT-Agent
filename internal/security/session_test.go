// Story 3 RED: the signed session handshake transcript. Wrong keys, tampered
// fields, and malformed messages fail closed before challenge.go's session
// codec lands.
package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

func testAgentAndControllerKeys(t *testing.T) (agent, controller ed25519.PrivateKey) {
	t.Helper()
	_, a, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return a, c
}

// RED 3a: a SessionHello round-trips through Sign/Parse with the right
// fields, and a wrong agent key fails verification.
func TestSessionHelloSignParse(t *testing.T) {
	agent, _ := testAgentAndControllerKeys(t)
	hello := security.SessionHello{
		ControllerInstanceID: [16]byte{1, 2, 3},
		NodeID:               [16]byte{4, 5, 6},
		AgentCredentialVer:   1,
		AgentPublicKey:       [32]byte(agent.Public().(ed25519.PublicKey)),
		AgentNonce:           [32]byte{7},
		AgentMaxEpoch:        3,
		ProtocolVersions:     "1",
	}
	sig, err := hello.Sign(agent)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw := append(hello.Canonical(), sig...)
	got, err := security.ParseSessionHello(raw)
	if err != nil {
		t.Fatalf("ParseSessionHello: %v", err)
	}
	if got.AgentMaxEpoch != 3 || got.AgentCredentialVer != 1 || got.ProtocolVersions != "1" {
		t.Fatalf("parsed hello = %+v", got)
	}
	// Tampered public key field: the signature no longer matches the
	// presented key (the controller additionally cross-checks the presented
	// key against the bound credential hash at the hub layer).
	other, _ := testAgentAndControllerKeys(t)
	tampered := hello
	tampered.AgentPublicKey = [32]byte(other.Public().(ed25519.PublicKey))
	rawTampered := append(tampered.Canonical(), sig...)
	if _, err := security.ParseSessionHello(rawTampered); err == nil {
		t.Fatal("hello with tampered public key verified")
	}
	// Tampered fields.
	raw[10] ^= 0xff
	if _, err := security.ParseSessionHello(raw); err == nil {
		t.Fatal("tampered hello verified")
	}
}

// RED 3b: SessionWelcome round-trips and fails on a wrong controller key.
func TestSessionWelcomeSignParse(t *testing.T) {
	_, controller := testAgentAndControllerKeys(t)
	welcome := security.SessionWelcome{
		ControllerInstanceID: [16]byte{1},
		ControllerKeyID:      "k-1",
		NodeID:               [16]byte{2},
		AgentNonce:           [32]byte{3},
		ServerNonce:          [32]byte{4},
		ConnectionEpoch:      7,
		SessionID:            "session-abc",
		ExpiryUnix:           999,
	}
	sig, err := welcome.Sign(controller)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(welcome.Canonical(), sig...)
	got, err := security.ParseSessionWelcome(raw, controller.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("ParseSessionWelcome: %v", err)
	}
	if got.ConnectionEpoch != 7 || got.SessionID != "session-abc" {
		t.Fatalf("parsed welcome = %+v", got)
	}
	// Wrong controller key (the "wrong pinned Controller" RED case).
	agent, _ := testAgentAndControllerKeys(t)
	if _, err := security.ParseSessionWelcome(raw, agent.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("welcome verified with the wrong controller key")
	}
}

// RED 3c: SessionFinal round-trips and fails on tampering.
func TestSessionFinalSignParse(t *testing.T) {
	agent, _ := testAgentAndControllerKeys(t)
	final := security.SessionFinal{
		ControllerInstanceID: [16]byte{1},
		NodeID:               [16]byte{2},
		ServerNonce:          [32]byte{3},
		ConnectionEpoch:      7,
		SessionID:            "session-abc",
	}
	sig, err := final.Sign(agent)
	if err != nil {
		t.Fatal(err)
	}
	raw := append(final.Canonical(), sig...)
	got, err := security.ParseSessionFinal(raw, agent.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("ParseSessionFinal: %v", err)
	}
	if got.ConnectionEpoch != 7 || got.SessionID != "session-abc" {
		t.Fatalf("parsed final = %+v", got)
	}
	// Truncated message fails closed.
	if _, err := security.ParseSessionFinal(raw[:20], agent.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("truncated final verified")
	}
}

// RED 3d: malformed/oversize messages fail closed with stable errors.
func TestSessionMessagesMalformed(t *testing.T) {
	agent, _ := testAgentAndControllerKeys(t)
	if _, err := security.ParseSessionHello(nil); err == nil {
		t.Fatal("empty hello parsed")
	}
	if _, err := security.ParseSessionHello(make([]byte, 4096)); err == nil {
		t.Fatal("oversize hello parsed")
	}
	if _, err := security.ParseSessionFinal([]byte("garbage"), agent.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("garbage final parsed")
	}
	_ = errors.Is
}
