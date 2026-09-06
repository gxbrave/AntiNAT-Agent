package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// R13 RED: a validly signed control envelope does not make ambiguous semantic
// JSON safe. Duplicate, unknown, and trailing receipt fields must fail before
// OnReceipt or any durable outbox transition is reached.
func TestR13SignedReceiptEnvelopeUsesStrictSemanticJSON(t *testing.T) {
	st, err := localstate.Open(filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	controllerPub, controllerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instance := [16]byte{1, 2, 3}
	if err := st.SaveControllerPin(localstate.ControllerPin{
		InstanceID: hex.EncodeToString(instance[:]), KeyID: "controller-r13",
		PublicKeyRaw: controllerPub, Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AdvanceSession(1, "session-r13"); err != nil {
		t.Fatal(err)
	}
	key, err := security.LoadOrCreateNodeKey(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	client, err := NewClient(ClientOptions{
		Endpoint: "https://controller.invalid", NodeID: "node-r13", Store: st, Key: key,
		OnReceipt: func(context.Context, string) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.epoch = 1
	client.session = "session-r13"
	var nodeID [16]byte
	copy(nodeID[:], "node-r13")

	for i, payload := range [][]byte{
		[]byte(`{"operation_id":"first","operation_id":"second"}`),
		[]byte(`{"operation_id":"first","unknown":true}`),
		[]byte(`{"operation_id":"first"} {}`),
	} {
		client.active = &sessionIdentity{
			epoch:   1,
			session: "session-r13",
			inSeq:   uint64(i),
		}
		header := protocol.ProtectedHeader{
			ProtocolDomain: protocol.ProtocolDomain, ControllerInstanceID: instance,
			NodeID: nodeID, ControllerKeyID: "controller-r13", AgentCredentialVer: 1,
			ConnectionEpoch: 1, SessionID: "session-r13", Direction: protocol.DirectionC2A,
			Sequence: uint64(i + 1), MessageID: [16]byte{byte(i + 1)},
			MessageType: "message_receipt", SchemaVersion: 1,
		}
		frame, err := protocol.BuildEnvelope(controllerPriv, header, payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.handleInboundFrame(context.Background(), frame); err == nil {
			t.Fatalf("ambiguous signed receipt accepted: %s", payload)
		}
	}
	if called {
		t.Fatal("ambiguous signed receipt reached OnReceipt")
	}
}
