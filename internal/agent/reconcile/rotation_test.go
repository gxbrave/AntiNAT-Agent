// P14 Story 4 (agent side): accepting a controller key-rotation pin only after
// verifying the signed certificate against the current pin and persisting the
// higher generation. Downgrade / wrong signer / foreign instance fail closed.
//
// RED: when first written, `AcceptControllerRotationPin` did not exist (no real
// certificate decode -> the tests could not compile), the generation-vs-pin
// anti-downgrade comparison was unimplemented, and same-generation / wrong-
// instance / forged certificates were not refused. See internal/security/tdd-red.
package reconcile

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

func seedPin(t *testing.T, st *localstate.Store, instanceID string, pub ed25519.PublicKey) {
	t.Helper()
	if err := st.SaveControllerPin(localstate.ControllerPin{
		InstanceID: instanceID, KeyID: security.KeyIDOf(pub),
		PublicKeyRaw: append(ed25519.PublicKey(nil), pub...), Generation: 1,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAgentAcceptsRotationPinEndToEnd signs a real rotation cert with the old
// key, feeds it through the agent acceptance path, and the successor pin is
// durable with the higher generation.
func TestAgentAcceptsRotationPinEndToEnd(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub := newPriv.Public().(ed25519.PublicKey)
	seedPin(t, st, "inst-1", oldPub)

	now := time.Now().Unix()
	cert := security.NewRotationCertificate(
		"controller", oldPub, 1, security.KeyIDOf(oldPub), newPub, 2, security.KeyIDOf(newPub), now, now+3600)
	if err := security.SignRotationCertificate(&cert, oldPriv); err != nil {
		t.Fatal(err)
	}
	raw, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	next, decoded, err := AcceptControllerRotationPin(st, "inst-1", []byte(raw))
	if err != nil {
		t.Fatalf("accept rotation pin: %v", err)
	}
	if next.Generation != 2 || next.KeyID == "" {
		t.Fatalf("next pin = %+v", next)
	}
	if decoded.NewKeyID != next.KeyID {
		t.Fatalf("decoded new id %q != persisted %q", decoded.NewKeyID, next.KeyID)
	}
	persisted, found, err := st.ControllerPin("inst-1")
	if err != nil || !found {
		t.Fatalf("persisted pin missing found=%v err=%v", found, err)
	}
	if persisted.Generation != 2 {
		t.Fatalf("persisted generation = %d, want 2", persisted.Generation)
	}
}

// TestAgentRefusesDowngradePin: a legitimate sequence then a downgrade cert is
// refused (anti-downgrade persists the highest generation).
func TestAgentRefusesDowngradePin(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := newPriv.Public().(ed25519.PublicKey)
	seedPin(t, st, "inst-1", oldPub)

	now := time.Now().Unix()
	cert := security.NewRotationCertificate("controller", oldPub, 1, security.KeyIDOf(oldPub), newPub, 1, security.KeyIDOf(newPub), now, now+3600)
	_ = security.SignRotationCertificate(&cert, oldPriv)
	raw, _ := cert.Encode()
	if _, _, err := AcceptControllerRotationPin(st, "inst-1", []byte(raw)); err == nil {
		t.Fatal("same-generation rotation accepted")
	}
	persisted, _, _ := st.ControllerPin("inst-1")
	if persisted.Generation != 1 {
		t.Fatalf("downgrade changed persisted generation to %d", persisted.Generation)
	}
}

// TestAgentRefusesForgedDowngradeSignedByLegitGen4Key (repair-1 M1): the agent
// holds a gen-4 pin. An attacker forges a gen-1 -> gen-3 certificate SIGNED BY
// THE LEGITIMATE gen-4 key (e.g. from a compromise of the current successor key
// material). DecodeRotationCertificate only checks new>old and old-pub binds the
// pinned key, so without comparing against the PERSISTED pin generation this
// would be accepted as a downgrade. It must be refused and the gen-4 pin kept.
func TestAgentRefusesForgedDowngradeSignedByLegitGen4Key(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, gen4Priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	gen4Pub := gen4Priv.Public().(ed25519.PublicKey)
	if err := st.SaveControllerPin(localstate.ControllerPin{
		InstanceID: "inst-1", KeyID: security.KeyIDOf(gen4Pub),
		PublicKeyRaw: append(ed25519.PublicKey(nil), gen4Pub...), Generation: 4,
	}); err != nil {
		t.Fatal(err)
	}
	_, forgedNewPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedNewPub := forgedNewPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()
	tryAccept := func(label string, c security.RotationCertificate) {
		t.Helper()
		if err := security.SignRotationCertificate(&c, gen4Priv); err != nil {
			t.Fatal(err)
		}
		raw, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := AcceptControllerRotationPin(st, "inst-1", []byte(raw)); err == nil {
			t.Fatalf("%s: forged certificate signed by the legit gen-4 key was accepted", label)
		}
	}
	// (a) The exact M1 scenario: gen-1 -> gen-3 downgrade signed by the gen-4 key.
	tryAccept("gen-1->3 downgrade", security.NewRotationCertificate(
		"controller", gen4Pub, 1, security.KeyIDOf(gen4Pub), forgedNewPub, 3, security.KeyIDOf(forgedNewPub), now, now+3600))
	// (b) Cross-chain forgery: gen-1 -> gen-5 signed by the gen-4 key. Decode and
	// storage both accept gen 5 > gen 4, but the certificate's OldGeneration (1)
	// does not equal the persisted pin generation (4) — a cert chain the agent
	// never witnessed. Must be refused by AcceptControllerRotationPin itself.
	tryAccept("gen-1->5 oldGeneration mismatch", security.NewRotationCertificate(
		"controller", gen4Pub, 1, security.KeyIDOf(gen4Pub), forgedNewPub, 5, security.KeyIDOf(forgedNewPub), now, now+3600))

	persisted, found, err := st.ControllerPin("inst-1")
	if err != nil || !found {
		t.Fatalf("pin missing after refused downgrade found=%v err=%v", found, err)
	}
	if persisted.Generation != 4 {
		t.Fatalf("pin generation regressed to %d after a refused downgrade", persisted.Generation)
	}
}

// TestAgentRefusesWrongInstance: a certificate bound to a different pinned
// controller instance fails closed.
func TestAgentRefusesWrongInstance(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub := newPriv.Public().(ed25519.PublicKey)
	seedPin(t, st, "inst-A", oldPub)

	now := time.Now().Unix()
	cert := security.NewRotationCertificate("controller", oldPub, 1, security.KeyIDOf(oldPub), newPub, 2, security.KeyIDOf(newPub), now, now+3600)
	_ = security.SignRotationCertificate(&cert, oldPriv)
	raw, _ := cert.Encode()
	if _, _, err := AcceptControllerRotationPin(st, "inst-B", []byte(raw)); err == nil {
		t.Fatal("rotation for a different controller instance accepted")
	}
}
