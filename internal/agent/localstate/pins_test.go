// Story 3 RED: controller pin persistence on the Agent (bbolt
// controller_pins bucket). The pin set is durable, generation
// anti-downgrade, and survives reopen.
package localstate_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

func testPin(t *testing.T, instance string, generation uint64) localstate.ControllerPin {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return localstate.ControllerPin{
		InstanceID:   instance,
		KeyID:        "k-" + instance,
		PublicKeyRaw: priv.Public().(ed25519.PublicKey),
		Generation:   generation,
	}
}

// RED 3e: a saved pin survives reopen and round-trips.
func TestControllerPinSaveAndReopen(t *testing.T) {
	dir := t.TempDir()
	s1, err := localstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	pin := testPin(t, "inst-1", 1)
	if err := s1.SaveControllerPin(pin); err != nil {
		t.Fatalf("SaveControllerPin: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := localstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, ok, err := s2.ControllerPin("inst-1")
	if err != nil || !ok {
		t.Fatalf("ControllerPin = ok:%v err:%v", ok, err)
	}
	if got.KeyID != pin.KeyID || got.Generation != 1 || !got.PublicKey().Equal(pin.PublicKey()) {
		t.Fatalf("pin = %+v, want %+v", got, pin)
	}
}

// RED 3f: a generation downgrade is refused (v0.8 §8.3: persist the highest
// generation to prevent downgrade).
func TestControllerPinGenerationDowngradeRefused(t *testing.T) {
	s, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SaveControllerPin(testPin(t, "inst-1", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveControllerPin(testPin(t, "inst-1", 1)); !errors.Is(err, localstate.ErrPinDowngrade) {
		t.Fatalf("downgrade save = %v, want ErrPinDowngrade", err)
	}
	got, ok, err := s.ControllerPin("inst-1")
	if err != nil || !ok {
		t.Fatalf("ControllerPin = ok:%v err:%v", ok, err)
	}
	if got.Generation != 2 {
		t.Fatalf("generation after refused downgrade = %d, want 2", got.Generation)
	}
}

// RED 3g: absent pins report not-found and an empty list.
func TestControllerPinAbsent(t *testing.T) {
	s, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.ControllerPin("nope"); err != nil || ok {
		t.Fatalf("absent pin = ok:%v err:%v", ok, err)
	}
	pins, err := s.ListControllerPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 0 {
		t.Fatalf("pins = %d, want 0", len(pins))
	}
}
