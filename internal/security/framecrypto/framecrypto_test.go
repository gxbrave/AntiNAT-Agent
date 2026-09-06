package framecrypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// Story 1 RED: signing and verification over the exact protected bytes must
// reject wrong-size keys/signatures and never panic on malformed inputs.

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	msg := []byte("AntiNAT-Control-v1||header||hash")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("signature length %d, want %d", len(sig), SignatureSize)
	}
	if !Verify(priv.Public().(ed25519.PublicKey), msg, sig) {
		t.Fatal("Verify rejected a valid signature")
	}
	if Verify(priv.Public().(ed25519.PublicKey), []byte("tampered"), sig) {
		t.Fatal("Verify accepted a signature over a different message")
	}
}

func TestSignRejectsInvalidKeySize(t *testing.T) {
	if _, err := Sign(ed25519.PrivateKey{}, []byte("x")); err == nil {
		t.Fatal("Sign accepted an empty private key")
	}
	if _, err := Sign(ed25519.PrivateKey{0x01, 0x02}, []byte("x")); err == nil {
		t.Fatal("Sign accepted a short private key")
	}
}

func TestVerifyRejectsInvalidInputs(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	msg := []byte("message")
	sig, _ := Sign(priv, msg)
	// Wrong signature size must be rejected without panic.
	if Verify(priv.Public().(ed25519.PublicKey), msg, sig[:20]) {
		t.Fatal("Verify accepted a truncated signature")
	}
	// Wrong public key size must be rejected without panic.
	if Verify(ed25519.PublicKey{}, msg, sig) {
		t.Fatal("Verify accepted an empty public key")
	}
	// Empty inputs are not valid.
	if Verify(priv.Public().(ed25519.PublicKey), nil, sig) {
		t.Fatal("Verify accepted nil message")
	}
}

// TestEnvelopeSignatureInputPinsExactBytes pins the frozen signature input
// domain || protected_header_bytes || payload_sha256.
func TestEnvelopeSignatureInputPinsExactBytes(t *testing.T) {
	domain := []byte("AntiNAT-Control-v1")
	header := []byte{0x00, 0x00, 0x00, 0x01, 'a'}
	hash := sha256.Sum256([]byte("payload"))
	got := EnvelopeSignatureInput(domain, header, hash[:])
	want := append(append([]byte(nil), domain...), header...)
	want = append(want, hash[:]...)
	if string(got) != string(want) {
		t.Fatalf("signature input mismatch")
	}
	// Rejecting a wrong-size payload hash prevents ambiguity.
	if string(EnvelopeSignatureInput(domain, header, hash[:8])) == string(want) {
		t.Fatal("signature input accepted a truncated payload hash")
	}
}

func TestConstantsMatchEd25519(t *testing.T) {
	if PublicKeySize != ed25519.PublicKeySize ||
		PrivateKeySize != ed25519.PrivateKeySize ||
		SignatureSize != ed25519.SignatureSize {
		t.Fatal("framecrypto size constants diverge from crypto/ed25519")
	}
}
