// P14 Story 4 (security layer): rotation certificate format, signature
// verification against the pinned key, and the generation anti-downgrade rule.
//
// RED: when first written, `RotationCertificate` / `DecodeRotationCertificate`
// / `SignRotationCertificate` did not exist (the tests could not compile), and
// signature-against-pinned-key verification plus the strictly-increasing
// generation rule were unimplemented. See internal/security/tdd-red.
package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// TestRotationCertificateSignVerifyRoundTrips proves a certificate signed by
// the old key decodes and verifies against the old (pinned) public key.
func TestRotationCertificateSignVerifyRoundTrips(t *testing.T) {
	_, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPub := newPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()

	cert := NewRotationCertificate("controller", oldPub, 1, rotationKeyID(oldPub),
		newPub, 2, rotationKeyID(newPub), now, now+3600)
	if err := SignRotationCertificate(&cert, oldPriv); err != nil {
		t.Fatal(err)
	}
	raw, err := cert.Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRotationCertificate([]byte(raw), oldPub)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.NewKeyID != rotationKeyID(newPub) || decoded.NewGeneration != 2 {
		t.Fatalf("decoded = %+v", decoded)
	}
	if decoded.OldKeyID != rotationKeyID(oldPub) {
		t.Fatalf("decoded old id = %q", decoded.OldKeyID)
	}
}

// TestRotationCertificateRejectsWrongSigner: a certificate signed by a third
// key never verifies against the pinned key.
func TestRotationCertificateRejectsWrongSigner(t *testing.T) {
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPub := newPriv.Public().(ed25519.PublicKey)
	attackerPub := attackerPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()

	// Attacker signs with its own key but claims to bind old -> new.
	cert := NewRotationCertificate("controller", oldPub, 1, rotationKeyID(oldPub),
		newPub, 2, rotationKeyID(newPub), now, now+3600)
	if err := SignRotationCertificate(&cert, attackerPriv); err != nil {
		t.Fatal(err)
	}
	raw, _ := cert.Encode()
	if _, err := DecodeRotationCertificate([]byte(raw), attackerPub); err == nil {
		t.Fatal("attacker-signed cert verified against attacker's own key")
	}
	if _, err := DecodeRotationCertificate([]byte(raw), oldPub); err == nil {
		t.Fatal("attacker-signed cert verified against the pinned key")
	}
}

// TestRotationCertificateRejectsDowngrade: a certificate that keeps or lowers
// the generation is refused (anti-downgrade).
func TestRotationCertificateRejectsDowngrade(t *testing.T) {
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPub := newPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()

	for _, newGen := range []uint64{1, 0} {
		cert := NewRotationCertificate("controller", oldPub, 1, rotationKeyID(oldPub),
			newPub, newGen, rotationKeyID(newPub), now, now+3600)
		if err := SignRotationCertificate(&cert, oldPriv); err != nil {
			t.Fatal(err)
		}
		raw, _ := cert.Encode()
		if _, err := DecodeRotationCertificate([]byte(raw), oldPub); err == nil {
			t.Fatalf("downgrade to generation %d accepted", newGen)
		}
	}
}

// TestRotationCertificateRejectsScopeIdentityAndWindow is the R4-2 RED oracle:
// the pre-repair decoder accepted a legitimate old-key signature with blank or
// foreign scope, a forged OldKeyID, and structurally invalid time bounds.
func TestRotationCertificateRejectsScopeIdentityAndWindow(t *testing.T) {
	_, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPub := newPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()
	cases := []struct {
		name string
		cert RotationCertificate
	}{
		{name: "blank scope", cert: NewRotationCertificate("", oldPub, 1, KeyIDOf(oldPub), newPub, 2, KeyIDOf(newPub), now, now+1)},
		{name: "wrong scope", cert: NewRotationCertificate("agent", oldPub, 1, KeyIDOf(oldPub), newPub, 2, KeyIDOf(newPub), now, now+1)},
		{name: "forged old key id", cert: NewRotationCertificate("controller", oldPub, 1, "forged-old", newPub, 2, KeyIDOf(newPub), now, now+1)},
		{name: "zero not-before", cert: NewRotationCertificate("controller", oldPub, 1, KeyIDOf(oldPub), newPub, 2, KeyIDOf(newPub), 0, now+1)},
		{name: "zero deadline", cert: NewRotationCertificate("controller", oldPub, 1, KeyIDOf(oldPub), newPub, 2, KeyIDOf(newPub), now, 0)},
		{name: "reversed window", cert: NewRotationCertificate("controller", oldPub, 1, KeyIDOf(oldPub), newPub, 2, KeyIDOf(newPub), now+1, now)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := SignRotationCertificate(&tc.cert, oldPriv); err != nil {
				t.Fatal(err)
			}
			raw, err := tc.cert.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeRotationCertificate([]byte(raw), oldPub); err == nil {
				t.Fatalf("%s certificate accepted", tc.name)
			}
		})
	}
}

// TestRotationCertificateRejectsTamper: a bit flip in the new public key breaks
// verification.
func TestRotationCertificateRejectsTamper(t *testing.T) {
	_, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	newPub := newPriv.Public().(ed25519.PublicKey)
	now := time.Now().Unix()

	cert := NewRotationCertificate("controller", oldPub, 1, rotationKeyID(oldPub),
		newPub, 2, rotationKeyID(newPub), now, now+3600)
	if err := SignRotationCertificate(&cert, oldPriv); err != nil {
		t.Fatal(err)
	}
	raw, _ := cert.Encode()
	// Flip one bit of the signature payload in the raw transport.
	tampered := []byte(raw)
	for i := range tampered {
		tampered[i] ^= 0x01
		if i > 0 {
			break
		}
	}
	if _, err := DecodeRotationCertificate(tampered, oldPub); err == nil {
		t.Fatal("tampered certificate accepted")
	}
}
