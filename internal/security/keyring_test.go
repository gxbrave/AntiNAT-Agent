// Story 1/2 RED: controller signing keyring. Load-or-create must be stable,
// secret-safe (0600, no key material in errors), generation-tracked, and the
// derived key ID must be deterministic across reloads.
package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// RED 1g: LoadOrCreateKeyring persists the signing key with owner-only
// permissions and reloads the same key with the same key ID.
func TestKeyringLoadOrCreateStable(t *testing.T) {
	dir := t.TempDir()
	kr1, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatalf("LoadOrCreateKeyring: %v", err)
	}
	if kr1.KeyID() == "" || len(kr1.KeyID()) > 255 {
		t.Fatalf("key id = %q, want 1..255 utf8", kr1.KeyID())
	}
	info, err := os.Stat(filepath.Join(dir, security.KeyringFile))
	if err != nil {
		t.Fatalf("stat keyring: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("keyring mode = %v, want 0600", info.Mode().Perm())
	}
	kr2, err := security.LoadOrCreateKeyring(dir, 1)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if kr2.KeyID() != kr1.KeyID() {
		t.Fatalf("key id changed across reload: %q vs %q", kr1.KeyID(), kr2.KeyID())
	}
	if !kr2.PublicKey().Equal(kr1.PublicKey()) {
		t.Fatal("public key changed across reload")
	}
	if kr2.Generation() != 1 {
		t.Fatalf("generation = %d, want 1", kr2.Generation())
	}
}

// RED 1h: the keyring must sign and the public key must verify.
func TestKeyringSignAndVerify(t *testing.T) {
	kr, err := security.LoadOrCreateKeyring(t.TempDir(), 1)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("AntiNAT-Enroll-v1 payload")
	sig, err := kr.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !security.VerifyKeyringSignature(kr.PublicKey(), msg, sig) {
		t.Fatal("signature did not verify")
	}
	if security.VerifyKeyringSignature(kr.PublicKey(), []byte("tampered"), sig) {
		t.Fatal("tampered message verified")
	}
}

// RED 1i: a corrupt keyring file fails closed and never leaks key material.
func TestKeyringCorruptFailsClosed(t *testing.T) {
	dir := t.TempDir()
	secret := "CONTROLLER-SIGNING-SECRET-abcdef"
	if err := os.WriteFile(filepath.Join(dir, security.KeyringFile), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := security.LoadOrCreateKeyring(dir, 1)
	if err == nil {
		t.Fatal("corrupt keyring loaded")
	}
	if strings.Contains(err.Error(), "CONTROLLER-SIGNING-SECRET") || strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks key material: %v", err)
	}
}

// RED 1j: a future generation (downgrade protection) is refused on load.
func TestKeyringFutureGenerationRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := security.LoadOrCreateKeyring(dir, 1); err != nil {
		t.Fatal(err)
	}
	// Rewrite the generation field to a future value; load must fail closed.
	path := filepath.Join(dir, security.KeyringFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[4] = 0xff // generation u64 BE, first byte
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = security.LoadOrCreateKeyring(dir, 1)
	if err == nil {
		t.Fatal("future-generation keyring loaded")
	}
}
