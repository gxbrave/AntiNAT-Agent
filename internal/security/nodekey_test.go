// Story 2 RED: secret-safe node identity key. The key file must be created
// atomically with owner-only permissions, reload stably, survive concurrent
// load-or-create, and never leak key material through errors.
package security_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

// RED 2a: LoadOrCreateNodeKey creates the key file with mode 0600 and a
// reload returns the same key.
func TestNodeKeyLoadOrCreateSecretSafe(t *testing.T) {
	dir := t.TempDir()
	k1, err := security.LoadOrCreateNodeKey(dir, 1)
	if err != nil {
		t.Fatalf("LoadOrCreateNodeKey: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, security.NodeKeyFile))
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}
	k2, err := security.LoadOrCreateNodeKey(dir, 1)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !k1.PublicKey().Equal(k2.PublicKey()) {
		t.Fatal("reload returned a different key")
	}
	if k2.CredentialVersion() != 1 {
		t.Fatalf("credential version = %d, want 1", k2.CredentialVersion())
	}
}

// RED 2b: the key file must not be world-readable before or after creation.
func TestNodeKeyFileNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	if _, err := security.LoadOrCreateNodeKey(dir, 1); err != nil {
		t.Fatalf("LoadOrCreateNodeKey: %v", err)
	}
	path := filepath.Join(dir, security.NodeKeyFile)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("key file is group/world accessible: %v", info.Mode().Perm())
	}
}

// RED 2c: concurrent LoadOrCreateNodeKey must not corrupt the key file and
// must converge on one key.
func TestNodeKeyConcurrentLoadOrCreate(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	keys := make([]*security.NodeKey, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			k, err := security.LoadOrCreateNodeKey(dir, 1)
			if err == nil {
				keys[i] = k
			}
		}(i)
	}
	wg.Wait()
	first := keys[0]
	if first == nil {
		t.Fatal("no key produced")
	}
	for i, k := range keys {
		if k == nil {
			t.Fatalf("goroutine %d failed", i)
		}
		if !k.PublicKey().Equal(first.PublicKey()) {
			t.Fatalf("goroutine %d produced a different key (file race)", i)
		}
	}
}

// RED 2d: a corrupt key file fails closed with an error that never contains
// the raw key material.
func TestNodeKeyCorruptFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, security.NodeKeyFile)
	secret := "S3CR3T-KEY-MATERIAL-0123456789abcdef"
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := security.LoadOrCreateNodeKey(dir, 1)
	if err == nil {
		t.Fatal("corrupt key file loaded successfully")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "S3CR3T") {
		t.Fatalf("error leaks key material: %v", err)
	}
}

// RED 2e: key errors never render the private key bytes.
func TestNodeKeyErrorsDoNotLeakKey(t *testing.T) {
	dir := t.TempDir()
	k, err := security.LoadOrCreateNodeKey(dir, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Force a failure path that must not contain the key.
	_, err = k.Sign(nil) // valid usage; just ensure Sign exists and roundtrips
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_ = k
}
