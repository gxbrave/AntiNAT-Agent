// Story 1 RED: enrollment challenge manager. Unknown, replayed, expired, and
// bounded-cache cases fail closed before the challenge.go GREEN
// implementation. Cross-node enforcement is exercised at the token-binding
// layer (the EnrollRequest carries no node id; the challenge is the node
// identity and the token must match it).
package security_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/security"
)

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func testInstanceID(t *testing.T) [16]byte {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return id
}

// challengeHash is sha256 of the canonical challenge bytes — the binding the
// EnrollRequest must carry (docs/protocol.md §4.2 field 1).
func challengeHash(c protocol.EnrollChallenge) [32]byte {
	return sha256.Sum256(c.Canonical())
}

// testSigner adapts an ed25519 private key to the Signer interface.
func testSigner(t *testing.T, key ed25519.PrivateKey) security.Signer {
	t.Helper()
	return security.SignerFunc(func(msg []byte) ([]byte, error) {
		return ed25519.Sign(key, msg), nil
	})
}

// RED 1a: a freshly issued challenge validates and consumes exactly once,
// returning the node identity the challenge was issued for.
func TestChallengeIssueAndConsume(t *testing.T) {
	m := security.NewChallengeManager(5*time.Minute, 64)
	key := testKey(t)
	instance := testInstanceID(t)
	node := "node-a"

	ch, _, err := m.Issue(testSigner(t, key), instance, "k-1", node)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// The challenge binds the node as a fixed-width 16-byte field; the store
	// node id is the unpadded string, so the hub compares padded forms.
	want := [16]byte{}
	copy(want[:], node)
	if ch.NodeID != want {
		t.Fatalf("challenge node = %q, want %q", ch.NodeID, want)
	}
	sum := challengeHash(ch)
	bound, err := m.ValidateAndConsume(sum)
	if err != nil {
		t.Fatalf("ValidateAndConsume: %v", err)
	}
	if bound != node {
		t.Fatalf("consumed node = %q, want %q", bound, node)
	}
}

// RED 1b: consuming the same challenge twice is a nonce replay and fails.
func TestChallengeReplayRejected(t *testing.T) {
	m := security.NewChallengeManager(5*time.Minute, 64)
	key := testKey(t)
	instance := testInstanceID(t)
	node := "node-b"

	ch, _, err := m.Issue(testSigner(t, key), instance, "k-1", node)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sum := challengeHash(ch)
	if _, err := m.ValidateAndConsume(sum); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := m.ValidateAndConsume(sum); !errors.Is(err, security.ErrChallengeReplayed) {
		t.Fatalf("second consume = %v, want ErrChallengeReplayed", err)
	}
}

// RED 1c: an expired challenge is rejected before any consumption.
func TestChallengeExpired(t *testing.T) {
	m := security.NewChallengeManager(-time.Minute, 64) // TTL already past
	key := testKey(t)
	instance := testInstanceID(t)
	node := "node-c"

	ch, _, err := m.Issue(testSigner(t, key), instance, "k-1", node)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sum := challengeHash(ch)
	if _, err := m.ValidateAndConsume(sum); !errors.Is(err, security.ErrChallengeExpired) {
		t.Fatalf("expired consume = %v, want ErrChallengeExpired", err)
	}
}

// RED 1d: an unknown challenge hash (issued by a different controller or
// never issued) is rejected — cross-controller replay fails closed.
func TestChallengeUnknownHash(t *testing.T) {
	m := security.NewChallengeManager(5*time.Minute, 64)
	if _, err := m.ValidateAndConsume(sha256.Sum256([]byte("unknown"))); !errors.Is(err, security.ErrChallengeUnknown) {
		t.Fatalf("unknown consume = %v, want ErrChallengeUnknown", err)
	}
}

// RED 1f: the replay cache is bounded — issuing beyond capacity evicts the
// oldest expired entries or fails closed instead of growing without limit.
func TestChallengeCacheBounded(t *testing.T) {
	m := security.NewChallengeManager(5*time.Minute, 4)
	key := testKey(t)
	instance := testInstanceID(t)
	for i := 0; i < 4; i++ {
		node := "node-" + string(rune('a'+i))
		if _, _, err := m.Issue(testSigner(t, key), instance, "k-1", node); err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
	}
	// The 5th issue must either evict an expired entry or fail closed; it must
	// not silently grow the cache.
	if _, _, err := m.Issue(testSigner(t, key), instance, "k-1", "node-5"); err != nil && !errors.Is(err, security.ErrChallengeCacheFull) {
		t.Fatalf("5th Issue = %v, want nil (evict expired) or ErrChallengeCacheFull", err)
	}
	if got := m.Size(); got > 4 {
		t.Fatalf("cache size = %d, want <= 4", got)
	}
}
