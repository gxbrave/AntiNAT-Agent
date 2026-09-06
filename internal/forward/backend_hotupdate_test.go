// Story 4 RED: backend hot update must leave existing connections on their
// original target while new connections use the new snapshot (v0.8 §4.5
// NEW_SESSIONS_ONLY semantics: rate/stat updates apply to new sessions only;
// here the same applies to target updates). An invalid update must not
// corrupt the current snapshot.
package forward

import (
	"net/netip"
	"testing"
)

func TestBackendUpdateChangesTarget(t *testing.T) {
	backend, err := NewBackend("127.0.0.1:1001")
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Update("127.0.0.1:1002"); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if want := netip.MustParseAddrPort("127.0.0.1:1002"); backend.Target() != want {
		t.Fatalf("Target() = %v, want %v", backend.Target(), want)
	}
}

func TestBackendUpdateRejectsInvalidTargetAndKeepsSnapshot(t *testing.T) {
	backend, err := NewBackend("127.0.0.1:1001")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"", "host:80", "[::1]:80", "127.0.0.1:70000"} {
		if err := backend.Update(target); err == nil {
			t.Errorf("Update(%q) unexpectedly succeeded", target)
		}
	}
	want := netip.MustParseAddrPort("127.0.0.1:1001")
	if got := backend.Target(); got != want {
		t.Fatalf("Target() after failed updates = %v, want unchanged %v", got, want)
	}
}
