package localstate

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Story 5 RED: the terminal marker is written atomically (temp + fsync +
// rename + parent sync) and the shared latch refuses to start any actor after
// the marker engages; DECOMMISSIONING/DECOMMISSIONED load behavior must be
// explicit.

func TestMarkerWriteIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMarker(dir, MarkerDecommissioning); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, markerFile))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("marker mode = %#o, want 0600", got)
	}
	state, err := LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state != MarkerDecommissioning {
		t.Fatalf("marker state = %q, want DECOMMISSIONING", state)
	}
	// Upgrade to DECOMMISSIONED must leave no temp files behind.
	if err := WriteMarker(dir, MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}
	state, err = LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state != MarkerDecommissioned {
		t.Fatalf("marker state = %q, want DECOMMISSIONED", state)
	}
	matches, err := filepath.Glob(filepath.Join(dir, ".antinat-marker-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("leftover marker temp files: %v", matches)
	}
}

func TestMarkerStateDefaultsToActiveWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	state, err := LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state != MarkerActive {
		t.Fatalf("marker state without file = %q, want ACTIVE", state)
	}
}

func TestMarkerRejectsUnknownContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, markerFile), []byte("GARBAGE"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadMarker(dir); err == nil {
		t.Fatal("unknown marker content loaded successfully; want fail closed")
	}
}

func TestMarkerSurvivesReopenAndTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMarker(dir, MarkerDecommissioning); err != nil {
		t.Fatal(err)
	}
	// Marker is durable and read before any bbolt state.
	if _, err := Open(dir); err != nil {
		t.Fatalf("store open under DECOMMISSIONING marker failed: %v", err)
	}
	state, err := LoadMarker(dir)
	if err != nil || state != MarkerDecommissioning {
		t.Fatalf("marker after reopen = %q err=%v, want DECOMMISSIONING", state, err)
	}
}

func TestLatchEngagementBlocksNewActors(t *testing.T) {
	latch := NewLatch()
	if err := latch.RegisterActor("fwd-1"); err != nil {
		t.Fatal(err)
	}
	if latch.ActiveCount() != 1 {
		t.Fatalf("active count = %d, want 1", latch.ActiveCount())
	}
	if !latch.TryEngage() {
		t.Fatal("first engage must succeed")
	}
	// From the marker onward no concurrent desired apply may start a new actor.
	if err := latch.RegisterActor("fwd-2"); !errors.Is(err, ErrTerminalEngaged) {
		t.Fatalf("register after engage error = %v, want ErrTerminalEngaged", err)
	}
	if latch.ActiveCount() != 1 {
		t.Fatalf("active count after rejected register = %d, want 1", latch.ActiveCount())
	}
	if !latch.Engaged() {
		t.Fatal("latch must report engaged")
	}
	if latch.TryEngage() {
		t.Fatal("second engage must fail (first one wins)")
	}
	// Deregistering the pre-engage actor cannot open the latch.
	latch.UnregisterActor("fwd-1")
	if err := latch.RegisterActor("fwd-3"); !errors.Is(err, ErrTerminalEngaged) {
		t.Fatalf("register after deregister on engaged latch error = %v, want ErrTerminalEngaged", err)
	}
}

func TestLatchAllowsActorsBeforeEngagement(t *testing.T) {
	latch := NewLatch()
	for i := 0; i < 5; i++ {
		name := string(rune('a' + i))
		if err := latch.RegisterActor(name); err != nil {
			t.Fatalf("register %s before engage error = %v", name, err)
		}
	}
	if latch.ActiveCount() != 5 {
		t.Fatalf("active count = %d, want 5", latch.ActiveCount())
	}
	if latch.Engaged() {
		t.Fatal("latch must not report engaged before TryEngage")
	}
}
