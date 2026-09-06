// P14 Story 5 (reconcile side): RecoveryDeferred decision for the restore
// quarantine / terminal-marker one-way boundaries.
package reconcile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// TestRecoveryDeferredCorruptQuarantineFailsClosed (repair-1 L6): an ambiguous
// quarantine FILE must fail closed — recovery is DEFERRED and the error is
// surfaced. Before the fix the error returned (false, RecoveryAllowed), so a
// caller ignoring the error would auto-recover LKG listeners on an unreadable
// quarantine marker.
func TestRecoveryDeferredCorruptQuarantineFailsClosed(t *testing.T) {
	// A stateDir that is a regular FILE makes opening "<dir>/recovery.quarantine"
	// fail with ENOTDIR: the quarantine state is ambiguous, so RecoveryDeferred
	// must defer (fail closed) and surface the error instead of allowing recovery.
	fileDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(fileDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	deferred, reason, err := RecoveryDeferred(fileDir, localstate.MarkerActive)
	if err == nil {
		t.Fatal("ambiguous quarantine state must surface an error")
	}
	if !deferred {
		t.Fatal("ambiguous quarantine state must DEFER recovery (fail-closed), not allow it")
	}
	if reason != DeferredByRecoveryQuarantine {
		t.Fatalf("reason = %q, want %q", reason, DeferredByRecoveryQuarantine)
	}
}

// TestRecoveryDeferredBoundaries covers the three outcomes: terminal marker
// deferral, quarantine deferral, and normal recovery allowed.
func TestRecoveryDeferredBoundaries(t *testing.T) {
	dir := t.TempDir()

	// Normal: no marker, no quarantine -> recovery allowed.
	deferred, reason, err := RecoveryDeferred(dir, localstate.MarkerActive)
	if err != nil {
		t.Fatal(err)
	}
	if deferred || reason != RecoveryAllowed {
		t.Fatalf("normal state deferred=%v reason=%q", deferred, reason)
	}

	// Terminal marker is the highest-priority boundary.
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}
	deferred, reason, err = RecoveryDeferred(dir, localstate.MarkerDecommissioned)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred || reason != DeferredByTerminalMarker {
		t.Fatalf("terminal state deferred=%v reason=%q", deferred, reason)
	}

	// Quarantine alone defers recovery.
	dir2 := t.TempDir()
	if err := localstate.WriteRecoveryQuarantine(dir2); err != nil {
		t.Fatal(err)
	}
	deferred, reason, err = RecoveryDeferred(dir2, localstate.MarkerActive)
	if err != nil {
		t.Fatal(err)
	}
	if !deferred || reason != DeferredByRecoveryQuarantine {
		t.Fatalf("quarantine state deferred=%v reason=%q", deferred, reason)
	}
}
