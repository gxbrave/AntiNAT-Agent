package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/control"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// RED R4-4/B: an authenticated delayed restore result for an older operation
// must not clear a newer quarantine binding.
func TestRestoreResultCannotClearNewerQuarantine(t *testing.T) {
	dir := t.TempDir()
	if err := localstate.WriteRecoveryQuarantineForOperation(dir, "restore-a", 1); err != nil {
		t.Fatal(err)
	}
	if err := localstate.WriteRecoveryQuarantineForOperation(dir, "restore-b", 2); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: Config{StateDir: dir}}
	_, err := a.handleRestoreResult(context.Background(), control.Operation{
		OperationID: "restore-a",
		Payload:     []byte(`{"restore_operation_id":"restore-a","generation":1,"status":"authorized"}`),
	})
	if !errors.Is(err, localstate.ErrRecoveryOperationMismatch) {
		t.Fatalf("stale restore result error=%v, want binding mismatch", err)
	}
	q, found, err := localstate.LoadRecoveryQuarantineBinding(dir)
	if err != nil || !found || q.OperationID != "restore-b" || q.Generation != 2 {
		t.Fatalf("quarantine=%+v found=%v err=%v, newer binding was cleared", q, found, err)
	}
}

// RED R4-5/E: once the terminal marker is DECOMMISSIONED, concurrent or later
// attempts to write DECOMMISSIONING cannot downgrade it.
func TestTerminalMarkerNeverDowngradesAfterDecommissioned(t *testing.T) {
	dir := t.TempDir()
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}
	if err := localstate.WriteMarker(dir, localstate.MarkerDecommissioning); err == nil {
		t.Fatal("DECOMMISSIONED marker accepted a downgrade")
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker=%q err=%v after downgrade attempt", marker, err)
	}
}
