// P14 Story 5 (agent side): RECOVERY_QUARANTINE marker lifecycle and the
// terminal-marker protection rule (an old backup can never quarantine over — or
// reopen — a DECOMMISSIONED uninstall).
package localstate

import (
	"errors"
	"testing"
)

// TestRecoveryQuarantineWriteLoadClear round-trips the marker.
func TestRecoveryQuarantineWriteLoadClear(t *testing.T) {
	dir := t.TempDir()
	q, err := LoadRecoveryQuarantine(dir)
	if err != nil || q {
		t.Fatalf("initial quarantine = %v err=%v, want false", q, err)
	}
	if err := WriteRecoveryQuarantine(dir); err != nil {
		t.Fatal(err)
	}
	q, err = LoadRecoveryQuarantine(dir)
	if err != nil || !q {
		t.Fatalf("quarantine after write = %v err=%v", q, err)
	}
	if err := ClearRecoveryQuarantine(dir); err != nil {
		t.Fatal(err)
	}
	q, err = LoadRecoveryQuarantine(dir)
	if err != nil || q {
		t.Fatalf("quarantine after clear = %v err=%v", q, err)
	}
	// Idempotent clear.
	if err := ClearRecoveryQuarantine(dir); err != nil {
		t.Fatal(err)
	}
}

// TestRecoveryQuarantineNeverOverTerminal: quarantine over a DECOMMISSIONED
// marker is refused — the current terminal/uninstall marker can never be
// overwritten by an old backup.
func TestRecoveryQuarantineConcurrentNextGenerationKeepsOneWinner(t *testing.T) {
	dir := t.TempDir()
	results := make(chan error, 2)
	for _, operationID := range []string{"restore-a", "restore-b"} {
		go func(operationID string) {
			_, err := WriteNextRecoveryQuarantineForOperation(dir, operationID)
			results <- err
		}(operationID)
	}
	var successes int
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, ErrRecoveryOperationMismatch) {
			t.Fatalf("unexpected concurrent quarantine error: %v", err)
		}
	}
	if successes != 2 {
		t.Fatalf("concurrent quarantine successes=%d, want both serialized generations", successes)
	}
	q, found, err := LoadRecoveryQuarantineBinding(dir)
	if err != nil || !found || q.Generation != 2 {
		t.Fatalf("quarantine=%+v found=%v err=%v, want serialized generation-2 binding", q, found, err)
	}
}

func TestRecoveryQuarantineRejectsEqualGenerationDifferentOperation(t *testing.T) {
	dir := t.TempDir()
	if err := WriteRecoveryQuarantineForOperation(dir, "restore-a", 9); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecoveryQuarantineForOperation(dir, "restore-b", 9); err == nil {
		t.Fatal("equal-generation different-operation quarantine was accepted")
	}
	q, found, err := LoadRecoveryQuarantineBinding(dir)
	if err != nil || !found || q.OperationID != "restore-a" || q.Generation != 9 {
		t.Fatalf("quarantine=%+v found=%v err=%v, equal-generation overwrite occurred", q, found, err)
	}
}

func TestRecoveryQuarantineNeverOverTerminal(t *testing.T) {
	dir := t.TempDir()
	if err := WriteMarker(dir, MarkerDecommissioning); err != nil {
		t.Fatal(err)
	}
	if err := WriteMarker(dir, MarkerDecommissioned); err != nil {
		t.Fatal(err)
	}
	if err := WriteRecoveryQuarantine(dir); err == nil {
		t.Fatal("quarantine accepted over a DECOMMISSIONED terminal marker")
	}
	marker, err := LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if marker != MarkerDecommissioned {
		t.Fatalf("terminal marker was overwritten: %q", marker)
	}
}
