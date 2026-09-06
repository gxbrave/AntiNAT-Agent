package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/control"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// RED R5-1: a matching operation/status without a non-zero generation must not
// clear the currently-bound quarantine.
func TestRestoreResultRejectsStaleGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := localstate.WriteRecoveryQuarantineForOperation(dir, "restore-r5", 7); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: Config{StateDir: dir}}
	_, err := a.handleRestoreResult(context.Background(), control.Operation{
		OperationID: "restore-r5",
		Payload:     []byte(`{"restore_operation_id":"restore-r5","generation":6,"status":"authorized"}`),
	})
	if !errors.Is(err, localstate.ErrRecoveryOperationMismatch) {
		t.Fatalf("stale generation error=%v, want binding mismatch", err)
	}
}

func TestRestoreResultRequiresExactNonzeroGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := localstate.WriteRecoveryQuarantineForOperation(dir, "restore-r5", 7); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: Config{StateDir: dir}}
	_, err := a.handleRestoreResult(context.Background(), control.Operation{
		OperationID: "restore-r5",
		Payload:     []byte(`{"restore_operation_id":"restore-r5","status":"authorized"}`),
	})
	if !errors.Is(err, localstate.ErrRecoveryOperationMismatch) {
		t.Fatalf("missing generation error=%v, want binding mismatch", err)
	}
	q, found, err := localstate.LoadRecoveryQuarantineBinding(dir)
	if err != nil || !found || q.OperationID != "restore-r5" || q.Generation != 7 {
		t.Fatalf("quarantine=%+v found=%v err=%v, wildcard result cleared current binding", q, found, err)
	}
}
