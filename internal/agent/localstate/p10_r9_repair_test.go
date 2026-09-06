package localstate

import (
	"testing"
)

func TestRecoverApplyingOperationsQueuesNack(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := store.ReceiveCommandWithPayload(
		1, "session-1", "op-recover", "msg-recover", "desired",
		[]byte(`{"node_id":"node-recover","forwards":[]}`), "desired",
	); err != nil || duplicate {
		t.Fatalf("ReceiveCommandWithPayload = duplicate %v, err %v", duplicate, err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-recover"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-recover"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverApplyingOperations(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if phase, ok, err := store.OperationPhase("op-recover"); err != nil || !ok || phase != phaseNacked {
		t.Fatalf("recovered operation phase = %q (present %v, err %v), want NACKED", phase, ok, err)
	}
	state, present, err := store.OutboxState("op-recover")
	if err != nil || !present || state != phasePending {
		t.Fatalf("recovered outbox = %q (present %v, err %v), want PENDING", state, present, err)
	}
}

func TestRecoverApplyingOperationsNacksNonDeletionKinds(t *testing.T) {
	for _, kind := range []string{"probe_arm", "probe_outcome", "node_decommission"} {
		t.Run(kind, func(t *testing.T) {
			store, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.AdvanceSession(1, "session-1"); err != nil {
				t.Fatal(err)
			}
			if duplicate, err := store.ReceiveCommand(
				1, "session-1", "op", "msg", kind, "payload-hash", kind,
			); err != nil || duplicate {
				t.Fatalf("ReceiveCommand duplicate=%v err=%v", duplicate, err)
			}
			if err := store.PersistOperationIntent(1, "session-1", "op"); err != nil {
				t.Fatal(err)
			}
			if err := store.MarkOperationApplying(1, "session-1", "op"); err != nil {
				t.Fatal(err)
			}
			if err := store.RecoverApplyingOperations(1, "session-1"); err != nil {
				t.Fatal(err)
			}
			if phase, ok, err := store.OperationPhase("op"); err != nil || !ok || phase != phaseNacked {
				t.Fatalf("phase=%q present=%v err=%v, want NACKED", phase, ok, err)
			}
		})
	}
}
