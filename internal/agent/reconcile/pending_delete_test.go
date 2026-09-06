package reconcile

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func TestApplyDesiredPendingDeleteFencesPresentAndAllowsMatchingAbsentRetry(t *testing.T) {
	store := testStore(t)
	deleteSpec := absent("fwd-fenced", "del-fenced", 2)
	if err := store.PutForwardDeleteIntents([]localstate.ForwardDeleteIntent{{
		ForwardID: deleteSpec.ForwardID, DeletionOperationID: deleteSpec.DeletionOperationID, DesiredRevision: deleteSpec.DesiredRevision,
	}}); err != nil {
		t.Fatal(err)
	}
	var applyCalls atomic.Int64
	presentReport, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), testDesired(present("fwd-fenced", 9)), func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
		applyCalls.Add(1)
		return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if applyCalls.Load() != 0 || len(presentReport.Results) != 1 || presentReport.Results[0].Outcome != OutcomeTombstonedRejected {
		t.Fatalf("fenced PRESENT calls=%d report=%+v, want no apply/TOMBSTONED_REJECTED", applyCalls.Load(), presentReport)
	}
	// Persist the stale PRESENT through the transport merge path. It must be
	// represented durably as ABSENT, not allowed to replace the deletion fence.
	if err := store.SaveReceivedDesired(testDesired(present("fwd-fenced", 9))); err != nil {
		t.Fatal(err)
	}
	stored, ok, err := store.LoadReceivedDesired()
	if err != nil || !ok || len(stored.Forwards) != 1 || stored.Forwards[0].Presence != protocol.PresenceAbsent {
		t.Fatalf("stored after fenced PRESENT=%+v ok=%v err=%v, want durable ABSENT", stored, ok, err)
	}
	var stopCalls atomic.Int64
	if _, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), testDesired(deleteSpec), nil, func(ctx context.Context, forwardID string) error {
		stopCalls.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if stopCalls.Load() != 1 {
		t.Fatalf("matching ABSENT stop calls=%d, want 1", stopCalls.Load())
	}
	if _, pending, _, tombstoned, err := store.ForwardDeleteFence(deleteSpec.ForwardID); err != nil || pending || !tombstoned {
		t.Fatalf("fence after matching ABSENT pending=%v tombstoned=%v err=%v, want completed", pending, tombstoned, err)
	}
}

func TestApplyDesiredCompletedDeleteDoesNotRepeatStop(t *testing.T) {
	store := testStore(t)
	d := testDesired(absent("fwd-idempotent", "del-idempotent", 1))
	var stopCalls atomic.Int64
	stop := func(ctx context.Context, forwardID string) error { stopCalls.Add(1); return nil }
	if _, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), d, nil, stop); err != nil {
		t.Fatal(err)
	}
	if stopCalls.Load() != 1 {
		t.Fatalf("first stop calls=%d, want 1", stopCalls.Load())
	}
	if _, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), d, nil, stop); err != nil {
		t.Fatal(err)
	}
	if stopCalls.Load() != 1 {
		t.Fatalf("duplicate stop calls=%d, want unchanged at 1", stopCalls.Load())
	}
}

func TestApplyDesiredDeleteFailureRetainsPendingFenceForRetry(t *testing.T) {
	store := testStore(t)
	d := testDesired(absent("fwd-retry", "del-retry", 1))
	stopErr := errors.New("temporary cleanup error")
	if report, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), d, nil, func(context.Context, string) error { return stopErr }); err != nil {
		t.Fatal(err)
	} else if len(report.Results) != 1 || report.Results[0].Outcome != OutcomeDeleteFailed {
		t.Fatalf("first report=%+v, want delete failure", report)
	}
	if _, pending, _, tombstoned, err := store.ForwardDeleteFence("fwd-retry"); err != nil || !pending || !tombstoned {
		t.Fatalf("after failed stop pending=%v tombstoned=%v err=%v, want both", pending, tombstoned, err)
	}
	var calls atomic.Int64
	if _, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), d, nil, func(context.Context, string) error { calls.Add(1); return nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("retry stop calls=%d, want 1", calls.Load())
	}
}
