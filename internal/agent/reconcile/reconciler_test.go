package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// reconciler.go RED: the reconcile control loop applies desired, records
// durable deletion results, refuses to run decommissioned, and survives actor
// panics without stopping the loop.

func TestReconcileOnceAppliesAndRecordsDeletionResult(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error { return nil })

	d := testDesired(present("fwd-a", 1), absent("fwd-b", "del-op-b", 1))
	report, err := reconciler.ReconcileOnce(context.Background(), d, 1, "session-1")
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != localstate.ApplyStatusFull {
		t.Fatalf("report status = %v, want FULL", report.Status)
	}
	// fwd-a applied, fwd-b tombstoned.
	if _, ok, err := store.GetAppliedState("fwd-a"); err != nil || !ok {
		t.Fatalf("fwd-a applied present=%v err=%v", ok, err)
	}
	if ok, err := store.TombstoneExists("fwd-b"); err != nil || !ok {
		t.Fatalf("fwd-b tombstone present=%v err=%v", ok, err)
	}
	// The durable deletion result must be queued to the outbox.
	state, present, err := store.OutboxState("del-op-b")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("del-op-b outbox = %q present=%v err=%v, want PENDING", state, present, err)
	}
}

func TestReconcileOnceWithoutSessionSkipsResultRecording(t *testing.T) {
	store := testStore(t)
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive, nil,
		func(ctx context.Context, forwardID string) error { return nil })
	report, err := reconciler.ReconcileOnce(context.Background(), testDesired(absent("fwd-c", "del-op-c", 1)), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-c" && r.Outcome != OutcomeDeleted {
			t.Fatalf("result = %+v, want OutcomeDeleted", r)
		}
	}
	// No session: the tombstone is durable but no result is queued yet.
	if ok, err := store.TombstoneExists("fwd-c"); err != nil || !ok {
		t.Fatalf("tombstone present=%v err=%v", ok, err)
	}
	if store.OutboxContains("del-op-c") {
		t.Fatal("deletion result queued without a session; want skipped")
	}
}

func TestReconcileOnceRefusesWhenDecommissioned(t *testing.T) {
	store := testStore(t)
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerDecommissioned, nil, nil)
	_, err := reconciler.ReconcileOnce(context.Background(), testDesired(present("fwd-x", 1)), 1, "s")
	if !errors.Is(err, ErrDecommissioned) {
		t.Fatalf("decommissioned reconcile error = %v, want ErrDecommissioned", err)
	}
}

func TestReconcileRunLoopSurvivesActorPanicAndProcessesTriggers(t *testing.T) {
	store := testStore(t)
	// Seed the received desired so each loop trigger actually reconciles and
	// starts the panicking actor through the apply hook.
	if err := store.SaveReceivedDesired(testDesired(present("panic-fwd", 1))); err != nil {
		t.Fatal(err)
	}
	supervisor := NewSupervisor()
	panicActor := &funcActor{name: "panic-fwd", run: func(ctx context.Context) error { panic("boom") }}
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			// The hook starts a panicking actor; the supervisor contains the
			// panic and the control loop must not stop.
			if err := supervisor.Start(ctx, panicActor); err != nil {
				return protocol.AppliedForwardState{}, err
			}
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error { return nil })

	trigger := make(chan struct{}, 2)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- reconciler.Run(ctx, trigger) }()

	trigger <- struct{}{}
	trigger <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("loop exited early: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop exit error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop on cancel")
	}
	// The panicking actor was reported PANICKED and everything else survived.
	sawPanic := false
	deadline := time.After(time.Second)
readLoop:
	for !sawPanic {
		select {
		case result := <-supervisor.Results():
			if result.Actor == "panic-fwd" && result.Outcome == ActorPanicked {
				sawPanic = true
			}
		case <-deadline:
			break readLoop
		}
	}
	if !sawPanic {
		t.Fatal("actor panic was not reported by the supervisor")
	}
}

func TestReconcileOnceActorPanicDoesNotFailTheReconcile(t *testing.T) {
	store := testStore(t)
	supervisor := NewSupervisor()
	var calls atomic.Int64
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			calls.Add(1)
			_ = supervisor.Start(ctx, &funcActor{name: "boom", run: func(ctx context.Context) error { panic("x") }})
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		nil)
	report, err := reconciler.ReconcileOnce(context.Background(), testDesired(present("fwd-p", 1)), 0, "")
	if err != nil {
		t.Fatalf("reconcile with panicking actor errored: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("apply hook calls = %d, want 1", calls.Load())
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-p" && r.Outcome != OutcomeApplied {
			t.Fatalf("result = %+v, want OutcomeApplied", r)
		}
	}
}

// Repair-cycle Q1 RED: re-reconciling the same desired snapshot while its
// deletion result is in flight (SENT then SEMANTIC_ACKED, no durable receipt)
// must return nil, leave the outbox row untouched, and not disturb the
// subsequent receipt path. Before the fix ReconcileOnce propagated
// ErrIllegalPhase and the control loop died.
func TestReconcileOnceRepeatedWhileDeletionResultInFlight(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error { return nil })
	d := testDesired(present("fwd-a", 1), absent("fwd-b", "del-op-b", 1))
	if _, err := reconciler.ReconcileOnce(context.Background(), d, 1, "session-1"); err != nil {
		t.Fatal(err)
	}
	// Advance the deletion result to SENT, then SEMANTIC_ACKED: the durable
	// result is in flight with no receipt yet.
	if err := store.ClaimOutbox(1, "session-1", "del-op-b"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "del-op-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.ReconcileOnce(context.Background(), d, 1, "session-1"); err != nil {
		t.Fatalf("re-reconcile while row SENT error = %v, want nil", err)
	}
	state, present, err := store.OutboxState("del-op-b")
	if err != nil || !present || state != "SENT" {
		t.Fatalf("outbox after re-reconcile while SENT = %q present=%v err=%v, want SENT", state, present, err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "del-op-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.ReconcileOnce(context.Background(), d, 1, "session-1"); err != nil {
		t.Fatalf("re-reconcile while row SEMANTIC_ACKED error = %v, want nil", err)
	}
	state, present, err = store.OutboxState("del-op-b")
	if err != nil || !present || state != "SEMANTIC_ACKED" {
		t.Fatalf("outbox after re-reconcile while SEMANTIC_ACKED = %q present=%v err=%v, want SEMANTIC_ACKED", state, present, err)
	}
	// The subsequent receipt path must be undisturbed.
	if err := store.AcceptReceipt(1, "session-1", "del-op-b"); err != nil {
		t.Fatalf("receipt after in-flight re-reconcile error = %v", err)
	}
	if store.OutboxContains("del-op-b") {
		t.Fatal("durable receipt must GC the outbox row")
	}
}

// Repair-cycle Q1 RED: the Run control loop must survive a re-trigger while a
// deletion result is in flight (SENT, no receipt). Before the fix the second
// trigger's re-record returned ErrIllegalPhase and Run exited permanently.
func TestReconcileRunSurvivesInFlightDeletionResult(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveReceivedDesired(testDesired(present("fwd-a", 1), absent("fwd-b", "del-op-b", 1))); err != nil {
		t.Fatal(err)
	}
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error { return nil })
	trigger := make(chan struct{}, 2)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- reconciler.Run(ctx, trigger) }()

	trigger <- struct{}{}
	// Wait until the first pass has durably queued the deletion result, then
	// advance it to SENT while the loop is live.
	deadline := time.Now().Add(2 * time.Second)
	for !store.OutboxContains("del-op-b") {
		if time.Now().After(deadline) {
			t.Fatal("deletion result was not queued by the loop")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := store.ClaimOutbox(1, "session-1", "del-op-b"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "del-op-b"); err != nil {
		t.Fatal(err)
	}
	// Second trigger while the row is SENT: the loop must not exit.
	trigger <- struct{}{}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("loop exited while deletion result in flight: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop exit error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop on cancel")
	}
}

// Repair-cycle N2 RED: a deletion result whose outcome FLIPS between
// reconciles while the earlier result is in flight must not terminate the
// Run control loop. The stop hook fails on the first pass (durable
// "deleted=false,reason=..." queued and advanced to SENT), then succeeds on
// the re-reconcile ("deleted=true"); the re-record is tolerated because the
// result is already durably queued (the Controller re-issues with a fresh
// deletion_operation_id for a different outcome), so ReconcileOnce returns
// nil and Run survives. Before the fix the second pass failed with
// ErrStaleWriter and Run exited permanently.
func TestReconcileRunSurvivesStopOutcomeFlip(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveReceivedDesired(testDesired(present("fwd-a", 1), absent("fwd-b", "del-op-flip", 1))); err != nil {
		t.Fatal(err)
	}
	var stopCalls atomic.Int64
	var stopFails atomic.Bool // when true the stop hook fails transiently
	stopFails.Store(true)
	reconciler := New(store, localstate.NewLatch(), localstate.MarkerActive,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error {
			stopCalls.Add(1)
			if stopFails.Load() {
				return errors.New("stop hook transient failure")
			}
			return nil
		})
	trigger := make(chan struct{}, 2)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- reconciler.Run(ctx, trigger) }()

	// First pass: the stop hook fails -> durable "deleted=false,reason=...".
	trigger <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for !store.OutboxContains("del-op-flip") {
		if time.Now().After(deadline) {
			t.Fatal("deletion result was not queued by the first pass")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if stopCalls.Load() != 1 {
		t.Fatalf("stop hook calls after first pass = %d, want 1", stopCalls.Load())
	}
	// Advance the earlier result to SENT while the loop is live.
	if err := store.ClaimOutbox(1, "session-1", "del-op-flip"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "del-op-flip"); err != nil {
		t.Fatal(err)
	}
	// Second pass: the stop hook now succeeds -> the outcome flips while the
	// earlier result is in flight. Run must survive.
	stopFails.Store(false)
	trigger <- struct{}{}
	deadline = time.Now().Add(2 * time.Second)
	for stopCalls.Load() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("stop hook was not re-invoked by the second pass")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("loop exited when the deletion outcome flipped: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("loop exit error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not stop on cancel")
	}
	// The durable result from the first pass must not have been silently
	// overwritten with the flipped outcome, and the in-flight row must be
	// untouched.
	state, present, err := store.OutboxState("del-op-flip")
	if err != nil || !present || state != "SENT" {
		t.Fatalf("outbox after tolerated flip = %q present=%v err=%v, want SENT", state, present, err)
	}
	durable, err := store.ResultForOperation(1, "session-1", "del-op-flip")
	if err != nil {
		t.Fatal(err)
	}
	var result DeleteForwardResult
	if err := json.Unmarshal(durable, &result); err != nil {
		t.Fatal(err)
	}
	if result.ForwardID != "fwd-b" || result.DeletionOperationID != "del-op-flip" {
		t.Fatalf("durable result identity = %+v, want fwd-b/del-op-flip", result)
	}
	if result.Deleted {
		t.Fatal("durable result was silently overwritten with the flipped outcome")
	}
}
