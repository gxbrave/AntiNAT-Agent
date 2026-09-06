package reconcile

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Reconcile desired-apply RED: per-resource PARTIAL through the reconcile
// layer, old-revision skip, tombstone no-resurrect, latch no-new-actor, and
// tombstone-before-stop ordering.

func testStore(t *testing.T) *localstate.Store {
	t.Helper()
	store, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func testDesired(forwards ...protocol.ForwardSpec) protocol.DesiredState {
	return protocol.DesiredState{NodeID: "node-1", Forwards: forwards}
}

func present(id string, rev uint64) protocol.ForwardSpec {
	return protocol.ForwardSpec{
		ForwardID: id, Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
		Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent,
		DesiredRevision: rev,
	}
}

func absent(id, delOp string, rev uint64) protocol.ForwardSpec {
	return protocol.ForwardSpec{
		ForwardID: id, Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
		Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
		DesiredRevision: rev, DeletionOperationID: delOp,
	}
}

func appliedFor(id string, rev uint64) protocol.AppliedForwardState {
	return protocol.AppliedForwardState{
		ForwardID: id, SpecRevision: rev, DesiredRevision: rev,
		ActualBindHost: "127.0.0.1", ActualBindPort: 20000,
		Strategy: "direct-v4", LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	}
}

func TestApplyDesiredRollsBackNewActorsWhenCommitLosesCapability(t *testing.T) {
	store := testStore(t)
	var sideEffect bool
	var stopCalls int
	rollbackErr := errors.New("rollback stop failed")
	_, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), testDesired(present("fwd-r", 1)),
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			sideEffect = true
			// Simulate a capability-loss/deletion race after the side effect
			// but before the atomic desired commit.
			if _, err := store.CommitDesired(testDesired(absent("fwd-r", "race-delete", 2)), []localstate.ForwardApply{{
				ForwardID: "fwd-r", Outcome: localstate.ApplyDeleted,
			}}); err != nil {
				return protocol.AppliedForwardState{}, err
			}
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error {
			stopCalls++
			sideEffect = false
			return rollbackErr
		})
	if err == nil {
		t.Fatal("ApplyDesired succeeded after commit race, want rollback error")
	}
	if !errors.Is(err, rollbackErr) {
		t.Fatalf("rollback error = %v, want rollback failure to be surfaced", err)
	}
	if stopCalls != 1 || sideEffect {
		t.Fatalf("rollback stop calls=%d sideEffect=%v, want one stop and no side effect", stopCalls, sideEffect)
	}
	if _, ok, err := store.GetAppliedState("fwd-r"); err != nil || ok {
		t.Fatalf("applied state after failed commit present=%v err=%v, want absent", ok, err)
	}
}

func TestApplyDesiredRejectsCapabilityLossBeforeCommit(t *testing.T) {
	store := testStore(t)
	available := true
	var stopCalls int
	_, err := ApplyDesiredWithGuard(context.Background(), store, localstate.NewLatch(), testDesired(present("fwd-c", 1)),
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			available = false
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		},
		func(ctx context.Context, forwardID string) error {
			stopCalls++
			return nil
		},
		func() error {
			if !available {
				return errors.New("route disappeared")
			}
			return nil
		})
	if !errors.Is(err, ErrCapabilityLost) {
		t.Fatalf("capability loss error = %v, want ErrCapabilityLost", err)
	}
	if stopCalls != 1 {
		t.Fatalf("rollback stop calls = %d, want 1", stopCalls)
	}
}

func TestApplyDesiredPartialKeepsOldAppliedAndAdvancesSibling(t *testing.T) {
	store := testStore(t)
	seed := testDesired(present("fwd-a", 1), present("fwd-b", 1))
	report, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), seed,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		}, nil)
	if err != nil || report.Status != localstate.ApplyStatusFull {
		t.Fatalf("seed report=%+v err=%v, want FULL", report, err)
	}

	failErr := errors.New("apply failed for fwd-a")
	next := testDesired(present("fwd-a", 2), present("fwd-b", 2))
	report, err = ApplyDesired(context.Background(), store, localstate.NewLatch(), next,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			if spec.ForwardID == "fwd-a" {
				return protocol.AppliedForwardState{}, failErr
			}
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != localstate.ApplyStatusPartial {
		t.Fatalf("report status = %v, want PARTIAL", report.Status)
	}
	found := false
	for _, r := range report.Results {
		if r.ForwardID == "fwd-a" {
			found = true
			if r.Outcome != OutcomeFailed || !errors.Is(r.Err, failErr) {
				t.Fatalf("fwd-a result = %+v, want OutcomeFailed(failErr)", r)
			}
		}
		if r.ForwardID == "fwd-b" && r.Outcome != OutcomeApplied {
			t.Fatalf("fwd-b result = %+v, want OutcomeApplied", r)
		}
	}
	if !found {
		t.Fatal("missing fwd-a result")
	}
	gotA, ok, err := store.GetAppliedState("fwd-a")
	if err != nil || !ok || gotA.DesiredRevision != 1 {
		t.Fatalf("fwd-a applied=%+v ok=%v err=%v, want old rev 1 retained", gotA, ok, err)
	}
	gotB, ok, err := store.GetAppliedState("fwd-b")
	if err != nil || !ok || gotB.DesiredRevision != 2 {
		t.Fatalf("fwd-b applied=%+v ok=%v err=%v, want advanced rev 2", gotB, ok, err)
	}
}

func TestApplyDesiredSkipsOldRevisionWithoutSideEffect(t *testing.T) {
	store := testStore(t)
	seed := testDesired(present("fwd-a", 2))
	if _, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), seed,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		}, nil); err != nil {
		t.Fatal(err)
	}
	calls := 0
	// A stale desired (revision 1 <= applied 2) must not restart the actor.
	stale := testDesired(present("fwd-a", 1))
	report, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), stale,
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			calls++
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("apply hook called %d times for old revision, want 0", calls)
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-a" && r.Outcome != OutcomeUnchanged {
			t.Fatalf("stale desired outcome = %+v, want OutcomeUnchanged", r)
		}
	}
}

func TestApplyDesiredRejectsTombstonedForward(t *testing.T) {
	store := testStore(t)
	if _, err := store.CommitDesired(testDesired(absent("fwd-t", "del-op-t", 1)), []localstate.ForwardApply{
		{ForwardID: "fwd-t", Outcome: localstate.ApplyDeleted},
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	report, err := ApplyDesired(context.Background(), store, localstate.NewLatch(),
		testDesired(present("fwd-t", 5)),
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			calls++
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("apply hook called %d times for tombstoned forward, want 0", calls)
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-t" && r.Outcome != OutcomeTombstonedRejected {
			t.Fatalf("tombstoned outcome = %+v, want OutcomeTombstonedRejected", r)
		}
	}
	if _, ok, err := store.GetAppliedState("fwd-t"); err != nil || ok {
		t.Fatalf("tombstoned forward applied present=%v err=%v, want absent", ok, err)
	}
}

func TestApplyDesiredTerminalRejectedWhenLatchEngaged(t *testing.T) {
	store := testStore(t)
	latch := localstate.NewLatch()
	if !latch.TryEngage() {
		t.Fatal("engage failed")
	}
	calls := 0
	report, err := ApplyDesired(context.Background(), store, latch, testDesired(present("fwd-l", 1)),
		func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			calls++
			return appliedFor(spec.ForwardID, spec.DesiredRevision), nil
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("apply hook called %d times on engaged latch, want 0", calls)
	}
	for _, r := range report.Results {
		if r.ForwardID == "fwd-l" && r.Outcome != OutcomeTerminalRejected {
			t.Fatalf("engaged-latch outcome = %+v, want OutcomeTerminalRejected", r)
		}
	}
}

func TestApplyDesiredTombstoneBeforeStopHook(t *testing.T) {
	store := testStore(t)
	if _, err := store.CommitDesired(testDesired(present("fwd-d", 1)), []localstate.ForwardApply{
		{ForwardID: "fwd-d", Outcome: localstate.ApplyApplied, Applied: func() *protocol.AppliedForwardState {
			s := appliedFor("fwd-d", 1)
			return &s
		}()},
	}); err != nil {
		t.Fatal(err)
	}
	stopCalls := 0
	report, err := ApplyDesired(context.Background(), store, localstate.NewLatch(),
		testDesired(absent("fwd-d", "del-op-d", 2)),
		nil, // no PRESENT forwards
		func(ctx context.Context, forwardID string) error {
			stopCalls++
			// The tombstone must already be durable when the stop hook runs.
			ok, err := store.TombstoneExists(forwardID)
			if err != nil || !ok {
				t.Fatalf("stop hook: tombstone present=%v err=%v, want durable before stop", ok, err)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if stopCalls != 1 {
		t.Fatalf("stop hook calls = %d, want 1", stopCalls)
	}
	if len(report.Results) != 1 || report.Results[0].Outcome != OutcomeDeleted {
		t.Fatalf("delete result = %+v, want OutcomeDeleted", report.Results)
	}
	if ok, err := store.TombstoneExists("fwd-d"); err != nil || !ok {
		t.Fatalf("tombstone after delete present=%v err=%v", ok, err)
	}
	if _, ok, err := store.GetAppliedState("fwd-d"); err != nil || ok {
		t.Fatalf("applied after delete present=%v err=%v, want absent", ok, err)
	}
}

func TestApplyDesiredStopHookFailureKeepsTombstone(t *testing.T) {
	store := testStore(t)
	stopErr := errors.New("cannot stop listener")
	report, err := ApplyDesired(context.Background(), store, localstate.NewLatch(),
		testDesired(absent("fwd-f", "del-op-f", 1)),
		nil,
		func(ctx context.Context, forwardID string) error { return stopErr })
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Results) != 1 || report.Results[0].Outcome != OutcomeDeleteFailed || !errors.Is(report.Results[0].Err, stopErr) {
		t.Fatalf("delete result = %+v, want OutcomeDeleteFailed(stopErr)", report.Results)
	}
	// The deletion intent stays durable even though the stop side effect
	// failed, so a crash cannot resurrect the Forward.
	if ok, err := store.TombstoneExists("fwd-f"); err != nil || !ok {
		t.Fatalf("tombstone after stop failure present=%v err=%v, want durable", ok, err)
	}
}
