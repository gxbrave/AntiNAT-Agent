package reconcile

import (
	"context"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func TestConsumedProbeSourceRemainsGatedDuringReplayWindow(t *testing.T) {
	e := newProbeTestEnv(t)
	arm := e.mustArm(t)
	e.mgr.mu.Lock()
	e.mgr.ops[arm.ProbeID].used = true
	e.mgr.replay[arm.ProbeID] = time.Now().Add(time.Minute)
	e.mgr.mu.Unlock()
	if !e.mgr.hasArmedBySource(arm.ExpectedSourceIP, e.forward) {
		t.Fatal("consumed probe source fell through to business path during replay window")
	}
}

func TestApplyDesiredRollsBackExistingHotUpdateWhenCommitFails(t *testing.T) {
	store := testStore(t)
	oldSpec := present("hot-update", 1)
	if _, err := ApplyDesired(context.Background(), store, localstate.NewLatch(), testDesired(oldSpec),
		func(context.Context, protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			return appliedFor("hot-update", 1), nil
		}, nil); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	liveTarget := oldSpec.Target
	newSpec := oldSpec
	newSpec.Target = "10.0.0.2:81"
	newSpec.DesiredRevision = 2
	_, err := ApplyDesiredWithGuardAndRollback(context.Background(), store, localstate.NewLatch(), testDesired(newSpec),
		func(context.Context, protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
			liveTarget = newSpec.Target
			if _, err := store.CommitDesired(testDesired(absent("hot-update", "delete-race", 3)), []localstate.ForwardApply{{
				ForwardID: "hot-update", Outcome: localstate.ApplyDeleted,
			}}); err != nil {
				return protocol.AppliedForwardState{}, err
			}
			return appliedFor("hot-update", 2), nil
		}, nil, nil, func(_ context.Context, previous protocol.ForwardSpec, _ protocol.AppliedForwardState) error {
			liveTarget = previous.Target
			return nil
		})
	if err == nil {
		t.Fatal("hot update succeeded after commit failure")
	}
	if liveTarget != oldSpec.Target {
		t.Fatalf("live target = %q, want rollback to %q", liveTarget, oldSpec.Target)
	}
	_ = time.Now()
}
