package localstate

import (
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Story 2 RED: one Forward apply failure must retain the old applied state
// while a sibling advances; a desired snapshot that merely omits a Forward
// must never delete it; ABSENT deletes are tombstoned atomically.

func validApplied(id string, desiredRev uint64) *protocol.AppliedForwardState {
	return &protocol.AppliedForwardState{
		ForwardID:       id,
		SpecRevision:    desiredRev,
		DesiredRevision: desiredRev,
		ActualBindHost:  "127.0.0.1",
		ActualBindPort:  19001,
		Strategy:        "direct-v4",
		LayerVersion:    1,
		AppliedAtUnix:   time.Now().Unix(),
	}
}

func TestFailedForwardRetainsOldAppliedStateWhileSiblingAdvances(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	seed := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-a", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
		{ForwardID: "fwd-b", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
	}}
	report, err := store.CommitDesired(seed, []ForwardApply{
		{ForwardID: "fwd-a", Outcome: ApplyApplied, Applied: validApplied("fwd-a", 1)},
		{ForwardID: "fwd-b", Outcome: ApplyApplied, Applied: validApplied("fwd-b", 1)},
	})
	if err != nil || report.Status != ApplyStatusFull {
		t.Fatalf("seed commit report=%+v err=%v, want FULL", report, err)
	}

	// Second desired: fwd-a apply fails (hook error), fwd-b advances to rev 2.
	next := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-a", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:81",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 2},
		{ForwardID: "fwd-b", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:90",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 2},
	}}
	failErr := errors.New("apply hook failed for fwd-a")
	report, err = store.CommitDesired(next, []ForwardApply{
		{ForwardID: "fwd-a", Outcome: ApplyFailed, Err: failErr},
		{ForwardID: "fwd-b", Outcome: ApplyApplied, Applied: validApplied("fwd-b", 2)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != ApplyStatusPartial {
		t.Fatalf("report status = %v, want PARTIAL", report.Status)
	}
	if report.FailedCount != 1 || report.AppliedCount != 1 || len(report.FailedForwards) != 1 || report.FailedForwards[0] != "fwd-a" {
		t.Fatalf("report counts = %+v, want 1 failed (fwd-a), 1 applied", report)
	}

	// fwd-a must still carry its old applied record (revision 1), never the
	// failed candidate; fwd-b must have advanced to revision 2.
	gotA, ok, err := store.GetAppliedState("fwd-a")
	if err != nil || !ok {
		t.Fatalf("fwd-a applied present=%v err=%v, want retained old state", ok, err)
	}
	if gotA.DesiredRevision != 1 {
		t.Fatalf("fwd-a applied desired_revision = %d, want 1 (old retained)", gotA.DesiredRevision)
	}
	gotB, ok, err := store.GetAppliedState("fwd-b")
	if err != nil || !ok {
		t.Fatalf("fwd-b applied present=%v err=%v, want advanced", ok, err)
	}
	if gotB.DesiredRevision != 2 {
		t.Fatalf("fwd-b applied desired_revision = %d, want 2", gotB.DesiredRevision)
	}

	// The received desired must be the latest snapshot regardless of PARTIAL.
	received, ok, err := store.LoadReceivedDesired()
	if err != nil || !ok {
		t.Fatalf("received desired present=%v err=%v", ok, err)
	}
	if received.NodeID != "node-1" || len(received.Forwards) != 2 {
		t.Fatalf("received desired = %+v, want the latest 2-forward snapshot", received)
	}
}

func TestDesiredOmissionDoesNotDeleteAppliedState(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seed := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-c", Protocol: protocol.ProtocolTCP, Target: "10.0.0.3:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
	}}
	if _, err := store.CommitDesired(seed, []ForwardApply{
		{ForwardID: "fwd-c", Outcome: ApplyApplied, Applied: validApplied("fwd-c", 1)},
	}); err != nil {
		t.Fatal(err)
	}
	// A snapshot that omits fwd-c entirely must not imply deletion.
	omitting := protocol.DesiredState{NodeID: "node-1", Forwards: nil}
	if _, err := store.CommitDesired(omitting, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.GetAppliedState("fwd-c"); err != nil || !ok {
		t.Fatalf("fwd-c applied present=%v err=%v; omission must never delete", ok, err)
	}
	if ok, err := store.TombstoneExists("fwd-c"); err != nil || ok {
		t.Fatalf("fwd-c tombstone = %v err=%v; omission must not create a tombstone", ok, err)
	}
}

func TestCommitDesiredDeletedForwardWritesTombstoneAndRemovesApplied(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	seed := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-d", Protocol: protocol.ProtocolTCP, Target: "10.0.0.4:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
	}}
	if _, err := store.CommitDesired(seed, []ForwardApply{
		{ForwardID: "fwd-d", Outcome: ApplyApplied, Applied: validApplied("fwd-d", 1)},
	}); err != nil {
		t.Fatal(err)
	}
	deleting := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-d", Protocol: protocol.ProtocolTCP, Target: "10.0.0.4:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
			DesiredRevision: 2, DeletionOperationID: "del-op-1"},
	}}
	report, err := store.CommitDesired(deleting, []ForwardApply{
		{ForwardID: "fwd-d", Outcome: ApplyDeleted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.DeletedCount != 1 || report.Status != ApplyStatusFull {
		t.Fatalf("delete report = %+v, want 1 deleted FULL", report)
	}
	if _, ok, err := store.GetAppliedState("fwd-d"); err != nil || ok {
		t.Fatalf("fwd-d applied present=%v err=%v, want removed", ok, err)
	}
	ok, err := store.TombstoneExists("fwd-d")
	if err != nil || !ok {
		t.Fatalf("fwd-d tombstone = %v err=%v, want present", ok, err)
	}
}

func TestCommitDesiredInvalidOutcomeFailsClosedAtomically(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// An Applied outcome carrying an invalid applied record (empty bind) must
	// fail the whole commit: no partial writes, received desired unchanged.
	bad := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-e", Protocol: protocol.ProtocolTCP, Target: "10.0.0.5:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
	}}
	if _, err := store.CommitDesired(bad, []ForwardApply{
		{ForwardID: "fwd-e", Outcome: ApplyApplied, Applied: &protocol.AppliedForwardState{
			ForwardID:       "fwd-e",
			DesiredRevision: 1,
			Strategy:        "direct-v4",
			AppliedAtUnix:   time.Now().Unix(),
		}},
	}); err == nil {
		t.Fatal("commit with invalid applied record succeeded; want fail closed")
	}
	if _, ok, err := store.GetAppliedState("fwd-e"); err != nil || ok {
		t.Fatalf("fwd-e applied present=%v err=%v after failed commit, want absent", ok, err)
	}
	if _, ok, err := store.LoadReceivedDesired(); err != nil || ok {
		t.Fatalf("received desired present=%v err=%v after failed commit, want absent", ok, err)
	}
}
