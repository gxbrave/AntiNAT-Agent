package localstate

import (
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Story 4 RED: deletion intent followed by crash / old snapshot / controller
// rollback must never resurrect a Forward; tombstone GC must wait for the
// Controller's durable receipt.

func deleteDesired(fwdID, delOpID string, rev uint64) protocol.DesiredState {
	return protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: fwdID, Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
			DesiredRevision: rev, DeletionOperationID: delOpID},
	}}
}

func presentDesired(fwdID string, rev uint64) protocol.DesiredState {
	return protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: fwdID, Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: rev},
	}}
}

func TestTombstonedForwardCannotResurrect(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Seed and delete fwd-r.
	if _, err := store.CommitDesired(presentDesired("fwd-r", 1), []ForwardApply{
		{ForwardID: "fwd-r", Outcome: ApplyApplied, Applied: validApplied("fwd-r", 1)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitDesired(deleteDesired("fwd-r", "del-op-r", 2), []ForwardApply{
		{ForwardID: "fwd-r", Outcome: ApplyDeleted},
	}); err != nil {
		t.Fatal(err)
	}
	// A stale desired snapshot / controller rollback re-asserting PRESENT
	// must fail closed; the tombstone is authoritative forever (until GC).
	if _, err := store.CommitDesired(presentDesired("fwd-r", 3), []ForwardApply{
		{ForwardID: "fwd-r", Outcome: ApplyApplied, Applied: validApplied("fwd-r", 3)},
	}); !errors.Is(err, ErrTombstonedForward) {
		t.Fatalf("resurrect attempt error = %v, want ErrTombstonedForward", err)
	}
	ok, err := store.TombstoneExists("fwd-r")
	if err != nil || !ok {
		t.Fatalf("tombstone after failed resurrect = %v err=%v, want still present", ok, err)
	}
	if _, ok, err := store.GetAppliedState("fwd-r"); err != nil || ok {
		t.Fatalf("applied after failed resurrect present=%v err=%v, want absent", ok, err)
	}
}

func TestDeleteCommitAtomicityUnderFailure(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CommitDesired(presentDesired("fwd-a", 1), []ForwardApply{
		{ForwardID: "fwd-a", Outcome: ApplyApplied, Applied: validApplied("fwd-a", 1)},
	}); err != nil {
		t.Fatal(err)
	}
	// One ABSENT (tombstone) plus one invalid Applied sibling: the whole
	// commit must roll back — the deletion intent must not half-apply.
	bad := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-a", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
			DesiredRevision: 2, DeletionOperationID: "del-op-a"},
		{ForwardID: "fwd-b", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 2},
	}}
	if _, err := store.CommitDesired(bad, []ForwardApply{
		{ForwardID: "fwd-a", Outcome: ApplyDeleted},
		{ForwardID: "fwd-b", Outcome: ApplyApplied, Applied: &protocol.AppliedForwardState{
			ForwardID: "fwd-b", DesiredRevision: 2, Strategy: "direct-v4", AppliedAtUnix: time.Now().Unix(),
		}},
	}); err == nil {
		t.Fatal("commit with invalid sibling succeeded; want atomic fail closed")
	}
	if ok, err := store.TombstoneExists("fwd-a"); err != nil || ok {
		t.Fatalf("tombstone after failed commit = %v err=%v, want absent (atomic rollback)", ok, err)
	}
	if _, ok, err := store.GetAppliedState("fwd-a"); err != nil || !ok {
		t.Fatalf("fwd-a applied present=%v err=%v after failed commit, want retained", ok, err)
	}
}

func TestTombstoneGCRequiresDurableReceipt(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.CommitDesired(deleteDesired("fwd-g", "del-op-g", 1), []ForwardApply{
		{ForwardID: "fwd-g", Outcome: ApplyDeleted},
	}); err != nil {
		t.Fatal(err)
	}
	// No receipt yet: GC must be refused.
	if err := store.GCForwardTombstone("fwd-g"); !errors.Is(err, ErrTombstoneNotGCReady) {
		t.Fatalf("GC before receipt error = %v, want ErrTombstoneNotGCReady", err)
	}
	if ok, err := store.TombstoneExists("fwd-g"); err != nil || !ok {
		t.Fatalf("tombstone after refused GC = %v err=%v, want present", ok, err)
	}
	// Drive the deletion operation (keyed by deletion_operation_id) to a
	// durable Controller receipt.
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "del-op-g", []byte(`{"forward_id":"fwd-g","deleted":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "del-op-g"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "del-op-g"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "del-op-g"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "del-op-g"); err != nil {
		t.Fatal(err)
	}
	if err := store.GCForwardTombstone("fwd-g"); err != nil {
		t.Fatalf("GC after durable receipt error = %v", err)
	}
	if ok, err := store.TombstoneExists("fwd-g"); err != nil || ok {
		t.Fatalf("tombstone after GC = %v err=%v, want gone", ok, err)
	}
}

func TestTombstoneSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitDesired(deleteDesired("fwd-k", "del-op-k", 1), []ForwardApply{
		{ForwardID: "fwd-k", Outcome: ApplyDeleted},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Crash + restart: the tombstone must be durable.
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if ok, err := store.TombstoneExists("fwd-k"); err != nil || !ok {
		t.Fatalf("tombstone after reopen = %v err=%v, want durable", ok, err)
	}
	if _, ok, err := store.GetAppliedState("fwd-k"); err != nil || ok {
		t.Fatalf("applied after reopen present=%v err=%v, want absent", ok, err)
	}
}
