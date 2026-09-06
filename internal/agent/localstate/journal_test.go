package localstate

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Story 3 RED: durable inbox/outbox journals. Duplicate message/type/hash,
// old revision (stale epoch/session), result resend and receipt GC cases all
// fail closed before the journal.go GREEN implementation.

func TestAdvanceSessionRejectsLowerEpoch(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(5, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(4, "session-old"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("lower-epoch advance error = %v, want ErrStaleSession", err)
	}
	if err := store.AdvanceSession(5, "session-other"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("same-epoch different-session advance error = %v, want ErrStaleSession", err)
	}
	if err := store.AdvanceSession(5, "session-a"); err != nil {
		t.Fatalf("idempotent same-session advance error = %v", err)
	}
}

func TestReceiveCommandDuplicateSameIdentityIsIdempotent(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	dup, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion))
	if err != nil {
		t.Fatal(err)
	}
	if dup {
		t.Fatal("first delivery reported duplicate")
	}
	dup, err = store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion))
	if err != nil {
		t.Fatalf("same identity redelivery error = %v, want cached duplicate", err)
	}
	if !dup {
		t.Fatal("same identity redelivery did not report duplicate")
	}
}

func TestReceiveCommandConflictingIdentityFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-2", "msg-1", "desired", "hash-DIFFERENT", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("same message ID different payload hash error = %v, want ErrMessageConflict", err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-2", "msg-1", "DIFFERENT-TYPE", "hash-1", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("same message ID different type error = %v, want ErrMessageConflict", err)
	}
}

func TestOperationInboxFSMEnforcesPhases(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	phase, ok, err := store.OperationPhase("op-1")
	if err != nil || !ok || phase != "RECEIVED" {
		t.Fatalf("phase after receive = %q ok=%v err=%v, want RECEIVED", phase, ok, err)
	}
	// Skip over INTENT_PERSISTED straight to APPLYING must fail closed.
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("skip-to-applying error = %v, want ErrIllegalPhase", err)
	}
	// Complete from RECEIVED (never INTENT_PERSISTED/APPLYING) must fail.
	if err := store.CompleteOperation(1, "session-1", "op-1", []byte("result")); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("complete-from-RECEIVED error = %v, want ErrIllegalPhase", err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Applying -> NACKED is legal.
	if err := store.NackOperation(1, "session-1", "op-1", "cannot reach target"); err != nil {
		t.Fatal(err)
	}
	phase, _, err = store.OperationPhase("op-1")
	if err != nil || phase != "NACKED" {
		t.Fatalf("phase after nack = %q err=%v, want NACKED", phase, err)
	}
	// APPLIED -> NACKED (a completed operation regressing) must fail closed.
	if _, err := store.ReceiveCommand(1, "session-1", "op-2", "msg-2", "desired", "hash-2", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOperation(1, "session-1", "op-2", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.NackOperation(1, "session-1", "op-2", "late"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("nack-after-applied error = %v, want ErrIllegalPhase", err)
	}
}

func TestOutboxOperationIDsAfterPagesBeyondFixedPrefix(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-page"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 300; i++ {
		if err := store.QueueResult(1, "session-page", fmt.Sprintf("op-%03d", i), []byte("result")); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.OutboxOperationIDsAfter("", 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 256 {
		t.Fatalf("first outbox page length = %d, want 256", len(first))
	}
	second, err := store.OutboxOperationIDsAfter(first[len(first)-1], 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 44 {
		t.Fatalf("second outbox page length = %d, want 44", len(second))
	}
	if second[0] != "op-256" || second[len(second)-1] != "op-299" {
		t.Fatalf("second outbox page = %q..%q, want op-256..op-299", second[0], second[len(second)-1])
	}
}

func TestCompleteOperationQueuesOutboxResult(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOperation(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("outbox after complete = %q present=%v err=%v, want PENDING", state, present, err)
	}
	result, err := store.ResultForOperation(1, "session-1", "op-1")
	if err != nil || string(result) != "deleted" {
		t.Fatalf("result = %q err=%v, want deleted", result, err)
	}
}

func TestStaleSessionMutationFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(2, "session-b"); err != nil {
		t.Fatal(err)
	}
	// A stale writer from session-a must not mutate state on session-b.
	if err := store.QueueResult(1, "session-a", "op-1", []byte("APPLIED")); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale-session write error = %v, want ErrStaleSession", err)
	}
	if _, err := store.ReceiveCommand(1, "session-a", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale-session receive error = %v, want ErrStaleSession", err)
	}
}

func TestOldEpochReceiptRejectedAndResultResentOnNewSession(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-a", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-a", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-a", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(2, "session-b"); err != nil {
		t.Fatal(err)
	}
	// Old-epoch semantic ACK and receipt are rejected: the new session
	// re-signs the same semantic result instead of repeating the side effect.
	if err := store.AcceptSemanticACK(1, "session-a", "op-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session ACK error = %v, want ErrStaleSession", err)
	}
	if err := store.AcceptReceipt(1, "session-a", "op-1"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old-session receipt error = %v, want ErrStaleSession", err)
	}
	// The durable semantic result is still available for resend.
	result, err := store.ResultForOperation(2, "session-b", "op-1")
	if err != nil || string(result) != "deleted" {
		t.Fatalf("result resend = %q err=%v, want deleted", result, err)
	}
	// The new session requeues the same semantic result without a side effect.
	n, err := store.RequeueOutboxForSession(2, "session-b")
	if err != nil || n != 1 {
		t.Fatalf("requeue count = %d err=%v, want 1", n, err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("outbox after requeue = %q present=%v err=%v, want PENDING", state, present, err)
	}
}

func TestOutboxForwardWalkAndIllegalTransitions(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("result")); err != nil {
		t.Fatal(err)
	}
	// Premature receipt from PENDING must fail closed and not GC.
	if err := store.AcceptReceipt(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("premature receipt error = %v, want ErrIllegalPhase", err)
	}
	if !store.OutboxContains("op-1") {
		t.Fatal("premature receipt garbage-collected a PENDING operation")
	}
	// Double claim must fail closed.
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("double claim error = %v, want ErrIllegalPhase", err)
	}
	// ACK before SENT must fail closed.
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("ACK from CLAIMED error = %v, want ErrIllegalPhase", err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Receipt from SENT (never semantically ACKed) must fail closed.
	if err := store.AcceptReceipt(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("receipt from SENT error = %v, want ErrIllegalPhase", err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if !store.OutboxContains("op-1") {
		t.Fatal("semantic ACK must not GC before durable receipt")
	}
	// Claim after ACK must fail closed.
	if err := store.ClaimOutbox(1, "session-1", "op-1"); !errors.Is(err, ErrIllegalPhase) {
		t.Fatalf("claim after ACK error = %v, want ErrIllegalPhase", err)
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if store.OutboxContains("op-1") {
		t.Fatal("durable receipt must GC the outbox row")
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("duplicate receipt error = %v, want ErrAlreadyReceipted", err)
	}
}

func TestReceiptGCBlocksResurrection(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	ok, err := store.ReceiptExists("op-1")
	if err != nil || !ok {
		t.Fatalf("receipt tombstone present=%v err=%v, want durable", ok, err)
	}
	// A replayed record after durable receipt must not resurrect the outbox.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("re-record after receipt error = %v, want ErrAlreadyReceipted", err)
	}
	if store.OutboxContains("op-1") {
		t.Fatal("replayed record after receipt resurrected the outbox row")
	}
	if _, err := store.ResultForOperation(1, "session-1", "op-1"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("result lookup after receipt error = %v, want ErrAlreadyReceipted", err)
	}
}

// A different payload on an already-queued result is tolerated: the durable
// result is already recorded and queued for delivery, so the re-record is
// never mutated in place and the fail-closed guard against silently
// overwriting a persisted semantic result is preserved. The Controller
// re-issues with a fresh operation ID when it needs a different outcome.
// (Repair-cycle N2: before the fix this returned ErrStaleWriter and the
// reconcile control loop exited.)
func TestQueueResultStaleWriterFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("APPLIED")); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("DIFFERENT")); err != nil {
		t.Fatalf("different payload on already-queued result error = %v, want nil (tolerated)", err)
	}
	if result, _ := store.ResultForOperation(1, "session-1", "op-1"); !bytes.Equal(result, []byte("APPLIED")) {
		t.Fatalf("result after tolerated conflicting write = %q, want APPLIED (never overwritten)", result)
	}
}

// The fail-closed stale-writer guard is preserved for a durable result that
// is NOT queued for delivery: a different payload must still be refused and
// the persisted result left untouched. (This state cannot be produced via
// the public API — the durable result and its outbox row are written and
// removed atomically together — so it is constructed directly to pin the
// guard.)
func TestQueueResultStaleWriterFailsClosedWithoutQueuedRow(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketOperations)).Put([]byte("op-guard"), []byte("APPLIED"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-guard", []byte("DIFFERENT")); !errors.Is(err, ErrStaleWriter) {
		t.Fatalf("conflicting overwrite error = %v, want ErrStaleWriter", err)
	}
	if result, _ := store.ResultForOperation(1, "session-1", "op-guard"); !bytes.Equal(result, []byte("APPLIED")) {
		t.Fatalf("result after conflicting write = %q, want APPLIED", result)
	}
}

// Repair-cycle N2 RED: re-recording a CHANGED semantic result while the
// earlier result is already durably queued (in flight: CLAIMED/SENT/
// SEMANTIC_ACKED) must be tolerated — the result is already durable and
// queued, and the Controller re-issues with a fresh deletion_operation_id if
// it needs a different outcome — and must never overwrite the persisted
// result (fail-closed guard against silent mutation). Before the fix the
// re-record failed with ErrStaleWriter and the reconcile control loop exited.
func TestQueueResultToleratesOutcomeFlipWhileQueued(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	first := []byte(`{"deleted":false,"reason":"context deadline exceeded"}`)
	flipped := []byte(`{"deleted":true}`)
	if err := store.QueueResult(1, "session-1", "del-op-z", first); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "del-op-z"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "del-op-z"); err != nil {
		t.Fatal(err)
	}
	// The outcome flipped on the next reconcile while the earlier result is
	// in flight: tolerated, and the durable row is never mutated.
	if err := store.QueueResult(1, "session-1", "del-op-z", flipped); err != nil {
		t.Fatalf("flipped re-record while row SENT error = %v, want nil (tolerated)", err)
	}
	state, present, err := store.OutboxState("del-op-z")
	if err != nil || !present || state != "SENT" {
		t.Fatalf("outbox after tolerated re-record = %q present=%v err=%v, want SENT (untouched)", state, present, err)
	}
	persisted, err := store.ResultForOperation(1, "session-1", "del-op-z")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(persisted, first) {
		t.Fatalf("durable result after tolerated re-record = %q, want original %q (no silent overwrite)", persisted, first)
	}
}

// Repair-cycle Q1 RED: re-recording the same semantic result while its outbox
// row is in flight (CLAIMED/SENT/SEMANTIC_ACKED, no durable receipt yet) must
// be idempotent, leave the row untouched, and not disturb the subsequent
// receipt path. Before the fix, recordResultAndQueue returned ErrIllegalPhase
// for any non-PENDING same-payload row and the reconcile control loop died.
func TestQueueResultIdempotentForInFlightOutboxRow(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Re-record while CLAIMED: already durably queued, must not fail.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatalf("re-record while CLAIMED error = %v, want nil (idempotent)", err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Re-record while SENT: idempotent, row untouched.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatalf("re-record while SENT error = %v, want nil (idempotent)", err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "SENT" {
		t.Fatalf("outbox after re-record while SENT = %q present=%v err=%v, want SENT", state, present, err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	// Re-record while SEMANTIC_ACKED: idempotent, row untouched.
	if err := store.QueueResult(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatalf("re-record while SEMANTIC_ACKED error = %v, want nil (idempotent)", err)
	}
	state, present, err = store.OutboxState("op-1")
	if err != nil || !present || state != "SEMANTIC_ACKED" {
		t.Fatalf("outbox after re-record while SEMANTIC_ACKED = %q present=%v err=%v, want SEMANTIC_ACKED", state, present, err)
	}
	// The subsequent receipt path must still work on the untouched row.
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatalf("receipt after in-flight re-record error = %v", err)
	}
	if store.OutboxContains("op-1") {
		t.Fatal("durable receipt must GC the outbox row")
	}
}

// Repair-cycle Q2 RED: AcceptReceipt must garbage-collect the control_inbox
// dedup row in the same transaction as the outbox/result/journal GC, and a
// replayed record must still fail closed via the receipt tombstone.
func TestAcceptReceiptGCsInboxDedupRow(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); err != nil {
		t.Fatal(err)
	}
	inboxCount := func() int {
		count := 0
		if err := store.db.View(func(tx *bolt.Tx) error {
			return tx.Bucket([]byte(bucketInbox)).ForEach(func(k, v []byte) error {
				count++
				return nil
			})
		}); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if n := inboxCount(); n != 1 {
		t.Fatalf("inbox rows before receipt = %d, want 1", n)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteOperation(1, "session-1", "op-1", []byte("deleted")); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptReceipt(1, "session-1", "op-1"); err != nil {
		t.Fatal(err)
	}
	if n := inboxCount(); n != 0 {
		t.Fatalf("inbox rows after durable receipt = %d, want 0 (control_inbox GC'd)", n)
	}
	// A replayed record must still fail closed via the receipt tombstone,
	// independent of the inbox dedup row.
	if _, err := store.ReceiveCommand(1, "session-1", "op-1", "msg-1", "desired", "hash-1", string(protocol.OperationForwardDeletion)); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("replayed record after receipt error = %v, want ErrAlreadyReceipted", err)
	}
}
