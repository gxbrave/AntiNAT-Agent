package localstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	bolt "go.etcd.io/bbolt"
)

// RED for the payload-aware receive path: a desired/forward_delete command
// must journal its payload, the deletion classification, and the durable
// pending delete fence atomically with the generic C journal row, so a crash
// between RECEIVE and the apply pipeline can never resurrect a deleted
// Forward, and recovery can re-assert the fence without the payload.

// mixedDesired builds a valid desired payload with one ABSENT and one PRESENT
// Forward so the fence ordering inside one snapshot is observable.
func mixedDesired(t *testing.T, absentID, delOpID string, rev uint64) []byte {
	t.Helper()
	d := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: absentID, Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent,
			DesiredRevision: rev, DeletionOperationID: delOpID},
		{ForwardID: "fwd-live", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:80",
			Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: rev},
	}}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReceiveCommandWithPayloadPersistsFenceAndClassification(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	payload := mixedDesired(t, "fwd-gone", "del-op-1", 4)
	dup, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", payload, "desired")
	if err != nil {
		t.Fatal(err)
	}
	if dup {
		t.Fatal("first delivery reported duplicate")
	}
	intent, ok, err := store.GetForwardDeleteIntent("fwd-gone")
	if err != nil || !ok {
		t.Fatalf("pending fence after receive ok=%v err=%v", ok, err)
	}
	if intent.DeletionOperationID != "del-op-1" || intent.DesiredRevision != 4 {
		t.Fatalf("fence identity=%+v, want del-op-1/4", intent)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Crash before any apply transition: the fence and the classification
	// survive reopen.
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(2, "session-2"); err != nil {
		t.Fatal(err)
	}
	_, pending, _, tombstoned, err := store.ForwardDeleteFence("fwd-gone")
	if err != nil || !pending || tombstoned {
		t.Fatalf("fence after reopen pending=%v tombstoned=%v err=%v, want true/false", pending, tombstoned, err)
	}
	// A later PRESENT desired for the fenced forward still cannot resurrect it.
	if _, err := store.CommitDesired(presentDesired("fwd-gone", 99), []ForwardApply{
		{ForwardID: "fwd-gone", Outcome: ApplyApplied, Applied: validApplied("fwd-gone", 99)},
	}); !errors.Is(err, ErrTombstonedForward) {
		t.Fatalf("fenced PRESENT commit error=%v, want ErrTombstonedForward", err)
	}
}

func TestReceiveCommandWithPayloadDuplicateIsIdempotent(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	payload := mixedDesired(t, "fwd-dup", "del-dup", 2)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", payload, "desired"); err != nil {
		t.Fatal(err)
	}
	dup, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", payload, "desired")
	if err != nil {
		t.Fatal(err)
	}
	if !dup {
		t.Fatal("same identity redelivery did not report duplicate")
	}
	intent, ok, err := store.GetForwardDeleteIntent("fwd-dup")
	if err != nil || !ok || intent.DeletionOperationID != "del-dup" {
		t.Fatalf("fence after duplicate ok=%v err=%v intent=%+v", ok, err, intent)
	}
}

func TestReceiveCommandWithPayloadConflictingHashFailsClosed(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	payload := mixedDesired(t, "fwd-conflict", "del-conflict", 2)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", payload, "desired"); err != nil {
		t.Fatal(err)
	}
	other := mixedDesired(t, "fwd-conflict", "del-conflict", 3)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-2", "msg-1", "desired", other, "desired"); !errors.Is(err, ErrMessageConflict) {
		t.Fatalf("same message ID different payload error=%v, want ErrMessageConflict", err)
	}
}

func TestReceiveCommandWithPayloadMalformedPayloadStillJournals(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	// Not a valid DesiredState: best-effort classification yields no links and
	// no fence, but the command is still journaled so the apply pipeline can
	// reject it with a NACK instead of tearing down the session.
	malformed := []byte(`{"node_id":"node-1","forwards":[{"forward_id":"fwd-x","presence":"ABSENT"}]}`)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", malformed, "desired"); err != nil {
		t.Fatalf("malformed payload receive error=%v, want journaled", err)
	}
	phase, ok, err := store.OperationPhase("msg-1")
	if err != nil || !ok || phase != "RECEIVED" {
		t.Fatalf("journal after malformed receive phase=%q ok=%v err=%v, want RECEIVED", phase, ok, err)
	}
	if _, ok, err := store.GetForwardDeleteIntent("fwd-x"); err != nil || ok {
		t.Fatalf("malformed payload fence ok=%v err=%v, want absent", ok, err)
	}
}

func TestReceiveCommandWithPayloadConflictingDeletionKeepsOldFence(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	first := mixedDesired(t, "fwd-old", "del-old", 5)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", first, "desired"); err != nil {
		t.Fatal(err)
	}
	// A second command carrying a different deletion identity for the same
	// Forward must not reopen the completed-deletion lifecycle or replace the
	// durable fence; receive stays alive and the apply pipeline reports the
	// conflict.
	second := mixedDesired(t, "fwd-old", "del-new", 6)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-2", "msg-2", "forward_delete", second, "forward_delete"); err != nil {
		t.Fatalf("conflicting deletion identity receive error=%v, want journaled", err)
	}
	intent, ok, err := store.GetForwardDeleteIntent("fwd-old")
	if err != nil || !ok || intent.DeletionOperationID != "del-old" || intent.DesiredRevision != 5 {
		t.Fatalf("fence after conflicting delete ok=%v err=%v intent=%+v, want del-old/5", ok, err, intent)
	}
}

func TestReceiveCommandWithPayloadUpgradesLegacyRecoveredDuplicate(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	payload := mixedDesired(t, "fwd-legacy", "del-legacy", 9)
	sum := sha256.Sum256(payload)
	if duplicate, err := store.ReceiveCommand(
		1, "session-1", "msg-legacy", "msg-legacy", "desired",
		hex.EncodeToString(sum[:]), "desired",
	); err != nil || duplicate {
		t.Fatalf("legacy receive duplicate=%v err=%v", duplicate, err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "msg-legacy"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "msg-legacy"); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(2, "session-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverApplyingOperations(2, "session-2"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.GetForwardDeleteIntent("fwd-legacy"); err != nil || ok {
		t.Fatalf("legacy recovery unexpectedly classified deletion ok=%v err=%v", ok, err)
	}

	duplicate, err := store.ReceiveCommandWithPayload(
		2, "session-2", "msg-legacy", "msg-legacy", "desired", payload, "desired",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !duplicate {
		t.Fatal("matching payload-aware redelivery was not reported as duplicate")
	}
	intent, ok, err := store.GetForwardDeleteIntent("fwd-legacy")
	if err != nil || !ok {
		t.Fatalf("legacy redelivery fence ok=%v err=%v", ok, err)
	}
	if intent.DeletionOperationID != "del-legacy" || intent.DesiredRevision != 9 {
		t.Fatalf("legacy redelivery fence=%+v, want del-legacy/9", intent)
	}
	j, ok, err := store.loadOperationJournalForTest("msg-legacy")
	if err != nil || !ok {
		t.Fatalf("upgraded journal ok=%v err=%v", ok, err)
	}
	if string(j.Payload) != string(payload) || len(j.ForwardDeletions) != 1 ||
		j.ForwardDeletions[0].ForwardID != "fwd-legacy" ||
		j.ForwardDeletions[0].DeletionOperationID != "del-legacy" {
		t.Fatalf("upgraded journal=%+v, want exact payload and deletion link", j)
	}
	if j.Phase != phaseApplying {
		t.Fatalf("upgraded journal phase=%q, want APPLYING until bounded cleanup converges", j.Phase)
	}
	if err := store.CompleteRecoveredDeletion(2, "session-2", "msg-legacy"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverApplyingOperations(2, "session-2"); err != nil {
		t.Fatal(err)
	}
	if phase, ok, err := store.OperationPhase("msg-legacy"); err != nil || !ok || phase != phaseNacked {
		t.Fatalf("post-upgrade recovery phase=%q ok=%v err=%v, want NACKED", phase, ok, err)
	}
	if store.OutboxContains("del-legacy") {
		t.Fatal("legacy duplicate upgrade fabricated a D-keyed delete result")
	}
}

func TestReceiveCommandWithPayloadUpgradesEmptyLegacyPayload(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nil)
	if duplicate, err := store.ReceiveCommand(
		1, "session-1", "op-empty", "msg-empty", "desired",
		hex.EncodeToString(sum[:]), "desired",
	); err != nil || duplicate {
		t.Fatalf("legacy receive duplicate=%v err=%v", duplicate, err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "op-empty"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "op-empty"); err != nil {
		t.Fatal(err)
	}
	duplicate, pending, err := store.ReceiveCommandWithPayloadStatus(
		1, "session-1", "op-empty", "msg-empty", "desired", nil, "desired",
	)
	if err != nil || !duplicate || pending {
		t.Fatalf("empty redelivery duplicate=%v pending=%v err=%v", duplicate, pending, err)
	}
	j, ok, err := store.loadOperationJournalForTest("op-empty")
	if err != nil || !ok || !j.PayloadPresent {
		t.Fatalf("empty payload journal ok=%v present=%v err=%v", ok, j.PayloadPresent, err)
	}
	if err := store.RecoverApplyingOperations(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	if phase, ok, err := store.OperationPhase("op-empty"); err != nil || !ok || phase != phaseNacked {
		t.Fatalf("empty payload recovery phase=%q ok=%v err=%v, want NACKED", phase, ok, err)
	}
}

func TestReceiveCommandWithPayloadLegacyDuplicateValidatesOperationIdentity(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	payload := mixedDesired(t, "fwd-legacy-conflict", "del-legacy-conflict", 3)
	sum := sha256.Sum256(payload)
	if _, err := store.ReceiveCommand(
		1, "session-1", "op-original", "msg-legacy-conflict", "desired",
		hex.EncodeToString(sum[:]), "desired",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReceiveCommandWithPayload(
		1, "session-1", "op-other", "msg-legacy-conflict", "desired", payload, "desired",
	); !errors.Is(err, ErrOperationConflict) {
		t.Fatalf("legacy duplicate operation mismatch error=%v, want ErrOperationConflict", err)
	}
	if _, ok, err := store.GetForwardDeleteIntent("fwd-legacy-conflict"); err != nil || ok {
		t.Fatalf("conflicting legacy duplicate installed fence ok=%v err=%v", ok, err)
	}
}

func (s *Store) loadOperationJournalForTest(operationID string) (operationJournal, bool, error) {
	var journal operationJournal
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		journal, found, err = s.loadOperationJournal(tx, operationID)
		return err
	})
	return journal, found, err
}

func TestRecoverApplyingDeletionWaitsForCleanupAndKeepsFence(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	payload := mixedDesired(t, "fwd-crash", "del-crash", 8)
	if _, err := store.ReceiveCommandWithPayload(1, "session-1", "msg-1", "msg-1", "desired", payload, "desired"); err != nil {
		t.Fatal(err)
	}
	if err := store.PersistOperationIntent(1, "session-1", "msg-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOperationApplying(1, "session-1", "msg-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Restart: a newer session recovers the APPLYING command. The generic C
	// identity is NACKed and its result queued; the deletion identity D never
	// receives a fabricated result; the fence stays durable.
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AdvanceSession(2, "session-2"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverApplyingOperations(2, "session-2"); err != nil {
		t.Fatal(err)
	}
	phase, ok, err := store.OperationPhase("msg-1")
	if err != nil || !ok || phase != phaseApplying {
		t.Fatalf("recovered command phase=%q ok=%v err=%v, want APPLYING pending cleanup", phase, ok, err)
	}
	if _, err := store.ResultForOperation(2, "session-2", "msg-1"); !errors.Is(err, ErrOperationNotFound) {
		t.Fatalf("premature C result error=%v, want ErrOperationNotFound", err)
	}
	// No fabricated D-keyed result: the deletion cleanup outcome stays unknown
	// until the controller retries.
	if store.OutboxContains("del-crash") {
		t.Fatal("recovery fabricated a D-keyed delete result")
	}
	if _, err := store.ResultForOperation(2, "session-2", "del-crash"); !errors.Is(err, ErrOperationNotFound) {
		t.Fatalf("D result error=%v, want ErrOperationNotFound", err)
	}
	_, pending, _, tombstoned, err := store.ForwardDeleteFence("fwd-crash")
	if err != nil || !pending || tombstoned {
		t.Fatalf("fence after recovery pending=%v tombstoned=%v err=%v, want true/false", pending, tombstoned, err)
	}
}
