package localstate

import (
	"errors"
	"testing"
	"time"
)

func TestForwardDeleteIntentPersistsAndIsIdempotentAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.PutForwardDeleteIntent(ForwardDeleteIntent{
		ForwardID: "fwd-pending", DeletionOperationID: "del-pending", DesiredRevision: 7,
	})
	if err != nil || !created {
		t.Fatalf("put intent created=%v err=%v, want true", created, err)
	}
	first, ok, err := store.GetForwardDeleteIntent("fwd-pending")
	if err != nil || !ok {
		t.Fatalf("get intent ok=%v err=%v", ok, err)
	}
	if first.CreatedAtUnix == 0 {
		t.Fatal("intent creation time was not assigned")
	}
	if created, err := store.PutForwardDeleteIntent(first); err != nil || created {
		t.Fatalf("same intent put created=%v err=%v, want false/nil", created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, ok, err := store.GetForwardDeleteIntent("fwd-pending")
	if err != nil || !ok || got != first {
		t.Fatalf("reopened intent=%+v ok=%v err=%v, want %+v", got, ok, err, first)
	}
	if _, err := store.PutForwardDeleteIntent(ForwardDeleteIntent{
		ForwardID: "fwd-pending", DeletionOperationID: "other-delete", DesiredRevision: 7,
		CreatedAtUnix: time.Now().Unix(),
	}); !errors.Is(err, ErrForwardDeleteConflict) {
		t.Fatalf("conflicting operation error=%v, want ErrForwardDeleteConflict", err)
	}
}

func TestCompleteForwardDeleteIntentRequiresMatchingCommittedTombstone(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	intent := ForwardDeleteIntent{ForwardID: "fwd-complete", DeletionOperationID: "del-complete", DesiredRevision: 3}
	if _, err := store.PutForwardDeleteIntent(intent); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteForwardDeleteIntent(intent.ForwardID, intent.DeletionOperationID); !errors.Is(err, ErrForwardDeleteNotCommitted) {
		t.Fatalf("completion before tombstone err=%v, want ErrForwardDeleteNotCommitted", err)
	}
	if _, err := store.CommitDesired(deleteDesired("fwd-complete", "del-complete", 3), []ForwardApply{{ForwardID: "fwd-complete", Outcome: ApplyDeleted}}); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteForwardDeleteIntent(intent.ForwardID, intent.DeletionOperationID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.GetForwardDeleteIntent(intent.ForwardID); err != nil || ok {
		t.Fatalf("intent after completion ok=%v err=%v, want absent", ok, err)
	}
	if err := store.CompleteForwardDeleteIntent(intent.ForwardID, intent.DeletionOperationID); err != nil {
		t.Fatalf("idempotent completion err=%v", err)
	}
}

func TestTombstoneGCWaitsForPendingIntentCompletion(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.PutForwardDeleteIntent(ForwardDeleteIntent{ForwardID: "fwd-gc-pending", DeletionOperationID: "del-gc-pending", DesiredRevision: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitDesired(deleteDesired("fwd-gc-pending", "del-gc-pending", 2), []ForwardApply{{ForwardID: "fwd-gc-pending", Outcome: ApplyDeleted}}); err != nil {
		t.Fatal(err)
	}
	if err := store.GCForwardTombstone("fwd-gc-pending"); !errors.Is(err, ErrTombstoneNotGCReady) {
		t.Fatalf("GC with pending intent err=%v, want ErrTombstoneNotGCReady", err)
	}
}
