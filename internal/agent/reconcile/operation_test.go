package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// operation.go RED: durable result recording, receipt handling and result
// resend on a new session.

func TestRecordResultAndDurableReceiptFlow(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	result := []byte(`{"forward_id":"fwd-x","deleted":true}`)
	if err := RecordResult(ctx, store, 1, "session-1", "del-op-x", result); err != nil {
		t.Fatal(err)
	}
	state, present, err := store.OutboxState("del-op-x")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("outbox after record = %q present=%v err=%v, want PENDING", state, present, err)
	}
	// Drive to SEMANTIC_ACKED then apply the durable receipt.
	if err := store.ClaimOutbox(1, "session-1", "del-op-x"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkOutboxSent(1, "session-1", "del-op-x"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "del-op-x"); err != nil {
		t.Fatal(err)
	}
	if err := HandleDurableReceipt(ctx, store, 1, "session-1", "del-op-x"); err != nil {
		t.Fatal(err)
	}
	if store.OutboxContains("del-op-x") {
		t.Fatal("durable receipt must GC the outbox row")
	}
	ok, err := store.ReceiptExists("del-op-x")
	if err != nil || !ok {
		t.Fatalf("receipt tombstone present=%v err=%v", ok, err)
	}
}

func TestRequeuePendingResendsResultOnNewSession(t *testing.T) {
	store := testStore(t)
	if err := store.AdvanceSession(1, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := RecordResult(context.Background(), store, 1, "session-a", "op-1", []byte("deleted")); err != nil {
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
	n, err := RequeuePending(context.Background(), store, 2, "session-b")
	if err != nil || n != 1 {
		t.Fatalf("requeue n=%d err=%v, want 1", n, err)
	}
	state, present, err := store.OutboxState("op-1")
	if err != nil || !present || state != "PENDING" {
		t.Fatalf("outbox after requeue = %q present=%v err=%v, want PENDING", state, present, err)
	}
	// Stale-session receipt must still be rejected.
	if err := store.AcceptReceipt(1, "session-a", "op-1"); !errors.Is(err, localstate.ErrStaleSession) {
		t.Fatalf("old-session receipt error = %v, want ErrStaleSession", err)
	}
}

func TestDeleteResultPayloadRoundTrip(t *testing.T) {
	payload := EncodeDeleteResult("fwd-y", "del-op-y", false, "target unreachable")
	var decoded DeleteForwardResult
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ForwardID != "fwd-y" || decoded.DeletionOperationID != "del-op-y" || decoded.Deleted || decoded.Reason != "target unreachable" {
		t.Fatalf("decoded = %+v, want fwd-y/del-op-y/deleted=false/reason", decoded)
	}
	ok := EncodeDeleteResult("fwd-z", "del-op-z", true, "")
	var okDecoded DeleteForwardResult
	if err := json.Unmarshal(ok, &okDecoded); err != nil {
		t.Fatal(err)
	}
	if !okDecoded.Deleted || okDecoded.Reason != "" {
		t.Fatalf("ok decode = %+v, want deleted=true no reason", okDecoded)
	}
}
