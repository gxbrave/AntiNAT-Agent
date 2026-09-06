// Durable operation result and delivery helpers (P07 Story 3 reconcile side).
//
// These wrap the localstate journal so the transport layer (P08) and the
// reconciler record semantic results, apply durable receipts, and resend
// results on a new session without touching bbolt directly.
package reconcile

import (
	"context"
	"encoding/json"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// RecordResult durably records a semantic operation result and queues it to
// the outbox as PENDING for the current session (v0.8 §6.4: the outbox stores
// semantic payloads, never session-bound signed frames).
func RecordResult(ctx context.Context, store *localstate.Store, epoch uint64, sessionID, operationID string, result []byte) error {
	return store.QueueResult(epoch, sessionID, operationID, result)
}

// HandleDurableReceipt applies a Controller durable receipt, garbage
// collecting the outbox and operation once the semantic ACK is in place.
// A premature, stale-session, or duplicate receipt fails closed.
func HandleDurableReceipt(ctx context.Context, store *localstate.Store, epoch uint64, sessionID, operationID string) error {
	return store.AcceptReceipt(epoch, sessionID, operationID)
}

// RequeuePending resets every non-receipted outbox row to PENDING for the
// current session so the same semantic result is re-enveloped and re-signed
// without repeating the side effect (the old-epoch ACK rejection path).
func RequeuePending(ctx context.Context, store *localstate.Store, epoch uint64, sessionID string) (int, error) {
	return store.RequeueOutboxForSession(epoch, sessionID)
}

// DeleteForwardResult is the durable semantic payload queued as a Forward
// deletion result (v0.8 §7.2 durable result + ACK).
type DeleteForwardResult struct {
	ForwardID           string `json:"forward_id"`
	DeletionOperationID string `json:"deletion_operation_id"`
	Deleted             bool   `json:"deleted"`
	Reason              string `json:"reason,omitempty"`
}

// EncodeDeleteResult marshals a deletion result payload. It cannot fail for
// this struct; a panic-free Marshal is guaranteed by the field types.
func EncodeDeleteResult(forwardID, deletionOperationID string, deleted bool, reason string) []byte {
	raw, _ := json.Marshal(DeleteForwardResult{
		ForwardID:           forwardID,
		DeletionOperationID: deletionOperationID,
		Deleted:             deleted,
		Reason:              reason,
	})
	return raw
}
