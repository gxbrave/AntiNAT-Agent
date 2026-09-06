// Mapping lifecycle → activation (P12W Story 7, D5).
//
// The traversal Manager delivers DEGRADED / LOST / RECOVERED off its renewal
// goroutine, in publication order, one event per contained callback. Each
// handler here is forward-scoped with a mapped guard (the forward must still
// be live AND mapping-capable before any activation axis is touched) and
// follows the onForwardRunError lock discipline: probeAdmissionMu, then dp.mu,
// then the activation map. A trailing event that lands after the forward was
// replaced is refused by the guard — the residual stale-window in which a
// replacement forward CAN satisfy the guard (it is live and mapping-capable)
// is documented in the handoff known_limits (D5 makes no library callback
// token change).
package agent

import (
	"context"
	"encoding/json"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// onMappingDegraded marks keepalive_state DEGRADED after three consecutive
// renewal failures; renewals continue so the mapping may still recover.
func (a *App) onMappingDegraded(forwardID, reason string) {
	a.onMappingLifecycle(forwardID, func(act *reconcile.Activation, actor *forwardActor) error {
		return act.Update("keepalive_state", "DEGRADED", act.Generation())
	})
}

// onMappingLost marks keepalive_state LOST and mapping_state LOST, then runs
// EvidenceLost so publication goes STALE and WAN/return-path return to
// NOT_TESTED — the manager never revives the old candidate.
func (a *App) onMappingLost(forwardID, reason string) {
	a.onMappingLifecycle(forwardID, func(act *reconcile.Activation, actor *forwardActor) error {
		generation := act.Generation()
		if err := act.Update("keepalive_state", "LOST", generation); err != nil {
			return err
		}
		if err := act.Update("mapping_state", "LOST", generation); err != nil {
			return err
		}
		return act.EvidenceLost()
	})
}

// onMappingRecovered restores keepalive_state HEALTHY after a successful
// renewal and rebuilds mapping_state from the acquisition's verdict and live
// mapping.
func (a *App) onMappingRecovered(forwardID string) {
	a.onMappingLifecycle(forwardID, func(act *reconcile.Activation, actor *forwardActor) error {
		generation := act.Generation()
		if err := act.Update("keepalive_state", "HEALTHY", generation); err != nil {
			return err
		}
		if actor != nil && actor.acq != nil {
			if state := mappingStateForVerdict(actor.acq.Verdict); state != "" {
				if err := act.Update("mapping_state", state, generation); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// onMappingLifecycle is the single guarded handler skeleton. mutate runs only
// when the forward is still live and mapping-capable; the snapshot is then
// persisted and the status message sent (outside the admission lock, mirroring
// onForwardRunError).
func (a *App) onMappingLifecycle(forwardID string, mutate func(act *reconcile.Activation, actor *forwardActor) error) {
	a.probeAdmissionMu.Lock()
	if a.dp == nil || a.activations == nil {
		a.probeAdmissionMu.Unlock()
		return
	}
	a.dp.mu.Lock()
	actor := a.dp.forwards[forwardID]
	// D5 mapped guard: the forward must be live and mapping-capable. A
	// non-acquisition forward (direct/UDP) has no mapped lifecycle.
	if actor == nil || actor.acq == nil {
		a.dp.mu.Unlock()
		a.probeAdmissionMu.Unlock()
		return
	}
	act := a.activations[forwardID]
	a.dp.mu.Unlock()
	if act == nil {
		a.probeAdmissionMu.Unlock()
		return
	}
	// Durable deletion fence (repair-2 finding 8): a lifecycle event that lands
	// in the deletion window (the durable tombstone is already committed) must
	// not recreate activation state for a forward being deleted. The deletion
	// path removes the activation mirror; this check closes the race between
	// tombstone commit and mirror removal. Read outside dp.mu (store I/O) under
	// the admission ordering.
	if a.store != nil {
		pendingDelete, tombstoned, err := readForwardDeleteFence(a.store, forwardID)
		if err != nil || pendingDelete || tombstoned {
			a.probeAdmissionMu.Unlock()
			return
		}
	}
	generation := act.Generation()
	if err := mutate(act, actor); err != nil {
		a.probeAdmissionMu.Unlock()
		return
	}
	state := act.Snapshot()
	var saveErr error
	if a.store != nil {
		saveErr = a.store.SaveActivationSnapshot(localstate.ActivationSnapshot{
			ForwardID: act.ForwardID(), Activation: act.ActivationID(),
			Generation: generation, States: state,
		})
	}
	payload, marshalErr := json.Marshal(struct {
		ForwardID  string                    `json:"forward_id"`
		Activation string                    `json:"activation"`
		Generation uint64                    `json:"generation"`
		Snapshot   protocol.ActivationStates `json:"snapshot"`
	}{act.ForwardID(), act.ActivationID(), generation, state})
	client := a.client
	a.probeAdmissionMu.Unlock()

	if saveErr != nil {
		if a.dp != nil && a.dp.cfg.OnCleanupError != nil {
			a.dp.cfg.OnCleanupError(forwardID, actor, saveErr)
		}
		return
	}
	if marshalErr == nil && client != nil {
		a.sendActivationStatus(context.Background(), payload)
	}
}

// mappingStateForVerdict maps one acquisition verdict onto the frozen
// mapping_state axis: a FIRST_HOP gateway mapping is FIRST_HOP_MAPPED, a
// probe-eligible (global) candidate is PUBLIC_CANDIDATE, everything else has
// no mapping to record.
func mappingStateForVerdict(verdict traversal.PipelineVerdict) string {
	if verdict.MappingStateFirstHop {
		return "FIRST_HOP_MAPPED"
	}
	if verdict.PublicCandidate {
		return "PUBLIC_CANDIDATE"
	}
	return "NOT_REQUIRED"
}
