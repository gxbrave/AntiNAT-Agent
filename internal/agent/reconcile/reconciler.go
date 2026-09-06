// Transport-independent reconcile control loop (P07).
//
// The Reconciler applies received desired snapshots through the per-resource
// apply/stop hooks, enforces the terminal marker/latch (no new actor after
// the marker engages, no reconcile on DECOMMISSIONED), and records durable
// deletion results. It holds no sockets and performs no network-specific
// forwarding; the data plane hooks are the P09 extension point.
package reconcile

import (
	"context"
	"fmt"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Reconciler is the Agent's reconcile control loop.
type Reconciler struct {
	store    *localstate.Store
	latch    *localstate.Latch
	marker   localstate.MarkerState
	apply    ApplyHook
	stop     StopHook
	rollback RollbackHook
	guard    CapabilityCheck
}

// New builds a Reconciler over the Agent store and the shared terminal latch.
// marker is loaded from disk before the store is opened (marker precedence).
func New(store *localstate.Store, latch *localstate.Latch, marker localstate.MarkerState, apply ApplyHook, stop StopHook, guards ...CapabilityCheck) *Reconciler {
	return NewWithRollback(store, latch, marker, apply, stop, nil, guards...)
}

// NewWithRollback wires the optional hot-update rollback hook used when a
// backend update happens before the enclosing desired commit.
func NewWithRollback(store *localstate.Store, latch *localstate.Latch, marker localstate.MarkerState, apply ApplyHook, stop StopHook, rollback RollbackHook, guards ...CapabilityCheck) *Reconciler {
	var guard CapabilityCheck
	if len(guards) > 0 {
		guard = guards[0]
	}
	return &Reconciler{store: store, latch: latch, marker: marker, apply: apply, stop: stop, rollback: rollback, guard: guard}
}

// ReconcileOnce applies one desired snapshot and records durable deletion
// results for the current session. epoch==0 / session=="" (no session yet)
// skips result recording; the tombstone and the actor stop are still durable.
func (r *Reconciler) ReconcileOnce(ctx context.Context, d protocol.DesiredState, epoch uint64, sessionID string) (DesiredApplyReport, error) {
	if r.marker == localstate.MarkerDecommissioned {
		return DesiredApplyReport{}, ErrDecommissioned
	}
	report, err := ApplyDesiredWithGuardAndRollback(ctx, r.store, r.latch, d, r.apply, r.stop, r.guard, r.rollback)
	if err != nil {
		return report, err
	}
	if epoch == 0 || sessionID == "" {
		return report, nil
	}
	delOpByForward := make(map[string]string, len(d.Forwards))
	for _, f := range d.Forwards {
		if f.Presence == protocol.PresenceAbsent {
			delOpByForward[f.ForwardID] = f.DeletionOperationID
		}
	}
	for _, res := range report.Results {
		var payload []byte
		switch res.Outcome {
		case OutcomeDeleted:
			payload = EncodeDeleteResult(res.ForwardID, delOpByForward[res.ForwardID], true, "")
		case OutcomeDeleteFailed:
			reason := ""
			if res.Err != nil {
				reason = res.Err.Error()
			}
			payload = EncodeDeleteResult(res.ForwardID, delOpByForward[res.ForwardID], false, reason)
		default:
			continue
		}
		delOp := delOpByForward[res.ForwardID]
		if delOp == "" {
			continue
		}
		if err := RecordResult(ctx, r.store, epoch, sessionID, delOp, payload); err != nil {
			return report, err
		}
	}
	return report, nil
}

// Run is the reconcile control loop. Each trigger loads the received desired
// snapshot from the store and reconciles it under the current session. A
// per-iteration panic is recovered so the loop survives one bad iteration;
// a persistent reconcile error is returned to the caller. Actor panics are
// contained by the Supervisor and never reach this loop.
func (r *Reconciler) Run(ctx context.Context, trigger <-chan struct{}) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
			epoch, session, err := r.store.CurrentSession()
			if err != nil {
				return err
			}
			if err := r.runOnceRecovered(ctx, epoch, session); err != nil {
				return err
			}
		}
	}
}

func (r *Reconciler) runOnceRecovered(ctx context.Context, epoch uint64, session string) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("reconcile: loop iteration panic: %v", rec)
		}
	}()
	d, ok, err := r.store.LoadReceivedDesired()
	if err != nil || !ok {
		return err
	}
	_, err = r.ReconcileOnce(ctx, d, epoch, session)
	return err
}
