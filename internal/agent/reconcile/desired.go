// Per-resource desired apply (P07 Story 2 through the reconcile layer).
//
// ApplyDesired turns a received desired snapshot into per-Forward decisions
// with PARTIAL semantics: one Forward's apply failure retains its old applied
// record while siblings advance. An old desired revision is idempotently
// skipped (no side effect), a durable tombstone is authoritative (never
// resurrect), the terminal latch blocks new actors after the marker engages,
// and ABSENT deletes commit the tombstone before the stop hook runs
// (tombstone-before-stop).
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// ApplyHook starts/applies one PRESENT Forward and returns its durable applied
// state. The real data plane (P09) fills the actual bind tuple, mapping
// journal reference, and recovery descriptor; a nil hook leaves PRESENT
// Forwards untouched (no data plane wired yet).
type ApplyHook func(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error)

// StopHook stops one deleted Forward's actor. It runs only after the durable
// tombstone commit, so a crash between the commit and the stop can never
// resurrect the Forward (state-model §4 tombstone-before-stop).
type StopHook func(ctx context.Context, forwardID string) error

// RollbackHook restores a hot-updated actor to the previous durable desired
// spec and applied generation when the enclosing desired commit fails. The
// context carries the opaque SideEffectFence issued to the corresponding apply
// hook; data-plane implementations must use it as a compare-and-swap token.
type RollbackHook func(ctx context.Context, previous protocol.ForwardSpec, applied protocol.AppliedForwardState) error

// ErrStaleSideEffect reports a compensation attempt for a live side effect that
// has already been superseded, deleted, or replaced. A stale compensation must
// never mutate the newer side effect.
var ErrStaleSideEffect = errors.New("reconcile: stale side effect")

// SideEffectFence is an opaque, per-apply identity used to fence compensation
// and callback delivery. Pointer identity is intentional: equal-looking
// desired revisions must not make two concurrent operations interchangeable.
// The value is populated by the side-effect owner (the data plane) and is never
// serialized or exposed on the wire.
type SideEffectFence struct {
	mu    sync.RWMutex
	value any
}

type sideEffectFenceContextKey struct{}

// NewSideEffectFence allocates one unique side-effect identity.
func NewSideEffectFence() *SideEffectFence { return &SideEffectFence{} }

// SetValue associates the owner-specific compare-and-swap token with fence.
// It is safe for a rollback hook to consume the same context after apply has
// returned, and for a failed compensation to leave the original token intact.
func (f *SideEffectFence) SetValue(value any) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.value = value
	f.mu.Unlock()
}

// Value returns the owner-specific token currently associated with fence.
func (f *SideEffectFence) Value() any {
	if f == nil {
		return nil
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.value
}

// WithSideEffectFence attaches fence to ctx. A nil context is treated as a
// background context so hooks may safely pass through caller contexts.
func WithSideEffectFence(ctx context.Context, fence *SideEffectFence) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, sideEffectFenceContextKey{}, fence)
}

// SideEffectFenceFromContext returns the fence attached by the reconcile layer,
// or nil for legacy/direct hook calls that have not opted into fencing.
func SideEffectFenceFromContext(ctx context.Context) *SideEffectFence {
	if ctx == nil {
		return nil
	}
	fence, _ := ctx.Value(sideEffectFenceContextKey{}).(*SideEffectFence)
	return fence
}

// DesiredOutcome is the per-Forward reconcile decision.
type DesiredOutcome int

const (
	OutcomeApplied DesiredOutcome = iota
	OutcomeUnchanged
	OutcomeFailed
	OutcomeTombstonedRejected
	OutcomeTerminalRejected
	OutcomeDeleted
	OutcomeDeleteFailed
)

func (o DesiredOutcome) String() string {
	switch o {
	case OutcomeApplied:
		return "APPLIED"
	case OutcomeUnchanged:
		return "UNCHANGED"
	case OutcomeFailed:
		return "FAILED"
	case OutcomeTombstonedRejected:
		return "TOMBSTONED_REJECTED"
	case OutcomeTerminalRejected:
		return "TERMINAL_REJECTED"
	case OutcomeDeleted:
		return "DELETED"
	case OutcomeDeleteFailed:
		return "DELETE_FAILED"
	}
	return "UNKNOWN"
}

// DesiredApplyResult is one per-Forward reconcile decision.
type DesiredApplyResult struct {
	ForwardID string
	Outcome   DesiredOutcome
	Err       error
}

// DesiredApplyReport summarizes one ApplyDesired pass.
type DesiredApplyReport struct {
	Status  localstate.ApplyStatus
	Results []DesiredApplyResult
}

// ErrDecommissioned reports reconcile work attempted on a DECOMMISSIONED
// Agent; only cleanup is allowed from that marker onward.
var ErrDecommissioned = errors.New("reconcile: agent is decommissioned")

// CapabilityCheck is evaluated before side effects and again immediately
// before the durable desired commit. A loss between those points rejects the
// batch and rolls back actors created by this pass.
type CapabilityCheck func() error

// ErrCapabilityLost is returned when a desired apply crosses a capability
// boundary and cannot safely be committed.
var ErrCapabilityLost = errors.New("reconcile: capability lost during desired apply")

func deletionOperationIDFor(d protocol.DesiredState, forwardID string) string {
	for _, spec := range d.Forwards {
		if spec.ForwardID == forwardID {
			return spec.DeletionOperationID
		}
	}
	return ""
}

// ApplyDesired reconciles one desired snapshot against the applied state.
func ApplyDesired(ctx context.Context, store *localstate.Store, latch *localstate.Latch, d protocol.DesiredState, apply ApplyHook, stop StopHook) (DesiredApplyReport, error) {
	return ApplyDesiredWithGuardAndRollback(ctx, store, latch, d, apply, stop, nil, nil)
}

// ApplyDesiredWithGuard is ApplyDesired with an optional capability fence.
func ApplyDesiredWithGuard(ctx context.Context, store *localstate.Store, latch *localstate.Latch, d protocol.DesiredState, apply ApplyHook, stop StopHook, guard CapabilityCheck) (DesiredApplyReport, error) {
	return ApplyDesiredWithGuardAndRollback(ctx, store, latch, d, apply, stop, guard, nil)
}

// ApplyDesiredWithGuardAndRollback adds a rollback seam for existing actors.
// New actors use StopHook; hot-updated actors use RollbackHook so a failed
// durable commit cannot leave live backend state ahead of localstate.
func ApplyDesiredWithGuardAndRollback(ctx context.Context, store *localstate.Store, latch *localstate.Latch, d protocol.DesiredState, apply ApplyHook, stop StopHook, guard CapabilityCheck, rollback RollbackHook) (DesiredApplyReport, error) {
	var report DesiredApplyReport
	if err := d.Validate(); err != nil {
		return report, fmt.Errorf("reconcile: desired: %w", err)
	}
	// Install every deletion fence before inspecting or applying any PRESENT
	// sibling. A mixed controller snapshot must not expose a window in which a
	// sibling apply (or a crash) can leave an ABSENT Forward unfenced.
	deleteIntents := make([]localstate.ForwardDeleteIntent, 0)
	for _, spec := range d.Forwards {
		if spec.Presence != protocol.PresenceAbsent {
			continue
		}
		deleteIntents = append(deleteIntents, localstate.ForwardDeleteIntent{
			ForwardID: spec.ForwardID, DeletionOperationID: spec.DeletionOperationID,
			DesiredRevision: spec.DesiredRevision,
		})
	}
	if err := store.PutForwardDeleteIntents(deleteIntents); err != nil {
		return report, fmt.Errorf("reconcile: persist forward delete intent: %w", err)
	}
	applied, err := store.ListAppliedStates()
	if err != nil {
		return report, err
	}
	prevByID := make(map[string]protocol.AppliedForwardState, len(applied))
	for _, s := range applied {
		prevByID[s.ForwardID] = s
	}
	previousDesired, previousDesiredFound, err := store.LoadReceivedDesired()
	if err != nil {
		return report, err
	}
	previousSpecByID := make(map[string]protocol.ForwardSpec)
	if previousDesiredFound {
		for _, spec := range previousDesired.Forwards {
			previousSpecByID[spec.ForwardID] = spec
		}
	}

	results := make([]DesiredApplyResult, 0, len(d.Forwards))
	commits := make([]localstate.ForwardApply, 0, len(d.Forwards))
	newActors := make([]string, 0, len(d.Forwards))
	type hotUpdate struct {
		previous protocol.ForwardSpec
		applied  protocol.AppliedForwardState
		fence    *SideEffectFence
	}
	var hotUpdates []hotUpdate
	rollbackNewActors := func() error {
		var rollbackErr error
		for _, forwardID := range newActors {
			if stop == nil {
				continue
			}
			if err := stop(ctx, forwardID); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("stop new forward %q during rollback: %w", forwardID, err))
			}
		}
		return rollbackErr
	}
	rollbackSideEffects := func() error {
		var rollbackErr error
		if rollback != nil {
			for i := len(hotUpdates) - 1; i >= 0; i-- {
				rollbackCtx := WithSideEffectFence(ctx, hotUpdates[i].fence)
				if err := rollback(rollbackCtx, hotUpdates[i].previous, hotUpdates[i].applied); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("rollback hot update for %q: %w", hotUpdates[i].applied.ForwardID, err))
				}
			}
		}
		return errors.Join(rollbackErr, rollbackNewActors())
	}

	for _, spec := range d.Forwards {
		switch spec.Presence {
		case protocol.PresenceAbsent:
			// A final tombstone plus no pending row means cleanup already
			// completed. Do not invoke StopHook again; report the durable delete
			// idempotently. A pending row means the final commit happened but the
			// stop side effect still needs retry.
			_, pending, tombstone, tombstoned, fenceErr := store.ForwardDeleteFence(spec.ForwardID)
			if fenceErr != nil {
				return report, fenceErr
			}
			if tombstoned && !pending {
				if tombstone.DeletionOperationID != spec.DeletionOperationID || (tombstone.DesiredRevision != 0 && tombstone.DesiredRevision != spec.DesiredRevision) {
					return report, fmt.Errorf("reconcile: forward %q delete identity conflicts with durable tombstone", spec.ForwardID)
				}
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeDeleted})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeDeleted})
			commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplyDeleted})
		case protocol.PresencePresent:
			if prev, ok := prevByID[spec.ForwardID]; ok && spec.DesiredRevision <= prev.SpecRevision {
				// Older than or equal to the serving revision;
				// idempotent skip, no side effect, no actor restart.
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeUnchanged})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			if latch.Engaged() {
				// The terminal marker has started: no concurrent desired
				// apply may start a new actor (state-model §3.4).
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeTerminalRejected})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			_, pendingDelete, _, tombstoned, err := store.ForwardDeleteFence(spec.ForwardID)
			if err != nil {
				return report, err
			}
			if pendingDelete || tombstoned {
				// A pending delete or final tombstone is authoritative: an old
				// snapshot or Controller rollback must never resurrect this Forward.
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeTombstonedRejected})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			if apply == nil {
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeUnchanged})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplySkipped})
				continue
			}
			if guard != nil {
				if err := guard(); err != nil {
					rollbackErr := rollbackSideEffects()
					return report, errors.Join(fmt.Errorf("%w: before forward %q: %v", ErrCapabilityLost, spec.ForwardID, err), rollbackErr)
				}
			}
			fence := NewSideEffectFence()
			appliedState, applyErr := apply(WithSideEffectFence(ctx, fence), spec)
			if applyErr == nil {
				applyErr = appliedState.Validate()
			}
			if applyErr != nil {
				results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeFailed, Err: applyErr})
				commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplyFailed, Err: applyErr})
				continue
			}
			if previousApplied, existed := prevByID[spec.ForwardID]; !existed {
				newActors = append(newActors, spec.ForwardID)
			} else if previousSpec, found := previousSpecByID[spec.ForwardID]; found {
				hotUpdates = append(hotUpdates, hotUpdate{previous: previousSpec, applied: previousApplied, fence: fence})
			}
			results = append(results, DesiredApplyResult{ForwardID: spec.ForwardID, Outcome: OutcomeApplied})
			commits = append(commits, localstate.ForwardApply{ForwardID: spec.ForwardID, Outcome: localstate.ApplyApplied, Applied: &appliedState})
		}
	}

	// One atomic commit: received desired + applied records + tombstones.
	if guard != nil {
		if err := guard(); err != nil {
			rollbackErr := rollbackSideEffects()
			return report, errors.Join(fmt.Errorf("%w: before desired commit: %v", ErrCapabilityLost, err), rollbackErr)
		}
	}
	if _, err := store.CommitDesired(d, commits); err != nil {
		// The hook may have created a real actor or hot-updated an existing
		// actor before a concurrent tombstone or capability change made the
		// durable commit fail. Restore both categories to their prior state.
		rollbackErr := rollbackSideEffects()
		return report, errors.Join(fmt.Errorf("reconcile: commit desired (rolled back %d new actors and %d hot updates): %w", len(newActors), len(hotUpdates), err), rollbackErr)
	}

	// Tombstone-before-stop: only now that the tombstone is durable do the
	// stop hooks run. A completed tombstone with no pending row is already
	// cleaned up and must not invoke StopHook again.
	for i := range results {
		if results[i].Outcome != OutcomeDeleted || stop == nil {
			continue
		}
		_, pending, _, tombstoned, fenceErr := store.ForwardDeleteFence(results[i].ForwardID)
		if fenceErr != nil {
			results[i].Outcome = OutcomeDeleteFailed
			results[i].Err = fenceErr
			continue
		}
		if !pending && tombstoned {
			continue
		}
		if err := stop(ctx, results[i].ForwardID); err != nil {
			results[i].Outcome = OutcomeDeleteFailed
			results[i].Err = err
			continue
		}
		if err := store.CompleteForwardDeleteIntent(results[i].ForwardID, deletionOperationIDFor(d, results[i].ForwardID)); err != nil {
			results[i].Outcome = OutcomeDeleteFailed
			results[i].Err = err
		}
	}

	var anyFailed, anyProgress bool
	for _, r := range results {
		switch r.Outcome {
		case OutcomeFailed, OutcomeDeleteFailed:
			anyFailed = true
		case OutcomeApplied, OutcomeDeleted:
			anyProgress = true
		}
	}
	switch {
	case !anyFailed:
		report.Status = localstate.ApplyStatusFull
	case anyProgress:
		report.Status = localstate.ApplyStatusPartial
	default:
		report.Status = localstate.ApplyStatusFailed
	}
	report.Results = results
	return report, nil
}
