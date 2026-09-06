// Probe/evidence state machine transitions (docs/state-model.md §5, v0.8
// §7.1). Local evidence loss immediately marks the publication
// STALE/UNPUBLISHED before any remap or reprobe is attempted, and probe
// outcomes are applied atomically across the WAN/return-path/publication
// axes so the snapshot always satisfies the frozen truth invariants.
package reconcile

import (
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// EvidenceLost implements state-model §5: on any local evidence of lease
// loss, route/interface change, or resume from suspend, the old publication
// is atomically marked STALE (or UNPUBLISHED when no remap is possible), the
// WAN/return-path axes stop claiming verified reachability, and a local
// EndpointDeactivated event is recorded. The caller then attempts
// remap/reprobe from NOT_TESTED.
func (a *Activation) EvidenceLost() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.states
	next.PublicationState = "STALE"
	next.WanReachabilityState = "NOT_TESTED"
	next.ReturnPathState = "NOT_TESTED"
	if err := next.Validate(); err != nil {
		return err
	}
	a.states = next
	return nil
}

// RecoverAfterRestart invalidates proof that was persisted by an earlier
// process/session. A recovered listener may remain available, but WAN and
// return-path evidence must be tested again before verified publication. Keep
// an existing verified publication visible only as explicitly unverified.
func (a *Activation) RecoverAfterRestart() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.states
	next.WanReachabilityState = "NOT_TESTED"
	next.ReturnPathState = "NOT_TESTED"
	if next.PublicationState == "PUBLISHED_VERIFIED" {
		next.PublicationState = "PUBLISHED_UNVERIFIED"
	}
	if err := next.Validate(); err != nil {
		return err
	}
	a.states = next
	return nil
}

// StartProbe moves the activation into a probe cycle: the WAN axis goes to
// PROBING and the old publication is unpublished (a fresh probe can never
// ride on a previous verification). Stale generations are rejected.
func (a *Activation) StartProbe(eventGeneration uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if eventGeneration != a.generation {
		return ErrStaleEvent
	}
	next := a.states
	next.WanReachabilityState = "PROBING"
	next.PublicationState = "UNPUBLISHED"
	next.ReturnPathState = "NOT_TESTED"
	if err := next.Validate(); err != nil {
		return err
	}
	a.states = next
	return nil
}

// RecordProbeOutcome atomically applies a probe outcome across the WAN,
// return-path, and publication axes so the snapshot always satisfies the
// frozen truth invariants: only OPEN_FROM_VANTAGE may drive a verified
// publication; every other terminal outcome unpublishes.
func (a *Activation) RecordProbeOutcome(outcome protocol.ProbeOutcome, eventGeneration uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if eventGeneration != a.generation {
		return ErrStaleEvent
	}
	next := a.states
	next.WanReachabilityState = string(outcome)
	if outcome == protocol.OutcomeOpenFromVantage {
		next.ReturnPathState = "VERIFIED"
		next.PublicationState = "PUBLISHED_VERIFIED"
	} else {
		next.ReturnPathState = "FAILED"
		next.PublicationState = "UNPUBLISHED"
	}
	if err := next.Validate(); err != nil {
		return err
	}
	a.states = next
	return nil
}
