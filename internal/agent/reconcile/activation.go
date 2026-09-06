// Orthogonal activation state container (docs/state-model.md §1, v0.8 §7.1).
//
// Every Forward activation holds one value per independent axis; a complete
// snapshot has exactly one legal value for every axis and obeys the frozen
// cross-axis truth invariants. Updates are CAS'd by activation generation:
// an event from a stale generation (an older activation or an out-of-order
// event) can never overwrite the current snapshot.
package reconcile

import (
	"errors"
	"sync"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// ErrStaleEvent rejects an activation update whose generation is older than
// the current activation generation (CAS violation).
var ErrStaleEvent = errors.New("reconcile: stale activation event rejected")

// ErrIllegalState rejects an axis update that violates the frozen enums or
// cross-axis truth invariants.
var ErrIllegalState = errors.New("reconcile: illegal activation state")

// Activation is one forward activation's orthogonal state machine. The zero
// value is not usable; create with NewActivation.
type Activation struct {
	mu         sync.Mutex
	forwardID  string
	activation string
	generation uint64
	states     protocol.ActivationStates
}

// ProbeAdmission is the compare-and-swap token returned when a probe cycle is
// admitted. Before and After let the caller roll back only the transition it
// made; an unrelated same-generation update is never overwritten.
type ProbeAdmission struct {
	ForwardID  string
	Activation string
	Generation uint64
	Before     protocol.ActivationStates
	After      protocol.ActivationStates
}

// NewActivation creates an activation at generation 1 with every axis at its
// neutral start value (NOT_TESTED / NONE / STOPPED).
func NewActivation(forwardID, activationID string, generation uint64) *Activation {
	a := &Activation{
		forwardID:  forwardID,
		activation: activationID,
		generation: generation,
		states: protocol.ActivationStates{
			ControlState:         "OFFLINE",
			ListenerState:        "STOPPED",
			MappingState:         "NOT_REQUIRED",
			KeepaliveState:       "NOT_REQUIRED",
			WanReachabilityState: "NOT_TESTED",
			ReturnPathState:      "NOT_TESTED",
			TargetHealthState:    "UNKNOWN",
			PublicationState:     "NONE",
			DataPlaneState:       "STOPPED",
		},
	}
	return a
}

// Set replaces the whole snapshot atomically after validation. Used for the
// initial snapshot and recovery; it is generation-CAS'd like any update.
func (a *Activation) Set(s protocol.ActivationStates) error {
	if err := s.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.states = s
	return nil
}

// StartProbeAdmission verifies the exact activation identity and generation,
// then atomically enters the probe state. The returned token can be used for a
// compare-and-swap rollback if a later durable admission step fails.
func (a *Activation) StartProbeAdmission(expectedActivation string, expectedGeneration uint64) (ProbeAdmission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if expectedActivation == "" || expectedGeneration == 0 ||
		a.activation != expectedActivation || a.generation != expectedGeneration {
		return ProbeAdmission{}, ErrStaleEvent
	}
	before := a.states
	next := before
	next.WanReachabilityState = "PROBING"
	next.PublicationState = "UNPUBLISHED"
	next.ReturnPathState = "NOT_TESTED"
	if err := next.Validate(); err != nil {
		return ProbeAdmission{}, err
	}
	a.states = next
	return ProbeAdmission{
		ForwardID: a.forwardID, Activation: a.activation, Generation: a.generation,
		Before: before, After: next,
	}, nil
}

// RollbackProbeAdmission restores only the exact transition represented by
// token. If another writer has changed identity, generation, or state since
// admission, the rollback fails closed rather than clobbering that update.
func (a *Activation) RollbackProbeAdmission(token ProbeAdmission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.forwardID != token.ForwardID || a.activation != token.Activation ||
		a.generation != token.Generation || a.states != token.After {
		return ErrStaleEvent
	}
	if err := token.Before.Validate(); err != nil {
		return err
	}
	a.states = token.Before
	return nil
}

// Update changes exactly one axis under the current generation. A stale
// generation fails with ErrStaleEvent and leaves the snapshot untouched.
// Every update re-validates the full snapshot including cross-axis truth
// invariants (protocol.ValidateAxisRelations), so an update that would make
// the snapshot illegal is rejected before it is applied.
func (a *Activation) Update(axis, value string, eventGeneration uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if eventGeneration != a.generation {
		return ErrStaleEvent
	}
	if !protocol.ValidAxisValue(axis, value) {
		return ErrIllegalState
	}
	next := a.states
	switch axis {
	case "control_state":
		next.ControlState = value
	case "listener_state":
		next.ListenerState = value
	case "mapping_state":
		next.MappingState = value
	case "keepalive_state":
		next.KeepaliveState = value
	case "wan_reachability_state":
		next.WanReachabilityState = value
	case "return_path_state":
		next.ReturnPathState = value
	case "target_health_state":
		next.TargetHealthState = value
	case "publication_state":
		next.PublicationState = value
	case "data_plane_state":
		next.DataPlaneState = value
	default:
		return ErrIllegalState
	}
	if err := next.Validate(); err != nil {
		return err
	}
	a.states = next
	return nil
}

// AdvanceGeneration moves the activation to a newer generation (a spec
// revision bump creates a new activation). All subsequent events must carry
// at least the new generation; older events are rejected as stale.
func (a *Activation) AdvanceGeneration(next uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if next > a.generation {
		a.generation = next
	}
}

// ResetForGeneration advances an activation and clears evidence axes. A
// specification revision is a new activation: an old WAN proof and
// publication decision cannot be carried into the new revision.
func (a *Activation) ResetForGeneration(next uint64) {
	a.ResetForGenerationWithID(next, a.ActivationID())
}

// ResetForGenerationWithID advances an activation, rotates its identity, and
// clears evidence axes. The identity rotation is part of the same generation
// transition so no live activation can retain proof from a prior revision.
func (a *Activation) ResetForGenerationWithID(next uint64, activationID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if next <= a.generation {
		return
	}
	a.resetForGenerationLocked(next, activationID)
}

// RestoreForGenerationWithID restores a previously committed activation
// revision after a failed desired-state transaction. Unlike Reset, rollback
// may move the generation backwards because the durable desired revision is
// the source of truth.
func (a *Activation) RestoreForGenerationWithID(previous uint64, activationID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if previous == a.generation && activationID == a.activation {
		return
	}
	a.resetForGenerationLocked(previous, activationID)
}

func (a *Activation) resetForGenerationLocked(next uint64, activationID string) {
	a.generation = next
	a.activation = activationID
	a.states.MappingState = "NOT_REQUIRED"
	a.states.KeepaliveState = "NOT_REQUIRED"
	a.states.WanReachabilityState = "NOT_TESTED"
	a.states.ReturnPathState = "NOT_TESTED"
	a.states.TargetHealthState = "UNKNOWN"
	a.states.PublicationState = "NONE"
	a.states.DataPlaneState = "STOPPED"
}

// IdentitySnapshot returns the activation identity and complete state under
// one lock. Callers that need to compare multiple fields must not compose the
// individual accessors across separate lock acquisitions.
func (a *Activation) IdentitySnapshot() (string, string, uint64, protocol.ActivationStates) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.forwardID, a.activation, a.generation, a.states
}

// ForwardID returns the identity bound to this activation.
func (a *Activation) ForwardID() string {
	forwardID, _, _, _ := a.IdentitySnapshot()
	return forwardID
}

// ActivationID returns the opaque activation identity.
func (a *Activation) ActivationID() string {
	_, activation, _, _ := a.IdentitySnapshot()
	return activation
}

// Generation returns the current activation generation.
func (a *Activation) Generation() uint64 {
	_, _, generation, _ := a.IdentitySnapshot()
	return generation
}

// Snapshot returns a copy of the current orthogonal snapshot.
func (a *Activation) Snapshot() protocol.ActivationStates {
	_, _, _, states := a.IdentitySnapshot()
	return states
}
