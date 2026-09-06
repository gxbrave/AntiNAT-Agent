// P14 Story 2: normal node decommission (docs/state-model §3.4, v0.8 §7.3).
//
// The decommission lifecycle is a bounded best-effort FSM (ACTIVE ->
// DECOMMISSIONING -> DECOMMISSIONED -> CLEANUP_ONLY) whose durability lives in
// the marker file and the localstate intent/cleanup-tombstone rows:
//
//  1. Begin persists the DecommissionIntent and writes the DECOMMISSIONING
//     marker (fsync + rename + parent fsync) BEFORE any Forward stops. The
//     shared terminal latch engages at the same instant, so no concurrent
//     desired apply can start a new actor.
//  2. StopAll stops every Forward through the caller's stop hook (the data
//     plane's stopAll, which releases each forwardLease: listener + gateway
//     mapping + journal record together).
//  3. Complete clears every Forward LKG/secret/job row, writes the cleanup
//     tombstone carrying all allowed key hashes / credential versions across
//     the rotation overlap, then writes DECOMMISSIONED.
//
// Node decommission/uninstall never promises permanent at-least-once: on the
// deadline the reconciler records DROPPED_DUE_TO_DECOMMISSION after best-effort
// clearing. The decommission ACK (node_decommission_ack) carries a minimal
// node identity and the operation result so an ACK loss is retryable without
// retaining any Forward secret.
package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
)

// DecommissionRequest is the semantic node-decommission command.
type DecommissionRequest struct {
	NodeID             string
	OperationID        string
	Force              bool
	DeadlineUnix       int64
	AllowedKeyHashes   []string
	CredentialVersions []uint32
}

// DecommissionAck is the minimal ACK identity (never carries forward secrets).
type DecommissionAck struct {
	NodeID      string `json:"node_id"`
	OperationID string `json:"decommission_operation_id"`
	Status      string `json:"status"` // DECOMMISSIONED | DROPPED_DUE_TO_DECOMMISSION
	Force       bool   `json:"force,omitempty"`
}

// DecommissionDeadlineResult reports the outcome of a bounded best-effort
// deadline reconcile.
type DecommissionDeadlineResult struct {
	DroppedDueToDecommission bool   `json:"dropped_due_to_decommission"`
	Status                   string `json:"status"`
}

// errDecommissionDeadline is a decommission best-effort failure class.
type errDecommissionDeadline string

func (e errDecommissionDeadline) Error() string { return string(e) }

// ErrDecommissionedAgent guards lifecycle starts on a terminal agent.
var ErrDecommissionedAgent = errors.New("reconcile: agent is decommissioned")

// Decommissioner drives the terminal decommission FSM over the agent state.
type Decommissioner struct {
	store        *localstate.Store
	latch        *localstate.Latch
	stateDir     string
	stopAll      func(ctx context.Context) error
	secretCleans []func() error
	// sessionIdentity supplies the current control epoch/session for terminal
	// result delivery. A nil callback uses the durable session-independent queue.
	sessionIdentity func() (uint64, string, error)
}

// NewDecommissioner wires a decommission driver. stateDir is the state
// directory whose terminal.marker file is the durability authority; stopAll
// must stop every Forward (releasing each mapping+journal+listener); extra
// secret cleaners run before DECOMMISSIONED is written.
func NewDecommissioner(store *localstate.Store, latch *localstate.Latch, stateDir string, stopAll func(ctx context.Context) error, secretCleans ...func() error) *Decommissioner {
	if stopAll == nil {
		stopAll = func(context.Context) error { return nil }
	}
	return &Decommissioner{store: store, latch: latch, stateDir: stateDir, stopAll: stopAll, secretCleans: secretCleans}
}

// SetSessionIdentity supplies the current live control session for terminal
// ACKs. It is optional so terminal results remain durable when no live session
// exists; callers must never invent an epoch/session pair.
func (d *Decommissioner) SetSessionIdentity(identity func() (uint64, string, error)) {
	d.sessionIdentity = identity
}

// markerState reports the durable marker.
func (d *Decommissioner) markerState() (localstate.MarkerState, error) {
	return localstate.LoadMarker(d.stateDir)
}

// Begin persists the decommission intent, engages the shared terminal latch and
// writes the DECOMMISSIONING marker. Ordering matters: the marker is durable
// (fsync+rename+parent fsync) before Begin returns, and no Forward stops happen
// inside Begin, so a crash at any point leaves DECOMMISSIONING on disk with no
// stop ever having run.
func (d *Decommissioner) Begin(ctx context.Context, req DecommissionRequest) error {
	if req.OperationID == "" || req.NodeID == "" {
		return errors.New("reconcile: decommission requires node and operation id")
	}
	marker, err := d.markerState()
	if err != nil {
		return err
	}
	switch marker {
	case localstate.MarkerDecommissioned:
		return fmt.Errorf("%w: terminal marker already final", ErrDecommissionedAgent)
	case localstate.MarkerDecommissioning:
		// A crash between Begin and Complete resumes from the durable marker;
		// the latch is already engaged (or is engaged first here) — either way
		// the resume is allowed and the same intent + marker are re-asserted.
	default:
		if !d.latch.TryEngage() {
			// Someone else engaged the latch first with a conflicting lifecycle.
			return errors.New("reconcile: terminal latch already engaged")
		}
	}
	if _, err := d.store.PutDecommissionIntent(localstate.DecommissionIntent{
		OperationID: req.OperationID, NodeID: req.NodeID, Force: req.Force,
		DeadlineUnix: req.DeadlineUnix, AllowedKeyHashes: append([]string(nil), req.AllowedKeyHashes...),
		CredentialVersions: append([]uint32(nil), req.CredentialVersions...),
		CreatedAtUnix:      time.Now().Unix(),
	}); err != nil {
		return fmt.Errorf("reconcile: persist decommission intent: %w", err)
	}
	if err := localstate.WriteMarker(d.stateDir, localstate.MarkerDecommissioning); err != nil {
		return fmt.Errorf("reconcile: write DECOMMISSIONING marker: %w", err)
	}
	return nil
}

// StopAll stops every Forward through the caller's stop hook (marker is
// already DECOMMISSIONING). A failure is reported but never rolls the marker
// back: cleanup is retried on the next pass / restart.
func (d *Decommissioner) StopAll(ctx context.Context) error {
	if err := d.stopAll(ctx); err != nil {
		return fmt.Errorf("reconcile: decommission stop-all: %w", err)
	}
	return nil
}

// Complete clears every Forward LKG/secret/job row, writes the cleanup
// tombstone with the allowed key versions, then writes DECOMMISSIONED.
func (d *Decommissioner) Complete(ctx context.Context, req DecommissionRequest) error {
	if err := d.requireIntent(req); err != nil {
		return err
	}
	marker, err := d.markerState()
	if err != nil {
		return err
	}
	if marker == localstate.MarkerDecommissioned {
		intent, found, err := d.store.LoadAgentCleanupTombstone()
		if err != nil {
			return err
		}
		if !found || intent.OperationID != req.OperationID || intent.NodeID != req.NodeID {
			return fmt.Errorf("%w: terminal marker belongs to a different operation", ErrDecommissionedAgent)
		}
		return nil
	}
	if marker != localstate.MarkerDecommissioning {
		return fmt.Errorf("reconcile: complete requires DECOMMISSIONING marker, got %s", marker)
	}
	if err := d.store.ClearForwardStateForDecommission(); err != nil {
		return fmt.Errorf("reconcile: decommission clear forward state: %w", err)
	}
	for _, clean := range d.secretCleans {
		if err := clean(); err != nil {
			return fmt.Errorf("reconcile: decommission secret cleanup: %w", err)
		}
	}
	if err := d.store.WriteAgentCleanupTombstone(localstate.AgentCleanupTombstone{
		OperationID: req.OperationID, NodeID: req.NodeID, Force: req.Force,
		AllowedKeyHashes:   append([]string(nil), req.AllowedKeyHashes...),
		CredentialVersions: append([]uint32(nil), req.CredentialVersions...),
		CreatedAtUnix:      time.Now().Unix(),
	}); err != nil {
		return fmt.Errorf("reconcile: write cleanup tombstone: %w", err)
	}
	if err := localstate.WriteMarker(d.stateDir, localstate.MarkerDecommissioned); err != nil {
		return fmt.Errorf("reconcile: write DECOMMISSIONED marker: %w", err)
	}
	return nil
}

// QueueAck queues the minimal node_decommission_ack for the operation so an
// ACK loss is retryable across reconnects without retaining any forward secret.
func (d *Decommissioner) QueueAck(ctx context.Context, req DecommissionRequest) error {
	return d.queueAckWithStatus(ctx, req, "DECOMMISSIONED")
}

func (d *Decommissioner) queueAckWithStatus(ctx context.Context, req DecommissionRequest, status string) error {
	if err := d.requireIntent(req); err != nil {
		return err
	}
	if marker, err := d.markerState(); err != nil {
		return err
	} else if marker != localstate.MarkerDecommissioned {
		return fmt.Errorf("reconcile: queue decommission ACK requires DECOMMISSIONED marker, got %s", marker)
	}
	if existing, found, err := d.store.LoadAgentCleanupTombstone(); err != nil {
		return err
	} else if !found || existing.OperationID != req.OperationID || existing.NodeID != req.NodeID {
		return fmt.Errorf("%w: terminal ACK identity mismatch", ErrDecommissionedAgent)
	}
	payload, err := json.Marshal(DecommissionAck{
		NodeID: req.NodeID, OperationID: req.OperationID,
		Status: status, Force: req.Force,
	})
	if err != nil {
		return err
	}
	return d.queueResult(ctx, req.OperationID, payload)
}

// ReconcileDeadline implements the bounded best-effort deadline rule: when the
// deadline has passed and forward cleanup could not complete, the secrets are
// still cleared and the state is marked DROPPED_DUE_TO_DECOMMISSION — never a
// permanent at-least-once promise for node decommission.
func (d *Decommissioner) ReconcileDeadline(ctx context.Context, req DecommissionRequest) (DecommissionDeadlineResult, error) {
	marker, err := d.markerState()
	if err != nil {
		return DecommissionDeadlineResult{}, err
	}
	if err := d.requireIntent(req); err != nil {
		return DecommissionDeadlineResult{}, err
	}
	if marker == localstate.MarkerDecommissioned {
		// A prior terminal attempt may have failed only while queuing its ACK.
		// Re-drive the idempotent terminal ACK on every retry using the current
		// session identity or the session-independent queue.
		if err := d.queueAckWithStatus(ctx, req, "DROPPED_DUE_TO_DECOMMISSION"); err != nil {
			return DecommissionDeadlineResult{}, err
		}
		return DecommissionDeadlineResult{Status: "DECOMMISSIONED"}, nil
	}
	sooner := req.DeadlineUnix
	if sooner == 0 {
		// A zero deadline degrades to "not yet expired"; never auto-drop on a
		// marker without a deadline.
		sooner = time.Now().Unix() + 1
	}
	if time.Now().Unix() < sooner {
		return DecommissionDeadlineResult{Status: "DECOMMISSIONING"}, nil
	}
	// Deadline reached: clear secrets best-effort, record the drop, finalize.
	if err := d.store.ClearForwardStateForDecommission(); err != nil {
		return DecommissionDeadlineResult{}, err
	}
	for _, clean := range d.secretCleans {
		_ = clean()
	}
	ts := localstate.AgentCleanupTombstone{
		OperationID: req.OperationID, NodeID: req.NodeID, Force: req.Force,
		AllowedKeyHashes:   append([]string(nil), req.AllowedKeyHashes...),
		CredentialVersions: append([]uint32(nil), req.CredentialVersions...),
		CreatedAtUnix:      time.Now().Unix(),
	}
	if err := d.store.WriteAgentCleanupTombstone(ts); err != nil {
		return DecommissionDeadlineResult{}, err
	}
	if err := localstate.WriteMarker(d.stateDir, localstate.MarkerDecommissioned); err != nil {
		return DecommissionDeadlineResult{}, err
	}
	payload, err := json.Marshal(DecommissionAck{
		NodeID: req.NodeID, OperationID: req.OperationID,
		Status: "DROPPED_DUE_TO_DECOMMISSION", Force: req.Force,
	})
	if err != nil {
		return DecommissionDeadlineResult{}, err
	}
	if err := d.queueResult(ctx, req.OperationID, payload); err != nil {
		return DecommissionDeadlineResult{}, fmt.Errorf("reconcile: queue decommission deadline ACK: %w", err)
	}
	return DecommissionDeadlineResult{DroppedDueToDecommission: true, Status: "DROPPED_DUE_TO_DECOMMISSION"}, nil
}

func (d *Decommissioner) requireIntent(req DecommissionRequest) error {
	if d.store == nil {
		return errors.New("reconcile: decommission requires localstate")
	}
	intent, found, err := d.store.LoadDecommissionIntent()
	if err != nil {
		return err
	}
	if !found || intent.OperationID != req.OperationID || intent.NodeID != req.NodeID ||
		intent.Force != req.Force || intent.DeadlineUnix != req.DeadlineUnix ||
		!slices.Equal(intent.AllowedKeyHashes, req.AllowedKeyHashes) ||
		!slices.Equal(intent.CredentialVersions, req.CredentialVersions) {
		return fmt.Errorf("%w: persisted decommission intent does not match request", ErrDecommissionedAgent)
	}
	return nil
}

func (d *Decommissioner) queueResult(ctx context.Context, operationID string, payload []byte) error {
	if d.sessionIdentity == nil {
		return d.store.QueueResultSessionIndependent(operationID, payload)
	}
	epoch, session, err := d.sessionIdentity()
	if err != nil {
		return err
	}
	if epoch == 0 || session == "" {
		return d.store.QueueResultSessionIndependent(operationID, payload)
	}
	return RecordResult(ctx, d.store, epoch, session, operationID, payload)
}

// StoreMarkerStateAssertDecommissioned is a small helper named to make the
// test intent readable; it reports whether the terminal marker is final.
func (d *Decommissioner) StoreMarkerStateAssertDecommissioned() error {
	marker, err := d.markerState()
	if err != nil {
		return err
	}
	if marker != localstate.MarkerDecommissioned {
		return fmt.Errorf("reconcile: marker %q is not DECOMMISSIONED", marker)
	}
	return nil
}
