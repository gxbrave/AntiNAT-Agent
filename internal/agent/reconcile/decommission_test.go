// P14 Story 2: normal node decommission.
//
// RED reasons captured:
//   - Decommissioner and the localstate DecommissionIntent / AgentCleanupTombstone
//     primitives do not exist -> tests cannot compile -> RED.
//   - The strict DECOMMISSIONING-before-stop ordering and the deadline
//     DROPPED_DUE_TO_DECOMMISSION semantics have no implementation.
package reconcile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal/pcp"
)

func openDecommissionStore(t *testing.T) (*localstate.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := localstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dir
}

// recordingStopAll observes the terminal marker state at the moment each
// forward is stopped, proving DECOMMISSIONING is durable before any stop.
type recordingStopAll struct {
	mu      sync.Mutex
	markers []localstate.MarkerState
	dir     string
}

func (r *recordingStopAll) stopAll(ctx context.Context) error {
	marker, err := localstate.LoadMarker(r.dir)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.markers = append(r.markers, marker)
	r.mu.Unlock()
	return nil
}

func (r *recordingStopAll) snapshot() []localstate.MarkerState {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]localstate.MarkerState(nil), r.markers...)
	return out
}

// TestDecommissionMarkerBeforeStop is the §7.3 ordering invariant: the
// DECOMMISSIONING marker (fsync+rename+parent fsync) is durable before any
// Forward stops, so a crash can never stop forwards while still allowing new
// actors.
func TestDecommissionMarkerBeforeStop(t *testing.T) {
	st, dir := openDecommissionStore(t)
	latch := localstate.NewLatch()
	rec := &recordingStopAll{dir: dir}
	dc := NewDecommissioner(st, latch, dir, rec.stopAll)

	req := DecommissionRequest{
		NodeID: "node-1", OperationID: "decom-op-1",
		AllowedKeyHashes: []string{"kid-old", "kid-new"},
	}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := dc.StopAll(context.Background()); err != nil {
		t.Fatalf("stopAll: %v", err)
	}
	for i, marker := range rec.snapshot() {
		if marker != localstate.MarkerDecommissioning {
			t.Fatalf("stop %d saw marker %q, want DECOMMISSIONING (must be durable before stops)", i, marker)
		}
	}
	// The latch engages at Begin: no new actor may start.
	if !latch.Engaged() {
		t.Fatal("latch not engaged after Begin")
	}
	if err := latch.RegisterActor("fwd-x"); err == nil {
		t.Fatal("RegisterActor succeeded after decommission Begin, must fail")
	}
	onDisk, err := localstate.LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk != localstate.MarkerDecommissioning {
		t.Fatalf("on-disk marker = %q, want DECOMMISSIONING", onDisk)
	}
}

// TestDecommissionCleanupClearsForwardSecrets asserts Complete clears every
// Forward LKG/secret and writes the DECOMMISSIONED marker + cleanup tombstone
// carrying the allowed key versions, while the decommission ACK remains
// deliverable.
func TestDecommissionCleanupClearsForwardSecrets(t *testing.T) {
	st, dir := openDecommissionStore(t)
	latch := localstate.NewLatch()
	dc := NewDecommissioner(st, latch, dir, func(ctx context.Context) error { return nil })

	// Seed a live applied forward + tombstone + mapping journal record.
	spec := protocol.ForwardSpec{
		ForwardID: "fwd-x", Name: "x", Protocol: protocol.ProtocolTCP,
		Target: "127.0.0.1:9", Strategy: protocol.StrategyDirectV4,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	applied := &protocol.AppliedForwardState{
		ForwardID: spec.ForwardID, SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "127.0.0.1", ActualBindPort: 23000,
		Strategy: "direct-v4", MappingJournalRef: "jr-seed",
		AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{spec}}, []localstate.ForwardApply{{
		ForwardID: "fwd-x", Outcome: localstate.ApplyApplied, Applied: applied,
	}}); err != nil {
		t.Fatal(err)
	}
	stateRaw, _ := json.Marshal(pcp.MapResult{InternalPort: 1, AssignedExternalPort: 1})
	if err := st.MappingJournal().Put(traversal.JournalRecord{
		ID: "jr-seed", ForwardID: "fwd-x", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
		InternalIP: "10.0.0.2", InternalPort: 1, ExternalIP: "100.64.0.2",
		ExternalPort: 1, State: stateRaw, CreatedAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	req := DecommissionRequest{NodeID: "node-1", OperationID: "decom-op-2",
		AllowedKeyHashes: []string{"kid-old", "kid-new"}, CredentialVersions: []uint32{1, 2}}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := dc.StopAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dc.Complete(context.Background(), req); err != nil {
		t.Fatalf("complete: %v", err)
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker = %q err=%v, want DECOMMISSIONED", marker, err)
	}
	if _, ok, err := st.GetAppliedState("fwd-x"); err != nil || ok {
		t.Fatalf("applied state survived decommission ok=%v err=%v", ok, err)
	}
	if ok, err := st.TombstoneExists("fwd-x"); err != nil || ok {
		t.Fatalf("tombstone survived decommission ok=%v err=%v", ok, err)
	}
	if _, ok, _ := st.MappingJournal().Get("jr-seed"); ok {
		t.Fatal("mapping journal survived decommission")
	}
	cleanup, found, err := st.LoadAgentCleanupTombstone()
	if err != nil || !found {
		t.Fatalf("cleanup tombstone missing found=%v err=%v", found, err)
	}
	if cleanup.OperationID != "decom-op-2" {
		t.Fatalf("cleanup tombstone op = %q", cleanup.OperationID)
	}
	if len(cleanup.AllowedKeyHashes) != 2 || cleanup.AllowedKeyHashes[1] != "kid-new" {
		t.Fatalf("cleanup tombstone key hashes = %v", cleanup.AllowedKeyHashes)
	}
	if len(cleanup.CredentialVersions) != 2 || cleanup.CredentialVersions[1] != 2 {
		t.Fatalf("cleanup tombstone credential versions = %v", cleanup.CredentialVersions)
	}
	// The controller must not try to reconcile a decommissioned agent.
	if err := dc.StoreMarkerStateAssertDecommissioned(); err != nil {
		t.Fatalf("decommissioned assertion: %v", err)
	}
}

// TestDecommissionDeadlineDropsSecrets is the bounded best-effort semantics:
// when the deadline passes before the forward cleanup finishes, secrets are
// still cleared and the state is marked DROPPED_DUE_TO_DECOMMISSION (never a
// permanent at-least-once promise for decommission).
func TestDecommissionDeadlineUsesLiveSessionIdentity(t *testing.T) {
	st, dir := openDecommissionStore(t)
	if err := st.AdvanceSession(8, "live-session"); err != nil {
		t.Fatal(err)
	}
	dc := NewDecommissioner(st, localstate.NewLatch(), dir, nil)
	dc.SetSessionIdentity(func() (uint64, string, error) { return 8, "live-session", nil })
	req := DecommissionRequest{NodeID: "node-1", OperationID: "decom-live-r5", DeadlineUnix: time.Now().Unix() - 1}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	result, err := dc.ReconcileDeadline(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.DroppedDueToDecommission {
		t.Fatalf("result=%+v, want deadline drop", result)
	}
	if _, err := st.ResultForOperation(8, "live-session", req.OperationID); err != nil {
		t.Fatalf("deadline ACK was not queued for live session: %v", err)
	}
}

// RED R5-5: a deadline ACK failure must leave the terminal result retryable;
// a later call with the current session must queue the same ACK without
// repeating or reopening terminal cleanup.
func TestDecommissionDeadlineRetriesAckAfterSessionFailure(t *testing.T) {
	st, dir := openDecommissionStore(t)
	if err := st.AdvanceSession(8, "live-session"); err != nil {
		t.Fatal(err)
	}
	current := false
	dc := NewDecommissioner(st, localstate.NewLatch(), dir, nil)
	dc.SetSessionIdentity(func() (uint64, string, error) {
		if !current {
			return 7, "stale-session", nil
		}
		return 8, "live-session", nil
	})
	req := DecommissionRequest{NodeID: "node-1", OperationID: "decom-retry-r5", DeadlineUnix: time.Now().Unix() - 1}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, err := dc.ReconcileDeadline(context.Background(), req); err == nil {
		t.Fatal("deadline ACK failure was swallowed")
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker=%q err=%v after ACK failure", marker, err)
	}
	current = true
	result, err := dc.ReconcileDeadline(context.Background(), req)
	if err != nil {
		t.Fatalf("deadline ACK retry: %v", err)
	}
	if result.Status != "DECOMMISSIONED" || result.DroppedDueToDecommission {
		t.Fatalf("retry result=%+v, want idempotent terminal ACK retry", result)
	}
	raw, err := st.ResultForOperation(8, "live-session", req.OperationID)
	if err != nil {
		t.Fatalf("deadline ACK was not retained for retry: %v", err)
	}
	var ack DecommissionAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatal(err)
	}
	if ack.Status != "DROPPED_DUE_TO_DECOMMISSION" {
		t.Fatalf("retry ACK status=%q, want DROPPED_DUE_TO_DECOMMISSION", ack.Status)
	}
}

// TestDecommissionDeadlineDropsSecrets is the bounded best-effort semantics:
func TestDecommissionDeadlineDropsSecrets(t *testing.T) {
	st, dir := openDecommissionStore(t)
	latch := localstate.NewLatch()

	// A stop-all that always fails: the forward cleanup can never complete.
	dc := NewDecommissioner(st, latch, dir, func(ctx context.Context) error {
		return errTestStopAllFailed
	})
	req := DecommissionRequest{
		NodeID: "node-1", OperationID: "decom-op-3",
		DeadlineUnix:     time.Now().Unix() - 1, // already expired
		AllowedKeyHashes: []string{"kid-old"},
	}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// On an expired deadline the reconciler must still clear secrets and record
	// the drop without promising a durable delivery.
	result, err := dc.ReconcileDeadline(context.Background(), req)
	if err != nil {
		t.Fatalf("deadline reconcile: %v", err)
	}
	if result.DroppedDueToDecommission != true {
		t.Fatalf("result = %+v, want DROPPED_DUE_TO_DECOMMISSION", result)
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker = %q err=%v, want DECOMMISSIONED after deadline drop", marker, err)
	}
	cleanup, found, err := st.LoadAgentCleanupTombstone()
	if err != nil || !found {
		t.Fatalf("cleanup tombstone missing found=%v err=%v", found, err)
	}
	if cleanup.OperationID != "decom-op-3" {
		t.Fatalf("cleanup tombstone op = %q", cleanup.OperationID)
	}
	// The decommission ACK must still be queued so the controller at least learns
	// the drop when connectivity returns; this is bounded best-effort.
	if !st.OutboxContains("decom-op-3") {
		t.Fatal("decommission result not queued to the outbox")
	}
}

// TestDecommissionRestartResumesFromMarker proves a crash between phases
// resumes from the durable marker + intent, never re-runs the whole lifecycle
// from ACTIVE.
func TestDecommissionRestartResumesFromMarker(t *testing.T) {
	st, dir := openDecommissionStore(t)
	latch := localstate.NewLatch()
	rec := &recordingStopAll{dir: dir}
	dc := NewDecommissioner(st, latch, dir, rec.stopAll)
	req := DecommissionRequest{NodeID: "node-1", OperationID: "decom-op-4"}

	// Crash after Begin (DECOMMISSIONING durable, stop-all never ran).
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	// Re-open the state from disk: the marker is the resume authority.
	reopened, err := localstate.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := localstate.LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != localstate.MarkerDecommissioning {
		t.Fatalf("restart marker = %q, want DECOMMISSIONING", loaded)
	}
	intent, found, err := reopened.LoadDecommissionIntent()
	if err != nil || !found {
		t.Fatalf("decommission intent missing found=%v err=%v", found, err)
	}
	if intent.OperationID != "decom-op-4" {
		t.Fatalf("intent op = %q", intent.OperationID)
	}
	// A fresh Decommissioner over the reopened store resumes: StopAll + Complete.
	dc2 := NewDecommissioner(reopened, localstate.NewLatch(), dir, rec.stopAll)
	if err := dc2.StopAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dc2.Complete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioned {
		t.Fatalf("marker = %q err=%v, want DECOMMISSIONED", marker, err)
	}
}

var errTestStopAllFailed = errDecommissionDeadline("test stop-all failure")

// TestDecommissionCompleteRejectsMismatchedPersistedIntent proves terminal
// cleanup cannot be finalized from stale request identity.
func TestDecommissionCompleteRejectsMismatchedPersistedIntent(t *testing.T) {
	st, dir := openDecommissionStore(t)
	dc := NewDecommissioner(st, localstate.NewLatch(), dir, nil)
	original := DecommissionRequest{NodeID: "node-1", OperationID: "decom-r5", Force: true,
		DeadlineUnix: 10, AllowedKeyHashes: []string{"old"}, CredentialVersions: []uint32{1}}
	if err := dc.Begin(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	mismatch := original
	mismatch.OperationID = "decom-stale"
	mismatch.AllowedKeyHashes = []string{"new"}
	if err := dc.Complete(context.Background(), mismatch); err == nil {
		t.Fatal("Complete accepted a request that did not match the durable intent")
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioning {
		t.Fatalf("marker=%q err=%v, mismatched Complete finalized terminal state", marker, err)
	}
	if _, found, err := st.LoadAgentCleanupTombstone(); err != nil || found {
		t.Fatalf("cleanup tombstone found=%v err=%v after mismatched Complete", found, err)
	}
}

// TestDecommissionDeadlineRejectsMismatchedPersistedIntent proves deadline
// cleanup cannot finalize from stale force/key/deadline identity.
func TestDecommissionDeadlineRejectsMismatchedPersistedIntent(t *testing.T) {
	st, dir := openDecommissionStore(t)
	dc := NewDecommissioner(st, localstate.NewLatch(), dir, nil)
	original := DecommissionRequest{NodeID: "node-1", OperationID: "decom-deadline-r5", Force: false,
		DeadlineUnix: time.Now().Unix() - 1, AllowedKeyHashes: []string{"old"}, CredentialVersions: []uint32{1}}
	if err := dc.Begin(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	mismatch := original
	mismatch.Force = true
	if _, err := dc.ReconcileDeadline(context.Background(), mismatch); err == nil {
		t.Fatal("ReconcileDeadline accepted a request that did not match the durable intent")
	}
	marker, err := localstate.LoadMarker(dir)
	if err != nil || marker != localstate.MarkerDecommissioning {
		t.Fatalf("marker=%q err=%v, mismatched deadline finalized terminal state", marker, err)
	}
}

// TestDecommissionCleanupLeavesAckDeliverable seeds an applied forward and a
// pending deletion result in the outbox, then confirms the decommission ACK
// (node_decommission_ack) is queued against the operation id so the controller
// receives the minimal node identity.
func TestDecommissionCleanupLeavesAckDeliverable(t *testing.T) {
	st, dir := openDecommissionStore(t)
	latch := localstate.NewLatch()
	dc := NewDecommissioner(st, latch, dir, func(ctx context.Context) error { return nil })
	req := DecommissionRequest{NodeID: "node-1", OperationID: "decom-op-5"}

	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := dc.StopAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dc.Complete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := dc.QueueAck(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	raw, err := st.ResultForOperationAnySession("decom-op-5")
	if err != nil {
		t.Fatalf("decommission result missing: %v", err)
	}
	var ack DecommissionAck
	if err := json.Unmarshal(raw, &ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if ack.NodeID != "node-1" || ack.OperationID != "decom-op-5" || ack.Status != "DECOMMISSIONED" {
		t.Fatalf("ack = %+v", ack)
	}
	// The wire ack must never carry forward secrets or key hashes.
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"allowed_key_hashes", "credential_versions"} {
		if _, present := wire[forbidden]; present {
			t.Fatalf("decommission ack leaked %q", forbidden)
		}
	}
}

// TestDecommissionDeniedWhenAlreadyDecommissioned guards the CLEANUP_ONLY
// boundary: once DECOMMISSIONED is durable, Begin is refused (no re-running
// the lifecycle).
func TestDecommissionDeniedWhenAlreadyDecommissioned(t *testing.T) {
	st, dir := openDecommissionStore(t)
	latch := localstate.NewLatch()
	dc := NewDecommissioner(st, latch, dir, func(ctx context.Context) error { return nil })
	req := DecommissionRequest{NodeID: "node-1", OperationID: "decom-op-6"}
	if err := dc.Begin(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := dc.StopAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := dc.Complete(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if err := dc.Begin(context.Background(), req); err == nil {
		t.Fatal("Begin succeeded on a DECOMMISSIONED agent")
	}
}

// ensure filepath import is used even when the assertion helper grows.
var _ = filepath.Join
var _ = os.Getenv
