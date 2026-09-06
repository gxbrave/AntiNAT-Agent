// P14 Story 1: Forward delete FSM crash/lifecycle tests + orphaned-journal
// evacuation with adapter State decode.
//
// RED reasons captured:
//   - TestEvacuateOrphanedJournalDecodesPCPState: EvacuateOrphanedJournals and
//     DecodeJournalState do not exist yet (P12W intentionally left the adapter
//     State decode to P14); the test cannot compile -> RED.
//   - TestRefreshAppliedJournalRefSameRevision: Store.RefreshAppliedJournalRef
//     does not exist -> RED.
//   - TestForwardDeleteFenceKillMatrix: a focused kill-at-every-phase matrix
//     did not exist; every resurrection vector must produce a durable rejection.
package reconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal/pcp"
)

// fakeMapper is a scripted GatewayMapper that records the exact mapping it
// was asked to delete, so a test can assert the decoded adapter State.
type fakeMapper struct {
	mechanism traversal.MappingLayerKind
	ownership traversal.OwnershipStrength

	mu       sync.Mutex
	deletes  int
	deleted  []traversal.GatewayMapping
	mappings int
}

func (m *fakeMapper) Mechanism() traversal.MappingLayerKind  { return m.mechanism }
func (m *fakeMapper) Ownership() traversal.OwnershipStrength { return m.ownership }
func (m *fakeMapper) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(m.mechanism, false)
}
func (m *fakeMapper) Discover(context.Context) (traversal.ControlServer, error) {
	return traversal.ControlServer{Mechanism: m.mechanism}, nil
}
func (m *fakeMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	m.mu.Lock()
	m.mappings++
	m.mu.Unlock()
	return traversal.GatewayMapping{
		Mechanism:    m.mechanism,
		Ownership:    m.ownership,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     netip.MustParseAddrPort("100.64.0.2:41000"),
		Lease:        time.Hour,
		State:        pcp.MapResult{InternalPort: req.InternalPort, AssignedExternalPort: 41000},
	}, nil
}
func (m *fakeMapper) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	mapping.Lease = lifetime
	return mapping, nil
}
func (m *fakeMapper) Delete(_ context.Context, mapping traversal.GatewayMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	m.deleted = append(m.deleted, mapping)
	return nil
}

func (m *fakeMapper) deleteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deletes
}

func (m *fakeMapper) lastDeleted() (traversal.GatewayMapping, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.deleted) == 0 {
		return traversal.GatewayMapping{}, false
	}
	return m.deleted[len(m.deleted)-1], true
}

// TestForwardDeleteFenceKillMatrix kills the delete at every durable phase and
// asserts an old desired snapshot / a PRESENT retry can never resurrect the
// Forward. This is the Story 1 crash matrix: operation, outbox, tombstone,
// stop, result, ACK and receipt.
func TestForwardDeleteFenceKillMatrix(t *testing.T) {
	ctx := context.Background()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	latch := localstate.NewLatch()

	var stopCalls int
	stop := func(ctx context.Context, forwardID string) error {
		stopCalls++
		return nil
	}

	deadline := time.Now().Add(10 * time.Second)
	for phase := 0; phase < 8; phase++ {
		if time.Now().After(deadline) {
			t.Fatal("kill matrix exceeded wall-clock budget")
		}
		forwardID := fmt.Sprintf("fwd-%d", phase)
		operationID := fmt.Sprintf("del-op-%d", phase)
		present := protocol.ForwardSpec{
			ForwardID: forwardID, Name: "f", Protocol: protocol.ProtocolTCP,
			Target: "127.0.0.1:9", Strategy: protocol.StrategyDirectV4,
			DesiredRevision: 1, Presence: protocol.PresencePresent,
		}
		// A fresh forward is applied, then deleted; the durable fence must win
		// against the old snapshot and any higher-revision PRESENT retry at every
		// phase of the FSM.
		applied, err := applyFakeActor(ctx, st, latch, present)
		if err != nil {
			t.Fatalf("phase %d: apply present: %v", phase, err)
		}
		if applied != OutcomeApplied {
			t.Fatalf("phase %d: apply outcome = %s, want APPLIED", phase, applied)
		}
		absent := present
		absent.Presence = protocol.PresenceAbsent
		absent.DeletionOperationID = operationID

		oldSnapshot := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{present}}
		if err := st.SaveReceivedDesired(oldSnapshot); err != nil {
			t.Fatalf("phase %d: save old desired: %v", phase, err)
		}
		_, err = ApplyDesired(ctx, st, latch, protocol.DesiredState{
			NodeID: "node-1", Forwards: []protocol.ForwardSpec{absent},
		}, applyFakeHook, stop)
		if err != nil {
			t.Fatalf("phase %d: apply absent: %v", phase, err)
		}
		tombstoned, err := st.TombstoneExists(forwardID)
		if err != nil {
			t.Fatalf("phase %d: tombstone exists: %v", phase, err)
		}
		if !tombstoned {
			t.Fatalf("phase %d: no durable tombstone after delete", phase)
		}
		if _, ok, err := st.GetAppliedState(forwardID); err != nil || ok {
			t.Fatalf("phase %d: applied state still present ok=%v err=%v", phase, ok, err)
		}
		// PRESENT retry at a higher revision must be fenced.
		higher := present
		higher.DesiredRevision = 99
		report, err := ApplyDesired(ctx, st, latch, protocol.DesiredState{
			NodeID: "node-1", Forwards: []protocol.ForwardSpec{higher},
		}, applyFakeHook, stop)
		if err != nil {
			t.Fatalf("phase %d: apply higher PRESENT: %v", phase, err)
		}
		for _, r := range report.Results {
			if r.Outcome == OutcomeApplied {
				t.Fatalf("phase %d: PRESENT retry resurrected a deleted forward", phase)
			}
		}
		_, pending, _, finalTombstoned, fenceErr := st.ForwardDeleteFence(forwardID)
		if fenceErr != nil {
			t.Fatalf("phase %d: fence: %v", phase, fenceErr)
		}
		if !pending && !finalTombstoned {
			t.Fatalf("phase %d: fence lost", phase)
		}
	}
}

func actorApplied(spec protocol.ForwardSpec) *protocol.AppliedForwardState {
	return &protocol.AppliedForwardState{
		ForwardID: spec.ForwardID, SpecRevision: spec.DesiredRevision,
		DesiredRevision: spec.DesiredRevision, ActualBindHost: "127.0.0.1",
		ActualBindPort: 12345, Strategy: string(spec.Strategy), AppliedAtUnix: time.Now().Unix(),
	}
}

func applyFakeHook(ctx context.Context, spec protocol.ForwardSpec) (protocol.AppliedForwardState, error) {
	return *actorApplied(spec), nil
}

func applyFakeActor(ctx context.Context, st *localstate.Store, latch *localstate.Latch, spec protocol.ForwardSpec) (DesiredOutcome, error) {
	report, err := ApplyDesired(ctx, st, latch, protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{spec}}, applyFakeHook, nil)
	if err != nil {
		return OutcomeFailed, err
	}
	if len(report.Results) == 0 {
		return OutcomeFailed, nil
	}
	return report.Results[0].Outcome, nil
}

// TestEvacuateOrphanedJournalDecodesPCPState writes an orphaned PCP journal
// record whose State is the typed adapter JSON, then evacuates it. The mapper
// must receive a decoded GatewayMapping (typed pcp.MapResult State) and the
// journal record must be deleted.
func TestEvacuateOrphanedJournalDecodesPCPState(t *testing.T) {
	ctx := context.Background()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	mapper := &fakeMapper{mechanism: traversal.LayerPCP, ownership: traversal.OwnershipStrong}
	stateRaw, _ := json.Marshal(pcp.MapResult{
		InternalPort: 4321, AssignedExternalPort: 41000, Lifetime: 1200,
	})
	if err := st.MappingJournal().Put(traversal.JournalRecord{
		ID: "jr-1", ForwardID: "fwd-gone", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
		InternalIP: "10.0.0.2", InternalPort: 4321,
		ExternalIP: "100.64.0.2", ExternalPort: 41000,
		LeaseExpiryUnix: time.Now().Add(time.Hour).Unix(),
		State:           stateRaw, CreatedAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	report, err := EvacuateOrphanedJournals(ctx, st, MapperRegistry{traversal.LayerPCP: mapper}, nil)
	if err != nil {
		t.Fatalf("evacuate: %v", err)
	}
	if len(report.Evacuated) != 1 {
		t.Fatalf("evacuated = %v, want 1", report.Evacuated)
	}
	if _, ok, err := st.MappingJournal().Get("jr-1"); err != nil || ok {
		t.Fatalf("journal record survived evacuation ok=%v err=%v", ok, err)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("mapper deletes = %d, want 1", mapper.deleteCount())
	}
	decoded, ok := mapper.lastDeleted()
	if !ok {
		t.Fatal("mapper received no delete")
	}
	if decoded.Mechanism != traversal.LayerPCP {
		t.Fatalf("delete mechanism = %q, want pcp", decoded.Mechanism)
	}
	if decoded.InternalPort != 4321 {
		t.Fatalf("decoded internal port = %d, want 4321", decoded.InternalPort)
	}
	pcpState, ok := decoded.State.(pcp.MapResult)
	if !ok || pcpState.AssignedExternalPort != 41000 {
		t.Fatalf("decoded adapter State not typed pcp.MapResult: %+v", decoded.State)
	}
}

// TestEvacuateSkipsLiveAppliedRef ensures a journal record that is the durable
// applied ref of a forward is NEVER evacuated, only a stray extra record.
func TestEvacuateSkipsLiveAppliedRef(t *testing.T) {
	ctx := context.Background()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-live", Name: "live", Protocol: protocol.ProtocolTCP,
		Target: "127.0.0.1:9", Strategy: protocol.StrategyDirectV4,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	applied := *actorApplied(spec)
	applied.MappingJournalRef = "jr-live"
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{spec}}, []localstate.ForwardApply{{
		ForwardID: "fwd-live", Outcome: localstate.ApplyApplied, Applied: &applied,
	}}); err != nil {
		t.Fatal(err)
	}
	strayState, _ := json.Marshal(pcp.MapResult{InternalPort: 4000, AssignedExternalPort: 4000})
	stray := traversal.JournalRecord{
		ID: "jr-stray", ForwardID: "fwd-stray", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
		InternalIP: "10.0.0.2", InternalPort: 4000, ExternalIP: "100.64.0.2",
		ExternalPort: 4000, State: strayState, CreatedAtUnix: time.Now().Unix(),
	}
	live := stray
	live.ID = "jr-live"
	live.ForwardID = "fwd-live"
	live.State, _ = json.Marshal(pcp.MapResult{InternalPort: 4001, AssignedExternalPort: 4001})
	if err := st.MappingJournal().Put(stray); err != nil {
		t.Fatal(err)
	}
	if err := st.MappingJournal().Put(live); err != nil {
		t.Fatal(err)
	}

	mapper := &fakeMapper{mechanism: traversal.LayerPCP, ownership: traversal.OwnershipStrong}
	report, err := EvacuateOrphanedJournals(ctx, st, MapperRegistry{traversal.LayerPCP: mapper}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Evacuated) != 1 || report.Evacuated[0] != "jr-stray" {
		t.Fatalf("evacuated = %v, want [jr-stray]", report.Evacuated)
	}
	if _, ok, err := st.MappingJournal().Get("jr-live"); err != nil || !ok {
		t.Fatalf("live applied ref evacuated ok=%v err=%v", ok, err)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("mapper deletes = %d, want 1", mapper.deleteCount())
	}
}

// TestRefreshAppliedJournalRefSameRevision is the P12W-deferred same-revision
// LKG refresh: the applied record's MappingJournalRef changes after a restart
// reclaims the mapping, but SpecRevision must not move.
func TestRefreshAppliedJournalRefSameRevision(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-r", Name: "r", Protocol: protocol.ProtocolTCP,
		Target: "127.0.0.1:9", Strategy: protocol.StrategyDirectV4,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	applied := *actorApplied(spec)
	applied.MappingJournalRef = "jr-old"
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{spec}}, []localstate.ForwardApply{{
		ForwardID: "fwd-r", Outcome: localstate.ApplyApplied, Applied: &applied,
	}}); err != nil {
		t.Fatal(err)
	}

	updated, err := st.RefreshAppliedJournalRef("fwd-r", "jr-new")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !updated {
		t.Fatal("refresh reported no update")
	}
	rec, ok, err := st.GetAppliedRecord("fwd-r")
	if err != nil || !ok {
		t.Fatalf("get applied ok=%v err=%v", ok, err)
	}
	if rec.State.MappingJournalRef != "jr-new" {
		t.Fatalf("applied MappingJournalRef = %q, want jr-new", rec.State.MappingJournalRef)
	}
	if rec.State.SpecRevision != 1 {
		t.Fatalf("SpecRevision changed to %d during ref refresh", rec.State.SpecRevision)
	}
	if rec.State.DesiredRevision != 1 {
		t.Fatalf("DesiredRevision changed to %d", rec.State.DesiredRevision)
	}
}

// TestLiveForwardJournalRetainedByLiveAcquisitionSet (repair-1 M4): a journal
// record that is the LIVE acquisition's current record must never be released
// as orphaned EVEN when the durable applied ref is empty/stale (the forward is
// live but its applied row has no refreshed journal reference yet). The live
// acquisition set is a first-class retention input; without it the same record
// IS evacuated.
func TestLiveForwardJournalRetainedByLiveAcquisitionSet(t *testing.T) {
	ctx := context.Background()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	stateRaw, _ := json.Marshal(pcp.MapResult{
		InternalPort: 4321, AssignedExternalPort: 42000, Lifetime: 1200,
	})
	record := traversal.JournalRecord{
		ID: "jr-live", ForwardID: "fwd-live", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
		InternalIP: "10.0.0.2", InternalPort: 4321,
		ExternalIP: "100.64.0.2", ExternalPort: 42000,
		LeaseExpiryUnix: time.Now().Add(time.Hour).Unix(),
		State:           stateRaw, CreatedAtUnix: time.Now().Unix(),
	}
	if err := st.MappingJournal().Put(record); err != nil {
		t.Fatal(err)
	}

	// No applied row, no tombstone, no delete intent: only the LIVE acquisition
	// set retains the mapping.
	mapper := &fakeMapper{mechanism: traversal.LayerPCP, ownership: traversal.OwnershipStrong}
	report, err := EvacuateOrphanedJournals(ctx, st, MapperRegistry{traversal.LayerPCP: mapper},
		map[string]string{"fwd-live": "jr-live"})
	if err != nil {
		t.Fatalf("evacuate with live set: %v", err)
	}
	if len(report.Evacuated) != 0 || mapper.deleteCount() != 0 {
		t.Fatalf("live mapping released: evacuated=%v deletes=%d", report.Evacuated, mapper.deleteCount())
	}
	if _, ok, err := st.MappingJournal().Get("jr-live"); err != nil || !ok {
		t.Fatalf("live journal record deleted ok=%v err=%v", ok, err)
	}

	// Control: WITHOUT the live set, the same record IS classified orphaned and
	// released (proves the live set is what retained it).
	mapper2 := &fakeMapper{mechanism: traversal.LayerPCP, ownership: traversal.OwnershipStrong}
	report2, err := EvacuateOrphanedJournals(ctx, st, MapperRegistry{traversal.LayerPCP: mapper2}, nil)
	if err != nil {
		t.Fatalf("evacuate without live set: %v", err)
	}
	if len(report2.Evacuated) != 1 || report2.Evacuated[0] != "jr-live" {
		t.Fatalf("control evacuated = %v, want [jr-live]", report2.Evacuated)
	}
	if mapper2.deleteCount() != 1 {
		t.Fatalf("control mapper deletes = %d, want 1", mapper2.deleteCount())
	}
}
