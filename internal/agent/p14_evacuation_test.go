// P14 Story 1 app-level wiring: the production recovery path runs the
// orphaned-journal evacuation with adapter State decode, and the same-revision
// applied MappingJournalRef refresh marks the live record.
package agent

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal/pcp"
)

// TestRecoveryEvacuatesOrphanedJournal is the dataPlane-level Story 1 wiring:
// after applying a gateway forward against a real store journal, an extra
// orphaned record survives the forward's own journal lifecycle; a recovery
// pass decodes it (pcp.MapResult typed State), releases it through the
// authoritative mapper, and deletes the record.
func TestRecoveryEvacuatesOrphanedJournal(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	mapper := &p12wMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
		lease:     time.Hour,
	}
	obs := &p12wObserver{result: netip.MustParseAddrPort("100.64.0.2:51234")}
	listeners := &p12wListenerSource{}
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable:  p12wRouteTable{},
		Listeners:   listeners,
		Mappers:     map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: mapper},
		Journal:     st.MappingJournal(),
		StunObserve: obs.observe,
	})
	profiles := newProfileStore(t.TempDir())
	fp, _ := traversal.Fingerprint(p12wRouteTable{})
	if err := profiles.Save(traversal.Profile{
		Fingerprint: fp, Protocol: traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway,
		ComputedAtUnix:  time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	d := newDataPlane(dataPlaneConfig{
		Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now,
		GatewayManager: manager,
		Mappers:        map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: mapper},
		Journal:        st.MappingJournal(),
		StunServers:    []string{"stun+tcp://100.64.0.1:3478"},
		ProfileStore:   profiles,
		StunObserver:   obs.observe,
		StunSource:     &p12wListenerSource{},
		OnApplied:      func(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {},
	})
	defer func() { _ = d.closeAll(ctx) }()

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-1", Name: "fwd", Protocol: protocol.ProtocolTCP,
		Target: "127.0.0.1:9", Strategy: protocol.StrategyExplicitGateway,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := d.apply(ctx, spec); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-1"]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil || actor.acq.JournalID == "" {
		t.Fatalf("actor/journal missing: %+v", actor)
	}
	liveID := actor.acq.JournalID
	if _, ok, _ := st.MappingJournal().Get(liveID); !ok {
		t.Fatalf("live journal record missing")
	}
	// The live forward must never be evacuated.
	orphanID := "orphan-1"
	stateRaw, _ := json.Marshal(pcp.MapResult{
		InternalAddress: netip.MustParseAddr("10.0.0.2"), InternalPort: 9000,
		AssignedExternalPort: 41000, Lifetime: 1200,
	})
	if err := st.MappingJournal().Put(traversal.JournalRecord{
		ID: orphanID, ForwardID: "fwd-gone", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
		InternalIP: "10.0.0.2", InternalPort: 9000,
		ExternalIP: "100.64.0.2", ExternalPort: 41000,
		State: stateRaw, CreatedAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	report, err := d.recover(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !sliceContains(report.Evacuation.Evacuated, orphanID) {
		t.Fatalf("evacuated = %v, want it to contain %s", report.Evacuation.Evacuated, orphanID)
	}
	if _, ok, _ := st.MappingJournal().Get(orphanID); ok {
		t.Fatal("orphaned journal record survived recovery evacuation")
	}
	if _, ok, _ := st.MappingJournal().Get(liveID); !ok {
		t.Fatal("live journal record was evacuated")
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("mapper deletes = %d, want 1", mapper.deleteCount())
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// TestRecoveryRefreshAppliedRefOnReopen is the same-revision LKG refresh:
// after reopen reclaims the mapping under a NEW journal id, the applied
// record's MappingJournalRef points at the live record while SpecRevision stays
// put.
func TestRecoveryRefreshAppliedRefOnReopen(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-2", Name: "fwd2", Protocol: protocol.ProtocolTCP,
		Target: "127.0.0.1:9", Strategy: protocol.StrategyDirectV4,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	applied := protocol.AppliedForwardState{
		ForwardID: "fwd-2", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "127.0.0.1", ActualBindPort: 24000,
		Strategy: "direct-v4", MappingJournalRef: "jr-stale",
		AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{spec}}, []localstate.ForwardApply{{
		ForwardID: "fwd-2", Outcome: localstate.ApplyApplied, Applied: &applied,
	}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.MappingJournal().Get("jr-stale"); ok {
		t.Fatal("continue: stale ref unexpectedly present in journal")
	}
	// The applied ref points at a vanished record: evacuate must refresh it to "".
	report, err := reconcile.EvacuateOrphanedJournals(ctx, st, reconcile.MapperRegistry{}, nil)
	if err != nil {
		t.Fatalf("evacuate: %v", err)
	}
	if !sliceContains(report.Refreshed, "fwd-2") {
		t.Fatalf("refreshed = %v, want it to contain fwd-2", report.Refreshed)
	}
	rec, ok, err := st.GetAppliedRecord("fwd-2")
	if err != nil || !ok {
		t.Fatalf("get applied ok=%v err=%v", ok, err)
	}
	if rec.State.MappingJournalRef != "" {
		t.Fatalf("applied ref = %q, want cleared", rec.State.MappingJournalRef)
	}
	if rec.State.SpecRevision != 1 || rec.State.DesiredRevision != 1 {
		t.Fatalf("revision moved during dangling-ref refresh: %+v", rec.State)
	}
}
