// P12W Story 8: startup journal replay + mapping ref exposure. A restart
// simulation writes a journal record and an applied record for a gateway
// forward via the real store methods; dp.recover reopens the forward through
// the Manager, the recovery's applied record carries the NEW JournalID, the
// activation mapping_state reflects the acquisition verdict, and staled
// (superseded) / orphaned records remain in the bucket and are surfaced by
// replayJournalBoundaries — never silently deleted.
package agent

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// recoveryJournalReporter captures the OnRecovery recovery-pass report so the
// test can assert the PRODUCTION recovery path surfaces the journal replay
// boundary (repair R1 finding 4), not just the test-invoked helper.
type recoveryJournalReporter struct {
	mu     sync.Mutex
	report recoverReport
}

func (r *recoveryJournalReporter) capture(report recoverReport) {
	r.mu.Lock()
	r.report = report
	r.mu.Unlock()
}

func (r *recoveryJournalReporter) get() recoverReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.report
}

// appliedRecorder captures the OnApplied argument so the test can assert the
// recovery's applied record carries the NEW journal ref.
type appliedRecorder struct {
	mu      sync.Mutex
	spec    protocol.ForwardSpec
	applied protocol.AppliedForwardState
}

func (r *appliedRecorder) record(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
	r.mu.Lock()
	r.spec = spec
	r.applied = applied
	r.mu.Unlock()
}

func (r *appliedRecorder) captured() (protocol.ForwardSpec, protocol.AppliedForwardState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.spec, r.applied
}

// p12wRecoveryApp wires a data plane exactly like the composed app but with
// the STORE-BACKED journal and a recording OnApplied hook.
func p12wRecoveryApp(t *testing.T) (*App, *dataPlane, *p12wRenewMapper, *appliedRecorder) {
	t.Helper()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mapper := &p12wRenewMapper{
		p12wMapper: p12wMapper{
			mechanism: traversal.LayerPCP,
			ownership: traversal.OwnershipStrong,
			control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
			external:  netip.MustParseAddrPort("100.64.0.2:43111"),
			lease:     time.Hour,
		},
		grantedLease: time.Hour,
	}
	obs := &p12wObserver{result: netip.MustParseAddrPort("100.64.0.2:51234")}
	journal := st.MappingJournal()
	recorder := &appliedRecorder{}
	d := newDataPlane(dataPlaneConfig{Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now})
	a := &App{store: st, dp: d, activations: make(map[string]*reconcile.Activation)}
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable:  p12wRouteTable{},
		Listeners:   &p12wListenerSource{},
		Mappers:     map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: mapper},
		Journal:     journal,
		StunObserve: obs.observe,
	})
	fp, fpErr := traversal.Fingerprint(p12wRouteTable{})
	if fpErr != nil {
		t.Fatal(fpErr)
	}
	profiles := newProfileStore(t.TempDir())
	if err := profiles.Save(traversal.Profile{
		Fingerprint: fp, Protocol: traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway, ComputedAtUnix: time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	d.cfg.GatewayManager = manager
	d.cfg.Journal = journal
	d.cfg.StunServers = []string{"stun+tcp://100.64.0.1:3478"}
	d.cfg.ProfileStore = profiles
	d.cfg.OnApplied = func(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
		recorder.record(spec, applied)
		a.onForwardApplied(spec, applied)
	}
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })
	return a, d, mapper, recorder
}

func TestDataPlaneRecoveryReopensGatewayWithNewJournalRef(t *testing.T) {
	a, d, _, recorder := p12wRecoveryApp(t)
	st := d.cfg.Store

	// Seed a durable applied record + its (now stale) journal record via real
	// store methods, exactly as a crash would leave them.
	oldRef := "fwd-gw-pcp-STALE"
	if err := st.MappingJournal().Put(traversal.JournalRecord{
		ID: oldRef, ForwardID: "fwd-gw", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
	}); err != nil {
		t.Fatal(err)
	}
	gwSpec := protocol.ForwardSpec{
		ForwardID: "fwd-gw", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	seeded := protocol.AppliedForwardState{
		ForwardID: "fwd-gw", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 12345,
		Strategy: "explicit-gateway", LayerVersion: 1,
		MappingJournalRef: oldRef, AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-r", Forwards: []protocol.ForwardSpec{gwSpec}},
		[]localstate.ForwardApply{{ForwardID: "fwd-gw", Outcome: localstate.ApplyApplied, Applied: &seeded}}); err != nil {
		t.Fatalf("seed applied record: %v", err)
	}

	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-gw"]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil {
		t.Fatal("recover did not reopen the gateway forward through the Manager")
	}
	newRef := actor.acq.JournalID
	if newRef == "" || newRef == oldRef {
		t.Fatalf("recovered journal ref = %q, want a NEW ref distinct from %q", newRef, oldRef)
	}
	// The recovery's applied record (OnApplied) carries the NEW journal id.
	recSpec, recApplied := recorder.captured()
	if recSpec.ForwardID != "fwd-gw" || recApplied.MappingJournalRef != newRef {
		t.Fatalf("recovery applied = spec %q ref %q, want the new journal ref %q",
			recSpec.ForwardID, recApplied.MappingJournalRef, newRef)
	}
	// The activation mapping_state reflects the acquisition verdict.
	snap := a.ActivationSnapshot("fwd-gw")
	if snap == nil || snap.MappingState != "FIRST_HOP_MAPPED" {
		t.Fatalf("activation mapping_state = %+v, want FIRST_HOP_MAPPED", snap)
	}

	// Orphaned records are detection temps / forwards with no live/applied row.
	if err := st.MappingJournal().Put(traversal.JournalRecord{ID: "det-temp-1", OperationID: "op-x"}); err != nil {
		t.Fatal(err)
	}
	if err := st.MappingJournal().Put(traversal.JournalRecord{ID: "fwd-deleted-pcp", ForwardID: "fwd-deleted",
		Mechanism: traversal.LayerPCP, Ownership: traversal.OwnershipStrong}); err != nil {
		t.Fatal(err)
	}

	// The stale record is NOT deleted and is surfaced as superseded.
	if _, ok, err := st.MappingJournal().Get(oldRef); err != nil || !ok {
		t.Fatalf("stale journal record deleted or unreadable: ok=%v err=%v", ok, err)
	}
	report, err := d.replayJournalBoundaries(d.cfg.Journal, d.cfg.Store, d.liveJournalRefs())
	if err != nil {
		t.Fatalf("replayJournalBoundaries: %v", err)
	}
	foundSuperseded := false
	for _, rec := range report.Superseded {
		if rec.ID == oldRef {
			foundSuperseded = true
		}
		if rec.ID == newRef {
			t.Fatalf("the LIVE journal ref %q was classified superseded", newRef)
		}
	}
	if !foundSuperseded {
		t.Fatalf("stale ref %q not surfaced as superseded: %+v", oldRef, report.Superseded)
	}
	orphans := map[string]bool{}
	for _, rec := range report.Orphaned {
		orphans[rec.ID] = true
	}
	if !orphans["det-temp-1"] || !orphans["fwd-deleted-pcp"] {
		t.Fatalf("orphaned records not surfaced: %+v", report.Orphaned)
	}
}

// Repair R1 finding 4: replayJournalBoundaries is wired into the PRODUCTION
// recovery path, not just test-invoked. The OnRecovery report's Journal field
// surfaced by d.recover is the Story 8 "surfaced by a diagnostic" claim being
// true at startup: Superseded and Orphaned records are listed on the real
// recovery path, never silently deleted.
func TestDataPlaneRecoverySurfacesJournalReplayBoundaries(t *testing.T) {
	_, d, _, _ := p12wRecoveryApp(t)
	st := d.cfg.Store
	reporter := &recoveryJournalReporter{}
	d.cfg.OnRecovery = reporter.capture

	// A stale journal record for a live applied forward (superseded after the
	// restart re-acquires a NEW journal ref) and an orphaned detection temp.
	oldRef := "fwd-jr-pcp-STALE"
	if err := st.MappingJournal().Put(traversal.JournalRecord{
		ID: oldRef, ForwardID: "fwd-jr", Mechanism: traversal.LayerPCP,
		Ownership: traversal.OwnershipStrong, Protocol: "tcp",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.MappingJournal().Put(traversal.JournalRecord{ID: "det-temp-r1", OperationID: "op-x"}); err != nil {
		t.Fatal(err)
	}
	gwSpec := protocol.ForwardSpec{
		ForwardID: "fwd-jr", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	seeded := protocol.AppliedForwardState{
		ForwardID: "fwd-jr", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 12345,
		Strategy: "explicit-gateway", LayerVersion: 1,
		MappingJournalRef: oldRef, AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-jr", Forwards: []protocol.ForwardSpec{gwSpec}},
		[]localstate.ForwardApply{{ForwardID: "fwd-jr", Outcome: localstate.ApplyApplied, Applied: &seeded}}); err != nil {
		t.Fatal(err)
	}

	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-jr"]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil {
		t.Fatal("recover did not reopen the gateway forward")
	}
	newRef := actor.acq.JournalID

	report := reporter.get()
	foundSuperseded := false
	for _, rec := range report.Journal.Superseded {
		if rec.ID == oldRef {
			foundSuperseded = true
		}
		if rec.ID == newRef {
			t.Fatalf("the LIVE journal ref %q was classified superseded", newRef)
		}
	}
	if !foundSuperseded {
		t.Fatalf("production recovery did not surface the superseded ref %q: %+v", oldRef, report.Journal.Superseded)
	}
	orphans := map[string]bool{}
	for _, rec := range report.Journal.Orphaned {
		orphans[rec.ID] = true
	}
	if !orphans["det-temp-r1"] {
		t.Fatalf("production recovery did not surface the orphaned record: %+v", report.Journal.Orphaned)
	}
	// The records remain in the durable bucket (never silently deleted).
	if _, ok, err := st.MappingJournal().Get(oldRef); err != nil || !ok {
		t.Fatalf("stale journal record deleted or unreadable: ok=%v err=%v", ok, err)
	}
}
