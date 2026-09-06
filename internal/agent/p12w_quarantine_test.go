// Repair R1 finding 3: a stale/absent cached detection profile must NOT fail
// the whole recover pass for an applied TCP auto forward. The auto forward is
// quarantined (the applied LKG stays durable, the forward is left
// non-applied/retry-intent, the per-forward error is surfaced), while direct /
// manual / gateway-with-resolved-profile siblings still recover. The detection
// job repopulates the profile and a later recover reopens the quarantined row.
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

// recoveryReporter captures the OnRecovery argument of every recover pass.
type recoveryReporter struct {
	mu     sync.Mutex
	report recoverReport
}

func (r *recoveryReporter) capture(report recoverReport) {
	r.mu.Lock()
	r.report = report
	r.mu.Unlock()
}

func (r *recoveryReporter) get() recoverReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.report
}

func TestDataPlaneRecoveryQuarantinesStaleAutoWhileSiblingsRecover(t *testing.T) {
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
	// STALE profile: fingerprint no longer matches the node, so auto cannot
	// resolve, but the PCP layer still passes for the explicit-gateway sibling.
	if err := profiles.Save(traversal.Profile{
		Fingerprint: "stale-fingerprint", Protocol: traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway, ComputedAtUnix: time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	reporter := &recoveryReporter{}
	d.cfg.GatewayManager = manager
	d.cfg.Journal = journal
	d.cfg.StunServers = []string{"stun+tcp://100.64.0.1:3478"}
	d.cfg.ProfileStore = profiles
	d.cfg.OnApplied = a.onForwardApplied
	d.cfg.OnRecovery = reporter.capture
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })

	// Seed two applied records exactly as a crash would leave them.
	seed := func(spec protocol.ForwardSpec, applied protocol.AppliedForwardState) {
		t.Helper()
		if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-q", Forwards: []protocol.ForwardSpec{spec}},
			[]localstate.ForwardApply{{ForwardID: spec.ForwardID, Outcome: localstate.ApplyApplied, Applied: &applied}}); err != nil {
			t.Fatalf("seed %s: %v", spec.ForwardID, err)
		}
	}
	autoSpec := protocol.ForwardSpec{
		ForwardID: "fwd-auto-stale", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyAuto, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	seed(autoSpec, protocol.AppliedForwardState{
		ForwardID: "fwd-auto-stale", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 11111,
		Strategy: "auto", LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	})
	gwSpec := protocol.ForwardSpec{
		ForwardID: "fwd-gw-ok", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	seed(gwSpec, protocol.AppliedForwardState{
		ForwardID: "fwd-gw-ok", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 22222,
		Strategy: "explicit-gateway", LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	})

	// recover must not abort the whole pass: the stale auto forward is
	// quarantined and the healthy gateway sibling still reopens.
	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover must not fail the whole pass for a stale auto forward: %v", err)
	}
	d.mu.Lock()
	gwActor := d.forwards["fwd-gw-ok"]
	_, autoLive := d.forwards["fwd-auto-stale"]
	d.mu.Unlock()
	if gwActor == nil || gwActor.acq == nil {
		t.Fatal("healthy explicit-gateway sibling did not reopen")
	}
	if autoLive {
		t.Fatal("stale auto forward unexpectedly reopened")
	}
	// The applied LKG stays durable (retry-intent), never deleted.
	if _, ok, err := st.GetAppliedState("fwd-auto-stale"); err != nil || !ok {
		t.Fatalf("quarantined LKG lost: ok=%v err=%v", ok, err)
	}
	// The per-forward error is surfaced through the recovery report.
	report := reporter.get()
	if len(report.Quarantined) != 1 || report.Quarantined[0].ForwardID != "fwd-auto-stale" {
		t.Fatalf("quarantine report = %+v, want the stale auto forward", report.Quarantined)
	}

	// The detection job repopulates the profile; a later recover reopens the
	// quarantined auto forward.
	if err := profiles.Save(traversal.Profile{
		Fingerprint: fp, Protocol: traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway, ComputedAtUnix: time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.recover(context.Background()); err != nil {
		t.Fatalf("recover after a fresh profile: %v", err)
	}
	d.mu.Lock()
	autoActor := d.forwards["fwd-auto-stale"]
	d.mu.Unlock()
	if autoActor == nil || autoActor.acq == nil {
		t.Fatal("quarantined auto forward did not reopen after a fresh profile")
	}
	// The recovery report for the refreshed pass no longer quarantines it.
	if quarantine := reporter.get(); len(quarantine.Quarantined) != 0 {
		t.Fatalf("post-refresh quarantine = %+v, want none", quarantine.Quarantined)
	}
}
