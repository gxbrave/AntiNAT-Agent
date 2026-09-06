// P12W Story 4: forward strategy translation and the truthful failure
// surface. planFor maps every concrete ForwardSpec to the resolved
// traversal.PlanRequest; absent operator input (manual endpoint, gateway
// mechanism, STUN server, cached profile default) fails the apply with the
// strategy-level error, never an Applied state, and the reconcile layer
// surfaces each failure as OutcomeFailed with the LKG preserved.
package agent

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func pcpPassingProfile() traversal.Profile {
	return traversal.Profile{
		Fingerprint:     "fp",
		Protocol:        traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway,
		ComputedAtUnix:  time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}
}

func TestPlanForTable(t *testing.T) {
	stunServers := []string{"stun+tcp://100.64.0.1:3478"}
	cases := []struct {
		name     string
		spec     protocol.ForwardSpec
		profile  traversal.Profile
		servers  []string
		wantPlan traversal.PlanRequest
		wantErr  error
	}{
		{
			name:     "direct minimal plan",
			spec:     protocol.ForwardSpec{Strategy: protocol.StrategyDirectV4},
			wantPlan: traversal.PlanRequest{Strategy: protocol.StrategyDirectV4},
		},
		{
			name:    "manual requires the operator endpoint",
			spec:    protocol.ForwardSpec{Strategy: protocol.StrategyManualStaticV4},
			wantErr: traversal.ErrOperatorEndpointRequired,
		},
		{
			name: "manual carries the operator endpoint",
			spec: protocol.ForwardSpec{Strategy: protocol.StrategyManualStaticV4,
				ManualExpectedEndpoint: "203.0.113.5:8443"},
			wantPlan: traversal.PlanRequest{Strategy: protocol.StrategyManualStaticV4,
				ManualExpectedEndpoint: "203.0.113.5:8443"},
		},
		{
			name:    "explicit-gateway without a resolved profile layer fails",
			spec:    protocol.ForwardSpec{Strategy: protocol.StrategyExplicitGateway},
			profile: traversal.Profile{},
			wantErr: errNoGatewayLayerInProfile,
		},
		{
			name: "explicit-gateway resolves the profile mechanism and the D4 policy",
			spec: protocol.ForwardSpec{Strategy: protocol.StrategyExplicitGateway,
				RequestedPublicPort: 43111},
			profile: pcpPassingProfile(),
			wantPlan: traversal.PlanRequest{Strategy: protocol.StrategyExplicitGateway,
				MappingLayer:            traversal.LayerPCP,
				GatewayPortPolicy:       traversal.PortPolicyStrict,
				FinalEndpointConstraint: traversal.PortPolicyStrict,
			},
		},
		{
			name: "pinned port on NAT-PMP degrades to a suggestion (D4)",
			spec: protocol.ForwardSpec{Strategy: protocol.StrategyExplicitGateway,
				RequestedPublicPort: 43111},
			profile: traversal.Profile{
				Results: []traversal.StrategyResult{
					{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "nat-pmp"},
				},
			},
			wantPlan: traversal.PlanRequest{Strategy: protocol.StrategyExplicitGateway,
				MappingLayer:            traversal.LayerNATPMP,
				GatewayPortPolicy:       traversal.PortPolicyAcceptAny,
				FinalEndpointConstraint: traversal.PortPolicyAcceptAssigned,
			},
		},
		{
			name: "explicit-gateway without a requested port defaults to accept_any",
			spec: protocol.ForwardSpec{Strategy: protocol.StrategyExplicitGateway},
			profile: traversal.Profile{
				Results: []traversal.StrategyResult{
					{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "upnp-igd"},
				},
			},
			wantPlan: traversal.PlanRequest{Strategy: protocol.StrategyExplicitGateway,
				MappingLayer:            traversal.LayerUPnP,
				GatewayPortPolicy:       traversal.PortPolicyAcceptAny,
				FinalEndpointConstraint: traversal.PortPolicyAcceptAssigned,
			},
		},
		{
			name:    "stun-only requires a configured STUN server",
			spec:    protocol.ForwardSpec{Strategy: protocol.StrategyStunOnly},
			servers: nil,
			wantErr: errNoStunServer,
		},
		{
			name:     "stun-only resolves with a configured server",
			spec:     protocol.ForwardSpec{Strategy: protocol.StrategyStunOnly},
			servers:  stunServers,
			wantPlan: traversal.PlanRequest{Strategy: protocol.StrategyStunOnly},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planFor(tc.spec, tc.profile, tc.servers)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("planFor error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("planFor: %v", err)
			}
			if plan != tc.wantPlan {
				t.Fatalf("plan = %+v, want %+v", plan, tc.wantPlan)
			}
		})
	}
}

func TestResolveAutoStrategyTable(t *testing.T) {
	passing := pcpPassingProfile()
	cases := []struct {
		name    string
		spec    protocol.ForwardSpec
		profile traversal.Profile
		have    bool
		want    protocol.Strategy
		wantErr error
	}{
		{name: "UDP auto resolves to direct-v4", spec: protocol.ForwardSpec{Protocol: protocol.ProtocolUDP, Strategy: protocol.StrategyAuto},
			want: protocol.StrategyDirectV4},
		{name: "TCP auto with passing default resolves to it",
			spec:    protocol.ForwardSpec{Protocol: protocol.ProtocolTCP, Strategy: protocol.StrategyAuto},
			profile: passing, have: true,
			want: protocol.StrategyExplicitGateway},
		{name: "TCP auto with no cached profile fails",
			spec: protocol.ForwardSpec{Protocol: protocol.ProtocolTCP, Strategy: protocol.StrategyAuto},
			have: false, wantErr: errAutoNoPassingDefault},
		{name: "TCP auto with a stale (not-passed) default fails",
			spec:    protocol.ForwardSpec{Protocol: protocol.ProtocolTCP, Strategy: protocol.StrategyAuto},
			profile: traversal.Profile{DefaultStrategy: protocol.StrategyExplicitGateway}, have: true,
			wantErr: errAutoNoPassingDefault},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAutoStrategy(tc.spec, tc.profile, tc.have, nil)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("resolveAutoStrategy error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveAutoStrategy: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolved = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDataPlaneStrategyTruthfulFailures: absent operator input fails the
// apply with the strategy error — never a successful Applied state.
func TestDataPlaneStrategyTruthfulFailures(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	d := newDataPlane(dataPlaneConfig{Store: st, Clock: time.Now})
	d.capabilityReady = true

	cases := []struct {
		name           string
		spec           protocol.ForwardSpec
		requireContain string
	}{
		{
			name: "manual-static without the operator endpoint",
			spec: protocol.ForwardSpec{ForwardID: "f-manual-no-endpoint", Protocol: protocol.ProtocolTCP,
				Target: "127.0.0.1:1", Strategy: protocol.StrategyManualStaticV4, DesiredRevision: 1, Presence: protocol.PresencePresent},
			requireContain: "OPERATOR_ENDPOINT_REQUIRED",
		},
		{
			name: "explicit-gateway without a resolved profile layer",
			spec: protocol.ForwardSpec{ForwardID: "f-gateway-no-profile", Protocol: protocol.ProtocolTCP,
				Target: "127.0.0.1:1", Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent},
			requireContain: "requires a resolved mapping layer",
		},
		{
			name: "stun-only without a configured STUN server",
			spec: protocol.ForwardSpec{ForwardID: "f-stun-no-server", Protocol: protocol.ProtocolTCP,
				Target: "127.0.0.1:1", Strategy: protocol.StrategyStunOnly, DesiredRevision: 1, Presence: protocol.PresencePresent},
			requireContain: "stun-only requires a configured STUN server",
		},
		{
			name: "auto without a cached profile",
			spec: protocol.ForwardSpec{ForwardID: "f-auto-no-profile", Protocol: protocol.ProtocolTCP,
				Target: "127.0.0.1:1", Strategy: protocol.StrategyAuto, DesiredRevision: 1, Presence: protocol.PresencePresent},
			requireContain: "auto requires a detection profile",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := d.apply(context.Background(), tc.spec)
			if err == nil {
				t.Fatal("apply succeeded, want a truthful strategy failure")
			}
			if !strings.Contains(err.Error(), tc.requireContain) {
				t.Fatalf("apply error = %v, want it to contain %q", err, tc.requireContain)
			}
		})
	}
}

// TestReconcileStrategyFailureKeepsLkgAndReportsPartial: the reconcile layer
// surfaces the failed forward as OutcomeFailed, keeps the old applied LKG and
// the sibling forward's progress, and reports PARTIAL.
func TestReconcileStrategyFailureKeepsLkgAndReportsPartial(t *testing.T) {
	// The good forward is an explicit-gateway forward through the gateway
	// manager (the lab host's direct-v4 source is private); the bad forward is
	// a manual-static without its operator endpoint.
	d, _, _, _ := p12wGatewayComposition(t)
	st := d.cfg.Store
	if err := st.AdvanceSession(1, "session-1"); err != nil {
		t.Fatal(err)
	}

	latch := localstate.NewLatch()
	r := reconcile.New(st, latch, localstate.MarkerActive, d.apply, d.stop)

	// A healthy explicit-gateway forward first establishes a FULL desired+
	// applied state.
	good := protocol.ForwardSpec{
		ForwardID: "fwd-gateway-good", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	first := protocol.DesiredState{NodeID: "node-s4", Forwards: []protocol.ForwardSpec{good}}
	if _, err := r.ReconcileOnce(context.Background(), first, 1, "session-1"); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}

	// The same snapshot now also carries a manual-static forward missing its
	// operator endpoint: it must fail closed and the previous good forward
	// must advance.
	goodRev2 := good
	goodRev2.DesiredRevision = 2
	bad := protocol.ForwardSpec{
		ForwardID: "fwd-manual-bad", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:8",
		Strategy: protocol.StrategyManualStaticV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	second := protocol.DesiredState{NodeID: "node-s4", Forwards: []protocol.ForwardSpec{goodRev2, bad}}
	report, err := r.ReconcileOnce(context.Background(), second, 1, "session-1")
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if report.Status != localstate.ApplyStatusPartial {
		t.Fatalf("report status = %s, want PARTIAL; results = %+v", report.Status, report.Results)
	}
	badOutcome := ""
	for _, res := range report.Results {
		if res.ForwardID == "fwd-manual-bad" {
			if res.Outcome != reconcile.OutcomeFailed {
				t.Fatalf("bad forward outcome = %v, want FAILED", res.Outcome)
			}
			badOutcome = "seen"
		}
	}
	if badOutcome == "" {
		t.Fatal("the manual-static failure was not reported")
	}
	// The good sibling advanced to revision 2.
	applied, ok, err := st.GetAppliedState("fwd-gateway-good")
	if err != nil || !ok {
		t.Fatalf("good forward applied ok=%v err=%v", ok, err)
	}
	if applied.SpecRevision != 2 {
		t.Fatalf("good forward applied revision = %d, want 2", applied.SpecRevision)
	}
	// The failed manual forward left no applied record (nothing to resurrect).
	if _, ok, err := st.GetAppliedState("fwd-manual-bad"); err != nil || ok {
		t.Fatalf("failed forward applied ok=%v err=%v, want absent", ok, err)
	}
}

// TestDataPlaneGatewayPinnedPortRoutesThroughManager exercises the D4 strict
// policy end to end: a pinned explicit-gateway port on PCP plans a strict
// request through the manager, and the same-tuple STUN observation must agree
// with the gateway-assigned port under the strict final constraint.
func TestDataPlaneGatewayPinnedPortStrictRequest(t *testing.T) {
	// The STUN observation must report the gateway-assigned port: under a
	// strict final constraint a rewritten port is FINAL_PORT_REWRITTEN.
	d, _, _, _ := p12wGatewayCompositionWithObserver(t, netip.MustParseAddrPort("100.64.0.2:43111"))
	spec := protocol.ForwardSpec{
		ForwardID: "fwd-pinned", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, RequestedPublicPort: 43999,
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("pinned-port explicit-gateway apply: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-pinned"]
	d.mu.Unlock()
	if actor == nil || actor.meta.assignedGatewayPort != 43111 {
		t.Fatalf("pinned-port applied assignment = %d, want the scripted PCP external port", actor.meta.assignedGatewayPort)
	}
}

// TestPlanForIgdV2Signature detects the IGDv2 capability from the profile
// signature the detector writes.
func TestPlanForIgdV2Signature(t *testing.T) {
	plan, err := planFor(protocol.ForwardSpec{Strategy: protocol.StrategyExplicitGateway, RequestedPublicPort: 1111},
		traversal.Profile{Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "upnp-igd:2"},
		}}, nil)
	if err != nil {
		t.Fatalf("planFor: %v", err)
	}
	if !plan.IGDv2 || plan.GatewayPortPolicy != traversal.PortPolicyStrict {
		t.Fatalf("IGDv2 plan = %+v, want strict policy + IGDv2 true", plan)
	}
}
