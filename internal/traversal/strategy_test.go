package traversal

import (
	"errors"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// ---------------------------------------------------------------------------
// Story 1 RED: strategy/layer contract.
//
// The layered strategy is a pipeline, not a mode switch (v0.8 §3.1). These
// tests pin the classification rules that gateway adapters must obey:
//   - a non-global first-hop mapped endpoint is never a public candidate;
//   - more than one explicit NAT control layer is rejected, never merged;
//   - a fixed strategy fails without silent fallback while `auto` walks its
//     ordered list;
//   - the gateway port policy and the final endpoint constraint are separate;
//   - each mechanism declares its honest port-control capability.
// ---------------------------------------------------------------------------

func globalLayer(endpoint string, lifetime time.Duration) LayerEvidence {
	return LayerEvidence{
		Kind:             LayerKindGateway,
		Mechanism:        LayerPCP,
		ControlServer:    "198.51.100.1:5351",
		InternalEndpoint: "10.0.0.2:3111",
		AssignedEndpoint: endpoint,
		LeaseLifetime:    lifetime,
		Ownership:        OwnershipStrong,
	}
}

func stunLayer(endpoint string) LayerEvidence {
	return LayerEvidence{
		Kind:             LayerKindSTUN,
		ControlServer:    "stun.example:3478",
		InternalEndpoint: "10.0.0.2:3111",
		AssignedEndpoint: endpoint,
		Ownership:        OwnershipObservedOnly,
		ParentLayer:      0,
	}
}

// R1-1: a non-global gateway-assigned endpoint classifies as FIRST_HOP only.
func TestEvaluateLayersNonGlobalFirstHopIsNeverPublic(t *testing.T) {
	verdict, err := EvaluateLayers([]LayerEvidence{
		globalLayer("100.64.0.2:43111", time.Hour),
	}, PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("non-global first hop must classify, not error: %v", err)
	}
	if verdict.Scope != ScopeFirstHop {
		t.Fatalf("scope = %q, want FIRST_HOP", verdict.Scope)
	}
	if verdict.PublicCandidate {
		t.Fatal("FIRST_HOP_MAPPED endpoint must never be a public candidate")
	}
	if !verdict.MappingStateFirstHop {
		t.Fatal("verdict must carry MappingStateFirstHop for the mapping_state axis")
	}
}

// R1-1b: a global-class gateway-assigned endpoint is a public candidate that
// only an independent WAN probe may verify.
func TestEvaluateLayersGlobalGatewayEndpointIsPublicCandidate(t *testing.T) {
	verdict, err := EvaluateLayers([]LayerEvidence{
		globalLayer("8.8.8.8:43111", time.Hour),
	}, PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("global gateway endpoint must classify: %v", err)
	}
	if verdict.Scope != ScopeGlobalPublic {
		t.Fatalf("scope = %q, want GLOBAL_PUBLIC", verdict.Scope)
	}
	if !verdict.PublicCandidate {
		t.Fatal("global candidate must be probe-eligible")
	}
}

// R1-2: two explicit NAT control layers are unsupported and never merged.
func TestEvaluateLayersRejectsMultipleExplicitLayers(t *testing.T) {
	_, err := EvaluateLayers([]LayerEvidence{
		globalLayer("8.8.8.8:43111", time.Hour),
		{
			Kind:             LayerKindGateway,
			Mechanism:        LayerNATPMP,
			ControlServer:    "198.51.100.2:5351",
			InternalEndpoint: "10.0.0.2:3111",
			AssignedEndpoint: "8.8.8.8:43112",
			Ownership:        OwnershipWeakLease,
		},
	}, PortPolicyAcceptAssigned)
	if err == nil {
		t.Fatal("two explicit mapping layers must be rejected")
	}
	if !errors.Is(err, ErrUnsupportedMultipleExplicitLayers) {
		t.Fatalf("error = %v, want ErrUnsupportedMultipleExplicitLayers", err)
	}
	var coded *StrategyError
	if !errors.As(err, &coded) || coded.Code != "UNSUPPORTED_MULTIPLE_EXPLICIT_NAT_LAYERS" {
		t.Fatalf("error must carry the UNSUPPORTED_MULTIPLE_EXPLICIT_NAT_LAYERS code, got %v", err)
	}
}

// R1-3a: a fixed explicit-gateway strategy with a PCP layer failure must not
// silently fall back to another mechanism.
func TestResolveAutoFixedStrategyDoesNotFallback(t *testing.T) {
	order := []protocol.Strategy{protocol.StrategyDirectV4, protocol.StrategyExplicitGateway}
	resolved, err := ResolveAuto(order, func(s protocol.Strategy) bool {
		return s == protocol.StrategyDirectV4 // only direct-v4 is available
	})
	if err != nil {
		t.Fatalf("auto resolution failed: %v", err)
	}
	if resolved != protocol.StrategyDirectV4 {
		t.Fatalf("auto resolved %q, want direct-v4", resolved)
	}
}

// R1-3b: `auto` walks its ordered list in order, skipping failed strategies.
func TestResolveAutoWalksOrderDeterministically(t *testing.T) {
	order := []protocol.Strategy{
		protocol.StrategyExplicitGateway,
		protocol.StrategyStunOnly,
		protocol.StrategyDirectV4,
	}
	calls := []protocol.Strategy{}
	resolved, err := ResolveAuto(order, func(s protocol.Strategy) bool {
		calls = append(calls, s)
		return s == protocol.StrategyDirectV4
	})
	if err != nil {
		t.Fatalf("auto resolution failed: %v", err)
	}
	if resolved != protocol.StrategyDirectV4 {
		t.Fatalf("auto resolved %q, want direct-v4", resolved)
	}
	if len(calls) != 3 || calls[0] != protocol.StrategyExplicitGateway || calls[2] != protocol.StrategyDirectV4 {
		t.Fatalf("auto must walk the declared order, called %v", calls)
	}
}

// R1-3c: every strategy failed -> stable NO_VIABLE_STRATEGY failure.
func TestResolveAutoAllFailed(t *testing.T) {
	_, err := ResolveAuto([]protocol.Strategy{protocol.StrategyDirectV4}, func(protocol.Strategy) bool {
		return false
	})
	if !errors.Is(err, ErrNoViableStrategy) {
		t.Fatalf("error = %v, want ErrNoViableStrategy", err)
	}
}

// R1-4: gateway port satisfied but upstream STUN rewrote the final port:
// strict final constraint fails, accept_assigned records the observed port.
func TestEvaluateLayersFinalPortConstraint(t *testing.T) {
	base := []LayerEvidence{
		globalLayer("8.8.8.8:43111", time.Hour), // gateway honored the requested port
		stunLayer("8.8.8.8:51234"),              // upstream NAT rewrote it
	}
	if _, err := EvaluateLayers(base, PortPolicyStrict); !errors.Is(err, ErrFinalPortRewritten) {
		t.Fatalf("strict final constraint must fail with ErrFinalPortRewritten, got %v", err)
	}
	verdict, err := EvaluateLayers(base, PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("accept_assigned must accept the observed port: %v", err)
	}
	if verdict.Candidate.String() != "8.8.8.8:51234" {
		t.Fatalf("candidate = %s, want observed endpoint 8.8.8.8:51234", verdict.Candidate)
	}
}

// R1-4b: the final port check only applies when an observed STUN layer exists;
// a gateway endpoint equals the final endpoint.
func TestEvaluateLayersFinalPortWithoutStunObservation(t *testing.T) {
	verdict, err := EvaluateLayers([]LayerEvidence{
		globalLayer("8.8.8.8:43111", time.Hour),
	}, PortPolicyStrict)
	if err != nil {
		t.Fatalf("gateway endpoint under strict final constraint must pass: %v", err)
	}
	if verdict.Candidate.String() != "8.8.8.8:43111" {
		t.Fatalf("candidate = %s, want gateway endpoint", verdict.Candidate)
	}
}

// R1-5: the honest per-mechanism port-control capability table (v0.8 §3.3).
func TestPortControlCapabilities(t *testing.T) {
	cases := []struct {
		kind    MappingLayerKind
		want    PortControlCapability
		igdV2   bool
		version string
	}{
		{
			kind: LayerPCP,
			want: PortControlCapability{
				Mechanism: LayerPCP, CanRequestExact: true, CanAcceptAssigned: true,
				CanRetryCandidate: true, FinalEndpointConstraint: PortPolicyStrict,
			},
		},
		{
			kind: LayerNATPMP,
			want: PortControlCapability{
				Mechanism: LayerNATPMP, CanRequestExact: false, CanAcceptAssigned: true,
				CanRetryCandidate: false, FinalEndpointConstraint: PortPolicyAcceptAssigned,
			},
		},
		{
			kind:  LayerUPnP,
			igdV2: true,
			want: PortControlCapability{
				Mechanism: LayerUPnP, CanRequestExact: true, CanAcceptAssigned: true,
				CanRetryCandidate: true, FinalEndpointConstraint: PortPolicyStrict,
			},
		},
		{
			kind:  LayerUPnP,
			igdV2: false,
			want: PortControlCapability{
				Mechanism: LayerUPnP, CanRequestExact: false, CanAcceptAssigned: true,
				CanRetryCandidate: true, FinalEndpointConstraint: PortPolicyAcceptAssigned,
			},
		},
	}
	for _, tc := range cases {
		got := PortControlCapabilityFor(tc.kind, tc.igdV2)
		if got != tc.want {
			t.Fatalf("%s (igdV2=%v) capability = %+v, want %+v", tc.kind, tc.igdV2, got, tc.want)
		}
	}
}

// R1-5b: planning refuses an exact-port requirement a mechanism cannot honor.
func TestPlanStrategyRefusesExactPortWithoutCapability(t *testing.T) {
	if _, err := PlanStrategy(PlanRequest{
		Strategy:                protocol.StrategyExplicitGateway,
		MappingLayer:            LayerNATPMP,
		GatewayPortPolicy:       PortPolicyStrict,
		FinalEndpointConstraint: PortPolicyAcceptAssigned,
	}); !errors.Is(err, ErrLayerCannotRequestExact) {
		t.Fatalf("strict gateway policy with NAT-PMP must fail planning: %v", err)
	}
}

// R1-5c: planning requires manual-static to carry the operator endpoint, and
// stun-only never claims a mapping layer.
func TestPlanStrategyValidation(t *testing.T) {
	if _, err := PlanStrategy(PlanRequest{
		Strategy: protocol.StrategyManualStaticV4,
	}); !errors.Is(err, ErrOperatorEndpointRequired) {
		t.Fatalf("manual-static without operator endpoint must fail planning: %v", err)
	}
	plan, err := PlanStrategy(PlanRequest{
		Strategy:     protocol.StrategyStunOnly,
		MappingLayer: LayerPCP, // silently ignored if this ever happens
	})
	if err != nil {
		t.Fatalf("stun-only planning failed: %v", err)
	}
	if plan.MappingLayer != "" {
		t.Fatalf("stun-only must never carry a mapping layer, got %q", plan.MappingLayer)
	}
}
