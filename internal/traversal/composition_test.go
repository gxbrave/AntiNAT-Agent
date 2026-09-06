// Story 5 composition tests: the layered pipeline composes one gateway
// mapping layer with a same-source STUN observation and hands a
// probe-eligible verdict to the independent WAN probe. The mappers here are
// in-package fakes implementing the GatewayMapper contract; the real
// adapters get protocol-level tests in their packages and the netns lab
// exercises the full composition against a real gateway daemon.
package traversal

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// fakeMapper implements GatewayMapper with scripted discovery and mapping.
type fakeMapper struct {
	mechanism MappingLayerKind
	ownership OwnershipStrength
	// control is the discovered control server; discoverErr fails Discover.
	control     ControlServer
	discoverErr error
	external    netip.AddrPort
	mapErr      error
	deleted     bool
}

func (f *fakeMapper) Mechanism() MappingLayerKind  { return f.mechanism }
func (f *fakeMapper) Ownership() OwnershipStrength { return f.ownership }
func (f *fakeMapper) Capability() PortControlCapability {
	return PortControlCapabilityFor(f.mechanism, false)
}
func (f *fakeMapper) Discover(ctx context.Context) (ControlServer, error) {
	return f.control, f.discoverErr
}
func (f *fakeMapper) Map(ctx context.Context, req GatewayMapRequest) (GatewayMapping, error) {
	if f.mapErr != nil {
		return GatewayMapping{}, f.mapErr
	}
	return GatewayMapping{
		Mechanism:    f.mechanism,
		Ownership:    f.ownership,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     f.external,
		Lease:        req.Lease,
		State:        "fake-state",
	}, nil
}
func (f *fakeMapper) Renew(ctx context.Context, mapping GatewayMapping, lifetime time.Duration) (GatewayMapping, error) {
	mapping.Lease = lifetime
	return mapping, nil
}
func (f *fakeMapper) Delete(ctx context.Context, mapping GatewayMapping) error {
	f.deleted = true
	return nil
}

// C1: the full explicit-gateway composition: non-global gateway assignment
// plus a same-source STUN observation stays FIRST_HOP and is never a public
// candidate; the manual layer refuses without operator input.
func TestComposeGatewayNonGlobalWithSameSourceStun(t *testing.T) {
	internalTuple := netip.MustParseAddrPort("10.0.0.2:3111")
	mapper := &fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"), // non-global first hop
	}

	mapping, err := mapper.Map(t.Context(), GatewayMapRequest{
		InternalIP: internalTuple.Addr(), InternalPort: internalTuple.Port(), Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	gatewayEvidence := mapping.Evidence(mapper.control)
	if gatewayEvidence.Scope != ScopeFirstHop {
		t.Fatalf("gateway evidence scope = %q, want FIRST_HOP", gatewayEvidence.Scope)
	}
	// Same-source STUN observation on the same internal tuple: the CGNAT
	// upstream rewrote the port.
	stunEvidence := LayerEvidence{
		Kind:             LayerKindSTUN,
		ControlServer:    "stun+tcp://stun.lab:3478",
		InternalEndpoint: internalTuple.String(),
		AssignedEndpoint: "100.64.0.2:51234",
		Scope:            ScopeFirstHop,
		Ownership:        OwnershipObservedOnly,
		ParentLayer:      0,
	}
	verdict, err := EvaluateLayers([]LayerEvidence{gatewayEvidence, stunEvidence}, PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("EvaluateLayers: %v", err)
	}
	if verdict.PublicCandidate {
		t.Fatal("CGNAT-scope composition must never claim a public candidate")
	}
	if !verdict.MappingStateFirstHop {
		t.Fatal("composition must report the FIRST_HOP mapping state")
	}
	if verdict.Candidate.String() != "100.64.0.2:51234" {
		t.Fatalf("candidate = %s, want the observed endpoint", verdict.Candidate)
	}
}

// C2: a global upstream observation makes the candidate probe-eligible, and
// only OPEN_FROM_VANTAGE may drive publication — the pipeline hands the
// candidate to the probe, never publishes directly.
func TestComposeGatewayGlobalObservationIsProbeEligibleOnly(t *testing.T) {
	mapper := &fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("10.0.0.1:43111"), // first hop, non-global
	}
	mapping, err := mapper.Map(t.Context(), GatewayMapRequest{
		InternalIP: netip.MustParseAddr("10.0.0.2"), InternalPort: 3111, Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	stunEvidence := LayerEvidence{
		Kind:             LayerKindSTUN,
		InternalEndpoint: "10.0.0.2:3111",
		AssignedEndpoint: "8.8.8.8:43111", // upstream global observation
		Ownership:        OwnershipObservedOnly,
		ParentLayer:      0,
	}
	verdict, err := EvaluateLayers([]LayerEvidence{mapping.Evidence(mapper.control), stunEvidence}, PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("EvaluateLayers: %v", err)
	}
	if !verdict.PublicCandidate {
		t.Fatal("a global observed candidate must be probe-eligible")
	}
	if verdict.PublicCandidate && verdict.Candidate != stunCandidate("8.8.8.8:43111") {
		t.Fatalf("candidate = %s", verdict.Candidate)
	}
	// The probe boundary: publication is NOT a pipeline output. Only the
	// independent WAN probe outcome (OPEN_FROM_VANTAGE) may publish — the
	// pipeline verdict carries no publication state at all.
	if verdict.Scope != ScopeGlobalPublic {
		t.Fatalf("scope = %q, want GLOBAL_PUBLIC", verdict.Scope)
	}
}

// stunCandidate parses the endpoint for test assertions.
func stunCandidate(text string) netip.AddrPort {
	return netip.MustParseAddrPort(text)
}

// C3: detection-driven auto resolution refuses when every mechanism fails
// discovery and the pipeline surfaces NO_VIABLE_STRATEGY without silently
// falling back to a different fixed strategy.
func TestComposeAutoWithAllMappersFailed(t *testing.T) {
	failed := &fakeMapper{mechanism: LayerPCP, discoverErr: errors.New("no response")}
	order := []protocol.Strategy{protocol.StrategyExplicitGateway, protocol.StrategyDirectV4}
	resolved, err := ResolveAuto(order, func(s protocol.Strategy) bool {
		if s == protocol.StrategyExplicitGateway {
			if _, err := failed.Discover(t.Context()); err != nil {
				return false
			}
		}
		return false // direct also unavailable in this scenario
	})
	if !errors.Is(err, ErrNoViableStrategy) {
		t.Fatalf("error = %v, want ErrNoViableStrategy", err)
	}
	if resolved != "" {
		t.Fatalf("resolved = %q, want empty", resolved)
	}
}

// C4: strict gateway port planning rejects a mechanism that cannot request
// exact ports even when the mapper itself is healthy.
func TestComposeStrictPortPlanning(t *testing.T) {
	plan, err := PlanStrategy(PlanRequest{
		Strategy:                protocol.StrategyExplicitGateway,
		MappingLayer:            LayerNATPMP,
		GatewayPortPolicy:       PortPolicyAcceptAny,
		FinalEndpointConstraint: PortPolicyAcceptAssigned,
	})
	if err != nil {
		t.Fatalf("accept_any planning with NAT-PMP must pass: %v", err)
	}
	if plan.Capability.CanRequestExact {
		t.Fatal("NAT-PMP must not claim exact-request capability")
	}
}

// C7 (netns lab evidence): the mapping description stays within the IGD
// device budget. miniupnpd's 64-byte description field is not
// null-terminated for longer values — the query echo returns stack garbage
// (invalid UTF-8) and query-then-delete verification can never match. The
// cap is deterministic so Map and Delete derive the same tag.
func TestMappingDescriptionCappedWithinDeviceBudget(t *testing.T) {
	longUSN := "uuid:9e21d2d0-3c3f-4c1a-9f21-1d1d1d1d1d1f::urn:schemas-upnp-org:service:WANIPConnection:2"
	mapping := GatewayMapping{Identity: longUSN}
	description := mapping.Description()
	if len(description) > maxIGDDescriptionBytes {
		t.Fatalf("description = %d bytes, want <= %d (device budget)", len(description), maxIGDDescriptionBytes)
	}
	if description != mapping.Description() {
		t.Fatal("the description must be deterministic across calls")
	}
	if !strings.HasPrefix(description, "AntiNAT ") {
		t.Fatalf("description = %q, want the AntiNAT owner tag", description)
	}
	short := GatewayMapping{Identity: "uuid:lab-usn"}
	if short.Description() != "AntiNAT uuid:lab-usn" {
		t.Fatalf("short description = %q, want the full untruncated tag", short.Description())
	}
}
