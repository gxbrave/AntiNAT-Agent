package traversal

// Story 7b RED: the manager's STUN observation seam is same-tuple-honest.
// The observer receives the forward's own bound tuple and a dial bound to
// it (v0.8 §3.1 step 6, §4.2): an observation from any other local socket
// classifies a different NAT binding and must never enter this pipeline.
// A configured-but-unparseable server is an operator error that fails the
// acquisition; a configured observation that cannot be honored (no
// observer, no same-tuple dialer, transport failure) is recorded on the
// acquisition — never silently dropped — and the gateway evidence stands
// alone.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

// recordingObserver captures every request and returns a scripted result.
type recordingObserver struct {
	mu       sync.Mutex
	requests []StunObserveRequest
	result   netip.AddrPort
	err      error
}

func (o *recordingObserver) observe(ctx context.Context, req StunObserveRequest) (netip.AddrPort, error) {
	o.mu.Lock()
	o.requests = append(o.requests, req)
	o.mu.Unlock()
	if o.err != nil {
		return netip.AddrPort{}, o.err
	}
	if req.Dial != nil {
		conn, err := req.Dial(ctx, req.Server.String())
		if err != nil {
			return netip.AddrPort{}, err
		}
		_ = conn.Close()
	}
	return o.result, nil
}

func (o *recordingObserver) lastRequest() StunObserveRequest {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.requests) == 0 {
		return StunObserveRequest{}
	}
	return o.requests[len(o.requests)-1]
}

// fakeDialSource adds the same-tuple dial capability to the scripted
// listener source and records the remotes the observer dialed.
type fakeDialSource struct {
	fakeListenerSource
	mu      sync.Mutex
	dials   []string
	dialErr error
}

func (f *fakeDialSource) DialFrom(ctx context.Context, bind TupleKey, remote string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, remote)
	dialErr := f.dialErr
	f.mu.Unlock()
	if dialErr != nil {
		return nil, dialErr
	}
	// A dead pipe conn is enough: the fake observer only closes it.
	client, server := net.Pipe()
	go func() { _ = server.Close() }()
	return client, nil
}

func (f *fakeDialSource) dialed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dials...)
}

// MS1: the observer receives the forward's own bound tuple with a dial
// bound to it, and the observed endpoint becomes the candidate through the
// appended STUN layer.
func TestManagerStunObservationUsesForwardTuple(t *testing.T) {
	observed := netip.MustParseAddrPort("100.64.0.2:51234")
	obs := &recordingObserver{result: observed}
	source := &fakeDialSource{}
	mapper := gatewayMapperFixture()
	manager := NewManager(ManagerOptions{
		RouteTable:  managerRouteTable(),
		Listeners:   source,
		Mappers:     map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:     NewMemoryJournal(),
		StunObserve: obs.observe,
	})
	request := gatewayAcquireRequest("forward-stun-1")
	request.StunServer = "stun+tcp://100.64.0.1:3478"
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	req := obs.lastRequest()
	if req.Bind != acquisition.Bind {
		t.Fatalf("observer bind = %+v, want the forward's own tuple %+v", req.Bind, acquisition.Bind)
	}
	if req.Dial == nil {
		t.Fatal("observer must receive the same-tuple dial")
	}
	if req.Server.String() != "100.64.0.1:3478" {
		t.Fatalf("observer server = %s", req.Server)
	}
	if req.Timeout <= 0 {
		t.Fatal("observer must receive a positive exchange timeout")
	}
	dials := source.dialed()
	if len(dials) != 1 || dials[0] != "100.64.0.1:3478" {
		t.Fatalf("same-tuple dials = %v, want exactly the STUN server", dials)
	}
	if acquisition.StunObserveError != nil {
		t.Fatalf("observation error = %v, want none", acquisition.StunObserveError)
	}
	if len(acquisition.Layers) != 2 {
		t.Fatalf("layers = %+v, want gateway + STUN", acquisition.Layers)
	}
	stunLayer := acquisition.Layers[1]
	if stunLayer.Kind != LayerKindSTUN || stunLayer.ParentLayer != 0 {
		t.Fatalf("stun layer = %+v, want a child of the gateway layer", stunLayer)
	}
	if stunLayer.AssignedEndpoint != observed.String() {
		t.Fatalf("stun endpoint = %s, want %s", stunLayer.AssignedEndpoint, observed)
	}
	if acquisition.Verdict.Candidate != observed {
		t.Fatalf("candidate = %s, want the observed endpoint", acquisition.Verdict.Candidate)
	}
}

// MS2: a failed observation is recorded on the acquisition — the gateway
// evidence stands alone, and nothing is silently swallowed.
func TestManagerStunObservationFailureRecorded(t *testing.T) {
	obs := &recordingObserver{err: errors.New("dial refused")}
	source := &fakeDialSource{}
	mapper := gatewayMapperFixture()
	manager := NewManager(ManagerOptions{
		RouteTable:  managerRouteTable(),
		Listeners:   source,
		Mappers:     map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:     NewMemoryJournal(),
		StunObserve: obs.observe,
	})
	request := gatewayAcquireRequest("forward-stun-2")
	request.StunServer = "stun+tcp://100.64.0.1:3478"
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	if acquisition.StunObserveError == nil {
		t.Fatal("a failed observation must be recorded on the acquisition")
	}
	if len(acquisition.Layers) != 1 || acquisition.Layers[0].Kind != LayerKindGateway {
		t.Fatalf("layers = %+v, want the gateway evidence standing alone", acquisition.Layers)
	}
}

// MS3: without a same-tuple dialer the observer receives no dial — an
// honest observer refuses, the failure is recorded, and no misattributed
// STUN layer is appended.
func TestManagerStunWithoutSameTupleDialerCannotObserve(t *testing.T) {
	observed := netip.MustParseAddrPort("100.64.0.2:51234")
	obs := &recordingObserver{result: observed, err: errors.New("no same-tuple dialer")}
	mapper := gatewayMapperFixture()
	manager := NewManager(ManagerOptions{
		RouteTable:  managerRouteTable(),
		Listeners:   &fakeListenerSource{}, // no DialFrom capability
		Mappers:     map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:     NewMemoryJournal(),
		StunObserve: obs.observe,
	})
	request := gatewayAcquireRequest("forward-stun-3")
	request.StunServer = "stun+tcp://100.64.0.1:3478"
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	if dial := obs.lastRequest().Dial; dial != nil {
		t.Fatal("a source without the same-tuple capability must pass no dial")
	}
	if acquisition.StunObserveError == nil {
		t.Fatal("the refused observation must be recorded")
	}
	if len(acquisition.Layers) != 1 {
		t.Fatalf("layers = %+v, want no STUN layer", acquisition.Layers)
	}
}

// MS4: an unparseable stun+tcp:// endpoint is an operator data error that
// fails the acquisition — it must never silently downgrade the composition
// to gateway-only evidence.
func TestManagerStunBadServerIsOperatorError(t *testing.T) {
	mapper := gatewayMapperFixture()
	listeners := &fakeDialSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
	})
	request := gatewayAcquireRequest("forward-stun-4")
	request.StunServer = "http://not-a-stun-server"
	if _, err := manager.Acquire(t.Context(), request); err == nil {
		t.Fatal("an unparseable STUN endpoint must fail the acquisition")
	}
	if mapper.deleteCount() != 0 {
		t.Fatal("the parse check must run before any mapping side effect")
	}
}

// MS5: a configured server with no observer wired is recorded, not
// silently dropped (a build without the stun wiring must say so).
func TestManagerStunWithoutObserverRecorded(t *testing.T) {
	mapper := gatewayMapperFixture()
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeDialSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
	})
	request := gatewayAcquireRequest("forward-stun-5")
	request.StunServer = "stun+tcp://100.64.0.1:3478"
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	if acquisition.StunObserveError == nil {
		t.Fatal("a configured server with no observer must be recorded as an observation error")
	}
	if len(acquisition.Layers) != 1 {
		t.Fatalf("layers = %+v, want gateway-only evidence", acquisition.Layers)
	}
}
