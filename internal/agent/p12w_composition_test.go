// P12W Stories 2/3 composition tests: the composed data plane acquires a TCP
// explicit-gateway forward through the traversal.Manager, the acquisition
// carries the durable journal reference, the mechanism's honest ownership and
// a same-tuple STUN layer, and hot updates preserve the SAME acquisition while
// a strategy change fails closed.
package agent

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// p12wRouteTable is a scripted private-source route table (the normal shape
// behind a NAT CPE).
type p12wRouteTable struct{}

func (p12wRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("10.0.0.1"), "lan0", true, nil
}

func (p12wRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}}, nil
}

// p12wMapper is a scripted PCP gateway mapper.
type p12wMapper struct {
	mechanism traversal.MappingLayerKind
	ownership traversal.OwnershipStrength
	control   traversal.ControlServer
	external  netip.AddrPort
	lease     time.Duration

	mu      sync.Mutex
	deletes int
}

func (m *p12wMapper) Mechanism() traversal.MappingLayerKind  { return m.mechanism }
func (m *p12wMapper) Ownership() traversal.OwnershipStrength { return m.ownership }
func (m *p12wMapper) Capability() traversal.PortControlCapability {
	return traversal.PortControlCapabilityFor(m.mechanism, false)
}
func (m *p12wMapper) Discover(context.Context) (traversal.ControlServer, error) {
	return m.control, nil
}
func (m *p12wMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	return traversal.GatewayMapping{
		Mechanism:    m.mechanism,
		Ownership:    m.ownership,
		InternalIP:   req.InternalIP,
		InternalPort: req.InternalPort,
		External:     m.external,
		Lease:        m.lease,
		State:        "fake-state",
	}, nil
}
func (m *p12wMapper) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	mapping.Lease = lifetime
	return mapping, nil
}
func (m *p12wMapper) Delete(context.Context, traversal.GatewayMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	return nil
}

func (m *p12wMapper) deleteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deletes
}

// p12wListenerSource is a scripted ListenerSource that reports the requested
// tuple but binds a real loopback listener so no private source address must
// exist on the test host.
type p12wListenerSource struct {
	mu       sync.Mutex
	acquired []traversal.TupleKey
	released int
}

func (s *p12wListenerSource) Acquire(ctx context.Context, owner string, key traversal.TupleKey) (net.Listener, traversal.TupleKey, traversal.ReleaseFunc, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, traversal.TupleKey{}, nil, err
	}
	actual := key
	actual.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	s.mu.Lock()
	s.acquired = append(s.acquired, actual)
	s.mu.Unlock()
	return listener, actual, func() error {
		s.mu.Lock()
		s.released++
		s.mu.Unlock()
		return listener.Close()
	}, nil
}

// p12wBlockerMapper is a gateway mapper whose Map blocks until released. It is
// the probe for repair R1 finding 1: while an apply is acquiring through the
// manager, the global dataPlane.mu must be FREE (the acquisition is external
// network RPC and must not serialize every concurrent forward op).
type p12wBlockerMapper struct {
	p12wMapper
	mu      sync.Mutex
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (m *p12wBlockerMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	m.once.Do(func() { close(m.entered) })
	<-m.release
	return m.p12wMapper.Map(ctx, req)
}

// p12wObserver is a scripted same-tuple STUN observer returning a fixed
// endpoint without dialing.
type p12wObserver struct {
	mu     sync.Mutex
	result netip.AddrPort
	reqs   int
}

func (o *p12wObserver) observe(ctx context.Context, req traversal.StunObserveRequest) (netip.AddrPort, error) {
	o.mu.Lock()
	o.reqs++
	o.mu.Unlock()
	return o.result, nil
}

func (o *p12wObserver) callCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.reqs
}

// p12wGatewayComposition builds a data plane wired exactly like the composed
// app for gateway routes: the shared-port gateway manager + the same manager
// observer + a cached detection profile resolving explicit-gateway to PCP.
func p12wGatewayComposition(t *testing.T) (*dataPlane, *p12wMapper, *p12wObserver, *traversal.MemoryJournal) {
	t.Helper()
	return p12wGatewayCompositionWithObserver(t, netip.MustParseAddrPort("100.64.0.2:51234"))
}

func p12wGatewayCompositionWithObserver(t *testing.T, observed netip.AddrPort) (*dataPlane, *p12wMapper, *p12wObserver, *traversal.MemoryJournal) {
	t.Helper()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mapper := &p12wMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
		lease:     time.Hour,
	}
	obs := &p12wObserver{result: observed}
	journal := traversal.NewMemoryJournal()
	listeners := &p12wListenerSource{}
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable:  p12wRouteTable{},
		Listeners:   listeners,
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
		Fingerprint:     fp,
		Protocol:        traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyExplicitGateway,
		ComputedAtUnix:  time.Now().Unix(),
		Results: []traversal.StrategyResult{
			{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	d := newDataPlane(dataPlaneConfig{
		Store:          st,
		RouteTable:     p12wRouteTable{},
		Clock:          time.Now,
		GatewayManager: manager,
		Journal:        journal,
		StunServers:    []string{"stun+tcp://100.64.0.1:3478"},
		ProfileStore:   profiles,
		StunObserver:   obs.observe,
		StunSource:     &p12wSameTupleSource{},
	})
	// The gateway route resolves its own (private) source inside the manager;
	// the data plane's capability gate is the Story 6 "route table usable +
	// fingerprint known" assessment (a private-source node stays capable).
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })
	return d, mapper, obs, journal
}

// Story 2 RED: a non-nil Manager on the data plane applies a TCP
// explicit-gateway forward. The acquisition carries a journal reference, a
// Mapping with the mechanism's Ownership and a same-tuple STUN layer when a
// STUN server is configured. (Before GREEN, apply rejected every non-direct
// strategy and dataPlaneConfig had no Manager field.)
func TestDataPlaneAppliesExplicitGatewayThroughManager(t *testing.T) {
	d, mapper, obs, journal := p12wGatewayComposition(t)

	spec := protocol.ForwardSpec{
		ForwardID:       "fwd-gateway",
		Name:            "gateway",
		Protocol:        protocol.ProtocolTCP,
		Target:          "127.0.0.1:9",
		Strategy:        protocol.StrategyExplicitGateway,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	applied, err := d.apply(context.Background(), spec)
	if err != nil {
		t.Fatalf("apply explicit-gateway: %v", err)
	}
	if applied.ForwardID != spec.ForwardID || applied.Strategy != "explicit-gateway" {
		t.Fatalf("applied = %+v", applied)
	}

	d.mu.Lock()
	actor := d.forwards[spec.ForwardID]
	d.mu.Unlock()
	if actor == nil {
		t.Fatal("no actor for the gateway forward")
	}
	if actor.acq == nil {
		t.Fatal("gateway actor must expose its acquisition")
	}
	if actor.acq.JournalID == "" {
		t.Fatal("acquisition must reference its journal record")
	}
	if _, ok, err := journal.Get(actor.acq.JournalID); err != nil || !ok {
		t.Fatalf("journal record for %q ok=%v err=%v", actor.acq.JournalID, ok, err)
	}
	mapping := actor.acq.CurrentMapping()
	if mapping == nil {
		t.Fatal("acquisition must carry a live gateway mapping")
	}
	if mapping.Ownership != traversal.OwnershipStrong {
		t.Fatalf("mapping ownership = %q, want STRONG_PROTOCOL_OWNERSHIP", mapping.Ownership)
	}
	if mapping.Mechanism != traversal.LayerPCP {
		t.Fatalf("mapping mechanism = %q, want pcp", mapping.Mechanism)
	}
	if len(actor.acq.Layers) != 2 {
		t.Fatalf("layers = %+v, want gateway + same-tuple STUN", actor.acq.Layers)
	}
	stunLayer := actor.acq.Layers[1]
	if stunLayer.Kind != traversal.LayerKindSTUN || stunLayer.ParentLayer != 0 {
		t.Fatalf("stun layer = %+v, want a child of the gateway layer", stunLayer)
	}
	if stunLayer.AssignedEndpoint != obs.result.String() {
		t.Fatalf("stun endpoint = %s, want the observed endpoint", stunLayer.AssignedEndpoint)
	}
	// The gateway manager's STUN seam received the forward's own tuple.
	if actor.acq.Layers[1].InternalEndpoint != netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), actor.acq.Bind.Port).String() {
		t.Fatalf("stun internal endpoint = %s", actor.acq.Layers[1].InternalEndpoint)
	}
	if mapper.deleteCount() != 0 {
		t.Fatalf("unexpected delete before release: %d", mapper.deleteCount())
	}
}

// Story 2 (regression): a direct-v4 TCP forward still follows the
// byte-identical inline PortRegistry path when no Manager is wired.
func TestDataPlaneDirectStillWorksWithoutManager(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })

	d := newDataPlane(dataPlaneConfig{Clock: time.Now})
	spec := protocol.ForwardSpec{
		ForwardID: "direct-plain", Protocol: protocol.ProtocolTCP, Target: target.Addr().String(),
		Strategy: protocol.StrategyDirectV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	actor, err := d.newForwardActor(context.Background(), spec, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("direct actor: %v", err)
	}
	if actor.acq != nil {
		t.Fatal("direct forward must not carry a manager acquisition")
	}
	if _, ok := actor.lease.(registryLease); !ok {
		t.Fatalf("direct lease = %T, want a registry lease", actor.lease)
	}
	if err := d.closeAll(context.Background()); err != nil {
		t.Fatalf("closeAll: %v", err)
	}
}

// p12wLoopbackRouteTable is a route table whose temp tuples fall back to
// loopback (DefaultRouteSource rejects loopback, so the Detector's tempSource
// returns 127.0.0.1 which binds on any host).
type p12wLoopbackRouteTable struct{}

func (p12wLoopbackRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("127.0.0.1"), "lo", true, nil
}

func (p12wLoopbackRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr("127.0.0.1")}}, nil
}

// Story 5 (a): a TCP auto forward resolves through the cached detection
// profile's PASSED default strategy and routes to the concrete gateway
// acquisition.
func TestDataPlaneAutoResolvesGatewayFromProfile(t *testing.T) {
	d, _, _, journal := p12wGatewayComposition(t)
	spec := protocol.ForwardSpec{
		ForwardID:       "fwd-auto-gateway",
		Protocol:        protocol.ProtocolTCP,
		Target:          "127.0.0.1:9",
		Strategy:        protocol.StrategyAuto,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	applied, err := d.apply(context.Background(), spec)
	if err != nil {
		t.Fatalf("auto apply: %v", err)
	}
	// The operator's durable choice stays "auto"; the live actor resolves to
	// the concrete gateway strategy.
	if applied.Strategy != "auto" {
		t.Fatalf("applied strategy = %q, want the operator's auto", applied.Strategy)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-auto-gateway"]
	d.mu.Unlock()
	if actor == nil || actor.acq == nil {
		t.Fatal("auto forward must acquire through the gateway manager")
	}
	if actor.strategy != protocol.StrategyExplicitGateway {
		t.Fatalf("auto resolved strategy = %q, want explicit-gateway", actor.strategy)
	}
	if actor.acq.JournalID == "" {
		t.Fatal("auto gateway acquisition must journal")
	}
	if records, _ := journal.ListByForward("fwd-auto-gateway"); len(records) != 1 {
		t.Fatalf("auto gateway journal records = %d, want 1", len(records))
	}
}

// Story 5 (b): a stale detection profile (fingerprint mismatch) fails an auto
// forward rather than silently reusing old capability.
func TestDataPlaneAutoRejectsStaleProfile(t *testing.T) {
	d, _, _, _ := p12wGatewayComposition(t)
	profile, ok, err := d.cfg.ProfileStore.Load()
	if err != nil || !ok {
		t.Fatalf("profile load ok=%v err=%v", ok, err)
	}
	profile.Fingerprint = "stale-fingerprint"
	if err := d.cfg.ProfileStore.Save(profile); err != nil {
		t.Fatal(err)
	}
	spec := protocol.ForwardSpec{
		ForwardID:       "fwd-auto-stale",
		Protocol:        protocol.ProtocolTCP,
		Target:          "127.0.0.1:9",
		Strategy:        protocol.StrategyAuto,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	if _, err := d.apply(context.Background(), spec); err == nil {
		t.Fatal("stale-profile auto apply must fail closed")
	}
}

// Story 5 (c): UDP auto resolves to direct-v4 (UDP detection is deferred to
// P13; the UDP path stays on the direct registry).
func TestDataPlaneAutoUDPResolvesDirect(t *testing.T) {
	// Repair R1 finding 2 restored the pre-P12W contract: the UDP apply path
	// resolves traversal.Assess and binds the SELECTED global source, so a
	// private-source-only node cannot complete a UDP apply (exactly as before
	// P12W). On hosts with a global source the full apply path runs; elsewhere
	// the strategy-level assertion is skipped.
	routeTable := traversal.HostRouteTable{}
	if _, capability, err := traversal.Assess(routeTable); err != nil || capability != traversal.CapabilityDirectV4Ready {
		t.Skipf("no global direct-v4 source for a UDP apply: %v (%s)", err, capability)
	}
	d := newDataPlane(dataPlaneConfig{RouteTable: routeTable, Clock: time.Now})
	spec := protocol.ForwardSpec{
		ForwardID:       "fwd-auto-udp",
		Protocol:        protocol.ProtocolUDP,
		Target:          "127.0.0.1:9",
		Strategy:        protocol.StrategyAuto,
		DesiredRevision: 1,
		Presence:        protocol.PresencePresent,
	}
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("UDP auto apply: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards["fwd-auto-udp"]
	d.mu.Unlock()
	if actor == nil {
		t.Fatal("UDP auto actor missing")
	}
	if actor.strategy != protocol.StrategyDirectV4 || actor.acq != nil {
		t.Fatalf("UDP auto actor = strategy %q acq %v, want direct/v4 and no acquisition",
			actor.strategy, actor.acq != nil)
	}
}

// Story 5 (d): the one-shot detection job runs the Detector and durably saves
// the profile (which is then fresh for auto resolution).
func TestDataPlaneRunDetectionSavesProfile(t *testing.T) {
	mapper := &p12wMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "127.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
		lease:     time.Hour,
	}
	fakeObserve := func(ctx context.Context, server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("100.64.0.2:51234"), nil
	}
	detector := traversal.NewDetector(traversal.DetectorOptions{
		RouteTable:  p12wLoopbackRouteTable{},
		Mappers:     map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: mapper},
		Registry:    traversal.NewPortRegistry(),
		AutoOrder:   []protocol.Strategy{protocol.StrategyExplicitGateway, protocol.StrategyDirectV4, protocol.StrategyStunOnly},
		StunServers: []string{"stun+tcp://100.64.0.1:3478"},
		StunObserve: fakeObserve,
	})
	profiles := newProfileStore(t.TempDir())
	d := newDataPlane(dataPlaneConfig{Clock: time.Now, Detector: detector, ProfileStore: profiles})
	if err := d.runDetection(context.Background()); err != nil {
		t.Fatalf("runDetection: %v", err)
	}
	profile, ok, err := profiles.Load()
	if err != nil || !ok {
		t.Fatalf("saved profile ok=%v err=%v", ok, err)
	}
	if profile.DefaultStrategy != protocol.StrategyExplicitGateway {
		t.Fatalf("saved default = %q, want explicit-gateway (pcp passed)", profile.DefaultStrategy)
	}
	if result, ok := profile.ResultFor(protocol.StrategyExplicitGateway); !ok || result.State != traversal.DetectionPassed {
		t.Fatalf("explicit-gateway result = %+v ok=%v, want PASSED", result, ok)
	}
}

// Story 6 (RED): on a NAT-CPE route table (private source) capabilityCheck
// must NOT report capability lost, and a gateway forward must apply without
// any manual capability override.
func TestCapabilityCheckAllowsPrivateSourceGateway(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	mapper := &p12wMapper{
		mechanism: traversal.LayerPCP,
		ownership: traversal.OwnershipStrong,
		control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
		lease:     time.Hour,
	}
	obs := &p12wObserver{result: netip.MustParseAddrPort("100.64.0.2:51234")}
	journal := traversal.NewMemoryJournal()
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

	d := newDataPlane(dataPlaneConfig{
		Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now,
		GatewayManager: manager, Journal: journal,
		StunServers: []string{"stun+tcp://100.64.0.1:3478"}, ProfileStore: profiles,
	})
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })
	// newDataPlane assessed the private route: readiness must be true without
	// any manual override.
	if !d.capabilityReady {
		t.Fatal("private-source node must be capability-ready for gateway strategies")
	}
	if err := d.capabilityCheck(); err != nil {
		t.Fatalf("capabilityCheck on private source = %v, want nil", err)
	}
	spec := protocol.ForwardSpec{
		ForwardID: "fwd-private-gateway", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("gateway forward on a private-source node must apply: %v", err)
	}
}

// Story 6: monitorLiveness keys teardown on a fingerprint change and rebuilds
// the adapters/Managers on restore so a forward re-maps onto the changed
// gateway.
func TestMonitorLivenessRebuildsManagersOnFingerprintRestore(t *testing.T) {
	routes := &mutableRouteTable{
		gateway:    netip.MustParseAddr("10.0.0.1"),
		iface:      "lan0",
		hasDefault: true,
		addrs:      []traversal.IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}},
	}
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	profiles := newProfileStore(t.TempDir())
	d := newDataPlane(dataPlaneConfig{Store: st, RouteTable: routes, Clock: time.Now, ProfileStore: profiles})
	oldPlain, oldGateway := d.cfg.PlainManager, d.cfg.GatewayManager
	a := &App{
		cfg:         Config{RouteTable: routes, LivenessInterval: 5 * time.Millisecond},
		store:       st,
		dp:          d,
		activations: make(map[string]*reconcile.Activation),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.monitorLiveness(ctx)

	// A fingerprint change tears the capability down and, on the next poll,
	// restores it by REBUILDING the adapters+Managers over the changed route.
	routes.mu.Lock()
	routes.gateway = netip.MustParseAddr("10.0.0.254")
	routes.mu.Unlock()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		rebuiltGW := d.cfg.GatewayManager
		rebuiltPlain := d.cfg.PlainManager
		ready := d.capabilityReady
		d.mu.Unlock()
		if rebuiltGW != oldGateway && rebuiltPlain != nil && rebuiltPlain != oldPlain && ready {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("fingerprint restore did not rebuild the traversal managers")
}

// p12wGlobalRouteTable is a route table whose default-route interface carries a
// global V4 source that Assess accepts but no test host owns (8.8.8.8). It is
// the probe for the UDP bind-host repair: resolving the source and requesting
// AcquireUDP on it must fail with a non-local bind, whereas the pre-repair
// wildcard fallback silently binds 0.0.0.0.
type p12wGlobalRouteTable struct{}

func (p12wGlobalRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("8.8.8.9"), "wan0", true, nil
}

func (p12wGlobalRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return []traversal.IPv4Address{{Interface: "wan0", Addr: netip.MustParseAddr("8.8.8.8")}}, nil
}

// Repair R1 finding 1: apply must NOT hold the global dataPlane.mu across the
// gateway Manager.Acquire (mapper Discover/Map + same-tuple STUN are external
// network RPC). A blocker mapper whose Map blocks is the probe: while an apply
// is mid-acquisition, another goroutine must be free to take d.mu (pre-repair
// the whole apply ran under d.mu, so the lock probe would block until the
// acquisition finished).
func TestDataPlaneApplyDoesNotHoldLockDuringGatewayAcquire(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blocker := &p12wBlockerMapper{
		p12wMapper: p12wMapper{
			mechanism: traversal.LayerPCP,
			ownership: traversal.OwnershipStrong,
			control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
			external:  netip.MustParseAddrPort("100.64.0.2:43111"),
			lease:     time.Hour,
		},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	obs := &p12wObserver{result: netip.MustParseAddrPort("100.64.0.2:51234")}
	journal := traversal.NewMemoryJournal()
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable:  p12wRouteTable{},
		Listeners:   &p12wListenerSource{},
		Mappers:     map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: blocker},
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

	d := newDataPlane(dataPlaneConfig{
		Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now,
		GatewayManager: manager, Journal: journal,
		StunServers: []string{"stun+tcp://100.64.0.1:3478"}, ProfileStore: profiles,
	})
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-lock-probe", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	applied := make(chan error, 1)
	go func() {
		_, err := d.apply(context.Background(), spec)
		applied <- err
	}()

	select {
	case <-blocker.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply never reached the gateway Map call")
	}
	// While the acquisition is blocked in Map, the data-plane lock must be free.
	locked := make(chan struct{})
	go func() {
		d.mu.Lock()
		close(locked)
		d.mu.Unlock()
	}()
	select {
	case <-locked:
		// GOOD: d.mu is not held across the gateway acquisition.
	case <-time.After(2 * time.Second):
		close(blocker.release)
		<-applied
		t.Fatal("dataPlane.mu is held across the gateway manager acquisition")
	}
	close(blocker.release)
	if err := <-applied; err != nil {
		t.Fatalf("apply: %v", err)
	}
}

// Repair R1 finding 2: the UDP branch must resolve traversal.Assess and pass
// the SELECTED global source to AcquireUDP (the pre-P12W "UDP path untouched"
// behavior), never fall back to the wildcard 0.0.0.0. A global source that no
// host interface owns is the probe: the resolved-source path fails the bind;
// the buggy wildcard path binds 0.0.0.0 and silently succeeds.
func TestDataPlaneUDPBindsSelectedGlobalSourceNotWildcard(t *testing.T) {
	sel, capability, err := traversal.Assess(p12wGlobalRouteTable{})
	if err != nil || capability != traversal.CapabilityDirectV4Ready {
		t.Fatalf("probe route table must assess direct-v4 ready: %v (%s)", err, capability)
	}
	d := newDataPlane(dataPlaneConfig{RouteTable: p12wGlobalRouteTable{}, Clock: time.Now})
	spec := protocol.ForwardSpec{
		ForwardID: "udp-bind-source", Protocol: protocol.ProtocolUDP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyDirectV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	// The apply/reopen UDP path passes an EMPTY address so the actor resolves
	// the selected global source itself.
	actor, err := d.newForwardActor(context.Background(), spec, "", 0)
	if actor != nil {
		// Best-effort cleanup for the pre-repair wildcard fallback.
		defer func() { _ = actor.fwd.CloseContext(context.Background()) }()
	}
	if err == nil {
		t.Fatalf("UDP actor bound %s (wildcard fallback); want the selected global source %s to be requested and rejected as non-local",
			actor.lease.Tuple().Address, sel.Source)
	}
}

// Repair R1 finding 2 (positive): on a host with a real global direct-v4
// source, the UDP listener must bind that selected source, not the wildcard.
// Skipped where no global source exists (no bindable address to pin).
// Repair R1 finding 7: a manual-static forward has no renewal loop (nothing
// to observe), so its activation must not claim keepalive_state HEALTHY.
// The truthful axis is NOT_REQUIRED, matching direct/UDP forwards.
func TestDataPlaneManualStaticKeepaliveStateNotRequired(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	plain := traversal.NewManager(traversal.ManagerOptions{
		RouteTable: p12wRouteTable{},
		Listeners:  traversal.PortRegistrySource{Registry: traversal.NewPortRegistry()},
	})
	d := newDataPlane(dataPlaneConfig{
		Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now, PlainManager: plain,
	})
	a := &App{store: st, dp: d, activations: make(map[string]*reconcile.Activation)}
	d.cfg.OnApplied = a.onForwardApplied
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-manual-live", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyManualStaticV4, ManualExpectedEndpoint: "203.0.113.7:443",
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("manual-static apply: %v", err)
	}
	snap := a.ActivationSnapshot("fwd-manual-live")
	if snap == nil {
		t.Fatal("no activation recorded for the manual-static forward")
	}
	if snap.KeepaliveState != "NOT_REQUIRED" {
		t.Fatalf("manual-static keepalive_state = %q, want NOT_REQUIRED (no renewal loop)", snap.KeepaliveState)
	}
	if snap.DataPlaneState != "READY" {
		t.Fatalf("manual-static data_plane_state = %q, want READY", snap.DataPlaneState)
	}
}

func TestDataPlaneStunOnlyActivationReflectsLiveCandidate(t *testing.T) {
	d, _, _, _ := p12wGatewayCompositionWithObserver(t, netip.MustParseAddrPort("8.8.8.8:51234"))
	a := &App{store: d.cfg.Store, dp: d, activations: make(map[string]*reconcile.Activation)}
	d.cfg.OnApplied = a.onForwardApplied

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-stun-only-live", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyStunOnly, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	applied, err := d.apply(context.Background(), spec)
	if err != nil {
		t.Fatalf("stun-only apply: %v", err)
	}
	if applied.PublicPort != 51234 {
		t.Fatalf("public_port = %d, want observed candidate port 51234", applied.PublicPort)
	}
	snap := a.ActivationSnapshot(spec.ForwardID)
	if snap == nil {
		t.Fatal("no activation recorded for stun-only forward")
	}
	if snap.ListenerState != "READY" || snap.DataPlaneState != "READY" {
		t.Fatalf("live axes = listener %q data-plane %q, want READY/READY", snap.ListenerState, snap.DataPlaneState)
	}
	if snap.MappingState != "PUBLIC_CANDIDATE" {
		t.Fatalf("mapping_state = %q, want PUBLIC_CANDIDATE", snap.MappingState)
	}
	if snap.KeepaliveState != "NOT_REQUIRED" {
		t.Fatalf("keepalive_state = %q, want NOT_REQUIRED", snap.KeepaliveState)
	}
}

func TestDataPlaneUDPApplyBindsSelectedSource(t *testing.T) {
	routeTable := traversal.HostRouteTable{}
	sel, capability, err := traversal.Assess(routeTable)
	if err != nil || capability != traversal.CapabilityDirectV4Ready {
		t.Skipf("no global direct-v4 source to bind: %v (%s)", err, capability)
	}
	d := newDataPlane(dataPlaneConfig{RouteTable: routeTable, Clock: time.Now})
	d.capabilityReady = true
	spec := protocol.ForwardSpec{
		ForwardID: "udp-bind-host", Protocol: protocol.ProtocolUDP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyDirectV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	actor, err := d.newForwardActor(context.Background(), spec, "", 0)
	if err != nil {
		t.Fatalf("UDP apply on a global-source host: %v", err)
	}
	defer func() { _ = d.closeAll(context.Background()) }()
	if got := actor.lease.Tuple().Address; got != sel.Source.String() {
		t.Fatalf("UDP bind host = %s, want the selected global source %s", got, sel.Source)
	}
}
