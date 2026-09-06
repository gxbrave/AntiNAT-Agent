package traversal

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Story 7 RED/2: the manager composes one Forward's TCP traversal
// acquisition with ownership-strength release and the §3.5 renewal
// contract: renew near 50% of the GRANTED lease with jitter, three
// consecutive failures degrade (DEGRADED), the expiry safety margin, a
// confirmed gateway reboot or a rewritten external endpoint loses, the
// journal carries the mechanism-private renewal state, and Release is
// idempotent while never destroying the only record of a mapping it could
// not delete.

// fakeListenerSource is a scripted ListenerSource.
type fakeListenerSource struct {
	mu        sync.Mutex
	acquired  []TupleKey
	released  int
	acquireFn func(key TupleKey) (net.Listener, TupleKey, error)
}

func (f *fakeListenerSource) Acquire(ctx context.Context, owner string, key TupleKey) (net.Listener, TupleKey, ReleaseFunc, error) {
	f.mu.Lock()
	f.acquired = append(f.acquired, key)
	f.mu.Unlock()
	if f.acquireFn != nil {
		listener, actual, err := f.acquireFn(key)
		if err != nil {
			return nil, TupleKey{}, nil, err
		}
		return listener, actual, func() error {
			f.mu.Lock()
			f.released++
			f.mu.Unlock()
			return listener.Close()
		}, nil
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, TupleKey{}, nil, err
	}
	return listener, TupleKey{Family: "ipv4", Protocol: "tcp", Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, func() error {
		f.mu.Lock()
		f.released++
		f.mu.Unlock()
		return listener.Close()
	}, nil
}

func (f *fakeListenerSource) releaseCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released
}

func (f *fakeListenerSource) acquiredKeys() []TupleKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]TupleKey(nil), f.acquired...)
}

// scriptedMapper records renew/delete activity and scripts the §3.5 ladder
// outcomes: renewal failures, a confirmed reboot, a rewritten external
// endpoint and a granted-shorter-than-requested lease.
type scriptedMapper struct {
	fakeMapper
	mu                   sync.Mutex
	renewals             int
	deletes              int
	renewErr             error
	renewPanic           any
	deleteErr            error
	deletePanic          any
	discoverPanic        any
	mapPanic             any
	statePanic           any
	rebootAfter          int // renewal ordinal (1-based) reporting ServerRebooted; 0 = never
	oscillatePeriod      int // failures/successes alternate every N renewals; 0 = steady
	rewriteExternalAfter int // renewal ordinal rewriting the external endpoint; 0 = never
	rewrittenExternal    netip.AddrPort
	grantedLease         time.Duration // granted lease overriding the request; 0 = grant the request
}

// panickingState serializes by panicking: the manager must contain it as an
// advisory journal error (S7k audit).
type panickingState struct{}

func (panickingState) MarshalJSON() ([]byte, error) { panic("state marshal panic") }

// Discover shadows the embedded fake mapper for panic scripting.
func (s *scriptedMapper) Discover(ctx context.Context) (ControlServer, error) {
	if s.discoverPanic != nil {
		panic(s.discoverPanic)
	}
	return s.fakeMapper.Discover(ctx)
}

// Map shadows the embedded fake mapper to apply the scripted grant.
func (s *scriptedMapper) Map(ctx context.Context, req GatewayMapRequest) (GatewayMapping, error) {
	if s.mapPanic != nil {
		panic(s.mapPanic)
	}
	mapping, err := s.fakeMapper.Map(ctx, req)
	if err != nil {
		return mapping, err
	}
	if s.statePanic != nil {
		mapping.State = panickingState{}
	}
	if s.grantedLease > 0 {
		mapping.Lease = s.grantedLease
	}
	return mapping, nil
}

func (s *scriptedMapper) Renew(ctx context.Context, mapping GatewayMapping, lifetime time.Duration) (GatewayMapping, error) {
	s.mu.Lock()
	s.renewals++
	renewals := s.renewals
	renewErr, renewPanic, rebootAfter, rewriteAfter, granted := s.renewErr, s.renewPanic, s.rebootAfter, s.rewriteExternalAfter, s.grantedLease
	s.mu.Unlock()
	failing := false
	if renewErr != nil || renewPanic != nil {
		// With an oscillation period the scripted failure alternates: odd
		// windows fail, even windows succeed (degrade/recover cycles).
		failing = !(s.oscillatePeriod > 0 && (renewals/s.oscillatePeriod)%2 == 0)
	}
	if failing && renewPanic != nil {
		panic(renewPanic)
	}
	if failing {
		return GatewayMapping{}, renewErr
	}
	mapping.Lease = lifetime
	if granted > 0 {
		mapping.Lease = granted
	}
	if rebootAfter > 0 && renewals >= rebootAfter {
		mapping.ServerRebooted = true
	}
	if rewriteAfter > 0 && renewals >= rewriteAfter {
		mapping.External = s.rewrittenExternal
	}
	return mapping, nil
}

func (s *scriptedMapper) Delete(ctx context.Context, mapping GatewayMapping) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	if s.deletePanic != nil {
		panic(s.deletePanic)
	}
	return s.deleteErr
}

func (s *scriptedMapper) renewalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewals
}

func (s *scriptedMapper) deleteCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deletes
}

func (s *scriptedMapper) setRenewErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewErr = err
}

// failingJournal fails every Put (durable-store IO error) and scripts panic
// and Get faults. Panic flags are guarded so tests can arm them while the
// renewal goroutine is live.
type failingJournal struct {
	*MemoryJournal
	mu                 sync.Mutex
	putErr             error
	putPanic           any
	putPanicAfterWrite any
	getPanic           any
	deletePanic        any
}

func (f *failingJournal) Put(record JournalRecord) error {
	f.mu.Lock()
	putErr, putPanic, putPanicAfterWrite := f.putErr, f.putPanic, f.putPanicAfterWrite
	f.mu.Unlock()
	if putPanic != nil {
		panic(putPanic)
	}
	if putErr != nil {
		return putErr
	}
	if err := f.MemoryJournal.Put(record); err != nil {
		return err
	}
	if putPanicAfterWrite != nil {
		panic(putPanicAfterWrite)
	}
	return nil
}

func (f *failingJournal) Get(id string) (JournalRecord, bool, error) {
	f.mu.Lock()
	getPanic := f.getPanic
	f.mu.Unlock()
	if getPanic != nil {
		panic(getPanic)
	}
	return f.MemoryJournal.Get(id)
}

func (f *failingJournal) Delete(id string) error {
	f.mu.Lock()
	deletePanic := f.deletePanic
	f.mu.Unlock()
	if deletePanic != nil {
		panic(deletePanic)
	}
	return f.MemoryJournal.Delete(id)
}

func (f *failingJournal) armPutPanic(value any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putPanic = value
}

func (f *failingJournal) armGetPanic(value any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getPanic = value
}

// stepClock advances a fixed step on every read: journal timestamps and
// lease deadlines become observable without real-time waits.
type stepClock struct {
	mu   sync.Mutex
	cur  time.Time
	step time.Duration
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cur = c.cur.Add(c.step)
	return c.cur
}

// managerRouteTable is the scripted route table (in-package helper): the
// default-route interface holds the PRIVATE address 10.0.0.2 — the normal
// shape behind a NAT CPE.
type managerRouteTableImpl struct {
	addresses []IPv4Address
}

func (m managerRouteTableImpl) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.MustParseAddr("10.0.0.1"), "lan0", true, nil
}

func (m managerRouteTableImpl) IPv4Addresses() ([]IPv4Address, error) {
	return m.addresses, nil
}

func managerRouteTable() managerRouteTableImpl {
	return managerRouteTableImpl{
		addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("10.0.0.2")}},
	}
}

// gatewayMapperFixture is the scripted PCP mapper every acquisition test
// starts from.
func gatewayMapperFixture() *scriptedMapper {
	return &scriptedMapper{fakeMapper: fakeMapper{
		mechanism: LayerPCP,
		ownership: OwnershipStrong,
		control:   ControlServer{Mechanism: LayerPCP, Address: "10.0.0.1:5351"},
		external:  netip.MustParseAddrPort("100.64.0.2:43111"),
	}}
}

func gatewayAcquireRequest(forwardID string) AcquireRequest {
	return AcquireRequest{
		ForwardID: forwardID,
		Owner:     forwardID,
		Spec: protocol.ForwardSpec{
			ForwardID: forwardID, Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyExplicitGateway,
		},
		Plan: PlanRequest{
			Strategy:     protocol.StrategyExplicitGateway,
			MappingLayer: LayerPCP,
		},
	}
}

// withPacing injects the fast test renewal interval through the request.
func withPacing(request AcquireRequest, interval time.Duration) AcquireRequest {
	request.RenewalInterval = interval
	request.RenewalJitterMax = time.Millisecond
	return request
}

// MA1: acquiring with an explicit-gateway plan composes the mapping layer,
// binds the default-route interface's own (private) address — never the
// 127.0.0.1 fallback — journals the record with honest ownership, the
// serialized renewal state, and yields the FIRST_HOP verdict for a
// non-global assignment.
func TestManagerAcquireExplicitGateway(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := NewMemoryJournal()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})

	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-1"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	keys := listeners.acquiredKeys()
	if len(keys) != 1 || keys[0].Address != "10.0.0.2" {
		t.Fatalf("listener keys = %+v, want the private default-route source 10.0.0.2", keys)
	}
	if acquisition.Mapping == nil || acquisition.Mapping.Mechanism != LayerPCP {
		t.Fatalf("mapping = %+v", acquisition.Mapping)
	}
	if acquisition.Mapping.InternalIP.String() != "10.0.0.2" {
		t.Fatalf("mapping internal IP = %s, want 10.0.0.2", acquisition.Mapping.InternalIP)
	}
	if acquisition.Verdict.Scope != ScopeFirstHop || acquisition.Verdict.PublicCandidate {
		t.Fatalf("verdict = %+v, want FIRST_HOP and no public candidate", acquisition.Verdict)
	}
	records, err := journal.ListByForward("forward-1")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v", records, err)
	}
	if records[0].Ownership != OwnershipStrong || records[0].ExternalPort != 43111 {
		t.Fatalf("journal record = %+v", records[0])
	}
	if records[0].InternalIP != "10.0.0.2" {
		t.Fatalf("journal internal IP = %s, want 10.0.0.2", records[0].InternalIP)
	}
	// The mechanism-private renewal state is journaled: the fake mapper's
	// State "fake-state" must serialize to the quoted JSON string, so
	// recovery can renew or release after a restart.
	if string(records[0].State) != `"fake-state"` {
		t.Fatalf("journal state = %q, want the serialized ownership state", records[0].State)
	}
	if acquisition.JournalID != records[0].ID {
		t.Fatalf("journal ref = %q, want %q", acquisition.JournalID, records[0].ID)
	}
	if len(acquisition.Layers) != 1 || acquisition.Layers[0].Kind != LayerKindGateway {
		t.Fatalf("layers = %+v", acquisition.Layers)
	}
}

// MA2: release deletes the mapping per ownership and releases the listener;
// the journal record is removed.
func TestManagerRelease(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := NewMemoryJournal()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-2"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("deletes = %d, want 1", mapper.deleteCount())
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want 1", got)
	}
	if _, ok, _ := journal.Get(acquisition.JournalID); ok {
		t.Fatal("released mapping must leave the journal")
	}
}

// MA3: direct-v4 acquisition requires a global source and yields the
// GLOBAL_PUBLIC probe-eligible verdict; the manual strategy requires the
// operator endpoint.
func TestManagerDirectAndManualPlans(t *testing.T) {
	privateRoute := managerRouteTableImpl{
		addresses: []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("192.168.1.10")}},
	}
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: privateRoute,
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{},
		Journal:    NewMemoryJournal(),
	})
	_, err := manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "f-direct",
		Owner:     "f-direct",
		Spec: protocol.ForwardSpec{
			ForwardID: "f-direct", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyDirectV4,
		},
		Plan: PlanRequest{Strategy: protocol.StrategyDirectV4},
	})
	var capabilityErr *CapabilityError
	if !errors.As(err, &capabilityErr) || capabilityErr.Capability != CapabilityNoGlobalV4Source {
		t.Fatalf("error = %v, want NO_GLOBAL_V4_SOURCE capability error", err)
	}

	globalRoute := managerRouteTable()
	globalRoute.addresses = []IPv4Address{{Interface: "lan0", Addr: netip.MustParseAddr("8.8.8.8")}}
	// The direct listener must bind the global source; without the alias
	// the bind itself fails, which is an honest skip on unprivileged hosts.
	if os.Geteuid() != 0 {
		t.Skip("direct-v4 global bind requires the global literal alias; run with sudo -E")
	}
	if out, err := exec.Command("ip", "addr", "add", "8.8.8.8/32", "dev", "lo").CombinedOutput(); err != nil && !strings.Contains(string(out), "Address already assigned") {
		t.Fatalf("alias global literal: %v\n%s", err, out)
	}
	defer exec.Command("ip", "addr", "del", "8.8.8.8/32", "dev", "lo").Run() //nolint:errcheck
	globalManager := NewManager(ManagerOptions{
		RouteTable: globalRoute,
		Listeners: &fakeListenerSource{acquireFn: func(key TupleKey) (net.Listener, TupleKey, error) {
			listener, err := net.Listen("tcp4", "8.8.8.8:0")
			if err != nil {
				return nil, TupleKey{}, err
			}
			return listener, TupleKey{Family: "ipv4", Protocol: "tcp",
				Address: "8.8.8.8", Port: uint16(listener.Addr().(*net.TCPAddr).Port)}, nil
		}},
		Mappers: map[MappingLayerKind]GatewayMapper{},
		Journal: NewMemoryJournal(),
	})
	acquisition, err := globalManager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "f-direct2",
		Owner:     "f-direct2",
		Spec: protocol.ForwardSpec{
			ForwardID: "f-direct2", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyDirectV4,
		},
		Plan: PlanRequest{Strategy: protocol.StrategyDirectV4},
	})
	if err != nil {
		t.Fatalf("direct acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	if !acquisition.Verdict.PublicCandidate || acquisition.Verdict.Scope != ScopeGlobalPublic {
		t.Fatalf("verdict = %+v, want probe-eligible GLOBAL_PUBLIC", acquisition.Verdict)
	}

	// Manual without operator endpoint refuses.
	_, err = manager.Acquire(t.Context(), AcquireRequest{
		ForwardID: "f-manual",
		Owner:     "f-manual",
		Spec: protocol.ForwardSpec{
			ForwardID: "f-manual", Protocol: protocol.ProtocolTCP,
			Strategy: protocol.StrategyManualStaticV4,
		},
		Plan: PlanRequest{Strategy: protocol.StrategyManualStaticV4},
	})
	if !errors.Is(err, ErrOperatorEndpointRequired) {
		t.Fatalf("manual error = %v, want ErrOperatorEndpointRequired", err)
	}
}

// MA4: Release is idempotent — the second call re-deletes nothing and
// returns the first outcome.
func TestManagerReleaseIdempotent(t *testing.T) {
	mapper := gatewayMapperFixture()
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-idem"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("second Release must return the first (clean) outcome: %v", err)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("deletes = %d, want exactly 1 across both releases", mapper.deleteCount())
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want exactly 1", got)
	}
}

// MA5: three consecutive renewal failures degrade the mapping (keepalive
// DEGRADED) — the lost callback must NOT fire while renewals continue, the
// lease margin (1h/10) is far away.
func TestManagerRenewalDegradesAfterThreeFailures(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	degraded := make(chan string, 4)
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:        managerRouteTable(),
		Listeners:         &fakeListenerSource{},
		Mappers:           map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:           NewMemoryJournal(),
		OnMappingDegraded: func(forwardID string, reason string) { degraded <- reason },
		OnMappingLost:     func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-3"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-degraded:
		if reason == "" {
			t.Fatal("degraded reason must not be empty")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("three consecutive renewal failures must fire the degraded callback")
	}
	select {
	case reason := <-lost:
		t.Fatalf("a degraded mapping is not lost while the lease margin is far: %s", reason)
	case <-time.After(300 * time.Millisecond):
	}
	// Renewals continue after DEGRADED: the mapping may still recover.
	first := mapper.renewalCount()
	deadline := time.Now().Add(500 * time.Millisecond)
	for mapper.renewalCount() <= first && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mapper.renewalCount() <= first {
		t.Fatal("renewals must continue after DEGRADED")
	}
}

// MA6: sustained failures crossing the expiry safety margin lose the
// mapping and stop the renewal loop.
func TestManagerRenewalLostAtExpiryMargin(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	request := gatewayAcquireRequest("forward-4")
	request.Lease = 2 * time.Second // margin = lease/10 = 200ms
	acquisition, err := manager.Acquire(t.Context(), withPacing(request, 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if !strings.Contains(reason, "margin") {
			t.Fatalf("lost reason = %q, want the expiry safety margin crossing", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the expiry safety margin must lose the mapping")
	}
	// The renewal loop stops after LOST.
	time.Sleep(150 * time.Millisecond)
	stable := mapper.renewalCount()
	time.Sleep(150 * time.Millisecond)
	if mapper.renewalCount() != stable {
		t.Fatal("renewals must stop after LOST")
	}
}

// MA7: a successful renewal after DEGRADED recovers (HEALTHY) — the
// recovered callback fires once and a fresh failure streak can degrade
// again.
func TestManagerRenewalRecoversAfterDegraded(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	degraded := make(chan string, 4)
	recovered := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:         managerRouteTable(),
		Listeners:          &fakeListenerSource{},
		Mappers:            map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:            NewMemoryJournal(),
		OnMappingDegraded:  func(forwardID string, reason string) { degraded <- reason },
		OnMappingRecovered: func(forwardID string) { recovered <- forwardID },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-5"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case <-degraded:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the degraded callback first")
	}
	mapper.setRenewErr(nil)
	select {
	case forwardID := <-recovered:
		if forwardID != "forward-5" {
			t.Fatalf("recovered forward = %q", forwardID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a successful renewal after DEGRADED must fire the recovered callback")
	}
}

// MA8: a confirmed gateway reboot (epoch rollback) loses immediately and
// stops the renewal loop.
func TestManagerRenewalRebootLosesImmediately(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.rebootAfter = 2
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-6"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if !strings.Contains(reason, "reboot") {
			t.Fatalf("lost reason = %q, want the gateway reboot signal", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a confirmed reboot must lose immediately")
	}
	time.Sleep(120 * time.Millisecond)
	stable := mapper.renewalCount()
	time.Sleep(120 * time.Millisecond)
	if mapper.renewalCount() != stable {
		t.Fatal("renewals must stop after a reboot loss")
	}
}

// MA9: a renewal that rewrites the external endpoint under a live
// acquisition is a loss — the published endpoint is no longer the mapped
// one (RFC 6887 §11.5).
func TestManagerRenewalEndpointChangeLoses(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.rewriteExternalAfter = 2
	mapper.rewrittenExternal = netip.MustParseAddrPort("100.64.0.2:9999")
	lost := make(chan string, 4)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-7"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	select {
	case reason := <-lost:
		if !strings.Contains(reason, "endpoint") {
			t.Fatalf("lost reason = %q, want the rewritten external endpoint", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a rewritten external endpoint must lose the mapping")
	}
}

// MA10: renewal pacing adopts the GRANTED lease (§3.5: the granted
// lifetime is authoritative) — a short grant accelerates renewals without
// explicit test pacing.
func TestManagerRenewalPacesFromGrantedLease(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.grantedLease = 300 * time.Millisecond // requested 1h below
	lost := make(chan string, 1)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	request := gatewayAcquireRequest("forward-8")
	request.Lease = time.Hour
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())

	// Granted 300ms paces renewals at ~150ms: at least three within 1s.
	deadline := time.Now().Add(1 * time.Second)
	for mapper.renewalCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := mapper.renewalCount(); got < 3 {
		t.Fatalf("renewals = %d in 1s with a 300ms grant, want >= 3 (pacing must adopt the granted lease)", got)
	}
	select {
	case reason := <-lost:
		t.Fatalf("a healthy short-lease mapping must not be lost: %s", reason)
	default:
	}
}

// MA11: a healthy mapping renews within the paced interval and stays quiet.
func TestManagerRenewalHealthy(t *testing.T) {
	mapper := gatewayMapperFixture()
	lost := make(chan string, 1)
	manager := NewManager(ManagerOptions{
		RouteTable:    managerRouteTable(),
		Listeners:     &fakeListenerSource{},
		Mappers:       map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:       NewMemoryJournal(),
		OnMappingLost: func(forwardID string, reason string) { lost <- reason },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-9"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	select {
	case reason := <-lost:
		t.Fatalf("healthy mapping must not be lost: %s", reason)
	default:
	}
	if got := mapper.renewalCount(); got == 0 {
		t.Fatal("healthy mapping must have renewed at least once")
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	renewalsAfterRelease := mapper.renewalCount()
	time.Sleep(60 * time.Millisecond)
	if mapper.renewalCount() != renewalsAfterRelease {
		t.Fatal("renewals must stop after release")
	}
}

// MA12: journal renewals never rewrite the record's creation time — the
// step clock makes every write land on a distinct second.
func TestManagerJournalCreatedAtStable(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := NewMemoryJournal()
	clock := &stepClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
		Clock:      clock.Now,
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-10"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	createdAt := func() int64 {
		records, err := journal.ListByForward("forward-10")
		if err != nil || len(records) != 1 {
			t.Fatalf("journal records = %v/%v", records, err)
		}
		return records[0].CreatedAtUnix
	}
	first := createdAt()
	deadline := time.Now().Add(300 * time.Millisecond)
	for mapper.renewalCount() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mapper.renewalCount() < 3 {
		t.Fatal("expected renewals before checking timestamps")
	}
	records, err := journal.ListByForward("forward-10")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v", records, err)
	}
	if records[0].CreatedAtUnix != first {
		t.Fatalf("CreatedAtUnix = %d after renewals, want the original %d", records[0].CreatedAtUnix, first)
	}
	if records[0].UpdatedAtUnix == records[0].CreatedAtUnix {
		t.Fatal("renewals must update UpdatedAtUnix")
	}
}

// MA13: a failed journal write leaves no mapping_journal_ref — the
// reference must never name a record that was never persisted.
func TestManagerJournalPutFailureLeavesNoRef(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal(), putErr: errors.New("disk full")}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-11"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	if acquisition.JournalID != "" {
		t.Fatalf("journal ref = %q after a failed Put, want empty", acquisition.JournalID)
	}
}

// MA14: a failed mapping delete keeps the journal record — it is the only
// durable evidence of a mapping that may still be live.
func TestManagerReleaseKeepsJournalOnDeleteFailure(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.deleteErr = errors.New("gateway refused the delete")
	journal := NewMemoryJournal()
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-12"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if err := acquisition.Release(t.Context()); err == nil {
		t.Fatal("a failed mapping delete must surface on Release")
	}
	if _, ok, _ := journal.Get(acquisition.JournalID); !ok {
		t.Fatal("the journal record must survive a failed mapping delete")
	}
}

// MA15 (Angle A reconciliation finding): a consumer callback that calls
// Release must always complete, even while the renewal loop keeps producing
// lifecycle events behind it. The oscillating mapper degrades and recovers
// every 3 renewals: while the degraded callback blocks, events queue up;
// a bounded delivery channel would fill, block the renewal goroutine under
// renewMu, and deadlock the Release join against the blocked callback.
func TestManagerReleaseFromBlockingCallbackCompletes(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	mapper.oscillatePeriod = 3
	releaseDone := make(chan error, 1)
	var callbackOnce sync.Once
	var acquired atomic.Pointer[Acquisition]
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
		OnMappingDegraded: func(forwardID string, reason string) {
			callbackOnce.Do(func() {
				// Simulate a slow consumer: keep it blocked while the
				// oscillating loop produces well beyond any bounded buffer.
				time.Sleep(900 * time.Millisecond)
				releaseDone <- acquired.Load().Release(t.Context())
			})
		},
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-callback"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	acquired.Store(acquisition) // released by the callback; no deferred
	// release here — a deadlocked Release in a defer would hang the test.
	select {
	case err := <-releaseDone:
		if err != nil {
			t.Fatalf("Release from within a callback failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Release called from within a lifecycle callback deadlocked")
	}
}

// MA16 (quality/security review M1): a panicking lifecycle callback must be
// contained and later events must still flow. Regression for the S7g drain
// lock-out: a panic unwinding through drain ran its deferred Unlock while
// the mutex was NOT held - an unrecoverable fatal that killed the process.
func TestManagerCallbackPanicContainedAndDeliveryContinues(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewErr = errors.New("gateway gone")
	mapper.oscillatePeriod = 3
	recovered := make(chan string, 4)
	var panicOnce sync.Once
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
		OnMappingDegraded: func(forwardID string, reason string) {
			panicOnce.Do(func() { panic("consumer callback bug") })
		},
		OnMappingRecovered: func(forwardID string) { recovered <- forwardID },
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-panic"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	select {
	case <-recovered:
	case <-time.After(5 * time.Second):
		t.Fatal("a panicking callback must be contained and later events must still be delivered")
	}
}

// MA17 (S7h quality/lifecycle review): an adapter panic during Delete must be
// contained as a release error. Teardown continues exactly once; the listener
// is closed and the journal is retained because the mapping was not confirmed
// deleted. A later Release returns the same error rather than false success.
func TestManagerReleaseContainsDeletePanicAndFinishesTeardown(t *testing.T) {
	listeners := &fakeListenerSource{}
	mapper := gatewayMapperFixture()
	mapper.deletePanic = "mapper delete panic"
	journal := NewMemoryJournal()
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-delete-panic"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	firstErr := acquisition.Release(t.Context())
	if firstErr == nil || !strings.Contains(firstErr.Error(), "mapper delete panic") {
		t.Fatalf("first Release error = %v, want the contained adapter panic", firstErr)
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want teardown to continue exactly once", got)
	}
	if _, ok, err := journal.Get(acquisition.JournalID); err != nil || !ok {
		t.Fatalf("journal after unconfirmed delete = present %v, err %v; want retained", ok, err)
	}
	secondErr := acquisition.Release(t.Context())
	if secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Fatalf("second Release error = %v, want the original %v", secondErr, firstErr)
	}
	if got := mapper.deleteCount(); got != 1 {
		t.Fatalf("delete attempts = %d, want exactly one", got)
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases after retry = %d, want exactly one", got)
	}
}

// MA18 (S7h quality/lifecycle review): journal status is observed only through
// the locked accessor while renewals overwrite it. Run with -race: a public
// JournalError field would race this loop against renewOnce.
func TestManagerCurrentJournalErrorConcurrentRead(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal(), putErr: errors.New("disk full")}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-journal-race"), time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := acquisition.CurrentJournalError(); err == nil {
			t.Fatal("CurrentJournalError = nil, want the failed journal write")
		}
	}
}

// MA19 (S7i lifecycle review): a panic from Journal.Delete is a cleanup
// failure, not a process panic. Listener teardown must still run and repeated
// Release calls must return the stable first error.
func TestManagerReleaseContainsJournalDeletePanic(t *testing.T) {
	listeners := &fakeListenerSource{}
	journal := &failingJournal{MemoryJournal: NewMemoryJournal(), deletePanic: "journal delete panic"}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(), Listeners: listeners,
		Mappers: map[MappingLayerKind]GatewayMapper{LayerPCP: gatewayMapperFixture()}, Journal: journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-journal-delete-panic"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	firstErr := acquisition.Release(t.Context())
	if firstErr == nil || !strings.Contains(firstErr.Error(), "journal delete panic") {
		t.Fatalf("Release error = %v, want contained journal panic", firstErr)
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want cleanup to continue", got)
	}
	if secondErr := acquisition.Release(t.Context()); secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Fatalf("second Release error = %v, want stable %v", secondErr, firstErr)
	}
}

// MA20 (S7i lifecycle review): a listener ReleaseFunc panic is contained and
// becomes the stable idempotent Release outcome rather than escaping through
// sync.Once and turning later calls into false success.
func TestManagerReleaseContainsListenerPanic(t *testing.T) {
	listeners := &fakeListenerSource{}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(), Listeners: listeners,
		Mappers: map[MappingLayerKind]GatewayMapper{LayerPCP: gatewayMapperFixture()}, Journal: NewMemoryJournal(),
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-listener-panic"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	acquisition.releaseFn = func() error { panic("listener release panic") }
	firstErr := acquisition.Release(t.Context())
	if firstErr == nil || !strings.Contains(firstErr.Error(), "listener release panic") {
		t.Fatalf("Release error = %v, want contained listener panic", firstErr)
	}
	if secondErr := acquisition.Release(t.Context()); secondErr == nil || secondErr.Error() != firstErr.Error() {
		t.Fatalf("second Release error = %v, want stable %v", secondErr, firstErr)
	}
}

// MA21 (S7j lifecycle review): Journal.Put panic has the same advisory
// contract as an ordinary journal write error. Acquire returns the live,
// releasable binding, keeps JournalID honest, and exposes the failure through
// CurrentJournalError rather than leaking a mapping/listener via panic.
func TestManagerAcquireContainsJournalPutPanic(t *testing.T) {
	listeners := &fakeListenerSource{}
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal(), putPanic: "journal put panic"}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(), Listeners: listeners,
		Mappers: map[MappingLayerKind]GatewayMapper{LayerPCP: mapper}, Journal: journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-journal-put-panic"))
	if err != nil {
		t.Fatalf("Acquire: %v; journal failures are advisory", err)
	}
	if acquisition == nil {
		t.Fatal("Acquire returned nil binding after contained journal panic")
	}
	if acquisition.JournalID != "" {
		t.Fatalf("JournalID = %q, want empty after failed first write", acquisition.JournalID)
	}
	if journalErr := acquisition.CurrentJournalError(); journalErr == nil || !strings.Contains(journalErr.Error(), "journal put panic") {
		t.Fatalf("CurrentJournalError = %v, want contained panic", journalErr)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if mapper.deleteCount() != 1 || listeners.releaseCount() != 1 {
		t.Fatalf("cleanup deletes/releases = %d/%d, want 1/1", mapper.deleteCount(), listeners.releaseCount())
	}
}

// panickingListenerSource simulates a listener source whose Acquire panics.
type panickingListenerSource struct{}

func (panickingListenerSource) Acquire(context.Context, string, TupleKey) (net.Listener, TupleKey, ReleaseFunc, error) {
	panic("listener acquire panic")
}

// MA22 (S7k audit): a panicking injected callback anywhere in Acquire becomes
// an ordinary error, never a process panic escaping to the caller.
func TestManagerAcquireContainsListenerAcquirePanic(t *testing.T) {
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  panickingListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: gatewayMapperFixture()},
		Journal:    NewMemoryJournal(),
	})
	if _, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-listener-acquire-panic")); err == nil || !strings.Contains(err.Error(), "listener acquire panicked") {
		t.Fatalf("Acquire error = %v, want contained listener acquire panic", err)
	}
}

// MA23 (S7k audit): a panicking mapper.Discover fails the acquisition before
// any side effect.
func TestManagerAcquireContainsDiscoverPanic(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.discoverPanic = "discover panic"
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
	})
	if _, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-discover-panic")); err == nil || !strings.Contains(err.Error(), "discover panicked") {
		t.Fatalf("Acquire error = %v, want contained discover panic", err)
	}
}

// MA24 (S7k audit): a panicking mapper.Map after the listener bind must not
// leak the listener; the outer Acquire releases it on the contained error.
func TestManagerMapPanicReleasesListener(t *testing.T) {
	listeners := &fakeListenerSource{}
	mapper := gatewayMapperFixture()
	mapper.mapPanic = "map panic"
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
	})
	if _, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-map-panic")); err == nil || !strings.Contains(err.Error(), "map panicked") {
		t.Fatalf("Acquire error = %v, want contained map panic", err)
	}
	if got := listeners.releaseCount(); got != 1 {
		t.Fatalf("listener releases = %d, want the bound listener released", got)
	}
}

// MA25 (S7k audit): a panicking STUN observer follows the ordinary advisory
// observe-error contract — the acquisition stays live with StunObserveError.
func TestManagerStunObservePanicIsAdvisory(t *testing.T) {
	listeners := &fakeListenerSource{}
	mapper := gatewayMapperFixture()
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
		StunObserve: func(context.Context, StunObserveRequest) (netip.AddrPort, error) {
			panic("stun observe panic")
		},
	})
	request := gatewayAcquireRequest("forward-stun-panic")
	request.StunServer = "stun+tcp://10.0.0.1:3478"
	acquisition, err := manager.Acquire(t.Context(), request)
	if err != nil {
		t.Fatalf("Acquire: %v; a STUN panic must follow the advisory observe-error contract", err)
	}
	if acquisition.StunObserveError == nil || !strings.Contains(acquisition.StunObserveError.Error(), "stun observe panic") {
		t.Fatalf("StunObserveError = %v, want the contained panic", acquisition.StunObserveError)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if mapper.deleteCount() != 1 || listeners.releaseCount() != 1 {
		t.Fatalf("cleanup deletes/releases = %d/%d, want 1/1", mapper.deleteCount(), listeners.releaseCount())
	}
}

// MA26 (S7k audit): a panicking mapper.Renew counts as an ordinary failed
// renewal — three consecutive panics degrade instead of vanishing into a
// blanket recover, and the recovery cycle still fires.
func TestManagerRenewPanicFollowsLadder(t *testing.T) {
	mapper := gatewayMapperFixture()
	mapper.renewPanic = "renew panic"
	mapper.oscillatePeriod = 3
	degraded := make(chan string, 1)
	recovered := make(chan string, 1)
	var degradedOnce, recoveredOnce sync.Once
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    NewMemoryJournal(),
		OnMappingDegraded: func(forwardID string, reason string) {
			degradedOnce.Do(func() { degraded <- reason })
		},
		OnMappingRecovered: func(forwardID string) {
			recoveredOnce.Do(func() { recovered <- forwardID })
		},
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-renew-panic"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	select {
	case reason := <-degraded:
		if !strings.Contains(reason, "renew panic") {
			t.Fatalf("degraded reason = %q, want the contained renew panic", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("renew panics must count toward the degradation ladder")
	}
	select {
	case <-recovered:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery must still follow the panicking-renewal episodes")
	}
}

// MA27 (S7k audit): a renewal whose Put fails and whose reconciliation Get
// also fails keeps the durable row untouched and keeps the failure observable:
// CurrentJournalError stays set, no duplicate ID is generated, and the next
// renewal retries the same private attempt ID.
func TestManagerRenewalGetFailureObservable(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal()}
	clock := &stepClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
		Clock:      clock.Now,
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-get-panic"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	if acquisition.JournalID == "" {
		t.Fatal("the initial write must succeed before the injected faults")
	}
	records, err := journal.ListByForward("forward-get-panic")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v, want exactly the initial row", records, err)
	}
	originalCreatedAt := records[0].CreatedAtUnix
	originalUpdatedAt := records[0].UpdatedAtUnix
	journal.armPutPanic("journal put panic")
	journal.armGetPanic("journal get panic")
	deadline := time.Now().Add(400 * time.Millisecond)
	for mapper.renewalCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mapper.renewalCount() < 2 {
		t.Fatal("expected renewals under the injected faults")
	}
	if journalErr := acquisition.CurrentJournalError(); journalErr == nil {
		t.Fatal("CurrentJournalError = nil, want the ambiguous put/get failure surfaced")
	}
	records, err = journal.ListByForward("forward-get-panic")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records after renewals = %v/%v, want the single untouched row (no duplicate IDs)", records, err)
	}
	if records[0].CreatedAtUnix != originalCreatedAt || records[0].UpdatedAtUnix != originalUpdatedAt {
		t.Fatalf("durable record rewritten during the fault window: created %d->%d updated %d->%d",
			originalCreatedAt, records[0].CreatedAtUnix, originalUpdatedAt, records[0].UpdatedAtUnix)
	}
}

// MA28 (S7k audit): a Put that commits then panics is reconciled through the
// read-back at the unique attempt ID: the durable row is published as the
// journal reference and Release deletes it — no orphan, no duplicate.
func TestManagerPutPersistThenPanicReconciled(t *testing.T) {
	listeners := &fakeListenerSource{}
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal(), putPanicAfterWrite: "journal put panic"}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-postcommit-panic"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	records, err := journal.List()
	if err != nil || len(records) != 1 {
		t.Fatalf("journal rows = %v/%v, want exactly the reconciled attempt", records, err)
	}
	if acquisition.JournalID != records[0].ID {
		t.Fatalf("JournalID = %q, want the durable row %q published", acquisition.JournalID, records[0].ID)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	remaining, err := journal.List()
	if err != nil || len(remaining) != 0 {
		t.Fatalf("journal rows after release = %v/%v, want the reconciled row deleted", remaining, err)
	}
	if mapper.deleteCount() != 1 || listeners.releaseCount() != 1 {
		t.Fatalf("cleanup deletes/releases = %d/%d, want 1/1", mapper.deleteCount(), listeners.releaseCount())
	}
}

// MA30 (S7l network review): an ordinary renewal Put error must surface
// immediately — the read-back reconciliation may not mistake the previous
// generation's durable row for this attempt's outcome and clear
// CurrentJournalError.
func TestManagerRenewalPutErrorStaysObservable(t *testing.T) {
	mapper := gatewayMapperFixture()
	journal := &failingJournal{MemoryJournal: NewMemoryJournal()}
	clock := &stepClock{cur: time.Unix(1_700_000_000, 0), step: time.Second}
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  &fakeListenerSource{},
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
		Clock:      clock.Now,
	})
	acquisition, err := manager.Acquire(t.Context(), withPacing(gatewayAcquireRequest("forward-put-error"), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer acquisition.Release(t.Context())
	if acquisition.JournalID == "" {
		t.Fatal("the initial write must succeed before the injected Put errors")
	}
	records, err := journal.ListByForward("forward-put-error")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records = %v/%v, want exactly the initial row", records, err)
	}
	originalUpdatedAt := records[0].UpdatedAtUnix
	journal.mu.Lock()
	journal.putErr = errors.New("disk full")
	journal.mu.Unlock()
	deadline := time.Now().Add(400 * time.Millisecond)
	for mapper.renewalCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if mapper.renewalCount() < 2 {
		t.Fatal("expected renewals under the injected Put error")
	}
	if journalErr := acquisition.CurrentJournalError(); journalErr == nil || !strings.Contains(journalErr.Error(), "disk full") {
		t.Fatalf("CurrentJournalError = %v, want the ordinary Put error surfaced", journalErr)
	}
	records, err = journal.ListByForward("forward-put-error")
	if err != nil || len(records) != 1 {
		t.Fatalf("journal records after renewals = %v/%v, want the single stale row untouched", records, err)
	}
	if records[0].UpdatedAtUnix != originalUpdatedAt {
		t.Fatalf("durable row rewritten during the error window: updated %d->%d", originalUpdatedAt, records[0].UpdatedAtUnix)
	}
}

// MA29 (S7k audit): a panicking mechanism-private State serializer surfaces as
// an advisory journal error and writes no record.
func TestManagerStateSerializationPanicAdvisory(t *testing.T) {
	listeners := &fakeListenerSource{}
	mapper := gatewayMapperFixture()
	mapper.statePanic = "state marshal panic"
	journal := NewMemoryJournal()
	manager := NewManager(ManagerOptions{
		RouteTable: managerRouteTable(),
		Listeners:  listeners,
		Mappers:    map[MappingLayerKind]GatewayMapper{LayerPCP: mapper},
		Journal:    journal,
	})
	acquisition, err := manager.Acquire(t.Context(), gatewayAcquireRequest("forward-state-panic"))
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if acquisition.JournalID != "" {
		t.Fatalf("JournalID = %q, want empty (no durable record written)", acquisition.JournalID)
	}
	if journalErr := acquisition.CurrentJournalError(); journalErr == nil || !strings.Contains(journalErr.Error(), "state marshal panic") {
		t.Fatalf("CurrentJournalError = %v, want the serialization panic", journalErr)
	}
	if rows, _ := journal.List(); len(rows) != 0 {
		t.Fatalf("journal rows = %v, want none", rows)
	}
	if err := acquisition.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if mapper.deleteCount() != 1 || listeners.releaseCount() != 1 {
		t.Fatalf("cleanup deletes/releases = %d/%d, want 1/1", mapper.deleteCount(), listeners.releaseCount())
	}
}
