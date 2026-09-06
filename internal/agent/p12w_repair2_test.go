// P12W repair-cycle-2 tests: the deterministic regression coverage for the
// fresh-review findings — order-based auto resolution (2), nil-manager
// failures (3), generation fencing of in-flight acquisitions (4), same-Forward
// serialization (5), bounded ownership-preserving abandonment and the
// cleanup-completion recovery retry (7), and the lifecycle/probe deletion-window
// fence (8). Every behavior test drives the real data-plane path (blocking
// gateway mappers, durable delete fences, real recovery passes) rather than
// exercising the new helpers in isolation.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/control"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// p12wRepairMapper is a scripted PCP mapper for the repair-2 fencing tests. It
// can block Map until released (so a test can change generations or install a
// durable delete fence while an acquisition is in flight), counts Map/Delete
// calls, and fails a scripted number of Delete calls (finding 7).
type p12wRepairMapper struct {
	p12wMapper
	mu          sync.Mutex
	block       bool
	maps        int
	deletes     int
	failDeletes int
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
}

func newP12wRepairMapper(block bool) *p12wRepairMapper {
	return &p12wRepairMapper{
		p12wMapper: p12wMapper{
			mechanism: traversal.LayerPCP,
			ownership: traversal.OwnershipStrong,
			control:   traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: "10.0.0.1:5351"},
			external:  netip.MustParseAddrPort("100.64.0.2:43111"),
			lease:     time.Hour,
		},
		block:   block,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (m *p12wRepairMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	m.mu.Lock()
	m.maps++
	block := m.block
	m.mu.Unlock()
	if block {
		m.once.Do(func() { close(m.entered) })
		<-m.release
	}
	return m.p12wMapper.Map(ctx, req)
}

func (m *p12wRepairMapper) Delete(ctx context.Context, mapping traversal.GatewayMapping) error {
	m.mu.Lock()
	m.deletes++
	fail := m.failDeletes > 0
	if fail {
		m.failDeletes--
	}
	m.mu.Unlock()
	if fail {
		return errors.New("scripted delete failure")
	}
	return m.p12wMapper.Delete(ctx, mapping)
}

func (m *p12wRepairMapper) setBlocking(block bool) {
	m.mu.Lock()
	m.block = block
	m.mu.Unlock()
}

func (m *p12wRepairMapper) setFailDeletes(n int) {
	m.mu.Lock()
	m.failDeletes = n
	m.mu.Unlock()
}

func (m *p12wRepairMapper) mapCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.maps
}

func (m *p12wRepairMapper) deleteCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deletes
}

func (m *p12wRepairMapper) unblock() { close(m.release) }

// p12wRepairComposition builds a gateway data plane wired exactly like the
// composed app but with the caller-provided PCP mapper.
func p12wRepairComposition(t *testing.T, mapper traversal.GatewayMapper) *dataPlane {
	t.Helper()
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

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
		Store:          st,
		RouteTable:     p12wRouteTable{},
		Clock:          time.Now,
		GatewayManager: manager,
		Journal:        journal,
		StunServers:    []string{"stun+tcp://100.64.0.1:3478"},
		ProfileStore:   profiles,
		StunObserver:   obs.observe,
		StunSource:     &p12wListenerSource{},
	})
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })
	return d
}

func repairGatewaySpec(forwardID string, revision uint64, target string) protocol.ForwardSpec {
	if target == "" {
		target = "127.0.0.1:9"
	}
	return protocol.ForwardSpec{
		ForwardID: forwardID, Protocol: protocol.ProtocolTCP, Target: target,
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: revision, Presence: protocol.PresencePresent,
	}
}

// ---------------------------------------------------------------------------
// Finding 2: auto strategy resolves through the CURRENT configured order, and
// UDP auto is independent of the (TCP) detection profile.
// ---------------------------------------------------------------------------

func TestResolveAutoStrategyWalksConfiguredOrder(t *testing.T) {
	// explicit-gateway PASSED, direct-v4 PASSED: the configured order, not
	// Profile.DefaultStrategy, decides.
	profile := traversal.Profile{Results: []traversal.StrategyResult{
		{Strategy: protocol.StrategyExplicitGateway, State: traversal.DetectionPassed, LayerSignature: "pcp"},
		{Strategy: protocol.StrategyDirectV4, State: traversal.DetectionPassed},
	}}
	spec := protocol.ForwardSpec{Protocol: protocol.ProtocolTCP, Strategy: protocol.StrategyAuto}

	cases := []struct {
		name  string
		order []protocol.Strategy
		want  protocol.Strategy
	}{
		{
			name:  "explicit-gateway first wins",
			order: []protocol.Strategy{protocol.StrategyExplicitGateway, protocol.StrategyDirectV4},
			want:  protocol.StrategyExplicitGateway,
		},
		{
			name:  "direct-v4 first wins even though the profile default is gateway",
			order: []protocol.Strategy{protocol.StrategyDirectV4, protocol.StrategyExplicitGateway},
			want:  protocol.StrategyDirectV4,
		},
		{
			name:  "only the passing order entries are candidates",
			order: []protocol.Strategy{protocol.StrategyStunOnly, protocol.StrategyExplicitGateway},
			want:  protocol.StrategyExplicitGateway,
		},
		{
			name:  "manual-static and auto entries are ignored fail-closed",
			order: []protocol.Strategy{protocol.StrategyManualStaticV4, protocol.StrategyAuto, protocol.StrategyDirectV4},
			want:  protocol.StrategyDirectV4,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveAutoStrategy(spec, profile, true, tc.order)
			if err != nil {
				t.Fatalf("resolveAutoStrategy: %v", err)
			}
			if got != tc.want {
				t.Fatalf("resolved = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("no passing entry in the order fails", func(t *testing.T) {
		if _, err := resolveAutoStrategy(spec, profile, true,
			[]protocol.Strategy{protocol.StrategyStunOnly}); !errors.Is(err, errAutoNoPassingDefault) {
			t.Fatalf("error = %v, want errAutoNoPassingDefault", err)
		}
	})
}

func TestResolveAutoStrategyUDPIgnoresProfileAndOrder(t *testing.T) {
	udp := protocol.ForwardSpec{Protocol: protocol.ProtocolUDP, Strategy: protocol.StrategyAuto}
	// A stale/absent profile and a non-default order must never affect UDP auto.
	got, err := resolveAutoStrategy(udp, traversal.Profile{}, false, []protocol.Strategy{protocol.StrategyStunOnly})
	if err != nil {
		t.Fatalf("resolveAutoStrategy UDP: %v", err)
	}
	if got != protocol.StrategyDirectV4 {
		t.Fatalf("UDP auto resolved = %q, want direct-v4", got)
	}
}

func TestValidateAutoProfileMissingFingerprintIsStale(t *testing.T) {
	// A present profile without a route fingerprint is malformed evidence and
	// must be refused as stale, never treated as current capability.
	err := validateAutoProfile(p12wRouteTable{}, time.Now, traversal.Profile{DefaultStrategy: protocol.StrategyExplicitGateway}, true)
	if !errors.Is(err, errAutoStaleProfile) {
		t.Fatalf("error = %v, want errAutoStaleProfile", err)
	}
	if err == nil {
		t.Fatal("missing-fingerprint profile was accepted")
	}
}

func TestDataPlaneUDPAutoIgnoresStaleTCPProfile(t *testing.T) {
	// Finding 2: UDP auto resolves to direct-v4 BEFORE the TCP detection
	// profile is loaded or validated, so a stale/malformed/absent TCP profile
	// must not affect a UDP forward. (A stale profile in the store is the probe;
	// the UDP apply would be refused if it ever touched the profile.)
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	profiles := newProfileStore(t.TempDir())
	if err := profiles.Save(traversal.Profile{
		// Fingerprint of a DIFFERENT network: stale for this route table.
		Fingerprint: "some-other-network", Protocol: traversal.ProtocolTCP,
		DefaultStrategy: protocol.StrategyAuto, ComputedAtUnix: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	d := newDataPlane(dataPlaneConfig{Store: st, RouteTable: p12wGlobalRouteTable{}, Clock: time.Now,
		ProfileStore: profiles, StunServers: []string{"stun+tcp://100.64.0.1:3478"}})
	spec := protocol.ForwardSpec{
		ForwardID: "udp-auto", Protocol: protocol.ProtocolUDP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyAuto, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	// The stale TCP profile must never be consulted: the UDP route resolves to
	// direct-v4 unconditionally (P13 owns the UDP dataplane).
	route, err := d.resolveForwardRoute(spec)
	if err != nil {
		t.Fatalf("UDP auto route resolution touched the stale TCP profile: %v", err)
	}
	if route.plan.Strategy != protocol.StrategyDirectV4 {
		t.Fatalf("UDP auto plan = %q, want direct-v4", route.plan.Strategy)
	}
}

func TestDataPlaneRejectsFixedNonDirectUDP(t *testing.T) {
	// Finding 2: a fixed non-direct UDP strategy is a configuration error and
	// must fail closed, not be silently rewritten to direct-v4.
	d := newDataPlane(dataPlaneConfig{RouteTable: p12wGlobalRouteTable{}, Clock: time.Now})
	for _, strategy := range []protocol.Strategy{
		protocol.StrategyExplicitGateway, protocol.StrategyManualStaticV4, protocol.StrategyStunOnly,
	} {
		spec := protocol.ForwardSpec{
			ForwardID: "udp-fixed", Protocol: protocol.ProtocolUDP, Target: "127.0.0.1:9",
			Strategy: strategy, DesiredRevision: 1, Presence: protocol.PresencePresent,
		}
		if _, err := d.resolveForwardRoute(spec); err == nil {
			t.Fatalf("UDP strategy %q was accepted; want fail-closed", strategy)
		}
	}
}

// ---------------------------------------------------------------------------
// Finding 3: selected routes with a missing manager pointer return ordinary
// errors instead of panicking.
// ---------------------------------------------------------------------------

func TestResolveForwardRouteNilManagerFailures(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	// Explicit-gateway with a passing profile but a NIL gateway manager.
	profiles := newProfileStore(t.TempDir())
	if err := profiles.Save(pcpPassingProfile()); err != nil {
		t.Fatal(err)
	}
	d := newDataPlane(dataPlaneConfig{Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now, ProfileStore: profiles})
	gatewaySpec := protocol.ForwardSpec{
		ForwardID: "gw-nil", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := d.resolveForwardRoute(gatewaySpec); err == nil {
		t.Fatal("explicit-gateway with a nil gateway manager resolved; want an ordinary error")
	}

	// Manual-static with a NIL plain manager.
	manualSpec := protocol.ForwardSpec{
		ForwardID: "manual-nil", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyManualStaticV4, ManualExpectedEndpoint: "203.0.113.5:8443",
		DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if _, err := d.resolveForwardRoute(manualSpec); err == nil {
		t.Fatal("manual-static with a nil plain manager resolved; want an ordinary error")
	}

	// Direct-v4 stays manager-free and resolves fine with no manager at all.
	directSpec := protocol.ForwardSpec{
		ForwardID: "direct-nil", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyDirectV4, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}
	if route, err := d.resolveForwardRoute(directSpec); err != nil {
		t.Fatalf("direct-v4 route: %v", err)
	} else if route.plan.Strategy != protocol.StrategyDirectV4 {
		t.Fatalf("direct plan = %q", route.plan.Strategy)
	}
}

// ---------------------------------------------------------------------------
// Finding 4: an acquisition captured before a capability loss or composition
// rebuild is refused at install (generation fence) and abandoned with cleanup
// ownership retained.
// ---------------------------------------------------------------------------

func TestDataPlaneApplyRejectsCapabilityLossDuringAcquire(t *testing.T) {
	mapper := newP12wRepairMapper(true)
	d := p12wRepairComposition(t, mapper)

	spec := repairGatewaySpec("fwd-gen-cap", 1, "")
	result := make(chan error, 1)
	go func() {
		_, err := d.apply(context.Background(), spec)
		result <- err
	}()

	select {
	case <-mapper.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply never reached the gateway Map call")
	}
	// Capability is lost while the acquisition is in flight: the actor must not
	// be installed, and the acquired mapping must be released.
	d.markCapabilityLost(context.Background())
	mapper.unblock()

	if err := <-result; !errors.Is(err, errAcquisitionStale) {
		t.Fatalf("apply error = %v, want errAcquisitionStale", err)
	}
	d.mu.Lock()
	_, live := d.forwards[spec.ForwardID]
	pending := d.pendingActorsLocked(spec.ForwardID)
	d.mu.Unlock()
	if live {
		t.Fatal("actor installed despite the capability loss")
	}
	if len(pending) != 0 {
		t.Fatalf("abandoned actor not cleaned up: %d pending", len(pending))
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("mapping releases = %d, want 1 (abandoned acquisition released)", mapper.deleteCount())
	}
}

func TestDataPlaneApplyRejectsCompositionRebuildDuringAcquire(t *testing.T) {
	mapper := newP12wRepairMapper(true)
	d := p12wRepairComposition(t, mapper)

	spec := repairGatewaySpec("fwd-gen-rebuild", 1, "")
	result := make(chan error, 1)
	go func() {
		_, err := d.apply(context.Background(), spec)
		result <- err
	}()

	select {
	case <-mapper.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply never reached the gateway Map call")
	}
	// A liveness rebuild publishes a new composition while the acquisition is
	// in flight: the actor must not be installed against the old composition.
	d.mu.Lock()
	d.compositionGeneration++
	d.mu.Unlock()
	mapper.unblock()

	if err := <-result; !errors.Is(err, errAcquisitionStale) {
		t.Fatalf("apply error = %v, want errAcquisitionStale", err)
	}
	d.mu.Lock()
	_, live := d.forwards[spec.ForwardID]
	d.mu.Unlock()
	if live {
		t.Fatal("actor installed against an obsolete composition")
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("mapping releases = %d, want 1", mapper.deleteCount())
	}
}

// ---------------------------------------------------------------------------
// Finding 5: same-ForwardID side effects are serialized, so a concurrent
// apply/reopen can never run a duplicate acquisition or install a stale result.
// ---------------------------------------------------------------------------

func TestDataPlaneSameIDApplySerializesOneAcquisition(t *testing.T) {
	mapper := newP12wRepairMapper(true)
	d := p12wRepairComposition(t, mapper)

	spec1 := repairGatewaySpec("fwd-serialize", 1, "127.0.0.1:9")
	spec2 := repairGatewaySpec("fwd-serialize", 2, "127.0.0.1:99")
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() {
		_, err := d.apply(context.Background(), spec1)
		first <- err
	}()
	select {
	case <-mapper.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("first apply never reached the gateway Map call")
	}
	go func() {
		_, err := d.apply(context.Background(), spec2)
		second <- err
	}()

	// While the first acquisition is blocked, the second apply must be waiting
	// on the per-forward operation — not running a second acquisition.
	time.Sleep(150 * time.Millisecond)
	if got := mapper.mapCount(); got != 1 {
		t.Fatalf("second apply started a duplicate acquisition: Map calls = %d, want 1", got)
	}

	mapper.unblock()
	if err := <-first; err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if got := mapper.mapCount(); got != 1 {
		t.Fatalf("Map calls = %d, want exactly 1 (duplicate resources must never be acquired)", got)
	}
	// The second apply hot-updated the single actor to its target.
	d.mu.Lock()
	actor := d.forwards["fwd-serialize"]
	d.mu.Unlock()
	if actor == nil {
		t.Fatal("no actor installed")
	}
	if got := actor.backend.Target(); got != netip.MustParseAddrPort(spec2.Target) {
		t.Fatalf("backend target = %s, want the second apply's target %s", got, spec2.Target)
	}
}

func TestDataPlaneReopenVsApplySerializesOneAcquisition(t *testing.T) {
	mapper := newP12wRepairMapper(true)
	d := p12wRepairComposition(t, mapper)

	spec := repairGatewaySpec("fwd-reopen-race", 1, "127.0.0.1:9")
	st := protocol.AppliedForwardState{
		ForwardID: spec.ForwardID, SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 51234, Strategy: string(protocol.StrategyExplicitGateway),
		LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	}
	spec2 := repairGatewaySpec("fwd-reopen-race", 2, "127.0.0.1:99")
	reopenResult := make(chan error, 1)
	applyResult := make(chan error, 1)
	go func() {
		reopenResult <- d.reopen(context.Background(), spec, st)
	}()
	select {
	case <-mapper.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("reopen never reached the gateway Map call")
	}
	go func() {
		_, err := d.apply(context.Background(), spec2)
		applyResult <- err
	}()

	time.Sleep(150 * time.Millisecond)
	if got := mapper.mapCount(); got != 1 {
		t.Fatalf("apply raced a second acquisition while reopen was in flight: Map calls = %d, want 1", got)
	}

	mapper.unblock()
	if err := <-reopenResult; err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := <-applyResult; err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := mapper.mapCount(); got != 1 {
		t.Fatalf("Map calls = %d, want exactly 1", got)
	}
}

// ---------------------------------------------------------------------------
// Finding 7: bounded, ownership-preserving abandonment. A canceled caller
// context must never strand the mapping, and a failed release stays owned for
// the drain to retry.
// ---------------------------------------------------------------------------

func TestDataPlaneAbandonRetainsOwnershipOnFailedRelease(t *testing.T) {
	mapper := newP12wRepairMapper(true)
	mapper.setFailDeletes(1) // the first release fails: ownership must be retained
	d := p12wRepairComposition(t, mapper)
	st := d.cfg.Store

	var cleanupErrors int
	var cleanupMu sync.Mutex
	d.cfg.OnCleanupError = func(forwardID string, actor *forwardActor, err error) {
		cleanupMu.Lock()
		cleanupErrors++
		cleanupMu.Unlock()
	}

	spec := repairGatewaySpec("fwd-fail-release", 1, "")
	result := make(chan error, 1)
	go func() {
		_, err := d.apply(context.Background(), spec)
		result <- err
	}()
	select {
	case <-mapper.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("apply never reached the gateway Map call")
	}
	// A delete fence wins while the acquisition is in flight.
	if _, err := st.PutForwardDeleteIntent(localstate.ForwardDeleteIntent{
		ForwardID: spec.ForwardID, DeletionOperationID: "del-release-1", DesiredRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	// abandonAcquiredActor uses a DETACHED bounded context (it takes no caller
	// context at all), so a caller that walked away cannot strand the mapping;
	// this test verifies the fence rejection then fails the first release.
	mapper.setBlocking(false)
	mapper.unblock()

	if err := <-result; err == nil {
		t.Fatal("apply succeeded despite the delete fence")
	}
	d.mu.Lock()
	pending := d.pendingActorsLocked(spec.ForwardID)
	d.mu.Unlock()
	if len(pending) != 1 {
		t.Fatalf("pending actors = %d, want 1 (failed release must stay owned)", len(pending))
	}
	cleanupMu.Lock()
	failures := cleanupErrors
	cleanupMu.Unlock()
	if failures != 1 {
		t.Fatalf("OnCleanupError fired %d times, want 1", failures)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("delete attempts = %d, want 1 (the first release)", mapper.deleteCount())
	}

	// The drain retries, but a manager Acquisition.Release is sync.Once: it can
	// never re-run the failed delete, so the truthful state is to STAY owned
	// (the durable journal record is retained because the mapping may still be
	// live on the gateway). The retry must not claim a false clean state
	// (repair-2 finding 7).
	if err := d.drainCleanup(context.Background()); err == nil {
		t.Fatal("drain retry must not claim a clean release after the once-only failure")
	}
	d.mu.Lock()
	pending = d.pendingActorsLocked(spec.ForwardID)
	d.mu.Unlock()
	if len(pending) != 1 {
		t.Fatalf("pending actors after drain retry = %d, want 1 (once-only release keeps ownership)", len(pending))
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("delete attempts = %d, want 1 (Release never re-runs after sync.Once)", mapper.deleteCount())
	}
}

func TestDataPlaneCleanupCompletionSchedulesRecoveryRetry(t *testing.T) {
	mapper := newP12wRepairMapper(false)
	d := p12wRepairComposition(t, mapper)
	st := d.cfg.Store

	// A durably applied LKG for a forward whose actor is stranded in
	// cleanupPending (capability loss without a new route change).
	spec := repairGatewaySpec("fwd-cleanup-retry", 1, "127.0.0.1:9")
	applied := protocol.AppliedForwardState{
		ForwardID: spec.ForwardID, SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "10.0.0.2", ActualBindPort: 51234, Strategy: string(protocol.StrategyExplicitGateway),
		LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	}
	desired := protocol.DesiredState{NodeID: "node-r2", Forwards: []protocol.ForwardSpec{spec}}
	if _, err := st.CommitDesired(desired, []localstate.ForwardApply{
		{ForwardID: spec.ForwardID, Outcome: localstate.ApplyApplied, Applied: &applied},
	}); err != nil {
		t.Fatalf("commit applied LKG: %v", err)
	}

	// Wire the production retry hook: cleanup completion schedules a recovery
	// pass, which reopens the stranded forward from its durable LKG.
	var hookMu sync.Mutex
	hooked := 0
	d.cfg.OnActorCleaned = func(forwardID string) {
		hookMu.Lock()
		hooked++
		hookMu.Unlock()
		// The hook also fires from the t.Cleanup closeAll, where recover is a
		// benign no-op (errDataPlaneClosing); the production wiring ignores that
		// outcome too.
		if _, err := d.recover(context.Background()); err != nil && !errors.Is(err, errDataPlaneClosing) {
			t.Fatalf("recovery retry: %v", err)
		}
	}

	// Simulate the stranding: the actor is no longer live but still owns its
	// resources until cleanup finishes.
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	d.mu.Lock()
	actor := d.forwards[spec.ForwardID]
	delete(d.forwards, spec.ForwardID)
	d.addCleanupPendingLocked(spec.ForwardID, actor)
	d.mu.Unlock()

	if err := d.cleanupActor(context.Background(), spec.ForwardID, actor); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	hookMu.Lock()
	wasHooked := hooked
	hookMu.Unlock()
	if wasHooked != 1 {
		t.Fatalf("OnActorCleaned fired %d times, want 1", wasHooked)
	}
	// The retry reopened the forward from its durable LKG.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		_, live := d.forwards[spec.ForwardID]
		d.mu.Unlock()
		if live {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.mu.Lock()
	_, live := d.forwards[spec.ForwardID]
	d.mu.Unlock()
	t.Fatalf("forward was not reopened after cleanup completed (live=%v)", live)
}

// TestDataPlaneGatewayCloseAllLeavesNoPending pins the repair-2 finding-7 fix
// for the PRE-EXISTING latent double-close: a gateway actor's listener is owned
// by both the wrapped tcp.Forward and the manager acquisition, so teardown
// reported a redundant "use of closed network connection" as a failed release
// and stranded every gateway actor in cleanupPending forever. cleanupActor now
// treats an EXCLUSIVELY redundant close as a clean release.
func TestDataPlaneGatewayCloseAllLeavesNoPending(t *testing.T) {
	mapper := newP12wRepairMapper(false)
	d := p12wRepairComposition(t, mapper)
	// Remove the t.Cleanup closeAll: this test drives closeAll explicitly.
	// (t.Cleanup is installed by the helper; closeAll is idempotent, so the
	// explicit call below followed by the helper's is harmless.)
	if _, err := d.apply(context.Background(), repairGatewaySpec("fwd-closeall", 1, "")); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if err := d.closeAll(context.Background()); err != nil {
		t.Fatalf("closeAll: %v", err)
	}
	d.mu.Lock()
	pending := len(d.pendingActorsLocked("fwd-closeall"))
	d.mu.Unlock()
	if pending != 0 {
		t.Fatalf("gateway actor stranded in cleanupPending after closeAll (pending=%d); the redundant listener close was misreported as a failed release", pending)
	}
	if mapper.deleteCount() != 1 {
		t.Fatalf("mapping releases = %d, want 1", mapper.deleteCount())
	}
}

// ---------------------------------------------------------------------------
// Finding 8: lifecycle and probe-outcome events that land in the durable
// deletion window must not recreate activation state.
// ---------------------------------------------------------------------------

func TestMappingLifecycleDropsEventInDeletionWindow(t *testing.T) {
	a, d, _, _ := p12wLifecycleApp(t, time.Hour)
	spec := lifecycleGatewaySpec("fwd-del-window", 1)
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitForKeepalive(t, a, "fwd-del-window", "HEALTHY")

	// Positive control: without a fence the guarded handler runs.
	ran := false
	a.onMappingLifecycle("fwd-del-window", func(act *reconcile.Activation, actor *forwardActor) error {
		ran = true
		return nil
	})
	if !ran {
		t.Fatal("positive control: lifecycle handler did not run without a fence")
	}

	// A durable deletion intent lands while the forward is still live (the
	// deletion window between fence commit and mirror removal).
	if _, err := a.store.PutForwardDeleteIntent(localstate.ForwardDeleteIntent{
		ForwardID: "fwd-del-window", DeletionOperationID: "del-window-1", DesiredRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	ran = false
	a.onMappingLifecycle("fwd-del-window", func(act *reconcile.Activation, actor *forwardActor) error {
		ran = true
		return act.Update("keepalive_state", "HEALTHY", act.Generation())
	})
	if ran {
		t.Fatal("lifecycle event recreated activation state after the durable deletion fence")
	}
	// The pre-fence activation must be untouched (still HEALTHY, not rewritten).
	if snap := a.ActivationSnapshot("fwd-del-window"); snap == nil || snap.KeepaliveState != "HEALTHY" {
		t.Fatalf("activation after fence = %+v, want the pre-fence HEALTHY snapshot untouched", snap)
	}
}

func TestApplyProbeOutcomeRejectsFencedForward(t *testing.T) {
	a, d, _, _ := p12wLifecycleApp(t, time.Hour)
	spec := lifecycleGatewaySpec("fwd-probe-fence", 1)
	if _, err := d.apply(context.Background(), spec); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitForKeepalive(t, a, "fwd-probe-fence", "HEALTHY")
	act := a.activation("fwd-probe-fence")
	if act == nil {
		t.Fatal("no activation after apply")
	}

	// Positive control: an unfenced probe outcome is accepted. The outcome must
	// be a valid wan_reachability_state axis value (REJECTED); RecordProbeOutcome
	// writes the outcome string directly into the axis.
	payload, err := json.Marshal(map[string]any{
		"forward_id": "fwd-probe-fence", "activation": act.ActivationID(),
		"generation": act.Generation(), "outcome": "REJECTED",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.applyProbeOutcome(control.Operation{MessageType: "probe_outcome", Payload: payload}); err != nil {
		t.Fatalf("positive control probe outcome: %v", err)
	}

	// The durable deletion fence makes a LATER outcome stale.
	if _, err := a.store.PutForwardDeleteIntent(localstate.ForwardDeleteIntent{
		ForwardID: "fwd-probe-fence", DeletionOperationID: "del-probe-1", DesiredRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.applyProbeOutcome(control.Operation{MessageType: "probe_outcome", Payload: payload}); !errors.Is(err, reconcile.ErrStaleEvent) {
		t.Fatalf("fenced probe outcome error = %v, want ErrStaleEvent", err)
	}
}
