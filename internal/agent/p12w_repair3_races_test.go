// P12W repair-cycle-3 race probes (quality/security review of repair-2):
// the reviewer found two genuine data races on the synchronized dataPlane.cfg —
// newStunOnlyActor read d.cfg.StunObserver/StunSource unlocked while
// rebuildTraversal re-publishes them under dataPlane.mu, and runDetection read
// d.cfg.Detector the same way. These tests interleave exactly those goroutines
// so the `-race` detector is the oracle: with the route.cfg snapshot / locked
// Detector snapshot fixes they must be race-free, and they would fail loudly if
// a future change reintroduces an unlocked d.cfg read.
package agent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// p12wSameTupleSource is a minimal SameTupleDialer for the stun-only race
// probe; no dial is ever exercised by the probe.
type p12wSameTupleSource struct {
	p12wListenerSource
}

func (s *p12wSameTupleSource) DialFrom(ctx context.Context, bind traversal.TupleKey, remote string) (net.Conn, error) {
	return nil, errors.New("no dial exercised in the stun-only race probe")
}

func TestDataPlaneStunOnlyAcquireConcurrentWithRebuildNoDataRace(t *testing.T) {
	result := netip.MustParseAddrPort("100.64.0.2:51234")
	obs := (&p12wObserver{result: result}).observe
	d := newDataPlane(dataPlaneConfig{
		RouteTable:   p12wRouteTable{},
		Clock:        time.Now,
		StunServers:  []string{"stun+tcp://100.64.0.1:3478"},
		StunSource:   &p12wSameTupleSource{},
		StunObserver: obs,
	})
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })

	spec := protocol.ForwardSpec{
		ForwardID: "fwd-stun-race", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyStunOnly, DesiredRevision: 1, Presence: protocol.PresencePresent,
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	// Simulated liveness rebuild: republish fresh observer/source pointers under
	// dataPlane.mu exactly as rebuildTraversal does (repair-2 finding-6 review).
	// This is the READER the probe must not race: newStunOnlyActor used to read
	// d.cfg.StunObserver/StunSource with no lock.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			d.mu.Lock()
			d.cfg.StunObserver = obs
			d.cfg.StunSource = &p12wSameTupleSource{}
			d.mu.Unlock()
		}
	}()

	// The stun-only path must read its traversal seams from route.cfg (the
	// synchronized snapshot) while the rebuild writes above race it.
	var firstErr error
	for i := 0; i < 200; i++ {
		route, err := d.resolveForwardRoute(spec)
		if err != nil {
			firstErr = err
			break
		}
		backend, err := forward.NewBackend(spec.Target)
		if err != nil {
			firstErr = err
			break
		}
		actor, aerr := d.newForwardActorResolved(context.Background(), spec, backend, "", 0, route)
		if aerr != nil {
			firstErr = aerr
			break
		}
		d.abandonAcquiredActor(spec.ForwardID, actor)
	}
	close(stop)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("stun-only acquire under concurrent rebuilds: %v", firstErr)
	}
}

func TestDataPlaneRunDetectionConcurrentWithRebuildNoDataRace(t *testing.T) {
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
		StunServers: []string{"stun+tcp://100.64.0.1:3478"},
		StunObserve: fakeObserve,
	})
	profiles := newProfileStore(t.TempDir())
	d := newDataPlane(dataPlaneConfig{Clock: time.Now, Detector: detector, ProfileStore: profiles})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	// Simulated liveness rebuild: rebuildTraversal re-publishes the Detector
	// pointer under dataPlane.mu while the detection loop runs (repair-2
	// finding-6 review). This writes the SAME field runDetection used to read
	// unlocked.
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			d.mu.Lock()
			d.cfg.Detector = detector
			d.mu.Unlock()
		}
	}()
	// runDetection is called serially so the probe targets the FIELD access
	// (the lock discipline around the Detector pointer) and not any detector
	// internals shared across concurrent Run calls.
	for i := 0; i < 25; i++ {
		if err := d.runDetection(context.Background()); err != nil {
			t.Logf("detection pass %d failed (ok for the race probe): %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}
