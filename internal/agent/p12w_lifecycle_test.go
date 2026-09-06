// P12W Story 7: OnMapping* lifecycle callbacks drive the frozen activation
// axes through the real renewal loop. A scripted mapper forces consecutive
// renewal failures (DEGRADED), then a short-grant crossing of the expiry
// safety margin (LOST with publication STALE + WAN NOT_TESTED), then a
// success (HEALTHY recovery) — all asserted through App.activation(),
// SaveActivationSnapshot and sendActivationStatus.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// p12wRenewMapper is a scripted PCP mapper whose renewals can be failed or
// succeeded on demand, and which grants a custom lease (the granted lifetime
// paces the production renewal loop).
type p12wRenewMapper struct {
	p12wMapper
	mu           sync.Mutex
	renewals     int
	renewErr     error
	grantedLease time.Duration
}

func (m *p12wRenewMapper) Map(ctx context.Context, req traversal.GatewayMapRequest) (traversal.GatewayMapping, error) {
	mapping, err := m.p12wMapper.Map(ctx, req)
	if err != nil {
		return mapping, err
	}
	m.mu.Lock()
	granted := m.grantedLease
	m.mu.Unlock()
	if granted > 0 {
		mapping.Lease = granted
	}
	return mapping, nil
}

func (m *p12wRenewMapper) Renew(ctx context.Context, mapping traversal.GatewayMapping, lifetime time.Duration) (traversal.GatewayMapping, error) {
	m.mu.Lock()
	m.renewals++
	renewErr := m.renewErr
	granted := m.grantedLease
	m.mu.Unlock()
	if renewErr != nil {
		return traversal.GatewayMapping{}, renewErr
	}
	mapping.Lease = lifetime
	if granted > 0 {
		mapping.Lease = granted
	}
	return mapping, nil
}

func (m *p12wRenewMapper) setRenewErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.renewErr = err
}

func (m *p12wRenewMapper) renewalCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.renewals
}

// recordingLifecycleClient captures status messages so the test can assert
// that save+send happened, without a real control transport.
type recordingLifecycleClient struct {
	mu       sync.Mutex
	statuses [][]byte
}

func (c *recordingLifecycleClient) Connect(context.Context) error { return nil }
func (c *recordingLifecycleClient) SendMessage(ctx context.Context, mt string, p []byte) error {
	if mt == "status" {
		c.mu.Lock()
		c.statuses = append(c.statuses, append([]byte(nil), p...))
		c.mu.Unlock()
	}
	return nil
}
func (c *recordingLifecycleClient) Close()    {}
func (c *recordingLifecycleClient) Shutdown() {}
func (c *recordingLifecycleClient) Wait()     {}

func (c *recordingLifecycleClient) statusCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.statuses)
}

func (c *recordingLifecycleClient) statusPayloads() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.statuses))
	for i, payload := range c.statuses {
		out[i] = append([]byte(nil), payload...)
	}
	return out
}

// p12wLifecycleApp composes the agent wiring exactly like New() for the
// lifecycle tests: the gateway manager carries the OnMapping* handlers and the
// data plane publishes via onForwardApplied.
func p12wLifecycleApp(t *testing.T, granted time.Duration) (*App, *dataPlane, *p12wRenewMapper, *recordingLifecycleClient) {
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
		grantedLease: granted,
	}
	obs := &p12wObserver{result: netip.MustParseAddrPort("100.64.0.2:51234")}
	journal := traversal.NewMemoryJournal()
	client := &recordingLifecycleClient{}
	d := newDataPlane(dataPlaneConfig{Store: st, RouteTable: p12wRouteTable{}, Clock: time.Now,
		RenewalPacing: func() (time.Duration, time.Duration) { return 20 * time.Millisecond, time.Millisecond }})
	a := &App{store: st, dp: d, client: client, activations: make(map[string]*reconcile.Activation)}
	manager := traversal.NewManager(traversal.ManagerOptions{
		RouteTable:         p12wRouteTable{},
		Listeners:          &p12wListenerSource{},
		Mappers:            map[traversal.MappingLayerKind]traversal.GatewayMapper{traversal.LayerPCP: mapper},
		Journal:            journal,
		StunObserve:        obs.observe,
		OnMappingDegraded:  a.onMappingDegraded,
		OnMappingLost:      a.onMappingLost,
		OnMappingRecovered: a.onMappingRecovered,
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
	d.cfg.OnApplied = a.onForwardApplied
	t.Cleanup(func() { _ = d.closeAll(context.Background()) })
	return a, d, mapper, client
}

func lifecycleGatewaySpec(forwardID string, revision uint64) protocol.ForwardSpec {
	return protocol.ForwardSpec{
		ForwardID: forwardID, Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:9",
		Strategy: protocol.StrategyExplicitGateway, DesiredRevision: revision, Presence: protocol.PresencePresent,
	}
}

// waitForKeepalive waits until the activation's keepalive axis settles on want.
func waitForKeepalive(t *testing.T, a *App, forwardID, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := a.ActivationSnapshot(forwardID)
		if snap != nil && snap.KeepaliveState == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	snap := a.ActivationSnapshot(forwardID)
	t.Fatalf("keepalive_state never became %q (got %+v)", want, snap)
}

// waitForSavedKeepalive waits until the PERSISTED activation snapshot's
// keepalive axis settles on want. The in-memory activation is updated before
// SaveActivationSnapshot completes, so a test that polls only the in-memory
// state and then reads the store once can race the durable write (repair R1
// finding 6). Polling the saved snapshot closes that window.
func waitForSavedKeepalive(t *testing.T, a *App, forwardID, want string) {
	t.Helper()
	if a.store == nil {
		t.Fatal("waitForSavedKeepalive requires a store")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		saved, ok, err := a.store.LoadActivationSnapshot(forwardID)
		if err != nil {
			t.Fatal(err)
		}
		if ok && saved.States.KeepaliveState == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	saved, ok, err := a.store.LoadActivationSnapshot(forwardID)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("saved keepalive_state never became %q (ok=%v snapshot=%+v)", want, ok, saved)
}

func TestInitialApplyPublishesActivationStatus(t *testing.T) {
	a, d, _, client := p12wLifecycleApp(t, time.Hour)
	if _, err := d.apply(context.Background(), lifecycleGatewaySpec("fwd-initial-status", 1)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var status struct {
		ForwardID  string `json:"forward_id"`
		Generation uint64 `json:"generation"`
		Snapshot   struct {
			ListenerState  string `json:"listener_state"`
			DataPlaneState string `json:"data_plane_state"`
		} `json:"snapshot"`
	}
	found := false
	for _, payload := range client.statusPayloads() {
		if err := json.Unmarshal(payload, &status); err != nil {
			t.Fatalf("decode activation status: %v", err)
		}
		if status.ForwardID == "fwd-initial-status" && status.Generation == 1 {
			found = true
			if status.Snapshot.ListenerState != "READY" || status.Snapshot.DataPlaneState != "READY" {
				t.Fatalf("initial activation status snapshot = %+v, want READY listener/data plane", status.Snapshot)
			}
		}
	}
	if !found {
		t.Fatalf("initial activation status was not sent (count=%d, activation=%+v)", client.statusCount(), a.ActivationSnapshot("fwd-initial-status"))
	}
}

// Story 7 (a): three consecutive renewal failures set keepalive_state DEGRADED
// and a later success recovers to HEALTHY, with the snapshot persisted and the
// status sent.
func TestMappingLifecycleDegradedThenRecovered(t *testing.T) {
	a, d, mapper, client := p12wLifecycleApp(t, time.Hour) // long grant: margin far away
	if _, err := d.apply(context.Background(), lifecycleGatewaySpec("fwd-life", 1)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	waitForKeepalive(t, a, "fwd-life", "HEALTHY")
	snap := a.ActivationSnapshot("fwd-life")
	if snap.MappingState != "FIRST_HOP_MAPPED" {
		t.Fatalf("initial mapping_state = %q, want FIRST_HOP_MAPPED", snap.MappingState)
	}

	mapper.setRenewErr(errors.New("gateway gone"))
	waitForKeepalive(t, a, "fwd-life", "DEGRADED")

	mapper.setRenewErr(nil)
	waitForKeepalive(t, a, "fwd-life", "HEALTHY")
	// The durable write races the in-memory poll (repair R1 finding 6):
	// wait for the SAVED snapshot to report HEALTHY before the final assertion.
	waitForSavedKeepalive(t, a, "fwd-life", "HEALTHY")

	if client.statusCount() == 0 {
		t.Fatal("no activation status was sent through sendActivationStatus")
	}
	// The state was durably persisted each transition.
	saved, ok, err := a.store.LoadActivationSnapshot("fwd-life")
	if err != nil || !ok {
		t.Fatalf("saved snapshot ok=%v err=%v", ok, err)
	}
	if saved.States.KeepaliveState != "HEALTHY" {
		t.Fatalf("saved keepalive = %q, want HEALTHY", saved.States.KeepaliveState)
	}
}

// Story 7 (b): sustained failures crossing the expiry safety margin set
// keepalive_state LOST, mapping_state LOST, publication_state STALE and
// wan_reachability NOT_TESTED.
func TestMappingLifecycleLostAtExpiryMargin(t *testing.T) {
	a, d, mapper, _ := p12wLifecycleApp(t, 300*time.Millisecond) // margin = 30ms
	if _, err := d.apply(context.Background(), lifecycleGatewaySpec("fwd-lost", 1)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	mapper.setRenewErr(errors.New("gateway gone"))

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := a.ActivationSnapshot("fwd-lost")
		if snap != nil && snap.KeepaliveState == "LOST" {
			if snap.MappingState != "LOST" {
				t.Fatalf("mapping_state after loss = %q, want LOST", snap.MappingState)
			}
			if snap.PublicationState != "STALE" {
				t.Fatalf("publication_state after loss = %q, want STALE", snap.PublicationState)
			}
			if snap.WanReachabilityState != "NOT_TESTED" {
				t.Fatalf("wan_reachability after loss = %q, want NOT_TESTED", snap.WanReachabilityState)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	snap := a.ActivationSnapshot("fwd-lost")
	t.Fatalf("mapping never lost (snapshot %+v)", snap)
}
