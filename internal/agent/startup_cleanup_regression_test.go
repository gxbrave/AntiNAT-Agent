package agent

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/localstate"
	"github.com/gxbrave/AntiNAT-Agent/internal/agent/reconcile"
	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

type startupWaitClient struct {
	waited   atomic.Bool
	connects atomic.Int32
	waits    atomic.Int32
}

func (c *startupWaitClient) Connect(context.Context) error {
	c.connects.Add(1)
	return nil
}
func (c *startupWaitClient) SendMessage(context.Context, string, []byte) error { return nil }
func (c *startupWaitClient) Close()                                            {}
func (c *startupWaitClient) Shutdown()                                         {}
func (c *startupWaitClient) Wait() {
	c.waits.Add(1)
	c.waited.Store(true)
}

// TestStartRecoveryFailureWaitsForControlSession ensures every startup error
// path joins the control client before closing the localstate store. The fake
// client makes the lifecycle fence observable without relying on goroutine
// scheduling or a remote WebSocket's close timing.
func TestStartRecoveryFailureWaitsForControlSession(t *testing.T) {
	st, err := localstate.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	desired := protocol.DesiredState{NodeID: "node-startup", Forwards: []protocol.ForwardSpec{{
		ForwardID: "fwd-recovery", Protocol: protocol.ProtocolTCP, Target: "127.0.0.1:1",
		Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1,
	}}}
	applied := protocol.AppliedForwardState{
		ForwardID: "fwd-recovery", SpecRevision: 1, DesiredRevision: 1,
		ActualBindHost: "127.0.0.1", ActualBindPort: 40001,
		Strategy: "direct-v4", LayerVersion: 1, AppliedAtUnix: time.Now().Unix(),
	}
	if _, err := st.CommitDesired(desired, []localstate.ForwardApply{{
		ForwardID: "fwd-recovery", Outcome: localstate.ApplyApplied, Applied: &applied,
	}}); err != nil {
		st.Close()
		t.Fatal(err)
	}

	mgr := reconcile.NewProbeManager(reconcile.ProbeManagerOptions{Store: st, Clock: time.Now})
	routes := &mutableRouteTable{iface: "eth0", hasDefault: false}
	d := newDataPlane(dataPlaneConfig{Store: st, ProbeMgr: mgr, RouteTable: routes, Clock: time.Now})
	client := &startupWaitClient{}
	a := &App{
		cfg:         Config{LivenessInterval: time.Second, RouteTable: routes},
		store:       st,
		client:      client,
		probeMgr:    mgr,
		dp:          d,
		activations: make(map[string]*reconcile.Activation),
	}

	err = a.Start(context.Background())
	if err == nil {
		t.Fatal("Start unexpectedly succeeded without a direct-v4 route")
	}
	if !client.waited.Load() {
		t.Fatal("startup recovery failure did not wait for the control client")
	}
}

func TestTerminalMarkerStartupSkipsListenerRecovery(t *testing.T) {
	routes := &mutableRouteTable{
		gateway:    netip.MustParseAddr("192.168.1.1"),
		iface:      "eth0",
		hasDefault: true,
		addrs:      []traversal.IPv4Address{{Interface: "eth0", Addr: netip.MustParseAddr("8.8.8.8")}},
	}
	for _, marker := range []localstate.MarkerState{
		localstate.MarkerDecommissioning,
		localstate.MarkerDecommissioned,
	} {
		t.Run(marker.String(), func(t *testing.T) {
			st, err := localstate.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			desired := recoverySpec("fwd-terminal", "127.0.0.1:18081", 1)
			applied := recoveryApplied(desired, "8.8.8.8", 40001)
			if _, err := st.CommitDesired(protocol.DesiredState{NodeID: "node-terminal", Forwards: []protocol.ForwardSpec{desired}}, []localstate.ForwardApply{{
				ForwardID: "fwd-terminal", Outcome: localstate.ApplyApplied, Applied: &applied,
			}}); err != nil {
				_ = st.Close()
				t.Fatal(err)
			}
			mgr := reconcile.NewProbeManager(reconcile.ProbeManagerOptions{Store: st, Marker: marker, Clock: time.Now})
			d := newDataPlane(dataPlaneConfig{Store: st, ProbeMgr: mgr, RouteTable: routes, Clock: time.Now})
			client := &startupWaitClient{}
			a := &App{
				cfg:    Config{LivenessInterval: time.Second, RouteTable: routes},
				marker: marker, store: st, client: client, probeMgr: mgr, dp: d,
				activations: make(map[string]*reconcile.Activation),
			}
			if err := a.Start(context.Background()); err != nil {
				_ = st.Close()
				t.Fatal(err)
			}
			if err := a.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			d.mu.Lock()
			forwards := len(d.forwards)
			d.mu.Unlock()
			if forwards != 0 {
				t.Fatalf("terminal startup recovered %d listener(s), want none", forwards)
			}
		})
	}
}

func TestTerminalMarkerSkipsLivenessRecovery(t *testing.T) {
	routes := &mutableRouteTable{
		gateway:    netip.MustParseAddr("192.168.1.1"),
		iface:      "eth0",
		hasDefault: true,
		addrs:      []traversal.IPv4Address{{Interface: "eth0", Addr: netip.MustParseAddr("8.8.8.8")}},
	}
	d := newDataPlane(dataPlaneConfig{RouteTable: routes, Clock: time.Now})
	d.mu.Lock()
	d.capabilityReady = false
	d.mu.Unlock()
	a := &App{
		cfg:    Config{LivenessInterval: time.Millisecond, RouteTable: routes},
		marker: localstate.MarkerDecommissioning,
		dp:     d,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.monitorLiveness(ctx)
	time.Sleep(25 * time.Millisecond)
	d.mu.Lock()
	ready := d.capabilityReady
	d.mu.Unlock()
	if ready {
		t.Fatal("terminal-marker liveness restored data-plane capability")
	}
}

func TestTerminalMarkerSkipsControlReconnect(t *testing.T) {
	client := &startupWaitClient{}
	a := &App{marker: localstate.MarkerDecommissioned, client: client}
	a.reconnectControl(context.Background())
	if got := client.connects.Load(); got != 0 {
		t.Fatalf("terminal reconnect attempts = %d, want 0", got)
	}
	if got := client.waits.Load(); got != 0 {
		t.Fatalf("terminal reconnect waits = %d, want 0", got)
	}
}
