// Story 5 RED: honest concurrent mapping evidence (v0.8 §4.2). Two
// destinations are observed from one local tuple. EIM_OBSERVED_CONCURRENT is
// recorded only when the platform gate passes AND the first connection stays
// ESTABLISHED while the second observation completes. Otherwise the
// sequential result is PORT_REUSE_OBSERVED (same mapped port across
// destinations) or MAPPED_UNVERIFIED — never a claimed EIM.
package stun

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// observeTCPServer is a fake STUN TCP server whose reported mapped address
// can be overridden (to simulate NAT divergence) and which can close right
// after its response (to simulate a dropping first connection).
type observeTCPServer struct {
	*fakeTCPServer
	mappedOverride *netip.AddrPort
}

func newObserveTCPServer(t *testing.T) *observeTCPServer {
	t.Helper()
	server := &observeTCPServer{fakeTCPServer: newFakeTCPServer(t)}
	server.mu.Lock()
	server.handler = server.handleRequest
	server.mu.Unlock()
	return server
}

func (s *observeTCPServer) handleRequest(msg *Message, from netip.AddrPort) []replySpec {
	_ = from
	mapped := from
	if s.mappedOverride != nil {
		mapped = *s.mappedOverride
	}
	reply := &Message{Type: MessageTypeBindingSuccess, TransactionID: msg.TransactionID}
	_ = reply.AddXORMappedAddress(mapped)
	return []replySpec{{msg: reply}}
}

func TestObserveMappingEIMConcurrent(t *testing.T) {
	if !SharedPortSupported() {
		t.Skip("concurrent mapping evidence requires the native shared-port gate")
	}
	serverA := newObserveTCPServer(t)
	serverB := newObserveTCPServer(t)
	observation, err := ObserveMapping(context.Background(), ObserveMappingOptions{
		LocalIP: netip.MustParseAddr("127.0.0.1"),
		ServerA: serverA.addr,
		ServerB: serverB.addr,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("ObserveMapping: %v", err)
	}
	if observation.Verdict != VerdictEIMObservedConcurrent {
		t.Fatalf("verdict = %s, want EIM_OBSERVED_CONCURRENT", observation.Verdict)
	}
	if !observation.Concurrent {
		t.Fatal("observation not flagged concurrent")
	}
	if !observation.PlatformGate {
		t.Fatal("platform gate not recorded as passing")
	}
	if !observation.FirstConnStayedEstablished {
		t.Fatal("first connection not recorded as staying established")
	}
	if observation.MappedA != observation.MappedB {
		t.Fatalf("mapped endpoints differ: %v vs %v", observation.MappedA, observation.MappedB)
	}
}

func TestObserveMappingGateOffSequentialPortReuse(t *testing.T) {
	// Gate forced off: only sequential observation is allowed; the same
	// local port observed across both destinations yields
	// PORT_REUSE_OBSERVED, never EIM.
	serverA := newObserveTCPServer(t)
	serverB := newObserveTCPServer(t)
	observation, err := ObserveMapping(context.Background(), ObserveMappingOptions{
		LocalIP:       netip.MustParseAddr("127.0.0.1"),
		ServerA:       serverA.addr,
		ServerB:       serverB.addr,
		Timeout:       2 * time.Second,
		PlatformGate:  func() bool { return false },
		ReuseControl:  traversal.StunSharedPortControl,
		SameLocalPort: true,
	})
	if err != nil {
		t.Fatalf("ObserveMapping: %v", err)
	}
	if observation.Verdict != VerdictPortReuseObserved {
		t.Fatalf("verdict = %s, want PORT_REUSE_OBSERVED", observation.Verdict)
	}
	if observation.Concurrent {
		t.Fatal("sequential observation flagged concurrent")
	}
	if observation.PlatformGate {
		t.Fatal("gate-off run recorded gate as passing")
	}
}

func TestObserveMappingSameLocalPortDefaultReuseControl(t *testing.T) {
	// ReuseControl is documented as defaulting to the shared-port reuse
	// options: a gate-off sequential observation with SameLocalPort must
	// succeed without the caller setting the hook — the first socket's
	// TIME_WAIT must not block the same-tuple rebind (QUALITY #1).
	serverA := newObserveTCPServer(t)
	serverB := newObserveTCPServer(t)
	observation, err := ObserveMapping(context.Background(), ObserveMappingOptions{
		LocalIP:       netip.MustParseAddr("127.0.0.1"),
		ServerA:       serverA.addr,
		ServerB:       serverB.addr,
		Timeout:       2 * time.Second,
		PlatformGate:  func() bool { return false },
		SameLocalPort: true,
	})
	if err != nil {
		t.Fatalf("ObserveMapping: %v", err)
	}
	if observation.Verdict != VerdictPortReuseObserved {
		t.Fatalf("verdict = %s, want PORT_REUSE_OBSERVED", observation.Verdict)
	}
}

func TestObserveMappingGateOffMappedUnverified(t *testing.T) {
	// Gate off and diverging mapped ports: nothing is verified.
	divergent := netip.MustParseAddrPort("198.51.100.9:5000")
	serverA := newObserveTCPServer(t)
	serverB := newObserveTCPServer(t)
	serverB.mappedOverride = &divergent
	observation, err := ObserveMapping(context.Background(), ObserveMappingOptions{
		LocalIP:       netip.MustParseAddr("127.0.0.1"),
		ServerA:       serverA.addr,
		ServerB:       serverB.addr,
		Timeout:       2 * time.Second,
		PlatformGate:  func() bool { return false },
		ReuseControl:  traversal.StunSharedPortControl,
		SameLocalPort: true,
	})
	if err != nil {
		t.Fatalf("ObserveMapping: %v", err)
	}
	if observation.Verdict != VerdictMappedUnverified {
		t.Fatalf("verdict = %s, want MAPPED_UNVERIFIED", observation.Verdict)
	}
	if observation.Concurrent {
		t.Fatal("sequential observation flagged concurrent")
	}
}

func TestObserveMappingFirstConnectionDroppedFallsBack(t *testing.T) {
	// Gate passes, but the first connection closes before the second
	// observation finishes: EIM must NOT be recorded; the honest sequential
	// result (port reuse observed) is returned instead.
	if !SharedPortSupported() {
		t.Skip("concurrent mapping evidence requires the native shared-port gate")
	}
	serverA := newObserveTCPServer(t)
	serverA.closeAfterResp = 1 // respond once, then close
	serverB := newObserveTCPServer(t)
	observation, err := ObserveMapping(context.Background(), ObserveMappingOptions{
		LocalIP: netip.MustParseAddr("127.0.0.1"),
		ServerA: serverA.addr,
		ServerB: serverB.addr,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("ObserveMapping: %v", err)
	}
	if observation.Verdict == VerdictEIMObservedConcurrent {
		t.Fatalf("EIM recorded although the first connection dropped: %+v", observation)
	}
	if observation.FirstConnStayedEstablished {
		t.Fatal("dropped first connection recorded as established")
	}
	if observation.Verdict != VerdictPortReuseObserved && observation.Verdict != VerdictMappedUnverified {
		t.Fatalf("verdict = %s, want PORT_REUSE_OBSERVED or MAPPED_UNVERIFIED", observation.Verdict)
	}
}
