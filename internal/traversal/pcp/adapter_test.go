package pcp

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func netipMustParse(text string) netip.Addr { return netip.MustParseAddr(text) }

func controlServerFor(address string) traversal.ControlServer {
	return traversal.ControlServer{Mechanism: traversal.LayerPCP, Address: address}
}

// Story 5 RED: the PCP adapter bridges the wire client to the normalized
// traversal.GatewayMapper contract with strong ownership evidence.

// A1: the adapter advertises the honest mechanism identity and capability.
func TestAdapterIdentity(t *testing.T) {
	adapter := NewAdapter(AdapterOptions{})
	if adapter.Mechanism() != traversal.LayerPCP {
		t.Fatalf("mechanism = %q, want pcp", adapter.Mechanism())
	}
	if adapter.Ownership() != traversal.OwnershipStrong {
		t.Fatalf("ownership = %q, want STRONG_PROTOCOL_OWNERSHIP", adapter.Ownership())
	}
	capability := adapter.Capability()
	if !capability.CanRequestExact || !capability.CanRetryCandidate {
		t.Fatalf("PCP capability = %+v, want exact+retry", capability)
	}
}

// A2: Discover probes the gateway with ANNOUNCE and reports the control
// server with the observed epoch.
func TestAdapterDiscover(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if request[1]&0x7f == OpCodeAnnounce {
			response := make([]byte, HeaderSize)
			response[0] = Version
			response[1] = ResponseFlag | OpCodeAnnounce
			response[3] = ResultSuccess
			putUint32(response[8:12], 0x0f00)
			return response
		}
		return successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	control, err := adapter.Discover(t.Context())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if control.Mechanism != traversal.LayerPCP {
		t.Fatalf("mechanism = %q, want pcp", control.Mechanism)
	}
	if control.Address != server.peer.String() {
		t.Fatalf("control address = %q, want %q", control.Address, server.peer.String())
	}
}

// A3: Map returns the normalized mapping with the strong-ownership nonce in
// State, and the non-global assigned endpoint classifies as FIRST_HOP
// evidence — never a public candidate.
func TestAdapterMapAndEvidence(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		response := successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
		// A real gateway assigns the external port itself.
		putUint16(response[HeaderSize+18:HeaderSize+20], 43111)
		return response
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP:   netipMustParse("127.0.0.1"),
		InternalPort: 3111,
		Lease:        time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapping.Mechanism != traversal.LayerPCP || mapping.Ownership != traversal.OwnershipStrong {
		t.Fatalf("mapping identity = %s/%s", mapping.Mechanism, mapping.Ownership)
	}
	if mapping.External.Port() == 0 {
		t.Fatal("normalized mapping must carry the assigned external port")
	}
	if _, ok := mapping.State.(MapResult); !ok {
		t.Fatalf("State = %T, want the PCP MapResult renewal state", mapping.State)
	}

	evidence := mapping.Evidence(controlServerFor(server.peer.String()))
	verdict, err := traversal.EvaluateLayers([]traversal.LayerEvidence{evidence}, traversal.PortPolicyAcceptAssigned)
	if err != nil {
		t.Fatalf("EvaluateLayers: %v", err)
	}
	if verdict.PublicCandidate {
		t.Fatal("a TEST-NET assigned endpoint must never be a public candidate")
	}
	if verdict.Scope != traversal.ScopeFirstHop {
		t.Fatalf("scope = %q, want FIRST_HOP", verdict.Scope)
	}
}

// A5 (NAT audit H1): the ANNOUNCE header must carry the datagram's real
// source address (RFC 6887 §8.2). A wildcard-bound socket reports 0.0.0.0
// in LocalAddr and a compliant gateway answers ADDRESS_MISMATCH, so
// Discover resolves the route-selected source before binding.
func TestAdapterDiscoverNamesRealSourceAddress(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if request[1]&0x7f == OpCodeAnnounce {
			// Toward a loopback server the datagram source is 127.0.0.1.
			want := v4Mapped(netipMustParse("127.0.0.1"))
			if !equalBytes(request[8:24], want) {
				server.errorf("announce client address = % x, want the real source % x", request[8:24], want)
			}
			response := make([]byte, HeaderSize)
			response[0] = Version
			response[1] = ResponseFlag | OpCodeAnnounce
			response[3] = ResultSuccess
			putUint32(response[8:12], 0x0f00)
			return response
		}
		return successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	if _, err := adapter.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	assertServer(t, server)
}

// A6 (NAT audit H2): reboot detection must survive the adapter's
// per-transaction sockets — the epoch observed by the first transaction is
// the baseline of the next, so an epoch rollback in a renewal reports
// ServerRebooted.
func TestAdapterRenewDetectsRebootAcrossTransactions(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		epoch := uint32(0x1000)
		if seq >= 2 {
			epoch = 0x10 // rollback far beyond the 2s tolerance
		}
		return successResponse(request, netipMustParse("203.0.113.7"), epoch)
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP: netipMustParse("127.0.0.1"), InternalPort: 3111, Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapping.ServerRebooted {
		t.Fatal("the first transaction has no baseline and must not claim a reboot")
	}
	renewed, err := adapter.Renew(t.Context(), mapping, time.Hour)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !renewed.ServerRebooted {
		t.Fatal("an epoch rollback across transactions must report ServerRebooted")
	}
}

// A4: Delete passes the owning state back through the adapter.
func TestAdapterDeleteRoundTrip(t *testing.T) {
	var mu sync.Mutex
	deleteSeen := false
	var seenNonce [12]byte
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			return successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
		}
		lifetime := readUint32(request[4:8])
		if lifetime != 0 {
			server.errorf("delete lifetime = %d, want 0", lifetime)
		}
		mu.Lock()
		copy(seenNonce[:], request[HeaderSize:HeaderSize+12])
		deleteSeen = true
		mu.Unlock()
		response := successResponse(request, netipMustParse("203.0.113.7"), 0x0f00)
		putUint32(response[4:8], 0)
		return response
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP:   netipMustParse("127.0.0.1"),
		InternalPort: 3111,
		Lease:        time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if err := adapter.Delete(t.Context(), mapping); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	state := mapping.State.(MapResult)
	mu.Lock()
	seen, nonce := deleteSeen, seenNonce
	mu.Unlock()
	if !seen || nonce != state.Nonce {
		t.Fatalf("delete must carry the owning nonce (seen=%v nonce=%v)", deleteSeen, seenNonce)
	}
}

// A7 (quality/security review L3): a Gateway given as an address without a
// port takes the registered PCP port 5351 instead of being zeroed into a
// discover failure.
func TestAdapterDefaultsGatewayPort(t *testing.T) {
	addrOnly := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0)
	adapter := NewAdapter(AdapterOptions{Gateway: addrOnly})
	if adapter.gateway.Port() != DefaultServerPort {
		t.Fatalf("gateway port = %d, want the registered %d", adapter.gateway.Port(), DefaultServerPort)
	}
	if adapter.gateway.Addr().String() != "10.0.0.1" {
		t.Fatalf("gateway address = %s, want the given address preserved", adapter.gateway.Addr())
	}
}
