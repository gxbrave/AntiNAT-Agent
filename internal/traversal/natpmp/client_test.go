// Package natpmp implements the RFC 6886 NAT-PMP client subset the AntiNAT
// v1 gateway layer needs: public-address discovery, TCP/UDP MAP with the
// requested port treated strictly as a suggestion, epoch/reboot detection,
// bounded retry, weak lease ownership, and lifetime=0 deletes that always
// refuse internal port 0. ANNOUNCE and the NAT-PMP/PCP compatibility
// namespace are v1 non-goals.
package natpmp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

func newPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client packet conn: %v", err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	return packet
}

// fakeServer mirrors the pcp test gateway: deterministic responses scripted
// per request sequence, assertions replayed on the test goroutine.
type fakeServer struct {
	peer     netip.AddrPort
	mu       sync.Mutex
	script   func(seq int, request []byte) []byte
	requests [][]byte
	failures []string
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake NAT-PMP server listen: %v", err)
	}
	server := &fakeServer{peer: netip.MustParseAddrPort(packet.LocalAddr().String())}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := packet.ReadFrom(buf)
			if err != nil {
				return
			}
			request := append([]byte(nil), buf[:n]...)
			server.mu.Lock()
			server.requests = append(server.requests, request)
			seq := len(server.requests)
			script := server.script
			server.mu.Unlock()
			if script == nil {
				continue
			}
			response := script(seq, request)
			if response == nil {
				continue
			}
			if _, err := packet.WriteTo(response, from); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = packet.Close() })
	return server
}

func (s *fakeServer) handle(script func(seq int, request []byte) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.script = script
}

func (s *fakeServer) errorf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures = append(s.failures, fmt.Sprintf(format, args...))
}

func (s *fakeServer) failureMessage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.failures) == 0 {
		return ""
	}
	return s.failures[0]
}

func (s *fakeServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func assertServer(t *testing.T, server *fakeServer) {
	t.Helper()
	if msg := server.failureMessage(); msg != "" {
		t.Fatal(msg)
	}
}

// mapResponse crafts a success MAP response: opcode + 128 echo, result,
// epoch, internal port echo, assigned port, lifetime.
func mapResponseBytes(request []byte, assignedPort uint16, lifetime uint32, epoch uint32) []byte {
	response := make([]byte, 16)
	response[0] = Version
	response[1] = request[1] + ResponseOpBase
	putUint16(response[2:4], ResultSuccess)
	putUint32(response[4:8], epoch)
	copy(response[8:10], request[4:6]) // internal port echo
	putUint16(response[10:12], assignedPort)
	putUint32(response[12:16], lifetime)
	return response
}

// --- wire golden vector -----------------------------------------------------

// R1: the TCP MAP request wire format is byte-exact (RFC 6886 §3.2):
// version 0, TCP opcode 2, reserved, internal port, requested port,
// lifetime seconds.
func TestMapGoldenRequestBytes(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		want := []byte{
			0x00, 0x02, // version 0, TCP map opcode
			0x00, 0x00, // reserved
			0x0c, 0x27, // internal port 3111
			0xa8, 0x67, // requested external port 43111
			0x00, 0x00, 0x0e, 0x10, // lifetime 3600
		}
		if len(request) != len(want) {
			server.errorf("request length = %d, want %d: % x", len(request), len(want), request)
			return mapResponseBytes(request, 43111, 3600, 0x0f00)
		}
		for i := range want {
			if request[i] != want[i] {
				server.errorf("request byte %d = %02x, want %02x: % x", i, request[i], want[i], request)
				break
			}
		}
		return mapResponseBytes(request, 43111, 3600, 0x0f00)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	result, err := client.Map(t.Context(), MapRequest{
		Protocol:              ProtocolTCP,
		InternalPort:          3111,
		RequestedExternalPort: 43111,
		Lifetime:              time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	assertServer(t, server)
	if result.AssignedExternalPort != 43111 {
		t.Fatalf("assigned port = %d, want 43111", result.AssignedExternalPort)
	}
	if result.Lifetime != time.Hour {
		t.Fatalf("granted lifetime = %s, want 1h", result.Lifetime)
	}
	if result.Epoch != 0x0f00 {
		t.Fatalf("epoch = %d, want 3840", result.Epoch)
	}
}

// R1b: the public-address request is 4 bytes and the response carries the
// gateway's external IPv4; this is also the NAT-PMP discovery probe.
func TestPublicAddress(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if len(request) != 4 || request[0] != Version || request[1] != OpPublicAddress {
			server.errorf("public address request malformed: % x", request)
		}
		response := make([]byte, 12)
		response[0] = Version
		response[1] = OpPublicAddress + ResponseOpBase
		putUint16(response[2:4], ResultSuccess)
		putUint32(response[4:8], 0x0f00)
		a4 := netip.MustParseAddr("8.8.8.8").As4()
		copy(response[8:12], a4[:])
		return response
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	addr, epoch, err := client.PublicAddress(t.Context())
	if err != nil {
		t.Fatalf("PublicAddress: %v", err)
	}
	assertServer(t, server)
	if addr.String() != "8.8.8.8" {
		t.Fatalf("external address = %s, want 8.8.8.8", addr)
	}
	if epoch != 0x0f00 {
		t.Fatalf("epoch = %d, want 3840", epoch)
	}
}

// R2: the requested external port is only a suggestion: the assigned port in
// the response is authoritative and is what the result records.
func TestMapAssignedPortIsAuthoritative(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		return mapResponseBytes(request, 55555, 7200, 100)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	result, err := client.Map(t.Context(), MapRequest{
		Protocol:              ProtocolUDP,
		InternalPort:          3111,
		RequestedExternalPort: 43111,
		Lifetime:              time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	assertServer(t, server)
	if result.AssignedExternalPort != 55555 {
		t.Fatalf("assigned port = %d, want the gateway-assigned 55555", result.AssignedExternalPort)
	}
}

// R3: result codes are definitive failures and never retried (RFC 6886 has
// no transient codes; only transport timeouts retransmit).
func TestMapResultCodes(t *testing.T) {
	cases := []struct {
		code uint16
		want error
	}{
		{ResultUnsupportedVersion, ErrUnsupportedVersion},
		{ResultNotAuthorized, ErrNotAuthorized},
		{ResultOutOfResources, ErrOutOfResources},
	}
	for _, tc := range cases {
		server := newFakeServer(t)
		server.handle(func(seq int, request []byte) []byte {
			response := mapResponseBytes(request, 43111, 3600, 100)
			putUint16(response[2:4], tc.code)
			return response
		})
		client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
		_, err := client.Map(t.Context(), MapRequest{
			Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
		})
		if !errors.Is(err, tc.want) {
			t.Fatalf("result %d: error = %v, want %v", tc.code, err, tc.want)
		}
		if got := server.requestCount(); got != 1 {
			t.Fatalf("result %d: definitive failures never retry, got %d requests", tc.code, got)
		}
	}
}

// R4: transport timeouts retransmit within the bounded attempt budget.
func TestMapTimeoutRetryThenSucceeds(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			return nil // drop: timeout fault
		}
		return mapResponseBytes(request, 43111, 3600, 100)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{
		Timeout: 150 * time.Millisecond, Backoff: time.Millisecond,
	})
	if _, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, RequestedExternalPort: 43111, Lifetime: time.Hour,
	}); err != nil {
		t.Fatalf("timeout retry must succeed: %v", err)
	}
	assertServer(t, server)
	if got := server.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

// R4b: exhausted retries surface ErrNoResponse.
func TestMapExhaustedRetries(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte { return nil })

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{
		Timeout: 50 * time.Millisecond, Backoff: time.Millisecond, MaxAttempts: 2,
	})
	if _, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
	}); !errors.Is(err, ErrNoResponse) {
		t.Fatalf("error = %v, want ErrNoResponse", err)
	}
	if got := server.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want exactly MaxAttempts", got)
	}
}

// R5: epoch rollback beyond the 2s tolerance reports a gateway reboot so
// publication state goes stale (weak lease: the mapping may be gone).
func TestMapEpochRollbackDetectsReboot(t *testing.T) {
	epochs := []uint32{0x0f00, 0x0100}
	seq := 0
	server := newFakeServer(t)
	server.handle(func(_ int, request []byte) []byte {
		e := epochs[0]
		if seq > 0 {
			e = epochs[1]
		}
		seq++
		return mapResponseBytes(request, 43111, 3600, e)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	if _, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
	}); err != nil {
		t.Fatalf("first Map: %v", err)
	}
	result, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatalf("second Map: %v", err)
	}
	if !result.ServerRebooted {
		t.Fatal("epoch rollback must report ServerRebooted")
	}
}

// R5b: a 2s backward jitter is within the RFC tolerance.
func TestMapEpochSmallJitterNotReboot(t *testing.T) {
	epochs := []uint32{0x0f00, 0x0efe}
	seq := 0
	server := newFakeServer(t)
	server.handle(func(_ int, request []byte) []byte {
		e := epochs[0]
		if seq > 0 {
			e = epochs[1]
		}
		seq++
		return mapResponseBytes(request, 43111, 3600, e)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	if _, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
	}); err != nil {
		t.Fatalf("first Map: %v", err)
	}
	result, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatalf("second Map: %v", err)
	}
	if result.ServerRebooted {
		t.Fatal("a 2s backward jitter is within the tolerance")
	}
}

// R6: lifetime=0 deletes the exact owned mapping; the response carries
// lifetime 0.
func TestDeleteLifetimeZero(t *testing.T) {
	var deleteSeen atomic.Bool
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			return mapResponseBytes(request, 43111, 3600, 100)
		}
		if lifetime := readUint32(request[8:12]); lifetime != 0 {
			server.errorf("delete request lifetime = %d, want 0", lifetime)
		}
		if got := readUint16(request[6:8]); got != 0 {
			server.errorf("delete requested external port = %d, want 0 (RFC 6886 §3.4: the delete request zeroes the suggested external port)", got)
		}
		deleteSeen.Store(true)
		return mapResponseBytes(request, 0, 0, 100)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	mapping, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, RequestedExternalPort: 43111, Lifetime: time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	assertServer(t, server)
	result, err := client.Delete(t.Context(), mapping)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	assertServer(t, server)
	if !deleteSeen.Load() {
		t.Fatal("server never observed the delete request")
	}
	if result.Lifetime != 0 {
		t.Fatalf("delete result lifetime = %s, want 0", result.Lifetime)
	}
}

// R6b: deletes for mappings without an exact internal tuple are refused
// client-side and never sent: v1 never provides delete-all and always
// rejects internal port 0.
func TestDeleteRefusesZeroInternalPort(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		server.errorf("no request may be sent for an unowned delete")
		return nil
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	mapping := MapResult{InternalPort: 0, AssignedExternalPort: 43111}
	if _, err := client.Delete(t.Context(), mapping); !errors.Is(err, ErrUnownedMapping) {
		t.Fatalf("error = %v, want ErrUnownedMapping", err)
	}
	assertServer(t, server)
}

// R7: malformed responses are rejected, never parsed loosely.
func TestMapMalformedResponse(t *testing.T) {
	cases := []struct {
		name  string
		mutat func(response []byte) []byte
	}{
		{"truncated", func(r []byte) []byte { return r[:7] }},
		{"wrong version", func(r []byte) []byte { r[0] = 1; return r }},
		{"wrong opcode echo", func(r []byte) []byte { r[1] = 0x83; return r }},
		{"internal port mismatch", func(r []byte) []byte { r[8] = 0xff; return r }},
	}
	for _, tc := range cases {
		server := newFakeServer(t)
		server.handle(func(seq int, request []byte) []byte {
			return tc.mutat(mapResponseBytes(request, 43111, 3600, 100))
		})
		client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
		if _, err := client.Map(t.Context(), MapRequest{
			Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
		}); err == nil {
			t.Fatalf("%s: malformed response must fail", tc.name)
		}
	}
}

// R8: the unsupported-opcode result surfaces as a definitive failure — this
// is also how detection learns NAT-PMP is absent.
func TestMapUnsupportedOpcode(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		response := make([]byte, 16)
		response[0] = Version
		response[1] = request[1] + ResponseOpBase
		putUint16(response[2:4], ResultUnsupportedOpcode)
		putUint32(response[4:8], 100)
		return response
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{})
	if _, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtocolTCP, InternalPort: 3111, Lifetime: time.Hour,
	}); !errors.Is(err, ErrUnsupportedOpcode) {
		t.Fatalf("error = %v, want ErrUnsupportedOpcode", err)
	}
}

// A8 (network review MEDIUM): reboot detection must survive the adapter's
// per-transaction sockets — the epoch baseline observed by the first
// transaction is the baseline of the next, so an epoch rollback in a
// renewal reports ServerRebooted (RFC 6886 §3.6).
func TestAdapterRenewDetectsRebootAcrossTransactions(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		epoch := uint32(0x1000)
		if seq >= 2 {
			epoch = 0x10 // rollback far beyond the tolerance
		}
		return mapResponseBytes(request, 43111, 3600, epoch)
	})

	adapter := NewAdapter(AdapterOptions{Gateway: server.peer, Timeout: 300 * time.Millisecond})
	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalPort: 3111, Lease: time.Hour,
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
