// Package pcp implements the RFC 6887 MAP subset the AntiNAT v1 gateway
// layer needs: nonce ownership, requested/granted lifetime, epoch tracking
// with reboot detection, bounded retry for transient failures, the
// PREFER_FAILURE option for exact port requests, and lifetime=0 deletes.
// SADSP, FILTER, THIRD_PARTY and PCP-over-TCP are explicit non-goals of v1.
package pcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedNonce is the deterministic nonce generator used by the wire tests.
func fixedNonce(seed byte) func() ([12]byte, error) {
	return func() ([12]byte, error) {
		var n [12]byte
		for i := range n {
			n[i] = seed + byte(i)
		}
		return n, nil
	}
}

// newPacketConn is the client-side UDP socket.
func newPacketConn(t *testing.T) net.PacketConn {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client packet conn: %v", err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	return packet
}

// fakeServer is a deterministic loopback PCP server with scripted fault
// behavior. The script is installed after construction (server.handle) so
// closures can safely reference the server itself, and assertions recorded
// on the server goroutine are replayed on the test goroutine: t.Fatal is
// never called off the test goroutine.
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
		t.Fatalf("fake PCP server listen: %v", err)
	}
	server := &fakeServer{peer: netip.MustParseAddrPort(packet.LocalAddr().String())}
	go func() {
		buf := make([]byte, 1100)
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

// handle installs the scripted response behavior. Requests arriving before
// the script is installed are dropped.
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

// failureMessage replays recorded server-goroutine assertions; an empty
// result means every scripted assertion held.
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

// newRequest builds the canonical MapRequest used by the tests.
func newRequest() MapRequest {
	return MapRequest{
		Protocol:              ProtoTCP,
		InternalAddress:       netip.MustParseAddr("10.0.0.2"),
		InternalPort:          3111,
		SuggestedExternalPort: 43111,
		Lifetime:              time.Hour,
	}
}

// successResponse crafts a success MAP response echoing the request's opcode,
// client address and nonce, with the granted lifetime, epoch and endpoint.
func successResponse(request []byte, external netip.Addr, epoch uint32) []byte {
	header := make([]byte, HeaderSize)
	header[0] = Version
	header[1] = request[1] | ResponseFlag
	header[3] = ResultSuccess
	putUint32(header[4:8], 3600)
	putUint32(header[8:12], epoch)
	payload := make([]byte, MapPayloadSize)
	copy(payload[0:12], request[HeaderSize:HeaderSize+12])
	payload[12] = request[HeaderSize+12]
	putUint16(payload[16:18], readUint16(request[HeaderSize+16:HeaderSize+18]))
	putUint16(payload[18:20], readUint16(request[HeaderSize+18:HeaderSize+20]))
	copy(payload[20:36], v4Mapped(external))
	return append(header, payload...)
}

func equalBytes(got, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func assertServer(t *testing.T, server *fakeServer) {
	t.Helper()
	if msg := server.failureMessage(); msg != "" {
		t.Fatal(msg)
	}
}

// --- wire golden vector -----------------------------------------------------

// R1: the MAP request wire format is byte-exact (RFC 6887 §11.1): v2 header
// with requested lifetime, IPv4-mapped client address, 12-byte nonce,
// protocol, internal/suggested external ports, and PREFER_FAILURE when an
// exact port is required.
func TestMapGoldenRequestBytes(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		want := append([]byte{
			0x02, 0x01, 0x00, 0x00, // version 2, MAP request, reserved
			0x00, 0x00, 0x0e, 0x10, // lifetime 3600
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x02, // ::ffff:10.0.0.2
		},
			// MAP payload: nonce 01..0c, TCP, internal 3111, suggested 43111
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
			0x06, 0x00, 0x00, 0x00,
			0x0c, 0x27, 0xa8, 0x67,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			// PREFER_FAILURE option header: code(1), reserved(1), length(2)
			0x02, 0x00, 0x00, 0x00,
		)
		if !equalBytes(request, want) {
			server.errorf("request bytes mismatch\n got: % x\nwant: % x", request, want)
		}
		return successResponse(request, netip.MustParseAddr("8.8.8.8"), 0x0f00)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	result, err := client.Map(t.Context(), MapRequest{
		Protocol:              ProtoTCP,
		InternalAddress:       netip.MustParseAddr("10.0.0.2"),
		InternalPort:          3111,
		SuggestedExternalPort: 43111,
		Lifetime:              time.Hour,
		PreferFailure:         true,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	assertServer(t, server)
	if result.AssignedExternalPort != 43111 || result.AssignedExternalAddress.String() != "8.8.8.8" {
		t.Fatalf("assigned endpoint = %s:%d, want 8.8.8.8:43111", result.AssignedExternalAddress, result.AssignedExternalPort)
	}
	if result.Lifetime != time.Hour {
		t.Fatalf("granted lifetime = %s, want 1h", result.Lifetime)
	}
	if result.Epoch != 0x0f00 {
		t.Fatalf("epoch = %d, want 3840", result.Epoch)
	}
	if result.Nonce[0] != 1 || result.Nonce[11] != 12 {
		t.Fatal("result must echo the strong-ownership nonce")
	}
}

// R2: a response nonce that does not match the request nonce is a protocol
// violation: rejected as permanent, never retried, never treated as ours.
func TestMapNonceMismatchRejected(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		response := successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
		response[HeaderSize] ^= 0xff // corrupt the echoed nonce
		return response
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	_, err := client.Map(t.Context(), newRequest())
	if !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("error = %v, want ErrNonceMismatch", err)
	}
	if got := server.requestCount(); got != 1 {
		t.Fatalf("nonce mismatch must not be retried, got %d requests", got)
	}
}

// R3: permanent result codes surface with their code and never retry.
func TestMapPermanentResultCodes(t *testing.T) {
	cases := []struct {
		code byte
		want error
	}{
		{ResultNotAuthorized, ErrNotAuthorized},
		{ResultCannotProvideExternal, ErrCannotProvideExternal},
		{ResultUnsupportedVersion, ErrUnsupportedVersion},
	}
	for _, tc := range cases {
		server := newFakeServer(t)
		server.handle(func(seq int, request []byte) []byte {
			response := successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
			response[3] = tc.code
			return response
		})
		client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
		_, err := client.Map(t.Context(), newRequest())
		if !errors.Is(err, tc.want) {
			t.Fatalf("result %d: error = %v, want %v", tc.code, err, tc.want)
		}
		if got := server.requestCount(); got != 1 {
			t.Fatalf("result %d: permanent failures never retry, got %d requests", tc.code, got)
		}
	}
}

// R4: transient result codes (>= 128) retry with backoff and succeed.
func TestMapTransientRetriesThenSucceeds(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			response := successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
			response[3] = 200 // transient failure (RFC 6887 §7.4)
			return response
		}
		return successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{
		Nonce: fixedNonce(1), Backoff: time.Millisecond,
	})
	result, err := client.Map(t.Context(), newRequest())
	if err != nil {
		t.Fatalf("transient retry must succeed: %v", err)
	}
	assertServer(t, server)
	if result.AssignedExternalPort != 43111 {
		t.Fatalf("assigned port = %d, want 43111", result.AssignedExternalPort)
	}
	if got := server.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2 (one retry)", got)
	}
}

// R5: request timeouts retry up to the bounded attempt count.
func TestMapTimeoutRetryThenSucceeds(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			return nil // drop: timeout fault
		}
		return successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{
		Nonce: fixedNonce(1), Timeout: 150 * time.Millisecond, Backoff: time.Millisecond,
	})
	if _, err := client.Map(t.Context(), newRequest()); err != nil {
		t.Fatalf("timeout retry must succeed: %v", err)
	}
	assertServer(t, server)
	if got := server.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want 2", got)
	}
}

// R6: exhausted retries surface ErrNoResponse.
func TestMapExhaustedRetries(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte { return nil })

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{
		Nonce: fixedNonce(1), Timeout: 50 * time.Millisecond, Backoff: time.Millisecond, MaxAttempts: 2,
	})
	if _, err := client.Map(t.Context(), newRequest()); !errors.Is(err, ErrNoResponse) {
		t.Fatalf("error = %v, want ErrNoResponse", err)
	}
	if got := server.requestCount(); got != 2 {
		t.Fatalf("requests = %d, want exactly MaxAttempts", got)
	}
}

// R7: epoch rollback beyond the RFC tolerance reports a server reboot: the
// mapping may be lost and the caller must treat publication as stale.
func TestMapEpochRollbackDetectsReboot(t *testing.T) {
	epochs := []uint32{0x0f00, 0x0100} // backward jump far beyond 2s
	seq := 0
	server := newFakeServer(t)
	server.handle(func(_ int, request []byte) []byte {
		e := epochs[0]
		if seq > 0 {
			e = epochs[1]
		}
		seq++
		return successResponse(request, netip.MustParseAddr("8.8.8.8"), e)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	if _, err := client.Map(t.Context(), newRequest()); err != nil {
		t.Fatalf("first Map: %v", err)
	}
	result, err := client.Map(t.Context(), newRequest())
	if err != nil {
		t.Fatalf("second Map: %v", err)
	}
	if !result.ServerRebooted {
		t.Fatal("epoch rollback must report ServerRebooted so publication goes stale")
	}
}

// R7b: a small epoch jitter within the tolerance is not a reboot.
func TestMapEpochSmallJitterNotReboot(t *testing.T) {
	epochs := []uint32{0x0f00, 0x0efe} // 2s backward: within tolerance
	seq := 0
	server := newFakeServer(t)
	server.handle(func(_ int, request []byte) []byte {
		e := epochs[0]
		if seq > 0 {
			e = epochs[1]
		}
		seq++
		return successResponse(request, netip.MustParseAddr("8.8.8.8"), e)
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	if _, err := client.Map(t.Context(), newRequest()); err != nil {
		t.Fatalf("first Map: %v", err)
	}
	result, err := client.Map(t.Context(), newRequest())
	if err != nil {
		t.Fatalf("second Map: %v", err)
	}
	if result.ServerRebooted {
		t.Fatal("a 2s backward epoch jitter is within the RFC tolerance")
	}
}

// R8: PREFER_FAILURE is only sent with a non-zero suggested port; a request
// demanding an exact port without naming one is refused client-side.
func TestMapPreferFailureWithoutPortIsClientError(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		server.errorf("no request may be sent for a malformed exact-port request")
		return nil
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	_, err := client.Map(t.Context(), MapRequest{
		Protocol: ProtoTCP, InternalPort: 3111, Lifetime: time.Hour, PreferFailure: true,
	})
	if !errors.Is(err, ErrPreferFailureRequiresPort) {
		t.Fatalf("error = %v, want ErrPreferFailureRequiresPort", err)
	}
	assertServer(t, server)
}

// R9: lifetime=0 deletes the mapping with the owning nonce and the exact
// assigned tuple; the server grants lifetime 0 back.
func TestDeleteLifetimeZero(t *testing.T) {
	var deleteSeen atomic.Bool
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		if seq == 1 {
			return successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
		}
		if lifetime := readUint32(request[4:8]); lifetime != 0 {
			server.errorf("delete request lifetime = %d, want 0", lifetime)
		}
		if got := readUint16(request[HeaderSize+18 : HeaderSize+20]); got != 43111 {
			server.errorf("delete suggested external port = %d, want the assigned 43111", got)
		}
		deleteSeen.Store(true)
		response := successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
		putUint32(response[4:8], 0) // server confirms deletion with lifetime 0
		return response
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	mapping, err := client.Map(t.Context(), newRequest())
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

// R9b: a delete for a mapping without an exact internal tuple is refused
// client-side and never sent: v1 never provides delete-all.
func TestDeleteRefusesZeroInternalPort(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		server.errorf("no request may be sent for an unowned delete")
		return nil
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	mapping := MapResult{InternalPort: 0, AssignedExternalPort: 43111}
	if _, err := client.Delete(t.Context(), mapping); !errors.Is(err, ErrUnownedMapping) {
		t.Fatalf("error = %v, want ErrUnownedMapping", err)
	}
	assertServer(t, server)
}

// R11 (NAT audit L1): an error response MAY echo the request — including
// its options (RFC 6887 §8.2) — and only its header is classified: the
// echoed option bytes must not be misread as a malformed response.
func TestMapErrorResponseMayEchoRequestWithOptions(t *testing.T) {
	server := newFakeServer(t)
	server.handle(func(seq int, request []byte) []byte {
		response := successResponse(request, netip.MustParseAddr("8.8.8.8"), 100)
		response[3] = ResultUnsupportedOption
		echo := append(append([]byte{}, response...), request[HeaderSize:]...)
		return echo
	})

	client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
	_, err := client.Map(t.Context(), MapRequest{
		Protocol:              ProtoTCP,
		InternalAddress:       netip.MustParseAddr("10.0.0.2"),
		InternalPort:          3111,
		SuggestedExternalPort: 43111,
		Lifetime:              time.Hour,
		PreferFailure:         true,
	})
	if !errors.Is(err, ErrUnsupportedOption) {
		t.Fatalf("error = %v, want ErrUnsupportedOption from the echoed error response", err)
	}
}

// R10: malformed or short responses are rejected, never parsed loosely.
func TestMapMalformedResponse(t *testing.T) {
	cases := []struct {
		name  string
		mutat func(response []byte) []byte
	}{
		{"truncated header", func(r []byte) []byte { return r[:10] }},
		{"wrong version", func(r []byte) []byte { r[0] = 3; return r }},
		{"wrong opcode", func(r []byte) []byte { r[1] = 0x82; return r }},
		{"internal port mismatch", func(r []byte) []byte { r[HeaderSize+16] ^= 0xff; return r }},
		{"trailing bytes", func(r []byte) []byte { return append(r, 0) }},
	}
	for _, tc := range cases {
		server := newFakeServer(t)
		server.handle(func(seq int, request []byte) []byte {
			return tc.mutat(successResponse(request, netip.MustParseAddr("8.8.8.8"), 100))
		})
		client := NewClient(newPacketConn(t), server.peer, ClientOptions{Nonce: fixedNonce(1)})
		if _, err := client.Map(t.Context(), newRequest()); err == nil {
			t.Fatalf("%s: malformed response must fail", tc.name)
		}
	}
}
