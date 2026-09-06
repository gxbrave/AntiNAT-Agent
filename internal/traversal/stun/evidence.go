// Honest concurrent mapping evidence (v0.8 §4.2). Capability detection
// compares two STUN destinations from one local tuple: the first connection
// stays ESTABLISHED while a second remote 4-tuple is opened from the same
// tuple. EIM_OBSERVED_CONCURRENT is recorded only when the platform gate
// passes (native listener + multiple connected sockets dispatch evidence)
// AND the first connection stayed established through the second
// observation. Otherwise the sequential result is PORT_REUSE_OBSERVED (the
// same mapped port observed across destinations) or MAPPED_UNVERIFIED; EIM
// is never claimed from sequential or interrupted observations.
package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// MappingVerdict is the evidence classification for a two-destination
// observation (v0.8 §4.2).
type MappingVerdict string

const (
	// VerdictEIMObservedConcurrent: both observations succeeded concurrently
	// from one tuple and the mapped endpoints are equal.
	VerdictEIMObservedConcurrent MappingVerdict = "EIM_OBSERVED_CONCURRENT"
	// VerdictPortReuseObserved: the same mapped port was observed across the
	// two destinations, but the observation was sequential or interrupted,
	// so EIM is not verified.
	VerdictPortReuseObserved MappingVerdict = "PORT_REUSE_OBSERVED"
	// VerdictMappedUnverified: a mapped endpoint was observed but neither
	// EIM nor port reuse is verified (divergent endpoints, failed second
	// observation, or interrupted first connection).
	VerdictMappedUnverified MappingVerdict = "MAPPED_UNVERIFIED"
)

// MappingObservation is the structured evidence record.
type MappingObservation struct {
	Verdict                    MappingVerdict
	Concurrent                 bool
	PlatformGate               bool
	FirstConnStayedEstablished bool
	LocalTuple                 traversal.TupleKey
	MappedA                    netip.AddrPort
	MappedB                    netip.AddrPort
	Note                       string
}

// ObserveMappingOptions configures a two-destination observation.
type ObserveMappingOptions struct {
	LocalIP netip.Addr     // source IP for the local tuple
	ServerA netip.AddrPort // first STUN destination
	ServerB netip.AddrPort // second STUN destination
	Timeout time.Duration  // per-exchange deadline; default 5 s
	// PlatformGate overrides the shared-port gate (test seam). Defaults to
	// SharedPortSupported.
	PlatformGate func() bool
	// ReuseControl is the pre-bind socket-option hook used for sequential
	// same-tuple rebinding; defaults to traversal.StunSharedPortControl.
	ReuseControl func(network, address string, c syscall.RawConn) error
	// SameLocalPort forces the sequential path to rebind the first
	// connection's local port for the second connection.
	SameLocalPort bool
}

// ObserveMapping performs the two-destination observation and returns the
// honest verdict. It never fabricates concurrency: the gate and the
// first-connection liveness are both checked and recorded.
func ObserveMapping(ctx context.Context, options ObserveMappingOptions) (MappingObservation, error) {
	gate := options.PlatformGate
	if gate == nil {
		gate = SharedPortSupported
	}
	platformGate := gate()
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if options.ReuseControl == nil {
		// Documented default: the same-tuple rebind needs the reuse group
		// (SO_REUSEADDR+SO_REUSEPORT) on every participant (v0.8 §4.2);
		// without it the second bind collides with the first socket's
		// TIME_WAIT and the observation silently degrades.
		options.ReuseControl = traversal.StunSharedPortControl
	}
	if platformGate {
		return observeConcurrent(ctx, options, timeout)
	}
	return observeSequential(ctx, options, timeout)
}

// observeConcurrent opens the shared-port lease and dials both destinations
// from the same tuple while the first connection stays established.
func observeConcurrent(ctx context.Context, options ObserveMappingOptions, timeout time.Duration) (MappingObservation, error) {
	observation := MappingObservation{
		PlatformGate: true,
		LocalTuple: traversal.TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: options.LocalIP.String(), Port: 0,
		},
	}
	registry := NewSharedPortRegistry()
	lease, err := registry.Acquire(ctx, "mapping-evidence", observation.LocalTuple)
	if err != nil {
		return observation, err
	}
	defer lease.Release()
	observation.LocalTuple = lease.Actual

	connA, err := lease.Dial(ctx, options.ServerA.String())
	if err != nil {
		observation.Note = "first dial failed: " + err.Error()
		return observation, err
	}
	defer connA.Close()
	mappedA, err := observeMappedOverConn(ctx, connA, options.ServerA, timeout)
	if err != nil {
		observation.Note = "first observation failed: " + err.Error()
		return observation, err
	}
	observation.MappedA = mappedA

	connB, err := lease.Dial(ctx, options.ServerB.String())
	if err != nil {
		observation.Verdict = VerdictMappedUnverified
		observation.Note = "second dial failed: " + err.Error()
		return observation, nil
	}
	defer connB.Close()
	mappedB, err := observeMappedOverConn(ctx, connB, options.ServerB, timeout)
	if err != nil {
		observation.Verdict = VerdictMappedUnverified
		observation.Note = "second observation failed: " + err.Error()
		return observation, nil
	}
	observation.MappedB = mappedB

	// The first connection must still be established; otherwise the
	// concurrent claim collapses to a sequential observation.
	if !connEstablished(connA) {
		observation.Concurrent = false
		observation.FirstConnStayedEstablished = false
		observation.Verdict = sequentialVerdict(mappedA, mappedB)
		observation.Note = "first connection dropped before second observation completed"
		return observation, nil
	}
	observation.Concurrent = true
	observation.FirstConnStayedEstablished = true
	if mappedA == mappedB {
		observation.Verdict = VerdictEIMObservedConcurrent
	} else {
		observation.Verdict = VerdictMappedUnverified
		observation.Note = "concurrent mapped endpoints differ"
	}
	return observation, nil
}

// observeSequential dials each destination in turn. With SameLocalPort the
// first connection's local port is rebound for the second so port-reuse
// evidence can be collected honestly.
func observeSequential(ctx context.Context, options ObserveMappingOptions, timeout time.Duration) (MappingObservation, error) {
	observation := MappingObservation{
		PlatformGate: false,
		LocalTuple: traversal.TupleKey{
			Family: "ipv4", Protocol: "tcp", Address: options.LocalIP.String(), Port: 0,
		},
	}

	// First destination. When rebinding the same local port afterwards, the
	// first socket must join the same reuse group (SO_REUSEADDR+SO_REUSEPORT
	// on every participant, v0.8 §4.2).
	dialerA := &net.Dialer{Control: options.ReuseControl}
	connA, err := dialerA.DialContext(ctx, "tcp4", options.ServerA.String())
	if err != nil {
		return observation, err
	}
	localPort := connA.LocalAddr().(*net.TCPAddr).Port
	mappedA, err := observeMappedOverConn(ctx, connA, options.ServerA, timeout)
	connA.Close()
	if err != nil {
		observation.Note = "first observation failed: " + err.Error()
		return observation, err
	}
	observation.MappedA = mappedA
	observation.LocalTuple.Port = uint16(localPort)

	// Second destination, optionally from the same local port.
	dialer := net.Dialer{}
	if options.SameLocalPort {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(options.LocalIP.String()), Port: localPort}
		dialer.Control = options.ReuseControl
	}
	connB, err := dialer.DialContext(ctx, "tcp4", options.ServerB.String())
	if err != nil {
		observation.Verdict = VerdictMappedUnverified
		observation.Note = "second dial failed: " + err.Error()
		return observation, nil
	}
	defer connB.Close()
	mappedB, err := observeMappedOverConn(ctx, connB, options.ServerB, timeout)
	if err != nil {
		observation.Verdict = VerdictMappedUnverified
		observation.Note = "second observation failed: " + err.Error()
		return observation, nil
	}
	observation.MappedB = mappedB
	observation.Verdict = sequentialVerdict(mappedA, mappedB)
	return observation, nil
}

// sequentialVerdict classifies two sequential observations.
func sequentialVerdict(a, b netip.AddrPort) MappingVerdict {
	if a != (netip.AddrPort{}) && b != (netip.AddrPort{}) && a.Port() == b.Port() {
		return VerdictPortReuseObserved
	}
	return VerdictMappedUnverified
}

// observeMappedOverConn runs one Binding exchange over an established TCP
// connection and returns the mapped endpoint from XOR-MAPPED-ADDRESS.
func observeMappedOverConn(ctx context.Context, conn net.Conn, server netip.AddrPort, timeout time.Duration) (netip.AddrPort, error) {
	txid, err := NewTransactionID()
	if err != nil {
		return netip.AddrPort{}, err
	}
	request := NewBindingRequest(txid)
	wire, err := request.Marshal()
	if err != nil {
		return netip.AddrPort{}, err
	}
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(wire); err != nil {
		return netip.AddrPort{}, err
	}
	reply, err := readFrame(conn, MaxMessageSize)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if reply.TransactionID != txid {
		return netip.AddrPort{}, errors.New("stun: observation response transaction mismatch")
	}
	if reply.Type.Class() != ClassSuccess {
		return netip.AddrPort{}, errors.New("stun: observation got non-success response")
	}
	return reply.XORMappedAddress()
}

// connEstablished probes whether the connection is still alive with a short
// zero-byte read: a read timeout means established; EOF or a reset means the
// peer closed.
func connEstablished(conn net.Conn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err == nil {
		// Unexpected payload on an idle STUN connection; still alive.
		_ = conn.SetReadDeadline(time.Time{})
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		_ = conn.SetReadDeadline(time.Time{})
		return true
	}
	return false
}
