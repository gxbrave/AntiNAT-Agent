// Shared-port TCP sockets (v0.8 §4.2): one tuple holds a unique
// reuse-enabled listener plus connected sockets bound to the same local
// tuple, each created with SO_REUSEADDR+SO_REUSEPORT pre-bind (P02 Linux
// spike evidence: every listener/connected participant needs the reuse
// options; the listener alone is not an ownership boundary). The registry
// mirrors the P09 PortRegistry ownership discipline — owner, generation,
// atomic acquire with actual-port resolution, wildcard/specific overlap
// rejection, and stale releases that can never close a new owner — while
// the OS bind remains the final ownership authority (v0.8 §4.1 rule 6).
//
// The platform gate (SharedPortSupported) is true only where native evidence
// exists: Linux SUPPORTED_WITH_LIMITS from P02; Windows and other platforms
// fail closed until their native baseline runs.
package stun

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// SharedPortSupported reports whether STUN TCP shared-port sockets are
// usable on this platform (native evidence required; v0.8 §4.2).
func SharedPortSupported() bool { return traversal.StunSharedPortSupported() }

// sharedPortEntry is one owned tuple.
type sharedPortEntry struct {
	owner      string
	generation uint64
	lease      *SharedPortLease
}

// SharedPortRegistry owns shared-port tuples with P09 PortRegistry
// discipline (one tuple, one owner, generation-guarded release).
type SharedPortRegistry struct {
	mu         sync.Mutex
	entries    map[traversal.TupleKey]sharedPortEntry
	generation uint64
}

// NewSharedPortRegistry returns an empty registry.
func NewSharedPortRegistry() *SharedPortRegistry {
	return &SharedPortRegistry{entries: make(map[traversal.TupleKey]sharedPortEntry)}
}

// Acquire validates the tuple, rejects overlaps (including wildcard/
// specific), creates the reuse-enabled listener inside the registry
// critical section, resolves the OS-assigned port, and publishes the entry.
func (r *SharedPortRegistry) Acquire(ctx context.Context, owner string, key traversal.TupleKey) (*SharedPortLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if owner == "" {
		return nil, traversal.ErrOwnerRequired
	}
	if key.Family != "ipv4" || key.Protocol != "tcp" {
		return nil, traversal.ErrUnsupportedTuple
	}
	if !SharedPortSupported() {
		return nil, traversal.ErrStunSharedPortUnsupported
	}
	key = normalizeSharedKey(key)
	if r.overlapsLocked(key) {
		return nil, traversal.ErrTupleOverlap
	}

	listener, err := listenSharedTCP(ctx, key)
	if err != nil {
		return nil, err
	}
	actual := key
	actual.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	if r.overlapsLocked(actual) {
		_ = listener.Close()
		return nil, traversal.ErrTupleOverlap
	}

	r.generation++
	lease := &SharedPortLease{
		registry:   r,
		listener:   listener,
		Actual:     actual,
		owner:      owner,
		generation: r.generation,
	}
	r.entries[actual] = sharedPortEntry{owner: owner, generation: lease.generation, lease: lease}
	return lease, nil
}

func (r *SharedPortRegistry) overlapsLocked(candidate traversal.TupleKey) bool {
	for existing := range r.entries {
		if sharedOverlaps(existing, candidate) {
			return true
		}
	}
	return false
}

// normalizeSharedKey maps an unspecified address to the canonical wildcard,
// matching the P09 TupleKey normalization.
func normalizeSharedKey(k traversal.TupleKey) traversal.TupleKey {
	if k.Address == "" || k.Address == "::" || k.Address == "0.0.0.0" {
		k.Address = "0.0.0.0"
	}
	return k
}

// sharedOverlaps reports whether two tuples conflict: same family, protocol
// and port with equal or wildcard addresses (P09 semantics).
func sharedOverlaps(a, b traversal.TupleKey) bool {
	if a.Family != b.Family || a.Protocol != b.Protocol || a.Port != b.Port {
		return false
	}
	return a.Address == b.Address || a.Address == "0.0.0.0" || b.Address == "0.0.0.0"
}

// SharedPortLease owns one tuple: the reuse-enabled listener plus any
// connected sockets dialed from that tuple.
type SharedPortLease struct {
	registry   *SharedPortRegistry
	listener   net.Listener
	Actual     traversal.TupleKey
	owner      string
	generation uint64
	mu         sync.Mutex
	conns      []*net.TCPConn
	// released is set by Release before the conn list is drained; a Dial
	// completing afterwards closes its socket immediately instead of
	// leaving an unowned descriptor bound to the tuple.
	released bool
	// beforeAppend, when non-nil, runs after the dial completes and before
	// the socket is handed to the lease. Package-internal test seam that
	// makes the Dial-vs-Release race deterministic; production callers
	// cannot set it.
	beforeAppend func()
}

// Owner returns the lease owner identity.
func (l *SharedPortLease) Owner() string { return l.owner }

// Generation returns the registry generation the lease was issued at.
func (l *SharedPortLease) Generation() uint64 { return l.generation }

// Listener returns the lease's reuse-enabled listener — the production
// forward listener when the manager is wired through LeaseSource.
func (l *SharedPortLease) Listener() net.Listener { return l.listener }

// leaseFor returns the live lease owning bind (normalized), or
// ErrStaleLease when the registry holds no such tuple.
func (r *SharedPortRegistry) leaseFor(bind traversal.TupleKey) (*SharedPortLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[normalizeSharedKey(bind)]
	if !ok {
		return nil, traversal.ErrStaleLease
	}
	return entry.lease, nil
}

// Dial binds a connected socket to the lease's local tuple (with the
// platform reuse options) and connects it to remote. The socket becomes part
// of the lease and is closed by Release. A dial that completes after Release
// has run is refused: its socket is closed immediately and ErrStaleLease is
// returned, so no unowned descriptor can stay bound to the tuple.
func (l *SharedPortLease) Dial(ctx context.Context, remote string) (*net.TCPConn, error) {
	l.mu.Lock()
	if l.released {
		l.mu.Unlock()
		return nil, traversal.ErrStaleLease
	}
	l.mu.Unlock()
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP(l.Actual.Address),
			Port: int(l.Actual.Port),
		},
		Control: traversal.StunSharedPortControl,
	}
	conn, err := dialer.DialContext(ctx, "tcp4", remote)
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("stun: shared-port dial did not return *net.TCPConn")
	}
	if l.beforeAppend != nil { // package-internal test seam
		l.beforeAppend()
	}
	l.mu.Lock()
	if l.released {
		// Release won the race: this socket would never be closed by
		// anyone (a later Release is refused as stale), so close it here.
		l.mu.Unlock()
		tcpConn.Close()
		return nil, traversal.ErrStaleLease
	}
	l.conns = append(l.conns, tcpConn)
	l.mu.Unlock()
	return tcpConn, nil
}

// Release closes the connected sockets and the listener, then removes the
// registry entry — but only while the entry still matches this owner and
// generation. A stale release returns ErrStaleLease and never touches the
// new owner's sockets.
func (l *SharedPortLease) Release() error {
	registry := l.registry
	registry.mu.Lock()
	defer registry.mu.Unlock()
	entry, ok := registry.entries[l.Actual]
	if !ok || entry.owner != l.owner || entry.generation != l.generation || entry.lease != l {
		return traversal.ErrStaleLease
	}

	l.mu.Lock()
	l.released = true
	var joined error
	for _, conn := range l.conns {
		// An observer-owned connection may already be closed after its
		// exchange; that is the owner's choice, not a lease failure.
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			joined = errors.Join(joined, err)
		}
	}
	l.conns = nil
	l.mu.Unlock()

	if err := l.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		// Retain ownership when the OS close fails so a new lease can never
		// overlap a live descriptor.
		return err
	}
	delete(registry.entries, l.Actual)
	return joined
}

// Len returns the number of owned tuples.
func (r *SharedPortRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// LeaseSource adapts a SharedPortRegistry to the traversal.ListenerSource
// contract with the same-tuple dial capability the manager's STUN
// observation seam requires (v0.8 §4.2): every listener it acquires is
// reuse-enabled and DialFrom originates extra connections from the acquired
// tuple.
type LeaseSource struct {
	Registry *SharedPortRegistry
}

var (
	_ traversal.ListenerSource  = LeaseSource{}
	_ traversal.SameTupleDialer = LeaseSource{}
)

// Acquire implements traversal.ListenerSource.
func (s LeaseSource) Acquire(ctx context.Context, owner string, key traversal.TupleKey) (net.Listener, traversal.TupleKey, traversal.ReleaseFunc, error) {
	lease, err := s.Registry.Acquire(ctx, owner, key)
	if err != nil {
		return nil, traversal.TupleKey{}, nil, err
	}
	return lease.Listener(), lease.Actual, lease.Release, nil
}

// DialFrom implements traversal.SameTupleDialer: originate one more
// connection from the tuple acquired for bind. The connection joins the
// lease (closed by Release); the caller may close it earlier after its
// exchange.
func (s LeaseSource) DialFrom(ctx context.Context, bind traversal.TupleKey, remote string) (net.Conn, error) {
	lease, err := s.Registry.leaseFor(bind)
	if err != nil {
		return nil, err
	}
	return lease.Dial(ctx, remote)
}

// listenSharedTCP creates the reuse-enabled listener inside the registry
// critical section (platform adapter).
func listenSharedTCP(ctx context.Context, key traversal.TupleKey) (net.Listener, error) {
	address := net.JoinHostPort(key.Address, strconv.Itoa(int(key.Port)))
	config := net.ListenConfig{Control: traversal.StunSharedPortControl}
	return config.Listen(ctx, "tcp4", address)
}
