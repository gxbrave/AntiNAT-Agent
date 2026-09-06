// TCP direct data plane (v0.8 §4.2, §4.4): one listener per Forward tuple,
// bidirectional per-session copy with correct half-close semantics — an EOF
// on one direction propagates CloseWrite to the peer so the other direction
// can finish, and the connections are fully closed only when both directions
// are done. The accept loop survives backend dial failures and paces
// transient accept errors with a bounded backoff instead of busy-looping.
// The data path is the standard-library io.Copy on raw *net.TCPConn (Linux
// splice-eligible); no custom fast path and no runtime splice counters.
package tcp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
)

// Options configures one Forward instance.
type Options struct {
	// Backend is the target snapshot; each session resolves it once at
	// accept time.
	Backend *forward.Backend
	// Budget bounds accepted sessions (connections/FDs/pessimistic buffer).
	// Nil means unlimited.
	Budget *forward.Budget
	// OnReject is invoked with the explicit reason when a connection is
	// rejected because a budget axis is exhausted.
	OnReject func(reason error)
	// DialTimeout bounds each backend dial.
	DialTimeout time.Duration
	// AcceptBackoffMin/Max pace transient accept errors (default 10ms/1s,
	// doubling each failure).
	AcceptBackoffMin time.Duration
	AcceptBackoffMax time.Duration
}

// Forward is one TCP forward: it owns the listener and the sessions accepted
// from it. Run executes the accept loop; Close (the delete hook) closes the
// listener and every tracked session. Run is started by the owner in its
// own goroutine.
type Forward struct {
	listener net.Listener
	backend  *forward.Backend
	budget   *forward.Budget
	onReject func(reason error)

	dialTimeout time.Duration
	backoffMin  time.Duration
	backoffMax  time.Duration

	// runMu serializes Close against the accept loop's lifetime: Run holds it
	// for the whole loop, so once Close acquires it no further sessions can
	// be added and wg.Wait is safe.
	runMu sync.Mutex
	mu    sync.Mutex

	closed atomic.Bool

	// listenerMu serializes Close calls from the context cancellation watcher
	// and the explicit owner cleanup path. A listener may be a test or platform
	// implementation whose Close is not internally idempotent.
	listenerMu sync.Mutex

	// closeMu makes Close single-flight while still allowing a failed listener
	// close to be retried. A listener is not considered fully closed until the
	// underlying close and all session joins have completed successfully.
	closeMu         sync.Mutex
	closeInProgress bool
	closeDone       chan struct{}
	closeComplete   bool
	closeErr        error

	sessions map[*session]struct{}

	accepted atomic.Int64
	rejected atomic.Int64

	wg sync.WaitGroup
}

// session is one accepted client connection and its backend dial. Both
// sockets are closed exactly once, race-free against the stop hook.
type session struct {
	mu     sync.Mutex
	closed bool
	client net.Conn
	target net.Conn
}

// setTarget publishes the backend connection or, if the session was already
// closed by the stop hook, closes the freshly dialed connection immediately.
func (s *session) setTarget(conn net.Conn) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.target = conn
	s.mu.Unlock()
}

// close tears down both sockets exactly once.
func (s *session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	client, target := s.client, s.target
	s.mu.Unlock()
	if client != nil {
		_ = client.Close()
	}
	if target != nil {
		_ = target.Close()
	}
}

// New validates the options and wraps the listener. The caller owns the
// listener until Run is started.
func New(listener net.Listener, opts Options) (*Forward, error) {
	if listener == nil {
		return nil, errors.New("tcp: listener is required")
	}
	if opts.Backend == nil {
		return nil, errors.New("tcp: backend is required")
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.AcceptBackoffMin <= 0 {
		opts.AcceptBackoffMin = 10 * time.Millisecond
	}
	if opts.AcceptBackoffMax <= 0 {
		opts.AcceptBackoffMax = 1 * time.Second
	}
	return &Forward{
		listener:    listener,
		backend:     opts.Backend,
		budget:      opts.Budget,
		onReject:    opts.OnReject,
		dialTimeout: opts.DialTimeout,
		backoffMin:  opts.AcceptBackoffMin,
		backoffMax:  opts.AcceptBackoffMax,
		sessions:    make(map[*session]struct{}),
	}, nil
}

// Run accepts connections until the listener is closed, Close is called, or
// ctx is cancelled. It returns nil when the listener was closed (normal
// shutdown), ctx.Err() on cancellation, and the accept-loop error otherwise.
// runMu is held for the whole loop so Close can never race a session Add.
func (f *Forward) Run(ctx context.Context) error {
	f.runMu.Lock()
	defer f.runMu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	// A listener's Accept method is not required to observe ctx directly. This
	// watcher closes it on cancellation so an idle accept loop can exit; the
	// explicit CloseContext path remains serialized by listenerMu.
	acceptDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			f.closeListener()
		case <-acceptDone:
		}
	}()
	defer close(acceptDone)

	backoff := f.backoffMin
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			if f.closed.Load() {
				return nil
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if isTransientAcceptError(err) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > f.backoffMax {
					backoff = f.backoffMax
				}
				continue
			}
			return err
		}
		backoff = f.backoffMin
		sess := &session{client: conn}
		if f.budget != nil {
			if err := f.budget.Reserve(); err != nil {
				f.rejected.Add(1)
				if f.onReject != nil {
					f.onReject(err)
				}
				_ = conn.Close()
				continue
			}
		}
		f.mu.Lock()
		if f.closed.Load() {
			f.mu.Unlock()
			if f.budget != nil {
				f.budget.Release()
			}
			_ = conn.Close()
			return nil
		}
		f.sessions[sess] = struct{}{}
		f.mu.Unlock()
		f.accepted.Add(1)
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			defer f.untrack(sess)
			f.handleSession(sess)
		}()
	}
}

// untrack removes the session and frees its budget charge.
func (f *Forward) untrack(sess *session) {
	if f.budget != nil {
		f.budget.Release()
	}
	f.mu.Lock()
	delete(f.sessions, sess)
	f.mu.Unlock()
}

// Close is the delete hook: it closes the listener, waits for the accept
// loop to exit, then closes every tracked session and waits for them. It is
// idempotent and safe to call from another goroutine while Run is active
// (or before Run ever starts). It uses a background context for compatibility;
// callers with a lifecycle deadline should use CloseContext.
func (f *Forward) Close() error {
	return f.CloseContext(context.Background())
}

// CloseContext starts one close attempt and waits for its result, bounded by
// ctx. The actual attempt continues in its own goroutine after a caller
// deadline, so a later caller can join the same attempt rather than racing a
// second listener/session teardown. A listener-close failure leaves the
// Forward retryable; a successful close is permanently idempotent.
func (f *Forward) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	f.closeMu.Lock()
	if f.closeComplete {
		err := f.closeErr
		f.closeMu.Unlock()
		return err
	}
	if f.closeInProgress {
		done := f.closeDone
		f.closeMu.Unlock()
		select {
		case <-done:
			f.closeMu.Lock()
			err := f.closeErr
			f.closeMu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.closeInProgress = true
	f.closeDone = make(chan struct{})
	done := f.closeDone
	f.closeMu.Unlock()

	go f.finishClose(done)
	select {
	case <-done:
		f.closeMu.Lock()
		err := f.closeErr
		f.closeMu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *Forward) closeListener() error {
	f.listenerMu.Lock()
	defer f.listenerMu.Unlock()
	return f.listener.Close()
}

func (f *Forward) finishClose(done chan struct{}) {
	// Mark the Forward closed before touching the listener so Run treats any
	// resulting accept error as a normal shutdown boundary. Do not make this
	// marker permanent: a failed listener close must be retryable below.
	f.closed.Store(true)
	err := f.closeListener()
	// Wait until the accept loop has exited (no further session Adds),
	// then close every tracked session. runMu is free when Run never ran.
	f.runMu.Lock()
	f.mu.Lock()
	sessions := make([]*session, 0, len(f.sessions))
	for sess := range f.sessions {
		sessions = append(sessions, sess)
	}
	f.mu.Unlock()
	for _, sess := range sessions {
		sess.close()
	}
	f.wg.Wait()
	f.runMu.Unlock()

	f.closeMu.Lock()
	f.closeErr = err
	if err == nil || errors.Is(err, net.ErrClosed) {
		f.closeComplete = true
	}
	f.closeInProgress = false
	close(done)
	// A failed close remains retryable; waiters from this attempt still observe
	// its error, while the next caller gets a fresh close attempt.
	if f.closeComplete {
		f.closeDone = done
	}
	f.closeMu.Unlock()
}

// Stats returns cumulative accept/reject counters and the active session
// count.
type Stats struct {
	Accepted int64
	Rejected int64
	Active   int64
}

func (f *Forward) Stats() Stats {
	f.mu.Lock()
	active := int64(len(f.sessions))
	f.mu.Unlock()
	return Stats{
		Accepted: f.accepted.Load(),
		Rejected: f.rejected.Load(),
		Active:   active,
	}
}

// handleSession dials the backend snapshot and proxies both directions with
// half-close semantics. A failed backend dial closes the client connection;
// the accept loop is unaffected.
func (f *Forward) handleSession(sess *session) {
	clientConn := sess.client
	defer sess.close()

	targetConn, err := net.DialTimeout("tcp4", f.backend.Target().String(), f.dialTimeout)
	if err != nil {
		return
	}
	sess.setTarget(targetConn)
	defer targetConn.Close()

	clientTCP, clientOK := clientConn.(*net.TCPConn)
	targetTCP, targetOK := targetConn.(*net.TCPConn)
	if !clientOK || !targetOK {
		// Non-TCP transports (test doubles) cannot half-close: fall back to
		// full-duplex copy with full close on either direction's end.
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(targetConn, clientConn) }()
		go func() { defer wg.Done(); _, _ = io.Copy(clientConn, targetConn) }()
		wg.Wait()
		return
	}
	proxyTCP(clientTCP, targetTCP)
}

// proxyTCP copies both directions and propagates CloseWrite so a
// server-first or slow-client protocol can finish its reply after the peer
// half-closed, and vice versa. Both sockets are fully closed only after both
// directions are done.
func proxyTCP(client, target *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, client)
		_ = target.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		_ = client.CloseWrite()
	}()
	wg.Wait()
	_ = client.Close()
	_ = target.Close()
}

func isTransientAcceptError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Temporary() {
		return true
	}
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED)
}
