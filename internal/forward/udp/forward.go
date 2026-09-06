package udp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
)

const MaxDatagramSize = 65507

var (
	ErrClosed         = errors.New("udp: forward closed")
	ErrSessionLimit   = errors.New("udp: global session limit reached")
	ErrPerIPLimit     = errors.New("udp: per-IP session limit reached")
	ErrFDLimit        = errors.New("udp: FD limit reached")
	ErrBufferLimit    = errors.New("udp: buffer limit reached")
	ErrEphemeralLimit = errors.New("udp: ephemeral socket limit reached")
)

type Packet struct {
	Source netip.AddrPort
	Data   []byte
}

// Classification is the result of a strict full-match classifier. A matched
// control packet may supply an ACK which Forward sends through the sole ingress
// socket. This keeps probe/STUN handlers socket-agnostic and avoids import cycles.
type Classification struct {
	Matched bool
	Reply   []byte
	// OnReply reports whether Reply was written through the ingress socket. It
	// lets a socket-independent control handler durably mark transport delivery.
	OnReply func(error)
}

type Classifier interface{ Classify(Packet) Classification }
type ClassifierFunc func(Packet) Classification

func (fn ClassifierFunc) Classify(p Packet) Classification { return fn(p) }

type Options struct {
	Backend           *forward.Backend
	Classifiers       []Classifier
	IdleTimeout       time.Duration
	SweepInterval     time.Duration
	DialTimeout       time.Duration
	Shards            int
	MaxSessions       int
	MaxSessionsPerIP  int
	MaxFDs            int
	MaxBufferBytes    int64
	MaxEphemeralPorts int
	OnReject          func(error)
	OnTruncated       func()
	Now               func() time.Time
}

type packetReader interface {
	ReadPacket([]byte) (int, *net.UDPAddr, bool, error)
}
type connectedReader interface {
	ReadPacket([]byte) (int, bool, error)
}

type sessionKey struct{ client netip.AddrPort }
type session struct {
	key    sessionKey
	client *net.UDPAddr
	target *net.UDPConn
	reader connectedReader
	last   atomic.Int64
	closed atomic.Bool
}

func (s *session) touch(t time.Time) { s.last.Store(t.UnixNano()) }
func (s *session) close() {
	if s.closed.CompareAndSwap(false, true) {
		_ = s.target.Close()
	}
}

type shard struct {
	sync.Mutex
	sessions map[sessionKey]*session
}

type Forward struct {
	conn                            *net.UDPConn
	reader                          packetReader
	backend                         *forward.Backend
	classifiers                     []Classifier
	idle, sweep, dial               time.Duration
	now                             func() time.Time
	limits                          Options
	shards                          []shard
	ingressBuffer                   []byte
	mu                              sync.Mutex
	perIP                           map[netip.Addr]int
	active, fds, buffers, ephemeral int
	closed                          atomic.Bool
	closeOnce                       sync.Once
	closeDone                       chan struct{}
	waitOnce                        sync.Once
	waitDone                        chan struct{}
	wg                              sync.WaitGroup
	accepted                        atomic.Int64
	rejected                        atomic.Int64
	truncated                       atomic.Int64
}

type Stats struct {
	Accepted, Rejected, Truncated   int64
	Active, FDs, Buffers, Ephemeral int
}

func New(conn *net.UDPConn, opts Options) (*Forward, error) {
	if conn == nil {
		return nil, errors.New("udp: ingress socket is required")
	}
	if opts.Backend == nil {
		return nil, errors.New("udp: backend is required")
	}
	if opts.Shards <= 0 {
		opts.Shards = 16
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = 2 * time.Minute
	}
	if opts.SweepInterval <= 0 {
		opts.SweepInterval = opts.IdleTimeout / 4
		if opts.SweepInterval <= 0 {
			opts.SweepInterval = time.Second
		}
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.MaxSessions < 0 || opts.MaxSessionsPerIP < 0 || opts.MaxFDs < 0 || opts.MaxBufferBytes < 0 || opts.MaxEphemeralPorts < 0 {
		return nil, errors.New("udp: negative limit")
	}
	if opts.MaxBufferBytes > 0 && opts.MaxBufferBytes < MaxDatagramSize {
		return nil, ErrBufferLimit
	}
	f := &Forward{conn: conn, reader: newPacketReader(conn), backend: opts.Backend, classifiers: append([]Classifier(nil), opts.Classifiers...), idle: opts.IdleTimeout, sweep: opts.SweepInterval, dial: opts.DialTimeout, now: opts.Now, limits: opts, shards: make([]shard, opts.Shards), ingressBuffer: make([]byte, MaxDatagramSize), perIP: make(map[netip.Addr]int), buffers: MaxDatagramSize, closeDone: make(chan struct{}), waitDone: make(chan struct{})}
	for i := range f.shards {
		f.shards[i].sessions = make(map[sessionKey]*session)
	}
	return f, nil
}

func (f *Forward) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	f.wg.Add(1)
	go f.expirer(ctx)
	go func() {
		select {
		case <-ctx.Done():
			_ = f.Close()
		case <-f.closeDone:
		}
	}()
	for {
		n, src, trunc, err := f.reader.ReadPacket(f.ingressBuffer)
		if err != nil {
			if f.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ignoreIngressError(err) {
				continue
			}
			return err
		}
		if trunc {
			f.truncated.Add(1)
			if f.limits.OnTruncated != nil {
				f.limits.OnTruncated()
			}
			continue
		}
		ap := src.AddrPort()
		ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		p := Packet{Source: ap, Data: f.ingressBuffer[:n]}
		matched := false
		for _, c := range f.classifiers {
			if c == nil {
				continue
			}
			r := c.Classify(p)
			if r.Matched {
				matched = true
				if len(r.Reply) > 0 {
					var replyErr error
					if len(r.Reply) > n {
						replyErr = errors.New("udp: classifier reply amplification rejected")
					} else {
						_, replyErr = f.conn.WriteToUDP(r.Reply, src)
					}
					if replyErr != nil && !f.closed.Load() {
						f.reject(replyErr)
					}
					if r.OnReply != nil {
						r.OnReply(replyErr)
					}
				}
				break
			}
		}
		if matched {
			continue
		}
		data := append([]byte(nil), p.Data...)
		if err := f.forward(ap, src, data); err != nil {
			f.reject(err)
		}
	}
}

func (f *Forward) forward(client netip.AddrPort, src *net.UDPAddr, data []byte) error {
	key := sessionKey{client: client}
	sh := &f.shards[hash(client)%uint64(len(f.shards))]
	sh.Lock()
	s := sh.sessions[key]
	if s != nil && !s.closed.Load() {
		s.touch(f.now())
		sh.Unlock()
		_, err := s.target.Write(data)
		return err
	}
	sh.Unlock()
	if f.closed.Load() {
		return ErrClosed
	}
	if err := f.reserve(client.Addr(), MaxDatagramSize); err != nil {
		return err
	}
	target := f.backend.Target()
	d := net.Dialer{Timeout: f.dial}
	c, err := d.Dial("udp4", target.String())
	if err != nil {
		f.release(client.Addr(), MaxDatagramSize)
		return err
	}
	uc := c.(*net.UDPConn)
	candidate := &session{key: key, client: cloneUDPAddr(src), target: uc, reader: newConnectedReader(uc)}
	candidate.touch(f.now())
	sh.Lock()
	if f.closed.Load() {
		sh.Unlock()
		candidate.close()
		f.release(client.Addr(), MaxDatagramSize)
		return ErrClosed
	}
	if existing := sh.sessions[key]; existing != nil && !existing.closed.Load() {
		existing.touch(f.now())
		sh.Unlock()
		candidate.close()
		f.release(client.Addr(), MaxDatagramSize)
		_, err = existing.target.Write(data)
		return err
	}
	sh.sessions[key] = candidate
	f.accepted.Add(1)
	f.wg.Add(1)
	go f.replyLoop(sh, candidate)
	sh.Unlock()
	if _, err = uc.Write(data); err != nil {
		f.remove(sh, candidate)
		return err
	}
	return nil
}
func (f *Forward) reserve(ip netip.Addr, bytes int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.limits.MaxSessions > 0 && f.active >= f.limits.MaxSessions {
		return ErrSessionLimit
	}
	if f.limits.MaxSessionsPerIP > 0 && f.perIP[ip] >= f.limits.MaxSessionsPerIP {
		return ErrPerIPLimit
	}
	if f.limits.MaxFDs > 0 && f.fds+1 > f.limits.MaxFDs {
		return ErrFDLimit
	}
	if f.limits.MaxBufferBytes > 0 && int64(f.buffers+bytes) > f.limits.MaxBufferBytes {
		return ErrBufferLimit
	}
	if f.limits.MaxEphemeralPorts > 0 && f.ephemeral+1 > f.limits.MaxEphemeralPorts {
		return ErrEphemeralLimit
	}
	f.active++
	f.fds++
	f.buffers += bytes
	f.ephemeral++
	f.perIP[ip]++
	return nil
}
func (f *Forward) release(ip netip.Addr, bytes int) {
	f.mu.Lock()
	f.active--
	f.fds--
	f.buffers -= bytes
	f.ephemeral--
	f.perIP[ip]--
	if f.perIP[ip] <= 0 {
		delete(f.perIP, ip)
	}
	f.mu.Unlock()
}
func (f *Forward) reject(err error) {
	f.rejected.Add(1)
	if f.limits.OnReject != nil {
		f.limits.OnReject(err)
	}
}
func (f *Forward) replyLoop(sh *shard, s *session) {
	defer f.wg.Done()
	buf := make([]byte, MaxDatagramSize)
	for {
		n, trunc, err := s.reader.ReadPacket(buf)
		if err != nil {
			f.remove(sh, s)
			return
		}
		if trunc {
			f.truncated.Add(1)
			if f.limits.OnTruncated != nil {
				f.limits.OnTruncated()
			}
			continue
		}
		if _, err = f.conn.WriteToUDP(buf[:n], s.client); err != nil {
			f.remove(sh, s)
			return
		}
		s.touch(f.now())
	}
}
func (f *Forward) remove(sh *shard, s *session) {
	sh.Lock()
	if cur := sh.sessions[s.key]; cur == s {
		delete(sh.sessions, s.key)
		s.close()
		f.release(s.key.client.Addr(), MaxDatagramSize)
	}
	sh.Unlock()
}
func (f *Forward) expirer(ctx context.Context) {
	defer f.wg.Done()
	t := time.NewTicker(f.sweep)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cutoff := f.now().Add(-f.idle).UnixNano()
			for i := range f.shards {
				sh := &f.shards[i]
				sh.Lock()
				var old []*session
				for _, s := range sh.sessions {
					if s.last.Load() <= cutoff {
						delete(sh.sessions, s.key)
						old = append(old, s)
					}
				}
				sh.Unlock()
				for _, s := range old {
					s.close()
					f.release(s.key.client.Addr(), MaxDatagramSize)
				}
			}
		case <-ctx.Done():
			return
		case <-f.closeDone:
			return
		}
	}
}
func (f *Forward) Close() error { return f.CloseContext(context.Background()) }
func (f *Forward) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	f.closeOnce.Do(func() {
		f.closed.Store(true)
		close(f.closeDone)
		_ = f.conn.Close()
		for i := range f.shards {
			sh := &f.shards[i]
			sh.Lock()
			var all []*session
			for _, s := range sh.sessions {
				all = append(all, s)
				delete(sh.sessions, s.key)
			}
			sh.Unlock()
			for _, s := range all {
				s.close()
				f.release(s.key.client.Addr(), MaxDatagramSize)
			}
		}
	})
	f.waitOnce.Do(func() { go func() { f.wg.Wait(); close(f.waitDone) }() })
	select {
	case <-f.waitDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (f *Forward) Stats() Stats {
	f.mu.Lock()
	s := Stats{f.accepted.Load(), f.rejected.Load(), f.truncated.Load(), f.active, f.fds, f.buffers, f.ephemeral}
	f.mu.Unlock()
	return s
}
func hash(a netip.AddrPort) uint64 {
	b := a.Addr().As16()
	h := uint64(a.Port())
	for _, v := range b {
		h = h*1099511628211 ^ uint64(v)
	}
	return h
}
func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}
