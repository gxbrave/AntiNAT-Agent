package udp

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
)

func listen(t *testing.T) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func backend(t *testing.T, c *net.UDPConn) *forward.Backend {
	t.Helper()
	b, e := forward.NewBackend(c.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func run(t *testing.T, f *Forward) {
	t.Helper()
	go func() { _ = f.Run(context.Background()) }()
	t.Cleanup(func() { _ = f.Close() })
}
func exchange(t *testing.T, c *net.UDPConn, to *net.UDPAddr, p []byte) []byte {
	t.Helper()
	if _, e := c.WriteToUDP(p, to); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, MaxDatagramSize)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	n, from, e := c.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	if from.String() != to.String() {
		t.Fatalf("response source %s, want ingress %s", from, to)
	}
	return b[:n]
}

func TestClassifierReplyUsesIngressWithoutBusinessSession(t *testing.T) {
	target := listen(t)
	ing := listen(t)
	f, err := New(ing, Options{Backend: backend(t, target), Classifiers: []Classifier{
		ClassifierFunc(func(p Packet) Classification {
			if string(p.Data) == "probe" {
				return Classification{Matched: true, Reply: []byte("ack")}
			}
			return Classification{}
		}),
	}})
	if err != nil {
		t.Fatal(err)
	}
	run(t, f)
	client := listen(t)
	if got := exchange(t, client, ing.LocalAddr().(*net.UDPAddr), []byte("probe")); string(got) != "ack" {
		t.Fatalf("got %q", got)
	}
	if f.Stats().Active != 0 {
		t.Fatalf("matched control packet created business session: %+v", f.Stats())
	}
}

func TestStrictClassifierLookalikeFallsThrough(t *testing.T) {
	target := listen(t)
	go func() {
		b := make([]byte, 64)
		n, a, _ := target.ReadFromUDP(b)
		_, _ = target.WriteToUDP(append([]byte("biz:"), b[:n]...), a)
	}()
	ing := listen(t)
	f, e := New(ing, Options{Backend: backend(t, target), Classifiers: []Classifier{ClassifierFunc(func(p Packet) Classification { return Classification{Matched: string(p.Data) == "exact"} })}})
	if e != nil {
		t.Fatal(e)
	}
	run(t, f)
	client := listen(t)
	got := exchange(t, client, ing.LocalAddr().(*net.UDPAddr), []byte("STUN-lookalike"))
	if string(got) != "biz:STUN-lookalike" {
		t.Fatalf("got %q", got)
	}
}
func TestExactSourceAndHotUpdateNewSessionsOnly(t *testing.T) {
	one, two := listen(t), listen(t)
	echo := func(c *net.UDPConn, p string) {
		go func() {
			for {
				b := make([]byte, 64)
				n, a, e := c.ReadFromUDP(b)
				if e != nil {
					return
				}
				_, _ = c.WriteToUDP(append([]byte(p), b[:n]...), a)
			}
		}()
	}
	echo(one, "one:")
	echo(two, "two:")
	b := backend(t, one)
	ing := listen(t)
	f, e := New(ing, Options{Backend: b})
	if e != nil {
		t.Fatal(e)
	}
	run(t, f)
	c1 := listen(t)
	if got := exchange(t, c1, ing.LocalAddr().(*net.UDPAddr), []byte("a")); string(got) != "one:a" {
		t.Fatal(string(got))
	}
	if e = b.Update(two.LocalAddr().String()); e != nil {
		t.Fatal(e)
	}
	if got := exchange(t, c1, ing.LocalAddr().(*net.UDPAddr), []byte("b")); string(got) != "one:b" {
		t.Fatal(string(got))
	}
	c2 := listen(t)
	if got := exchange(t, c2, ing.LocalAddr().(*net.UDPAddr), []byte("c")); string(got) != "two:c" {
		t.Fatal(string(got))
	}
}
func TestCapsExpiryAndCloseContext(t *testing.T) {
	target := listen(t)
	ing := listen(t)
	rejected := make(chan error, 1)
	f, e := New(ing, Options{Backend: backend(t, target), MaxSessions: 1, MaxSessionsPerIP: 1, MaxFDs: 1, MaxBufferBytes: 2 * MaxDatagramSize, MaxEphemeralPorts: 1, IdleTimeout: 20 * time.Millisecond, SweepInterval: 5 * time.Millisecond, OnReject: func(e error) { rejected <- e }})
	if e != nil {
		t.Fatal(e)
	}
	run(t, f)
	c1, c2 := listen(t), listen(t)
	_, _ = c1.WriteToUDP([]byte("a"), ing.LocalAddr().(*net.UDPAddr))
	time.Sleep(10 * time.Millisecond)
	_, _ = c2.WriteToUDP([]byte("b"), ing.LocalAddr().(*net.UDPAddr))
	select {
	case e := <-rejected:
		if !errors.Is(e, ErrSessionLimit) && !errors.Is(e, ErrPerIPLimit) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("no rejection")
	}
	time.Sleep(50 * time.Millisecond)
	if f.Stats().Active != 0 {
		t.Fatalf("active=%d", f.Stats().Active)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e = f.CloseContext(ctx); e != nil {
		t.Fatal(e)
	}
}

type errorConnectedReader struct{ err error }

func (r errorConnectedReader) ReadPacket([]byte) (int, bool, error) { return 0, false, r.err }

func TestTargetErrorRemovesOnlyMatchingSession(t *testing.T) {
	target := listen(t)
	ing := listen(t)
	f, err := New(ing, Options{Backend: backend(t, target)})
	if err != nil {
		t.Fatal(err)
	}
	c1, c2 := listen(t), listen(t)
	a1 := c1.LocalAddr().(*net.UDPAddr).AddrPort()
	a2 := c2.LocalAddr().(*net.UDPAddr).AddrPort()
	s1 := &session{key: sessionKey{client: a1}, client: cloneUDPAddr(c1.LocalAddr().(*net.UDPAddr)), target: listen(t)}
	s2 := &session{key: sessionKey{client: a2}, client: cloneUDPAddr(c2.LocalAddr().(*net.UDPAddr)), target: listen(t)}
	s1.reader = errorConnectedReader{err: errors.New("correlated ICMP")}
	s2.reader = newConnectedReader(s2.target)
	s1.touch(time.Now())
	s2.touch(time.Now())
	sh1 := &f.shards[hash(a1)%uint64(len(f.shards))]
	sh2 := &f.shards[hash(a2)%uint64(len(f.shards))]
	if err := f.reserve(a1.Addr(), MaxDatagramSize); err != nil {
		t.Fatal(err)
	}
	if err := f.reserve(a2.Addr(), MaxDatagramSize); err != nil {
		t.Fatal(err)
	}
	sh1.Lock()
	sh1.sessions[s1.key] = s1
	sh1.Unlock()
	sh2.Lock()
	sh2.sessions[s2.key] = s2
	sh2.Unlock()
	f.wg.Add(1)
	go f.replyLoop(sh1, s1)
	deadline := time.Now().Add(time.Second)
	for f.Stats().Active != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.Stats().Active != 1 {
		t.Fatalf("stats %+v", f.Stats())
	}
	sh2.Lock()
	_, remains := sh2.sessions[s2.key]
	sh2.Unlock()
	if !remains {
		t.Fatal("unrelated session removed")
	}
	_ = f.Close()
}

type truncReader struct{ used bool }

func (r *truncReader) ReadPacket(b []byte) (int, *net.UDPAddr, bool, error) {
	if !r.used {
		r.used = true
		copy(b, "drop")
		return 4, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, true, nil
	}
	return 0, nil, false, net.ErrClosed
}
func TestTruncatedDropped(t *testing.T) {
	target := listen(t)
	ing := listen(t)
	f, e := New(ing, Options{Backend: backend(t, target)})
	if e != nil {
		t.Fatal(e)
	}
	f.reader = &truncReader{}
	if e = f.Run(context.Background()); e != nil {
		t.Fatal(e)
	}
	if f.Stats().Truncated != 1 || f.Stats().Active != 0 {
		t.Fatalf("stats %+v", f.Stats())
	}
}
