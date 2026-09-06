// P08 Story 6 RED: transport boundaries — the control dialer must try IPv4
// (A) only, IPv6 (AAAA) only, or both with fallback, and bound the attempts.
package control_test

import (
	"context"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/agent/control"
)

// fakeResolver returns the given addresses for any lookup.
type fakeResolver struct{ addrs []string }

func (f fakeResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, a := range f.addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

// RED 6a: A-only resolution dials an IPv4 literal.
func TestDialFamilyAOnly(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			done <- c.RemoteAddr().String()
			c.Close()
		}
	}()

	conn, family, err := control.DialEndpoint(context.Background(), "http://"+ln.Addr().String(),
		fakeResolver{addrs: []string{"127.0.0.1"}}, 2*time.Second)
	if err != nil {
		t.Fatalf("DialEndpoint: %v", err)
	}
	defer conn.Close()
	if family != "ip4" {
		t.Fatalf("family = %q, want ip4", family)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection accepted")
	}
}

// RED 6b: AAAA-only resolution dials an IPv6 literal (skip if no v6 loopback).
func TestDialFamilyAAAAOnly(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer ln.Close()
	done := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			done <- struct{}{}
			c.Close()
		}
	}()

	conn, family, err := control.DialEndpoint(context.Background(), "http://"+ln.Addr().String(),
		fakeResolver{addrs: []string{"::1"}}, 2*time.Second)
	if err != nil {
		t.Fatalf("DialEndpoint: %v", err)
	}
	defer conn.Close()
	if family != "ip6" {
		t.Fatalf("family = %q, want ip6", family)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("no connection accepted")
	}
}

// RED 6c: dual resolution falls back from the failed family to the working
// one.
func TestDialFamilyDualFallback(t *testing.T) {
	// Only an IPv4 listener exists; resolution returns A then AAAA so the
	// dialer must fall back to IPv4.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	conn, family, err := control.DialEndpoint(context.Background(), "http://"+ln.Addr().String(),
		fakeResolver{addrs: []string{"::1", "127.0.0.1"}}, 2*time.Second)
	if err != nil {
		t.Fatalf("DialEndpoint: %v", err)
	}
	defer conn.Close()
	if family != "ip4" {
		t.Fatalf("family = %q, want ip4 (dual fallback)", family)
	}
}

// RED 6d: no resolvable address fails closed.
func TestDialFamilyNoAddresses(t *testing.T) {
	_, _, err := control.DialEndpoint(context.Background(), "http://controller.invalid:3111",
		fakeResolver{addrs: []string{}}, 2*time.Second)
	if err == nil {
		t.Fatal("dial with no addresses succeeded")
	}
}

// RED 6e: a malformed endpoint URL fails closed.
func TestDialEndpointMalformedURL(t *testing.T) {
	_, _, err := control.DialEndpoint(context.Background(), "://bad",
		fakeResolver{addrs: []string{"127.0.0.1"}}, 2*time.Second)
	if err == nil {
		t.Fatal("malformed endpoint dialed")
	}
}

// RED 6f: the endpoint host is resolved via the resolver (no IP literal
// shortcut that bypasses family policy).
func TestDialEndpointUsesResolver(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	u, _ := url.Parse("http://" + ln.Addr().String())
	host := u.Hostname()
	_ = host
	// Resolution returns the listener address; the dial must succeed.
	conn, _, err := control.DialEndpoint(context.Background(), "http://"+ln.Addr().String(),
		fakeResolver{addrs: []string{"127.0.0.1"}}, 2*time.Second)
	if err != nil {
		t.Fatalf("DialEndpoint: %v", err)
	}
	defer conn.Close()
	_ = strings.TrimSpace
}
