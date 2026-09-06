// Story 6 RED: per-transport endpoint health (v0.8 §3.5 keepalive/renewal
// contract). DNS/IP resolution, cooldown, RTT and success-rate state are
// separated per transport: a TCP endpoint's failures must never cool down or
// skew the UDP endpoint for the same server. After repeated failures the
// endpoint enters cooldown so a public STUN server's acceptable frequency is
// respected instead of high-frequency retries. Fuzz targets must never
// panic.
package stun

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestHealthResolveLiteralIP(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{})
	key, err := health.Resolve(context.Background(), TransportUDP, "127.0.0.1", 3478)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if key.Transport != TransportUDP || key.Host != "127.0.0.1" || key.Port != 3478 {
		t.Fatalf("key = %+v", key)
	}
	if key.IP != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("IP = %v", key.IP)
	}
	// DNS must not have been needed for a literal.
	if health.dnsLookups(key) != 0 {
		t.Fatalf("literal triggered %d DNS lookups", health.dnsLookups(key))
	}
}

func TestHealthResolveDNS(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{})
	key, err := health.Resolve(context.Background(), TransportTCP, "localhost", 3478)
	if err != nil {
		t.Fatalf("Resolve localhost: %v", err)
	}
	if !key.IP.IsLoopback() {
		t.Fatalf("localhost resolved to %v, want loopback", key.IP)
	}
	// A second resolve for the same endpoint must reuse the cached IP.
	again, err := health.Resolve(context.Background(), TransportTCP, "localhost", 3478)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if again.IP != key.IP {
		t.Fatalf("cached IP changed: %v -> %v", key.IP, again.IP)
	}
	if got := health.dnsLookups(key); got != 1 {
		t.Fatalf("DNS lookups = %d, want 1 (cached)", got)
	}
}

func TestHealthTransportSeparation(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{FailureThreshold: 2, CooldownBase: time.Hour})
	udpKey, err := health.Resolve(context.Background(), TransportUDP, "127.0.0.1", 3478)
	if err != nil {
		t.Fatalf("Resolve udp: %v", err)
	}
	tcpKey, err := health.Resolve(context.Background(), TransportTCP, "127.0.0.1", 3478)
	if err != nil {
		t.Fatalf("Resolve tcp: %v", err)
	}
	// Fail the TCP endpoint past the threshold; the UDP endpoint for the
	// same host:port must stay healthy.
	health.Report(tcpKey, 0, errors.New("boom"))
	health.Report(tcpKey, 0, errors.New("boom"))
	if !health.inCooldown(tcpKey) {
		t.Fatal("TCP endpoint not in cooldown after two failures")
	}
	if health.inCooldown(udpKey) {
		t.Fatal("UDP endpoint cooled down by TCP failures (transport separation broken)")
	}
	if err := health.Ready(udpKey); err != nil {
		t.Fatalf("UDP endpoint not ready: %v", err)
	}
	if err := health.Ready(tcpKey); !errors.Is(err, ErrCooldown) {
		t.Fatalf("TCP endpoint Ready = %v, want ErrCooldown", err)
	}
}

func TestHealthCooldownClearsOnSuccess(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{FailureThreshold: 2, CooldownBase: time.Hour})
	key, err := health.Resolve(context.Background(), TransportUDP, "127.0.0.1", 3478)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	health.Report(key, 10*time.Millisecond, errors.New("fail"))
	health.Report(key, 10*time.Millisecond, errors.New("fail"))
	if !health.inCooldown(key) {
		t.Fatal("endpoint not in cooldown")
	}
	health.Report(key, 5*time.Millisecond, nil)
	if health.inCooldown(key) {
		t.Fatal("cooldown not cleared by success")
	}
	if err := health.Ready(key); err != nil {
		t.Fatalf("Ready after success: %v", err)
	}
}

func TestHealthStatsRTTAndSuccessRate(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{})
	key, err := health.Resolve(context.Background(), TransportUDP, "127.0.0.1", 3478)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	health.Report(key, 10*time.Millisecond, nil)
	health.Report(key, 20*time.Millisecond, nil)
	health.Report(key, 30*time.Millisecond, errors.New("fail"))
	stats := health.Stats(key)
	if stats.Successes != 2 || stats.Failures != 1 {
		t.Fatalf("counts = %+v, want 2 successes 1 failure", stats)
	}
	if stats.SuccessRate != 2.0/3.0 {
		t.Fatalf("success rate = %v, want %v", stats.SuccessRate, 2.0/3.0)
	}
	if stats.MeanRTT != 15*time.Millisecond {
		t.Fatalf("mean RTT = %v, want 15ms", stats.MeanRTT)
	}
	if stats.LastRTT != 30*time.Millisecond {
		t.Fatalf("last RTT = %v, want 30ms", stats.LastRTT)
	}
}

func TestHealthCooldownExpires(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{FailureThreshold: 1, CooldownBase: 30 * time.Millisecond})
	key, err := health.Resolve(context.Background(), TransportUDP, "127.0.0.1", 3478)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	health.Report(key, 0, errors.New("fail"))
	if !health.inCooldown(key) {
		t.Fatal("endpoint not in cooldown")
	}
	time.Sleep(60 * time.Millisecond)
	if err := health.Ready(key); err != nil {
		t.Fatalf("endpoint still cooling down after expiry: %v", err)
	}
}

func TestHealthDNSFailureCountsAndCoolsDown(t *testing.T) {
	health := NewEndpointHealth(HealthOptions{FailureThreshold: 1, CooldownBase: time.Hour})
	// An unresolvable host must fail the resolve, count as a failure, and
	// put the endpoint into cooldown.
	key, err := health.Resolve(context.Background(), TransportUDP, "nonexistent.invalid", 3478)
	if err == nil {
		t.Fatalf("Resolve of nonexistent.invalid succeeded: %+v", key)
	}
	stats := health.Stats(health.keyFor(TransportUDP, "nonexistent.invalid", 3478))
	if stats.Failures != 1 {
		t.Fatalf("failures = %d, want 1", stats.Failures)
	}
	if !health.inCooldown(health.keyFor(TransportUDP, "nonexistent.invalid", 3478)) {
		t.Fatal("endpoint not in cooldown after DNS failure")
	}
}
