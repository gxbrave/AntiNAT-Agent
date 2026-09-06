// Per-transport endpoint health (v0.8 §3.5 keepalive/renewal contract).
// Every health dimension — DNS/IP resolution, cooldown, RTT, success rate —
// is keyed by (transport, host, port), so a TCP endpoint's failures never
// cool down or skew the UDP endpoint for the same server. After repeated
// failures an endpoint enters cooldown so a public STUN server's acceptable
// request frequency is respected instead of sustained high-frequency
// retries; a success clears the cooldown.
package stun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Transport identifies the STUN transport.
type Transport string

const (
	TransportUDP Transport = "udp"
	TransportTCP Transport = "tcp"
)

// ErrCooldown reports that the endpoint is cooling down after failures and
// must not be contacted yet (v0.8 §3.5: cooldown instead of high-frequency
// retry).
var ErrCooldown = errors.New("stun: endpoint is in cooldown")

// HealthOptions tunes cooldown and threshold behavior.
type HealthOptions struct {
	FailureThreshold int           // consecutive failures before cooldown; default 3
	CooldownBase     time.Duration // first cooldown duration; default 5 s
	CooldownMax      time.Duration // cooldown ceiling; default 60 s
	Resolver         *net.Resolver // nil uses net.DefaultResolver
}

// EndpointKey identifies one (transport, host, port) health record. The
// resolved IP is recorded but resolution state stays per transport.
type EndpointKey struct {
	Transport Transport
	Host      string
	Port      uint16
	IP        netip.Addr
}

// HealthStats is a snapshot of one endpoint's counters.
type HealthStats struct {
	Successes   uint64
	Failures    uint64
	SuccessRate float64
	MeanRTT     time.Duration
	LastRTT     time.Duration
	InCooldown  bool
}

type healthState struct {
	key                EndpointKey
	resolvedIP         netip.Addr
	successes          uint64
	failures           uint64
	totalRTT           time.Duration
	lastRTT            time.Duration
	consecutiveFailure int
	cooldownUntil      time.Time
	dnsLookups         int
}

// NewEndpointHealth returns a per-transport health tracker.
func NewEndpointHealth(options HealthOptions) *EndpointHealth {
	if options.FailureThreshold <= 0 {
		options.FailureThreshold = 3
	}
	if options.CooldownBase <= 0 {
		options.CooldownBase = 5 * time.Second
	}
	if options.CooldownMax <= 0 {
		options.CooldownMax = 60 * time.Second
	}
	return &EndpointHealth{
		states:    make(map[healthKey]*healthState),
		threshold: options.FailureThreshold,
		base:      options.CooldownBase,
		max:       options.CooldownMax,
		resolver:  options.Resolver,
	}
}

// healthKey identifies one endpoint without the resolved IP, so lookups
// work before and after resolution.
type healthKey struct {
	transport Transport
	host      string
	port      uint16
}

func healthKeyOf(key EndpointKey) healthKey {
	return healthKey{transport: key.Transport, host: key.Host, port: key.Port}
}

// EndpointHealth tracks per-transport endpoint state.
type EndpointHealth struct {
	mu        sync.Mutex
	states    map[healthKey]*healthState
	threshold int
	base      time.Duration
	max       time.Duration
	resolver  *net.Resolver
}

// keyFor builds the lookup key for an endpoint (without resolution).
func (h *EndpointHealth) keyFor(transport Transport, host string, port uint16) EndpointKey {
	return EndpointKey{Transport: transport, Host: host, Port: port}
}

// Resolve returns the endpoint key with the resolved IP. Literal IPs skip
// DNS; hostnames resolve once per (transport, host, port) and the result is
// cached. An endpoint in cooldown fails fast with ErrCooldown (no network
// contact). A DNS failure counts as a failure and engages cooldown.
func (h *EndpointHealth) Resolve(ctx context.Context, transport Transport, host string, port uint16) (EndpointKey, error) {
	key := h.keyFor(transport, host, port)
	h.mu.Lock()
	state, ok := h.states[healthKeyOf(key)]
	if !ok {
		state = &healthState{key: key}
		h.states[healthKeyOf(key)] = state
	}
	if time.Now().Before(state.cooldownUntil) {
		h.mu.Unlock()
		return EndpointKey{}, ErrCooldown
	}
	if state.resolvedIP.IsValid() {
		key.IP = state.resolvedIP
		h.mu.Unlock()
		return key, nil
	}
	h.mu.Unlock()

	ip, err := h.resolveIP(ctx, state)
	if err != nil {
		h.Report(key, 0, err)
		return EndpointKey{}, err
	}
	h.mu.Lock()
	state.resolvedIP = ip
	h.mu.Unlock()
	key.IP = ip
	return key, nil
}

func (h *EndpointHealth) resolveIP(ctx context.Context, state *healthState) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(state.key.Host); err == nil {
		return addr.Unmap(), nil
	}
	h.mu.Lock()
	state.dnsLookups++
	h.mu.Unlock()
	resolver := h.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupIPAddr(ctx, state.key.Host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, address := range addresses {
		if addr, ok := netip.AddrFromSlice(address.IP); ok {
			if addr = addr.Unmap(); addr.Is4() {
				return addr, nil
			}
		}
	}
	return netip.Addr{}, errors.New("stun: no IPv4 address for host")
}

// Report records one exchange outcome for the endpoint and updates
// cooldown. A failure increments the consecutive-failure counter and, past
// the threshold, engages cooldown with exponential backoff capped at
// CooldownMax; a success clears cooldown and the failure streak.
func (h *EndpointHealth) Report(key EndpointKey, rtt time.Duration, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.states[healthKeyOf(key)]
	if !ok {
		state = &healthState{key: key}
		h.states[healthKeyOf(key)] = state
	}
	if err != nil {
		state.failures++
		state.lastRTT = rtt
		state.consecutiveFailure++
		if state.consecutiveFailure >= h.threshold {
			backoff := h.base
			for i := 1; i < state.consecutiveFailure-h.threshold+1 && backoff < h.max; i++ {
				backoff *= 2
			}
			if backoff > h.max {
				backoff = h.max
			}
			state.cooldownUntil = time.Now().Add(backoff)
		}
		return
	}
	state.successes++
	state.totalRTT += rtt
	state.lastRTT = rtt
	state.consecutiveFailure = 0
	state.cooldownUntil = time.Time{}
}

// Ready reports whether the endpoint may be contacted now. ErrCooldown is
// returned while cooling down.
func (h *EndpointHealth) Ready(key EndpointKey) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.states[healthKeyOf(key)]
	if !ok {
		return nil
	}
	if time.Now().Before(state.cooldownUntil) {
		return ErrCooldown
	}
	return nil
}

// Stats returns a snapshot of the endpoint's counters.
func (h *EndpointHealth) Stats(key EndpointKey) HealthStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.states[healthKeyOf(key)]
	if !ok {
		return HealthStats{}
	}
	total := state.successes + state.failures
	stats := HealthStats{
		Successes:  state.successes,
		Failures:   state.failures,
		LastRTT:    state.lastRTT,
		InCooldown: time.Now().Before(state.cooldownUntil),
	}
	if total > 0 {
		stats.SuccessRate = float64(state.successes) / float64(total)
	}
	if state.successes > 0 {
		stats.MeanRTT = state.totalRTT / time.Duration(state.successes)
	}
	return stats
}

// dnsLookups returns how many DNS resolutions the endpoint performed (test
// seam for cache verification).
func (h *EndpointHealth) dnsLookups(key EndpointKey) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if state, ok := h.states[healthKeyOf(key)]; ok {
		return state.dnsLookups
	}
	return 0
}

// inCooldown reports whether the endpoint is currently cooling down (test
// seam).
func (h *EndpointHealth) inCooldown(key EndpointKey) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	state, ok := h.states[healthKeyOf(key)]
	if !ok {
		return false
	}
	return time.Now().Before(state.cooldownUntil)
}
