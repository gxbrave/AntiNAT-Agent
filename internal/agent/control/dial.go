package control

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"time"
)

// Resolver resolves a host to IP addresses (A + AAAA records).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DialEndpoint dials the endpoint's host:port with an explicit family policy:
//   - only A (IPv4) records resolve -> IPv4 only;
//   - only AAAA (IPv6) records resolve -> IPv6 only;
//   - both -> try IPv4 first, fall back to IPv6 (dual).
//
// Each attempt is bounded by perAttemptTimeout; a host with no addresses or a
// malformed URL fails closed.
func DialEndpoint(ctx context.Context, endpoint string, resolver Resolver, perAttemptTimeout time.Duration) (net.Conn, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("control: parse endpoint: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, "", fmt.Errorf("control: endpoint %q has no host", endpoint)
	}
	port := u.Port()
	if port == "" {
		port = "3111"
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, "", fmt.Errorf("control: resolve %s: %w", host, err)
	}
	var v4, v6 []net.IPAddr
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, "", fmt.Errorf("control: host %s has no A or AAAA records", host)
	}

	dial := func(addr net.IPAddr) (net.Conn, error) {
		ctx2, cancel := context.WithTimeout(ctx, perAttemptTimeout)
		defer cancel()
		return (&net.Dialer{}).DialContext(ctx2, "tcp", net.JoinHostPort(addr.IP.String(), port))
	}

	// A-only / AAAA-only / dual (IPv4 first, IPv6 fallback).
	for _, ip := range v4 {
		conn, err := dial(ip)
		if err == nil {
			return conn, "ip4", nil
		}
	}
	for _, ip := range v6 {
		conn, err := dial(ip)
		if err == nil {
			return conn, "ip6", nil
		}
	}
	return nil, "", fmt.Errorf("control: dial %s: no reachable address", endpoint)
}
