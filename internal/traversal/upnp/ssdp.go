// SSDP discovery (UPnP 1.0 device architecture): one M-SEARCH per search
// target over UDP multicast 239.255.255.250:1900, bound to the selected
// interface (Linux implements the socket control; other platforms refuse
// interface-bound multicast rather than leak discovery across interfaces).
// Responses are size-capped, parsed strictly, deduped by USN and selected
// deterministically. An SSDP response only ever produces a gateway record;
// the HTTP fetches it enables are scoped in description.go.
package upnp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SSDP constants.
const (
	// MulticastAddr is the SSDP multicast group.
	MulticastAddr = "239.255.255.250:1900"
	// SSDPPort is the SSDP UDP port.
	SSDPPort = 1900
	// MaxResponseBytes caps one SSDP response datagram.
	MaxResponseBytes = 4096
	// DefaultSearchWait is the MX wait budget per search target.
	DefaultSearchWait = 2 * time.Second
)

// Search targets this client issues, in priority order (IGDv2 first).
var SearchTargets = []string{
	"urn:schemas-upnp-org:service:WANIPConnection:2",
	"urn:schemas-upnp-org:service:WANIPConnection:1",
	"urn:schemas-upnp-org:service:WANPPPConnection:1",
}

// Gateway is one discovered IGD advertisement: the USN is the stable
// identity recorded in the mapping journal, the LOCATION is the description
// URL and SearchTarget is the service that answered.
type Gateway struct {
	USN          string
	Location     string
	SearchTarget string
	// Server is the informational SERVER header; never used for control.
	Server string
}

// SSDP errors.
var (
	ErrNotAnSSDPResponse = errors.New("upnp: not an SSDP M-SEARCH response")
	ErrSSDPTooLarge      = errors.New("upnp: SSDP response exceeds the size cap")
	ErrMissingField      = errors.New("upnp: SSDP response missing a required header")
	// ErrSSDPUnsupportedPlatform reports platforms without native
	// interface-bound multicast evidence: discovery refuses to run instead
	// of leaking M-SEARCH across all interfaces (fail closed).
	ErrSSDPUnsupportedPlatform = errors.New("upnp: interface-bound SSDP unsupported on this platform")
)

// parseSSDPResponse parses one M-SEARCH response datagram. Only 200
// responses with USN + LOCATION + ST are accepted.
func parseSSDPResponse(datagram []byte) (Gateway, error) {
	if len(datagram) > MaxResponseBytes {
		return Gateway{}, ErrSSDPTooLarge
	}
	text := string(datagram)
	line, rest, ok := strings.Cut(text, "\r\n")
	if !ok {
		return Gateway{}, ErrNotAnSSDPResponse
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 || !strings.HasPrefix(strings.ToUpper(parts[0]), "HTTP/") || parts[1] != "200" {
		return Gateway{}, ErrNotAnSSDPResponse
	}
	gateway := Gateway{}
	for len(rest) > 0 {
		var header string
		header, rest, ok = strings.Cut(rest, "\r\n")
		if !ok {
			break
		}
		if header == "" {
			break // end of headers
		}
		name, value, ok := strings.Cut(header, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "location":
			gateway.Location = value
		case "usn":
			gateway.USN = value
		case "st":
			gateway.SearchTarget = value
		case "server":
			gateway.Server = value
		}
	}
	if gateway.USN == "" || gateway.Location == "" || gateway.SearchTarget == "" {
		return Gateway{}, ErrMissingField
	}
	return gateway, nil
}

// serviceRank ranks a search target for deterministic selection: exact
// WANIPConnection:2 first, then :1, then WANPPPConnection:1; anything else
// does not qualify as a control service.
func serviceRank(st string) int {
	switch st {
	case "urn:schemas-upnp-org:service:WANIPConnection:2":
		return 0
	case "urn:schemas-upnp-org:service:WANIPConnection:1":
		return 1
	case "urn:schemas-upnp-org:service:WANPPPConnection:1":
		return 2
	}
	return 99
}

// SelectGateways dedupes advertisements by USN and returns the control-capable
// ones in deterministic priority order (service version, then USN). The
// ordering is stable across runs on unchanged networks.
func SelectGateways(gateways []Gateway) []Gateway {
	byUSN := make(map[string]Gateway, len(gateways))
	for _, gateway := range gateways {
		if existing, seen := byUSN[gateway.USN]; seen {
			// Keep the higher-ranked advertisement for the same USN.
			if serviceRank(gateway.SearchTarget) < serviceRank(existing.SearchTarget) {
				byUSN[gateway.USN] = gateway
			}
			continue
		}
		byUSN[gateway.USN] = gateway
	}
	selected := make([]Gateway, 0, len(byUSN))
	for _, gateway := range byUSN {
		if serviceRank(gateway.SearchTarget) > 2 {
			continue // not a WAN control service
		}
		selected = append(selected, gateway)
	}
	sort.Slice(selected, func(i, j int) bool {
		ri, rj := serviceRank(selected[i].SearchTarget), serviceRank(selected[j].SearchTarget)
		if ri != rj {
			return ri < rj
		}
		return selected[i].USN < selected[j].USN
	})
	return selected
}

// DiscoverOptions tune one discovery round.
type DiscoverOptions struct {
	// InterfaceIP binds the multicast socket to this interface's IPv4
	// address. Required: discovery never runs unbound.
	InterfaceIP netip.Addr
	// Wait is the per-target MX wait; default 2s.
	Wait time.Duration
	// MaxGateways caps collected advertisements; default 16.
	MaxGateways int
}

// Discover issues M-SEARCH for every known search target on the given
// interface and returns the deduped, deterministically ordered gateways.
func Discover(ctx context.Context, opts DiscoverOptions) ([]Gateway, error) {
	if !opts.InterfaceIP.IsValid() || !opts.InterfaceIP.Is4() {
		return nil, fmt.Errorf("upnp: SSDP discovery requires a concrete interface IPv4, got %v", opts.InterfaceIP)
	}
	if opts.Wait <= 0 {
		opts.Wait = DefaultSearchWait
	}
	if opts.MaxGateways <= 0 {
		opts.MaxGateways = 16
	}

	packet, err := listenMulticastUDP4(opts.InterfaceIP)
	if err != nil {
		return nil, err
	}
	defer packet.Close()

	var collected []Gateway
	for _, target := range SearchTargets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		found, err := searchTarget(ctx, packet, target, opts)
		if err != nil {
			return nil, err
		}
		collected = append(collected, found...)
		if len(collected) >= opts.MaxGateways {
			collected = collected[:opts.MaxGateways]
			break
		}
	}
	return SelectGateways(collected), nil
}

// searchTarget sends one M-SEARCH and collects responses until the MX wait
// elapses. Late advertisements from earlier targets are fine: each datagram
// is parsed independently and dedup happens in SelectGateways.
func searchTarget(ctx context.Context, packet net.PacketConn, target string, opts DiscoverOptions) ([]Gateway, error) {
	search := buildMSearch(target, opts.Wait)
	group := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("239.255.255.250"), SSDPPort))
	if _, err := packet.WriteTo(search, group); err != nil {
		return nil, fmt.Errorf("upnp: M-SEARCH send: %w", err)
	}

	var found []Gateway
	deadline := time.Now().Add(opts.Wait + 500*time.Millisecond) // MX jitter grace
	// The caller's attempt budget caps each MX window: without this a
	// three-target discovery runs ~3×(MX+grace) regardless of the context.
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	buf := make([]byte, MaxResponseBytes+1)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := packet.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		n, _, err := packet.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || isTimeout(err) {
				return found, nil // MX window elapsed
			}
			return nil, fmt.Errorf("upnp: SSDP read: %w", err)
		}
		gateway, err := parseSSDPResponse(buf[:n])
		if err != nil {
			continue // unrelated multicast noise is ignored
		}
		if gateway.SearchTarget != target {
			continue
		}
		found = append(found, gateway)
		if len(found) >= opts.MaxGateways {
			return found, nil
		}
	}
}

// buildMSearch renders one M-SEARCH request (CRLF line endings, MX padded).
func buildMSearch(target string, wait time.Duration) []byte {
	mx := int(wait.Seconds())
	if mx < 1 {
		mx = 1
	}
	request := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: " + strconv.Itoa(mx) + "\r\n" +
		"ST: " + target + "\r\n" +
		"\r\n"
	return []byte(request)
}

// isTimeout reports whether the error is a deadline expiry.
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
