// Endpoint and network address classification (v0.8 §3.1, docs/protocol.md
// §7.1). Explicit table-based classification, never IsGlobalUnicast alone:
// RFC1918, CGNAT, loopback, link-local, benchmark, documentation, multicast,
// reserved, unspecified, and IPv4-mapped IPv6 are all distinct classes.
package protocol

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// EndpointClass is the explicit address class of an IP literal.
type EndpointClass int

const (
	ClassUnspecified EndpointClass = iota
	ClassLoopback
	ClassRFC1918
	ClassCGNAT
	ClassLinkLocal
	ClassBenchmark
	ClassDocumentation
	ClassMulticast
	ClassReserved
	ClassGlobalUnicast
	ClassIPv4MappedIPv6
)

var endpointClassNames = map[EndpointClass]string{
	ClassUnspecified:    "unspecified",
	ClassLoopback:       "loopback",
	ClassRFC1918:        "rfc1918",
	ClassCGNAT:          "cgnat",
	ClassLinkLocal:      "link-local",
	ClassBenchmark:      "benchmark",
	ClassDocumentation:  "documentation",
	ClassMulticast:      "multicast",
	ClassReserved:       "reserved",
	ClassGlobalUnicast:  "global-unicast",
	ClassIPv4MappedIPv6: "ipv4-mapped-ipv6",
}

// String returns a stable lowercase class name.
func (c EndpointClass) String() string {
	if n, ok := endpointClassNames[c]; ok {
		return n
	}
	return fmt.Sprintf("class(%d)", int(c))
}

// ClassifyIP returns the explicit class of ip.
func ClassifyIP(ip netip.Addr) EndpointClass {
	if !ip.IsValid() {
		return ClassUnspecified
	}
	// IPv4-mapped IPv6 is its own class, regardless of the mapped address.
	if ip.Is4In6() {
		return ClassIPv4MappedIPv6
	}
	if ip.IsUnspecified() {
		return ClassUnspecified
	}
	if ip.IsLoopback() {
		return ClassLoopback
	}
	if ip.Is4() {
		return classifyIPv4(ip.As4())
	}
	if ip.IsLinkLocalUnicast() {
		return ClassLinkLocal
	}
	if ip.IsMulticast() {
		return ClassMulticast
	}
	// ULA (fc00::/7) is private address space.
	if v := ip.As16(); v[0]&0xfe == 0xfc {
		return ClassRFC1918
	}
	// 2001:db8::/32 is documentation.
	if v := ip.As16(); v[0] == 0x20 && v[1] == 0x01 && v[2] == 0x0d && v[3] == 0xb8 {
		return ClassDocumentation
	}
	return ClassGlobalUnicast
}

func classifyIPv4(b [4]byte) EndpointClass {
	switch {
	case b[0] == 10: // 10/8 RFC1918
		return ClassRFC1918
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31: // 172.16/12 RFC1918
		return ClassRFC1918
	case b[0] == 192 && b[1] == 168: // 192.168/16 RFC1918
		return ClassRFC1918
	case b[0] == 100 && b[1] >= 64 && b[1] <= 127: // 100.64/10 CGNAT
		return ClassCGNAT
	case b[0] == 169 && b[1] == 254: // 169.254/16 link-local
		return ClassLinkLocal
	case b[0] == 198 && b[1] >= 18 && b[1] <= 19: // 198.18/15 benchmark
		return ClassBenchmark
	case b[0] == 192 && b[1] == 0 && b[2] == 2: // TEST-NET-1
		return ClassDocumentation
	case b[0] == 198 && b[1] == 51 && b[2] == 100: // TEST-NET-2
		return ClassDocumentation
	case b[0] == 203 && b[1] == 0 && b[2] == 113: // TEST-NET-3
		return ClassDocumentation
	case b[0] == 192 && b[1] == 0 && b[2] == 0: // IETF protocol assignments
		return ClassReserved
	case b[0] == 192 && b[1] == 31 && b[2] == 196: // AS112-v4
		return ClassReserved
	case b[0] == 192 && b[1] == 52 && b[2] == 193: // AMT
		return ClassReserved
	case b[0] == 192 && b[1] == 88 && b[2] == 99: // 6to4 relay anycast
		return ClassReserved
	case b[0] == 192 && b[1] == 175 && b[2] == 48: // Direct Delegation AS112
		return ClassReserved
	case b[0] >= 224 && b[0] <= 239: // 224/4 multicast
		return ClassMulticast
	case b[0] == 0: // 0/8 reserved (0.0.0.0 handled as unspecified above)
		return ClassReserved
	case b[0] >= 240: // 240/4 + 255.255.255.255 reserved
		return ClassReserved
	}
	return ClassGlobalUnicast
}

// IsGlobalEndpoint reports whether ip is a concrete global IPv4 literal for
// probe/publication purposes. IANA documentation ranges (TEST-NET) count as
// global; private/CGNAT/loopback/link-local/benchmark/multicast/reserved/
// unspecified and all IPv6 (including IPv4-mapped) do not.
func IsGlobalEndpoint(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	switch ClassifyIP(ip) {
	case ClassDocumentation, ClassGlobalUnicast:
		return true
	}
	return false
}

// ValidateEndpoint parses and validates a concrete global IPv4:port literal.
func ValidateEndpoint(endpoint string) (netip.AddrPort, error) {
	if endpoint == "" {
		return netip.AddrPort{}, errors.New("protocol: empty endpoint")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return netip.AddrPort{}, fmt.Errorf("protocol: %q is not a valid host:port", endpoint)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return netip.AddrPort{}, fmt.Errorf("protocol: %q is not an IPv4 literal", host)
	}
	if !IsGlobalEndpoint(ip) {
		return netip.AddrPort{}, fmt.Errorf("protocol: %q is not a global IPv4 literal", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("protocol: port %q is not an integer", portText)
	}
	if err := ValidatePort(port); err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(ip, uint16(port)), nil
}
