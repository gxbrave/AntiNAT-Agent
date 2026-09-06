//go:build !linux

// Non-Linux platforms have no native interface-bound multicast evidence:
// SSDP discovery refuses to run rather than leaking M-SEARCH across all
// interfaces (fail closed, mirroring the shared-port platform gate).
package upnp

import (
	"fmt"
	"net"
	"net/netip"
)

// listenMulticastUDP4 always refuses: v1 makes no interface-bound multicast
// claims on platforms without native evidence.
func listenMulticastUDP4(interfaceIP netip.Addr) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: %s", ErrSSDPUnsupportedPlatform, interfaceIP)
}
