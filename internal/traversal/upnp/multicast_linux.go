//go:build linux

// Interface-bound multicast socket control for SSDP on Linux: IP_MULTICAST_IF
// pins discovery to the selected interface, IP_MULTICAST_TTL keeps M-SEARCH
// link-local and IP_MULTICAST_LOOP lets a same-host gateway (lab topologies)
// answer. Non-Linux builds refuse interface-bound discovery (fail closed).
package upnp

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// listenMulticastUDP4 opens a UDP4 socket bound to the interface address and
// pins multicast egress to it.
func listenMulticastUDP4(interfaceIP netip.Addr) (net.PacketConn, error) {
	packet, err := net.ListenPacket("udp4", interfaceIP.String()+":0")
	if err != nil {
		return nil, fmt.Errorf("upnp: SSDP bind to %s: %w", interfaceIP, err)
	}
	raw, ok := packet.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		packet.Close()
		return nil, fmt.Errorf("upnp: SSDP socket does not expose raw control")
	}
	conn, err := raw.SyscallConn()
	if err != nil {
		packet.Close()
		return nil, fmt.Errorf("upnp: SSDP raw control: %w", err)
	}
	a4 := interfaceIP.As4()
	var controlErr error
	if err := conn.Control(func(fd uintptr) {
		// IP_MULTICAST_IF pins multicast egress to the interface.
		mreq := &syscall.IPMreq{}
		copy(mreq.Multiaddr[:], a4[:])
		copy(mreq.Interface[:], a4[:])
		if err := syscall.SetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, mreq); err != nil {
			controlErr = fmt.Errorf("upnp: IP_MULTICAST_IF: %w", err)
			return
		}
		// Link-local scope for M-SEARCH.
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 2); err != nil {
			controlErr = fmt.Errorf("upnp: IP_MULTICAST_TTL: %w", err)
			return
		}
		// Loop back on the same host so lab gateways can answer.
		if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 1); err != nil {
			controlErr = fmt.Errorf("upnp: IP_MULTICAST_LOOP: %w", err)
		}
	}); err != nil {
		packet.Close()
		return nil, fmt.Errorf("upnp: SSDP control: %w", err)
	}
	if controlErr != nil {
		packet.Close()
		return nil, controlErr
	}
	return packet, nil
}
