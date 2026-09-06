//go:build windows

package udp

import (
	"errors"
	"net"
	"syscall"
)

type nativePacketReader struct{ conn *net.UDPConn }

func newPacketReader(c *net.UDPConn) packetReader { return &nativePacketReader{c} }
func (r *nativePacketReader) ReadPacket(b []byte) (int, *net.UDPAddr, bool, error) {
	n, a, e := r.conn.ReadFromUDP(b)
	return n, a, n == len(b), e
}

type nativeConnectedReader struct{ conn *net.UDPConn }

func newConnectedReader(c *net.UDPConn) connectedReader { return &nativeConnectedReader{c} }
func (r *nativeConnectedReader) ReadPacket(b []byte) (int, bool, error) {
	n, e := r.conn.Read(b)
	return n, n == len(b), e
}

// WSAECONNRESET is an asynchronous ICMP indication; it does not terminate the sole ingress reader.
func ignoreIngressError(err error) bool { return errors.Is(err, syscall.Errno(10054)) }
