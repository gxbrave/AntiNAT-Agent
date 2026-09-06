//go:build linux

package udp

import (
	"net"
	"syscall"
)

type nativePacketReader struct{ conn *net.UDPConn }

func newPacketReader(c *net.UDPConn) packetReader { return &nativePacketReader{c} }
func (r *nativePacketReader) ReadPacket(buf []byte) (int, *net.UDPAddr, bool, error) {
	n, _, flags, a, e := r.conn.ReadMsgUDP(buf, nil)
	return n, a, flags&syscall.MSG_TRUNC != 0, e
}

type nativeConnectedReader struct{ conn *net.UDPConn }

func newConnectedReader(c *net.UDPConn) connectedReader { return &nativeConnectedReader{c} }
func (r *nativeConnectedReader) ReadPacket(buf []byte) (int, bool, error) {
	n, _, flags, _, e := r.conn.ReadMsgUDP(buf, nil)
	return n, flags&syscall.MSG_TRUNC != 0, e
}
func ignoreIngressError(error) bool { return false }
