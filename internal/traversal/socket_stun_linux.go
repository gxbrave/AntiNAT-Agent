//go:build linux

package traversal

import (
	"errors"
	"syscall"
)

// Linux STUN shared-port socket adapters (P11). Native evidence: P02
// tcp-shared-port-linux.json (SUPPORTED_WITH_LIMITS) proved a unique reuse
// listener plus multiple connected sockets share one local tuple with
// deterministic four-tuple routing. Every listener/connected participant
// needs pre-bind SO_REUSEADDR + SO_REUSEPORT; the listener alone is not an
// ownership boundary (v0.8 §4.2). The OS bind is the final ownership
// authority; the shared-port registry adds the owner/generation discipline.

// soReusePort is SO_REUSEPORT on Linux.
const soReusePort = 15

// ErrStunSharedPortUnsupported is retained on Linux for API symmetry; the
// gate is open here, so callers only see it when a socket option fails.
var ErrStunSharedPortUnsupported = errors.New("traversal: STUN TCP shared-port unsupported on this platform")

// StunSharedPortSupported reports whether STUN TCP shared-port sockets have
// native platform evidence. True on Linux per the P02 spike.
func StunSharedPortSupported() bool { return true }

// StunSharedPortControl is the pre-bind socket-option hook for shared-port
// participants: SO_REUSEADDR plus SO_REUSEPORT on every socket in the group.
func StunSharedPortControl(network, address string, raw syscall.RawConn) error {
	var socketError error
	if err := raw.Control(func(fd uintptr) {
		socketError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if socketError == nil {
			socketError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		}
	}); err != nil {
		return err
	}
	return socketError
}
