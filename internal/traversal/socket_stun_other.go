//go:build !linux && !windows

package traversal

import (
	"errors"
	"syscall"
)

// STUN shared-port socket adapters for platforms without native evidence.
// v1 makes no shared-port claim here; the gate stays off (v0.8 §4.2).

// ErrStunSharedPortUnsupported reports that STUN TCP shared-port sockets are
// unavailable on this platform (no native evidence).
var ErrStunSharedPortUnsupported = errors.New("traversal: STUN TCP shared-port unsupported on this platform")

// StunSharedPortSupported reports whether STUN TCP shared-port sockets have
// native platform evidence. False on unproven platforms.
func StunSharedPortSupported() bool { return false }

// StunSharedPortControl is the pre-bind socket-option hook for shared-port
// participants. Unsupported without native evidence.
func StunSharedPortControl(network, address string, raw syscall.RawConn) error {
	return ErrStunSharedPortUnsupported
}
