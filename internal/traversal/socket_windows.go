//go:build windows

package traversal

import (
	"errors"
	"syscall"
)

// STUN shared-port socket adapters (P11). Windows has only cross-build
// evidence (P02 tcp-shared-port-windows.json): the native baseline — unique
// listener plus multiple connected sockets sharing one tuple, half-close,
// restart, stale-process gates — has not executed, so v1 fails closed and
// disables STUN TCP shared-port instead of half-claiming support (v0.8 §4.2).
// The OS bind remains the final ownership authority.

// ErrStunSharedPortUnsupported reports that STUN TCP shared-port sockets are
// unavailable on this platform (no native evidence).
var ErrStunSharedPortUnsupported = errors.New("traversal: STUN TCP shared-port unsupported on this platform")

// StunSharedPortSupported reports whether STUN TCP shared-port sockets have
// native platform evidence. False on Windows until the native baseline runs.
func StunSharedPortSupported() bool { return false }

// StunSharedPortControl is the pre-bind socket-option hook for shared-port
// participants. Unsupported on Windows.
func StunSharedPortControl(network, address string, raw syscall.RawConn) error {
	return ErrStunSharedPortUnsupported
}
