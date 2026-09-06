// Backend holds the target snapshot of one Forward. The proxy resolves the
// target once per accepted session (Story 4 makes the snapshot hot-updatable
// via an atomic pointer; Story 3 uses the immutable first snapshot).
// v1 Forward targets are IPv4 literal:port only — hostnames and IPv6 are
// rejected here, not guessed.
package forward

import (
	"fmt"
	"net/netip"
	"sync/atomic"
)

// Backend is the immutable-per-session target holder.
type Backend struct {
	target atomic.Pointer[netip.AddrPort]
}

// NewBackend parses and validates an IPv4 literal:port target.
func NewBackend(target string) (*Backend, error) {
	addrPort, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil, fmt.Errorf("forward: invalid backend target %q: %w", target, err)
	}
	if !addrPort.Addr().Is4() {
		return nil, fmt.Errorf("forward: backend target %q is not an IPv4 literal (v1 Forwards are IPv4-only)", target)
	}
	backend := &Backend{}
	backend.target.Store(&addrPort)
	return backend, nil
}

// Target returns the current target snapshot.
func (b *Backend) Target() netip.AddrPort {
	return *b.target.Load()
}

// Update swaps the target snapshot atomically. Only sessions accepted after
// the swap resolve the new snapshot; established sessions keep their
// original target (NEW_SESSIONS_ONLY semantics, v0.8 §4.5). An invalid
// target leaves the current snapshot untouched.
func (b *Backend) Update(target string) error {
	addrPort, err := netip.ParseAddrPort(target)
	if err != nil {
		return fmt.Errorf("forward: invalid backend target %q: %w", target, err)
	}
	if !addrPort.Addr().Is4() {
		return fmt.Errorf("forward: backend target %q is not an IPv4 literal (v1 Forwards are IPv4-only)", target)
	}
	b.target.Store(&addrPort)
	return nil
}
