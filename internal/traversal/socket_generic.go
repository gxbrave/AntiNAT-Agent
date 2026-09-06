//go:build !linux

package traversal

import (
	"errors"
	"net/netip"
	"os"
)

// ErrUnsupportedPlatform reports platform-specific functionality that v1
// does not claim on the current OS. Linux route/source selection and the OS
// single-instance lock are native Linux evidence only (v0.8: no Windows/arm64
// runtime claims without native evidence; cross-builds are compile checks,
// not capability).
var ErrUnsupportedPlatform = errors.New("traversal: IPv4 route/source selection and instance lock unsupported on this platform")

// HostRouteTable exists on every platform so the traversal API compiles, but
// only Linux reads real routing state.
type HostRouteTable struct{}

func (HostRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	return netip.Addr{}, "", false, ErrUnsupportedPlatform
}

func (HostRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	return nil, ErrUnsupportedPlatform
}

// AcquireInstanceLock is unsupported off Linux: without native flock
// evidence the single-instance guarantee would be a false claim.
func AcquireInstanceLock(path string) (*InstanceLock, error) {
	return nil, ErrUnsupportedPlatform
}

func unlockInstance(file *os.File) error {
	return ErrUnsupportedPlatform
}
