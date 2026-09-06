//go:build linux

package traversal

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// HostRouteTable reads the live Linux IPv4 routing table and interface
// addresses. /proc/net/route is IPv4-only and needs no privileges.
type HostRouteTable struct{}

// DefaultRouteV4 returns the lowest-metric IPv4 default route (ties broken
// by interface name for determinism).
func (HostRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, "", false, err
	}
	return parseProcNetRoute(data)
}

// usableV4 converts one interface address to canonical IPv4. IPv6-enabled
// hosts deliver interface IPv4 as 16-byte IPv4-mapped addresses
// (::ffff:x.x.x.x), which netip.AddrFromSlice returns in IPv6 form; Unmap
// must run before the Is4 gate or every IPv4 address is silently dropped
// (F1 regression). Real IPv6 and unparsable input are rejected.
func usableV4(ip net.IP) (netip.Addr, bool) {
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	parsed = parsed.Unmap()
	if !parsed.Is4() {
		return netip.Addr{}, false
	}
	return parsed, true
}

// IPv4Addresses lists the IPv4 addresses of up, non-loopback interfaces.
func (HostRouteTable) IPv4Addresses() ([]IPv4Address, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IPv4Address
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("traversal: read addresses of interface %s: %w", iface.Name, err)
		}
		for _, address := range addrs {
			ipNet, ok := address.(*net.IPNet)
			if !ok {
				continue
			}
			parsed, ok := usableV4(ipNet.IP)
			if !ok {
				continue
			}
			out = append(out, IPv4Address{Interface: iface.Name, Addr: parsed})
		}
	}
	return out, nil
}

type procRouteLine struct {
	iface   string
	gateway netip.Addr
	metric  int
}

// parseProcNetRoute parses /proc/net/route and returns the best IPv4 default
// route (Destination 0.0.0.0 with mask 0.0.0.0). Addresses are 8-hex-digit
// little-endian.
func parseProcNetRoute(data []byte) (netip.Addr, string, bool, error) {
	var best *procRouteLine
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		text := scanner.Text()
		if lineNumber == 1 && strings.HasPrefix(text, "Iface") {
			continue // header row
		}
		fields := strings.Fields(text)
		if len(fields) < 8 {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d has %d fields, want >= 8", lineNumber, len(fields))
		}
		destination, err := parseHexIP(fields[1])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d destination: %w", lineNumber, err)
		}
		mask, err := parseHexIP(fields[7])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d mask: %w", lineNumber, err)
		}
		if !destination.IsUnspecified() || !mask.IsUnspecified() {
			continue // not a default route
		}
		gateway, err := parseHexIP(fields[2])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d gateway: %w", lineNumber, err)
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			return netip.Addr{}, "", false, fmt.Errorf("traversal: /proc/net/route line %d metric: %w", lineNumber, err)
		}
		candidate := procRouteLine{iface: fields[0], gateway: gateway, metric: metric}
		if best == nil || candidate.metric < best.metric ||
			(candidate.metric == best.metric && candidate.iface < best.iface) {
			best = &candidate
		}
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, "", false, err
	}
	if best == nil {
		return netip.Addr{}, "", false, nil
	}
	return best.gateway, best.iface, true, nil
}

// parseHexIP parses an 8-hex-digit little-endian IPv4 as printed by
// /proc/net/route (e.g. "0102A8C0" is 192.168.2.1).
func parseHexIP(text string) (netip.Addr, error) {
	if len(text) != 8 {
		return netip.Addr{}, fmt.Errorf("%q is not an 8-hex-digit address", text)
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		value, err := strconv.ParseUint(text[i*2:i*2+2], 16, 8)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%q: %w", text, err)
		}
		octets[3-i] = byte(value)
	}
	return netip.AddrFrom4(octets), nil
}

// AcquireInstanceLock takes the OS single-instance flock (v0.8 §4.1 rule 5:
// one Agent instance; upgrades default to stop-old-before-start-new). The
// path is never unlinked. O_NOFOLLOW, regular-file checks, and before/after
// inode comparison prevent symlink traversal and replacement during acquire;
// an abrupt owner exit releases the flock automatically so a quick restart
// can re-acquire immediately.
func AcquireInstanceLock(path string) (*InstanceLock, error) {
	if path == "" {
		return nil, ErrInvalidLockPath
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 || !ownedByCurrentUser(parent) {
		return nil, ErrInvalidLockPath
	}
	before, beforeErr := os.Lstat(path)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, beforeErr
	}
	flags := os.O_CREATE | os.O_RDWR | syscall.O_NOFOLLOW
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrInvalidLockPath
		}
		return nil, err
	}
	closeOnError := func(closeErr error) (*InstanceLock, error) {
		_ = unlockInstance(file)
		_ = file.Close()
		return nil, closeErr
	}
	info, err := file.Stat()
	if err != nil {
		return closeOnError(err)
	}
	if !info.Mode().IsRegular() || !sameLockFile(before, beforeErr, info) {
		return closeOnError(ErrInvalidLockPath)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrInstanceLocked
		}
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !sameLockFile(after, err, info) {
		if err == nil {
			err = ErrInvalidLockPath
		}
		return closeOnError(errors.Join(ErrInvalidLockPath, err))
	}
	// The PID marker is advisory; the lock is the open inode and stale suffix
	// bytes are intentionally ignored.
	marker := fmt.Sprintf("pid=%-16d\n", os.Getpid())
	if _, err := file.WriteAt([]byte(marker), 0); err != nil {
		return closeOnError(err)
	}
	return &InstanceLock{file: file}, nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func sameLockFile(before os.FileInfo, beforeErr error, after os.FileInfo) bool {
	if beforeErr != nil {
		return errors.Is(beforeErr, os.ErrNotExist)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	return beforeOK && afterOK && beforeStat.Dev == afterStat.Dev && beforeStat.Ino == afterStat.Ino
}

func unlockInstance(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}
