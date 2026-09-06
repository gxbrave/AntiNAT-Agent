// Route/interface fingerprint (v0.8 §2.3, §3.5): any change to the default
// route gateway/interface or to any IPv4 interface address must invalidate
// previously verified state. The fingerprint is a deterministic hash of the
// canonical route-table text, so it is stable across calls and across
// address-order changes.
package traversal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Fingerprint returns a stable hex digest of the route table state. Equal
// route state always yields an equal fingerprint; any default-route or IPv4
// address change yields a different one.
func Fingerprint(rt RouteTable) (string, error) {
	gateway, iface, ok, err := rt.DefaultRouteV4()
	if err != nil {
		return "", err
	}
	addrs, err := rt.IPv4Addresses()
	if err != nil {
		return "", err
	}
	sorted := append([]IPv4Address(nil), addrs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Interface != sorted[j].Interface {
			return sorted[i].Interface < sorted[j].Interface
		}
		return sorted[i].Addr.Compare(sorted[j].Addr) < 0
	})

	var canonical strings.Builder
	if ok {
		fmt.Fprintf(&canonical, "default %s %s\n", gateway, iface)
	} else {
		canonical.WriteString("default none\n")
	}
	for _, address := range sorted {
		fmt.Fprintf(&canonical, "%s %s\n", address.Interface, address.Addr)
	}
	sum := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(sum[:]), nil
}
