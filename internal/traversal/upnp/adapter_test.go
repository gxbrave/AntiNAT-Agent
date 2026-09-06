package upnp

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// A1: the adapter advertises the honest mechanism identity and the
// best-effort ownership; the capability upgrades to v2 only after a
// discovery resolved an IGDv2 service.
func TestAdapterIdentityAndCapabilityUpgrade(t *testing.T) {
	adapter := NewAdapter(AdapterOptions{InterfaceIP: netip.MustParseAddr("127.0.0.1")})
	if adapter.Mechanism() != traversal.LayerUPnP {
		t.Fatalf("mechanism = %q, want upnp-igd", adapter.Mechanism())
	}
	if adapter.Ownership() != traversal.OwnershipBestEffort {
		t.Fatalf("ownership = %q, want BEST_EFFORT_QUERY_THEN_DELETE", adapter.Ownership())
	}
	if adapter.Capability().CanRequestExact {
		t.Fatal("unresolved adapter must report the weaker IGDv1 capability")
	}

	// Resolve an IGDv2 service so the capability table upgrades.
	service := Service{
		Type:       "urn:schemas-upnp-org:service:WANIPConnection:2",
		ControlURL: "http://127.0.0.1:1/ctl",
		IGDv2:      true,
	}
	adapter.resolve = func(ctx context.Context, a *Adapter) (Service, string, error) {
		return service, "uuid:lab-usn", nil
	}
	adapter.usn = "uuid:lab-usn"
	adapter.delegate = NewClient(http.DefaultClient, service, ClientOptions{})
	if !adapter.Capability().CanRequestExact {
		t.Fatal("IGDv2 capability must allow exact requests (AddAnyPortMapping)")
	}
}

// A2: Map before Discover fails instead of silently re-probing.
func TestAdapterRequiresDiscovery(t *testing.T) {
	adapter := NewAdapter(AdapterOptions{InterfaceIP: netip.MustParseAddr("127.0.0.1")})
	_, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP: netip.MustParseAddr("127.0.0.1"), InternalPort: 3111, Lease: time.Hour,
	})
	if err == nil {
		t.Fatal("Map before Discover must fail")
	}
}

// A3: the journal description carries the USN identity for stable ownership
// verification.
func TestAdapterMappingDescription(t *testing.T) {
	mapping := traversal.GatewayMapping{
		Mechanism:    traversal.LayerUPnP,
		Ownership:    traversal.OwnershipBestEffort,
		InternalIP:   netip.MustParseAddr("10.0.0.2"),
		InternalPort: 3111,
		External:     netip.MustParseAddrPort("203.0.113.7:43111"),
		Identity:     "uuid:lab-usn",
	}
	if mapping.Description() != "AntiNAT uuid:lab-usn" {
		t.Fatalf("description = %q", mapping.Description())
	}
	anonymous := mapping
	anonymous.Identity = ""
	if anonymous.Description() != "AntiNAT" {
		t.Fatalf("anonymous description = %q", anonymous.Description())
	}
}

// newResolvedAdapter wires an adapter to a scripted control server.
func newResolvedAdapter(t *testing.T, v2 bool, handler func(action string, r *http.Request, w http.ResponseWriter)) *Adapter {
	t.Helper()
	_, service := newTestIGDService(t, v2, handler)
	adapter := NewAdapter(AdapterOptions{InterfaceIP: netip.MustParseAddr("127.0.0.1"), Timeout: 2 * time.Second})
	adapter.resolve = func(ctx context.Context, a *Adapter) (Service, string, error) {
		return service, "uuid:lab-usn", nil
	}
	if _, err := adapter.Discover(t.Context()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return adapter
}

// A4 (NAT audit M3): strict port policy is enforced against the device's
// answer — an IGDv2 reservation that differs from the requested port fails
// the mapping and deletes the entry it created; it never silently
// downgrades to accept-assigned.
func TestAdapterMapStrictPortEnforced(t *testing.T) {
	var mu sync.Mutex
	deleted := false
	adapter := newResolvedAdapter(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddAnyPortMapping":
			soapOK(w, "AddAnyPortMapping", `<NewReservedPort>55555</NewReservedPort>`)
		case "GetExternalIPAddress":
			soapOK(w, "GetExternalIPAddress", `<NewExternalIPAddress>192.168.99.1</NewExternalIPAddress>`)
		case "GetSpecificPortMappingEntry":
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>3111</NewInternalPort><NewInternalClient>10.0.0.2</NewInternalClient><NewPortMappingDescription>AntiNAT uuid:lab-usn</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>`)
		case "DeletePortMapping":
			mu.Lock()
			deleted = true
			mu.Unlock()
			soapOK(w, "DeletePortMapping", "")
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	_, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP: netip.MustParseAddr("10.0.0.2"), InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour, StrictPort: true,
	})
	if err == nil {
		t.Fatal("a rewritten strict-port reservation must fail the mapping")
	}
	mu.Lock()
	defer mu.Unlock()
	if !deleted {
		t.Fatal("the created-but-rewritten entry must be deleted before failing")
	}
}

// A5 (NAT audit L2): a renewal whose re-add lands on a different port
// deletes the stray entry and fails; the live mapping is never corrupted.
func TestAdapterRenewPortChangeDeletesStrayEntry(t *testing.T) {
	var mu sync.Mutex
	adds := 0
	deleted := 0
	adapter := newResolvedAdapter(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddAnyPortMapping":
			mu.Lock()
			adds++
			port := 43111
			if adds >= 2 {
				port = 55556 // the re-add lands elsewhere
			}
			mu.Unlock()
			soapOK(w, "AddAnyPortMapping", fmt.Sprintf(`<NewReservedPort>%d</NewReservedPort>`, port))
		case "GetExternalIPAddress":
			soapOK(w, "GetExternalIPAddress", `<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>`)
		case "GetSpecificPortMappingEntry":
			soapOK(w, "GetSpecificPortMappingEntry",
				`<NewInternalPort>3111</NewInternalPort><NewInternalClient>10.0.0.2</NewInternalClient><NewPortMappingDescription>AntiNAT uuid:lab-usn</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>`)
		case "DeletePortMapping":
			mu.Lock()
			deleted++
			mu.Unlock()
			soapOK(w, "DeletePortMapping", "")
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP: netip.MustParseAddr("10.0.0.2"), InternalPort: 3111,
		RequestedExternalPort: 43111, Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if _, err := adapter.Renew(t.Context(), mapping, time.Hour); err == nil {
		t.Fatal("a renewal that re-adds the entry at a different port must fail")
	}
	mu.Lock()
	defer mu.Unlock()
	if deleted != 1 {
		t.Fatalf("stray-entry deletes = %d, want exactly 1", deleted)
	}
}

// A6 (code-review finding): renewal keeps the gateway's real external
// address — the unspecified fallback must never regress the published
// endpoint after the first renewal.
func TestAdapterRenewKeepsExternalAddress(t *testing.T) {
	adapter := newResolvedAdapter(t, true, func(action string, r *http.Request, w http.ResponseWriter) {
		switch action {
		case "AddAnyPortMapping":
			soapOK(w, "AddAnyPortMapping", `<NewReservedPort>43111</NewReservedPort>`)
		case "GetExternalIPAddress":
			soapOK(w, "GetExternalIPAddress", `<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>`)
		default:
			writeSOAPFault(w, 401, "Invalid Action")
		}
	})

	mapping, err := adapter.Map(t.Context(), traversal.GatewayMapRequest{
		InternalIP: netip.MustParseAddr("10.0.0.2"), InternalPort: 3111, Lease: time.Hour,
	})
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapping.External.Addr().String() != "203.0.113.7" {
		t.Fatalf("Map external = %s, want 203.0.113.7", mapping.External.Addr())
	}
	renewed, err := adapter.Renew(t.Context(), mapping, time.Hour)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewed.External.Addr().String() != "203.0.113.7" {
		t.Fatalf("Renew external = %s, want 203.0.113.7 (the unspecified fallback must not regress the endpoint)", renewed.External.Addr())
	}
}
