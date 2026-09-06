package direct

import (
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// fakeRouteTable is the scripted route table.
type fakeRouteTable struct {
	defaultGateway netip.Addr
	defaultIface   string
	hasDefault     bool
	addresses      []traversal.IPv4Address
	err            error
}

func (f fakeRouteTable) DefaultRouteV4() (netip.Addr, string, bool, error) {
	if f.err != nil {
		return netip.Addr{}, "", false, f.err
	}
	return f.defaultGateway, f.defaultIface, f.hasDefault, nil
}

func (f fakeRouteTable) IPv4Addresses() ([]traversal.IPv4Address, error) {
	return f.addresses, f.err
}

// aliasGlobal aliases a global-class literal on lo so the direct layer can
// bind it. Requires root; the orchestrator runs the suite privileged and
// the skip is honest on unprivileged hosts.
const globalLiteral = "8.8.8.8"

func aliasGlobal(t *testing.T) func() {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("direct-v4 acquire requires the global literal alias; run with sudo -E")
	}
	out, err := exec.Command("ip", "addr", "add", globalLiteral+"/32", "dev", "lo").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "Address already assigned") {
		t.Fatalf("alias global literal: %v\n%s", err, out)
	}
	return func() {
		_ = exec.Command("ip", "addr", "del", globalLiteral+"/32", "dev", "lo").Run()
	}
}

// D1: a global source on the default-route interface assesses ready and the
// acquired candidate is the global source plus the actual bound port.
func TestAcquireGlobalSource(t *testing.T) {
	cleanup := aliasGlobal(t)
	defer cleanup()

	rt := fakeRouteTable{
		defaultGateway: netip.MustParseAddr("127.0.0.1"),
		defaultIface:   "lo",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "lo", Addr: netip.MustParseAddr(globalLiteral)}},
	}
	registry := traversal.NewPortRegistry()
	layer := New(rt, registry, "forward-1")

	selection, capability, err := layer.Assess()
	if err != nil || capability != traversal.CapabilityDirectV4Ready {
		t.Fatalf("Assess = %s/%v", capability, err)
	}
	if selection.Source.String() != globalLiteral {
		t.Fatalf("source = %s, want %s", selection.Source, globalLiteral)
	}

	lease, evidence, err := layer.Acquire(t.Context(), 0)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()
	if evidence.Scope != traversal.ScopeGlobalPublic {
		t.Fatalf("scope = %q, want GLOBAL_PUBLIC", evidence.Scope)
	}
	if evidence.Kind != traversal.LayerKindDirect {
		t.Fatalf("kind = %q, want direct", evidence.Kind)
	}
	if lease.Actual.Port == 0 {
		t.Fatal("actual bound port must be resolved")
	}
	if evidence.AssignedEndpoint != netip.AddrPortFrom(netip.MustParseAddr(globalLiteral), lease.Actual.Port).String() {
		t.Fatalf("candidate = %q, want the global source plus the actual port", evidence.AssignedEndpoint)
	}
}

// D2: a private-only source refuses with NO_GLOBAL_V4_SOURCE and never
// guesses a public endpoint.
func TestAcquirePrivateSourceRefused(t *testing.T) {
	rt := fakeRouteTable{
		defaultGateway: netip.MustParseAddr("192.168.1.1"),
		defaultIface:   "eth0",
		hasDefault:     true,
		addresses:      []traversal.IPv4Address{{Interface: "eth0", Addr: netip.MustParseAddr("192.168.1.10")}},
	}
	layer := New(rt, traversal.NewPortRegistry(), "forward-1")

	_, _, capability, err := assess(layer)
	if err == nil {
		t.Fatal("private-only source must refuse")
	}
	if capability != traversal.CapabilityNoGlobalV4Source {
		t.Fatalf("capability = %q, want NO_GLOBAL_V4_SOURCE", capability)
	}

	_, _, evidenceErr := layer.Acquire(t.Context(), 0)
	if evidenceErr == nil {
		t.Fatal("acquire on a private source must refuse")
	}
}

// D3: a missing default route yields V4_DEFAULT_ROUTE_UNAVAILABLE; a host
// with no IPv4 at all yields V4_SOURCE_UNAVAILABLE. The Agent control
// connection may still be ONLINE — these are data-plane capabilities.
func TestCapabilityCodes(t *testing.T) {
	noRoute := New(fakeRouteTable{addresses: []traversal.IPv4Address{
		{Interface: "eth0", Addr: netip.MustParseAddr("192.168.1.10")},
	}}, traversal.NewPortRegistry(), "f")
	_, _, capability, err := assess(noRoute)
	if err == nil || capability != traversal.CapabilityV4DefaultRouteUnavailable {
		t.Fatalf("capability = %q err = %v, want V4_DEFAULT_ROUTE_UNAVAILABLE", capability, err)
	}

	noV4 := New(fakeRouteTable{}, traversal.NewPortRegistry(), "f")
	_, _, capability, err = assess(noV4)
	if err == nil || capability != traversal.CapabilityV4SourceUnavailable {
		t.Fatalf("capability = %q err = %v, want V4_SOURCE_UNAVAILABLE", capability, err)
	}
}

// assess unwraps the assess triple for assertions.
func assess(l *Layer) (traversal.Selection, traversal.Capability, traversal.Capability, error) {
	selection, capability, err := l.Assess()
	return selection, capability, capability, err
}
