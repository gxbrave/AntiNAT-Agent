package manual

import (
	"errors"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
)

// M1: the operator endpoint is mandatory — an empty endpoint refuses before
// any side effect, so manual-static never auto-detects.
func TestAcquireRequiresOperatorEndpoint(t *testing.T) {
	layer := New(traversal.NewPortRegistry(), "forward-1")
	_, _, err := layer.Acquire(t.Context(), "", 0)
	if !errors.Is(err, traversal.ErrOperatorEndpointRequired) {
		t.Fatalf("error = %v, want ErrOperatorEndpointRequired", err)
	}
	_, _, err = layer.Acquire(t.Context(), "   ", 0)
	if !errors.Is(err, traversal.ErrOperatorEndpointRequired) {
		t.Fatalf("whitespace endpoint error = %v, want ErrOperatorEndpointRequired", err)
	}
}

// M2: a valid operator endpoint binds the listener and the evidence carries
// OPERATOR_EXPECTED scope with the operator endpoint as candidate — the
// independent WAN probe verifies it, never local binds.
func TestAcquireWithOperatorEndpoint(t *testing.T) {
	layer := New(traversal.NewPortRegistry(), "forward-1")
	lease, evidence, err := layer.Acquire(t.Context(), "203.0.113.7:43111", 0)
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	defer lease.Release()

	if evidence.Scope != traversal.ScopeOperatorInput {
		t.Fatalf("scope = %q, want OPERATOR_EXPECTED", evidence.Scope)
	}
	if evidence.Kind != traversal.LayerKindManual {
		t.Fatalf("kind = %q, want manual", evidence.Kind)
	}
	if evidence.AssignedEndpoint != "203.0.113.7:43111" {
		t.Fatalf("candidate = %q, want the operator endpoint", evidence.AssignedEndpoint)
	}
	if lease.Actual.Port == 0 {
		t.Fatal("actual bound port must be resolved")
	}
}

// M3: a malformed or non-IPv4 operator endpoint refuses.
func TestAcquireValidatesEndpointFormat(t *testing.T) {
	cases := []string{"not-an-endpoint", "example.com:80", "203.0.113.7", "[::1]:80", "203.0.113.7:0"}
	for _, endpoint := range cases {
		layer := New(traversal.NewPortRegistry(), "forward-1")
		if _, _, err := layer.Acquire(t.Context(), endpoint, 0); err == nil {
			t.Fatalf("endpoint %q must be refused", endpoint)
		}
	}
}
