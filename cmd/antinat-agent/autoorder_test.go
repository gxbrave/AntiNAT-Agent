// Repair R1 finding 8: --auto-order is an ORDER of concrete, probeable
// strategies; the literal "auto" is resolved post-order by the detection
// profile and must never appear in the operator's order (silently yielding a
// no-default profile). Reject it like unknown names and manual-static-v4.
package main

import (
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

func TestParseStrategyOrderRejectsAuto(t *testing.T) {
	if _, err := parseStrategyOrder("explicit-gateway,auto"); err == nil ||
		!strings.Contains(err.Error(), "auto") {
		t.Fatalf("parseStrategyOrder with auto = %v, want a rejection naming auto", err)
	}
}

func TestParseStrategyOrderTable(t *testing.T) {
	cases := []struct {
		name          string
		order         string
		want          []protocol.Strategy
		reject        bool
		rejectMention string
	}{
		{name: "empty is the default", order: "", want: nil},
		{
			name:  "concrete gateway/direct order parses",
			order: "explicit-gateway,direct-v4",
			want:  []protocol.Strategy{protocol.StrategyExplicitGateway, protocol.StrategyDirectV4},
		},
		{
			name:  "stun-only order entry parses",
			order: "stun-only",
			want:  []protocol.Strategy{protocol.StrategyStunOnly},
		},
		{
			name:          "unknown strategy rejected",
			order:         "bogus",
			reject:        true,
			rejectMention: "bogus",
		},
		{
			name:          "manual-static rejected",
			order:         "manual-static-v4,direct-v4",
			reject:        true,
			rejectMention: "manual-static-v4",
		},
		{
			name:          "literal auto rejected",
			order:         "auto",
			reject:        true,
			rejectMention: "auto",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStrategyOrder(tc.order)
			if tc.reject {
				if err == nil {
					t.Fatalf("parseStrategyOrder(%q) succeeded (got %v), want a rejection", tc.order, got)
				}
				if tc.rejectMention != "" && !strings.Contains(err.Error(), tc.rejectMention) {
					t.Fatalf("parseStrategyOrder(%q) error = %v, want it to mention %q", tc.order, err, tc.rejectMention)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStrategyOrder(%q): %v", tc.order, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseStrategyOrder(%q) = %v, want %v", tc.order, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("parseStrategyOrder(%q) = %v, want %v", tc.order, got, tc.want)
				}
			}
		})
	}
}
