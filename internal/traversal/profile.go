// Node traversal profile (v0.8 §3.2): per-protocol detection results with
// honest staleness. A profile is a capability record, never a binding
// forward endpoint: every Forward acquires, keeps alive and probes
// independently. TCP and UDP defaults are separate axes.
package traversal

import (
	"fmt"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Protocol axes. v1 detection runs TCP; UDP arrives with P13.
const (
	ProtocolTCP = "tcp"
	ProtocolUDP = "udp"
)

// DetectionState is the honest per-strategy outcome.
type DetectionState string

const (
	DetectionPassed   DetectionState = "PASSED"
	DetectionFailed   DetectionState = "FAILED"
	DetectionExcluded DetectionState = "EXCLUDED" // not eligible for auto detection (manual)
	DetectionDeferred DetectionState = "DEFERRED" // owned by a later plan (UDP dataplane)
)

// StrategyResult records one strategy's detection outcome.
type StrategyResult struct {
	Strategy protocol.Strategy
	State    DetectionState
	// LayerSignature identifies the concrete mechanism that answered
	// (e.g. "pcp", "upnp-igd:2"); empty when none did.
	LayerSignature string
	// Capability carries the stable capability code on failure
	// (NO_GLOBAL_V4_SOURCE, ...).
	Capability string
	// Evidence is the structured layer chain observed during the attempt.
	Evidence []LayerEvidence
	// Candidate is the temp-detection endpoint observed. It never binds a
	// Forward: every Forward acquires and probes independently.
	Candidate string
	// Note explains exclusions, deferrals or the decisive failure.
	Note           string
	StartedAtUnix  int64
	FinishedAtUnix int64
}

// Profile is one protocol axis's detection profile.
type Profile struct {
	// Fingerprint is the route-table fingerprint the profile was computed
	// under; any change makes the profile stale.
	Fingerprint string
	Protocol    string
	// DefaultStrategy is the selected default for this protocol; empty
	// when nothing passed (all-failed profiles are still saved).
	DefaultStrategy protocol.Strategy
	ComputedAtUnix  int64
	Results         []StrategyResult
}

// IsStale reports whether the profile no longer describes the node: a
// fingerprint mismatch invalidates immediately, and an aged profile goes
// stale even with an unchanged fingerprint. The reason names the decisive
// fact for UI display.
func (p Profile) IsStale(currentFingerprint string, maxAge time.Duration, now time.Time) (bool, string) {
	if p.Fingerprint != currentFingerprint {
		return true, "network fingerprint changed"
	}
	computed := time.Unix(p.ComputedAtUnix, 0)
	if now.Sub(computed) > maxAge {
		return true, fmt.Sprintf("profile older than %s", maxAge)
	}
	return false, ""
}

// ResultFor returns one strategy's result.
func (p Profile) ResultFor(strategy protocol.Strategy) (StrategyResult, bool) {
	for _, result := range p.Results {
		if result.Strategy == strategy {
			return result, true
		}
	}
	return StrategyResult{}, false
}

// PassedStrategies returns the strategies that passed, in result order.
func (p Profile) PassedStrategies() []protocol.Strategy {
	var passed []protocol.Strategy
	for _, result := range p.Results {
		if result.State == DetectionPassed {
			passed = append(passed, result.Strategy)
		}
	}
	return passed
}
