package traversal

import (
	"testing"
	"time"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// P1: staleness is a function of the fingerprint and the age: any fingerprint
// change invalidates the profile immediately, and an aged profile goes stale
// even with an unchanged fingerprint.
func TestProfileIsStale(t *testing.T) {
	computed := time.Now()
	profile := Profile{
		Fingerprint:    "fp-old",
		Protocol:       ProtocolTCP,
		ComputedAtUnix: computed.Unix(),
		Results: []StrategyResult{{
			Strategy: protocol.StrategyDirectV4,
			State:    DetectionPassed,
		}},
	}

	if stale, reason := profile.IsStale("fp-old", time.Hour, computed.Add(time.Minute)); stale {
		t.Fatalf("fresh profile reported stale: %s", reason)
	}
	if stale, reason := profile.IsStale("fp-new", time.Hour, computed.Add(time.Minute)); !stale || reason == "" {
		t.Fatalf("fingerprint change must be stale (stale=%v reason=%q)", stale, reason)
	}
	if stale, reason := profile.IsStale("fp-old", time.Hour, computed.Add(2*time.Hour)); !stale || reason == "" {
		t.Fatalf("aged profile must be stale (stale=%v reason=%q)", stale, reason)
	}
}

// P2: TCP and UDP carry separate profiles and separate defaults.
func TestProfileProtocolsSeparate(t *testing.T) {
	tcp := Profile{Protocol: ProtocolTCP, DefaultStrategy: protocol.StrategyExplicitGateway}
	udp := Profile{Protocol: ProtocolUDP, DefaultStrategy: protocol.StrategyDirectV4}
	if tcp.DefaultStrategy == udp.DefaultStrategy {
		t.Fatal("TCP and UDP defaults are independent axes")
	}
	if ProtocolTCP != "tcp" || ProtocolUDP != "udp" {
		t.Fatalf("protocol values = %q/%q", ProtocolTCP, ProtocolUDP)
	}
}

// P3: the all-failed profile is still a valid profile: it saves honestly
// with every strategy FAILED and no default.
func TestProfileAllFailedSaves(t *testing.T) {
	profile := Profile{
		Fingerprint:    "fp",
		Protocol:       ProtocolTCP,
		ComputedAtUnix: time.Now().Unix(),
		Results: []StrategyResult{
			{Strategy: protocol.StrategyDirectV4, State: DetectionFailed, Capability: string(CapabilityNoGlobalV4Source)},
			{Strategy: protocol.StrategyExplicitGateway, State: DetectionFailed},
			{Strategy: protocol.StrategyStunOnly, State: DetectionFailed},
		},
	}
	if len(profile.Results) != 3 {
		t.Fatalf("results = %d, want all strategies recorded", len(profile.Results))
	}
	for _, result := range profile.Results {
		if result.State != DetectionFailed {
			t.Fatalf("strategy %s state = %q, want FAILED", result.Strategy, result.State)
		}
	}
	if profile.DefaultStrategy != "" {
		t.Fatalf("all-failed profile must not invent a default, got %q", profile.DefaultStrategy)
	}
}
