// Story 6 RED: the data path must report go_tcp_copy_splice_eligible on
// Linux and never exact runtime splice counters (v0.8 §4.4: data_path =
// go_tcp_copy_splice_eligible | go_tcp_copy_buffered; zero_copy_evidence =
// eligible | lab_verified | runtime_observed | not_applicable; no per-activation
// splice_bytes/buffered_fallback_bytes without an ADR).
package tcp_test

import (
	"reflect"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
	"github.com/gxbrave/AntiNAT-Agent/internal/forward/tcp"
)

func TestClassifySpliceEligible(t *testing.T) {
	evidence := tcp.Classify(true)
	if evidence.DataPath != "go_tcp_copy_splice_eligible" {
		t.Fatalf("DataPath = %q, want go_tcp_copy_splice_eligible", evidence.DataPath)
	}
	if evidence.ZeroCopyEvidence != "eligible" {
		t.Fatalf("ZeroCopyEvidence = %q, want eligible", evidence.ZeroCopyEvidence)
	}
	if evidence.PessimisticFallbackBytesPerConnection != 2*32*1024 {
		t.Fatalf("PessimisticFallbackBytesPerConnection = %d, want 65536", evidence.PessimisticFallbackBytesPerConnection)
	}
}

func TestClassifyNotSpliceEligible(t *testing.T) {
	evidence := tcp.Classify(false)
	if evidence.DataPath != "go_tcp_copy_buffered" {
		t.Fatalf("DataPath = %q, want go_tcp_copy_buffered", evidence.DataPath)
	}
	if evidence.ZeroCopyEvidence != "not_applicable" {
		t.Fatalf("ZeroCopyEvidence = %q, want not_applicable", evidence.ZeroCopyEvidence)
	}
}

func TestEvidenceStructExposesNoRuntimeSpliceCounters(t *testing.T) {
	typ := reflect.TypeOf(tcp.Evidence{})
	if typ.NumField() != 3 {
		t.Fatalf("Evidence has %d fields, want exactly 3 (no runtime counters)", typ.NumField())
	}
	allowed := map[string]bool{
		"DataPath":                              true,
		"ZeroCopyEvidence":                      true,
		"PessimisticFallbackBytesPerConnection": true,
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if !allowed[field.Name] {
			t.Fatalf("Evidence exposes unexpected field %q (runtime counters are forbidden without an ADR)", field.Name)
		}
	}
}

func TestForwardEvidenceReportsClassificationOnly(t *testing.T) {
	target, stopEcho := startEchoServer(t, "T:")
	defer stopEcho()
	backend, err := forward.NewBackend(target)
	if err != nil {
		t.Fatal(err)
	}
	_, proxy := startForward(t, backend)
	evidence := proxy.Evidence()
	if evidence.DataPath != "go_tcp_copy_splice_eligible" {
		t.Fatalf("DataPath = %q, want go_tcp_copy_splice_eligible on Linux", evidence.DataPath)
	}
	if evidence.ZeroCopyEvidence != "eligible" {
		t.Fatalf("ZeroCopyEvidence = %q, want eligible", evidence.ZeroCopyEvidence)
	}
}
