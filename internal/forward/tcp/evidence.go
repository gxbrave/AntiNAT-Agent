// Data-path evidence (v0.8 §4.4): the runtime API reports only the
// classification — data_path = go_tcp_copy_splice_eligible | go_tcp_copy_buffered
// and zero_copy_evidence = eligible | lab_verified | runtime_observed |
// not_applicable — plus the frozen pessimistic per-connection fallback
// budget. Exact runtime splice/fallback byte counters are never exposed
// without a custom-observability ADR and benchmark; strace/eBPF-style
// evidence belongs in lab/release evidence (see lab_trace_test.go).
package tcp

import (
	"runtime"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
)

// Evidence is the frozen data-path evidence shape. It intentionally carries
// no runtime counters.
type Evidence struct {
	DataPath                              string `json:"data_path"`
	ZeroCopyEvidence                      string `json:"zero_copy_evidence"`
	PessimisticFallbackBytesPerConnection int64  `json:"pessimistic_fallback_bytes_per_connection"`
}

// Classify returns the evidence for a splice-eligible (Linux TCP-to-TCP
// io.Copy) or buffered data path. Eligibility is a platform property of the
// standard library, never a measured counter.
func Classify(spliceEligible bool) Evidence {
	evidence := Evidence{
		DataPath:                              "go_tcp_copy_buffered",
		ZeroCopyEvidence:                      "not_applicable",
		PessimisticFallbackBytesPerConnection: forward.PessimisticBufferBytesPerConnection,
	}
	if spliceEligible {
		evidence.DataPath = "go_tcp_copy_splice_eligible"
		evidence.ZeroCopyEvidence = "eligible"
	}
	return evidence
}

// Evidence reports the data-path classification for this Forward. On Linux
// the standard library may splice TCP-to-TCP copies; the pessimistic
// fallback budget is always reserved regardless.
func (f *Forward) Evidence() Evidence {
	return Classify(runtime.GOOS == "linux")
}
