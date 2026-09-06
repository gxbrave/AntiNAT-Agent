//go:build linux

// Story 6 RED/LAB: the lab trace test runs a real loopback TCP transfer
// through the proxy and records the data-path evidence separately in
// testdata (v0.8 §4.4: strace/eBPF-style evidence belongs in lab/release
// evidence, never in the runtime API). The recorded fields are
// deterministic — no wall-clock or duration — so the committed file stays
// byte-stable across runs.
package tcp_test

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
)

// labEvidence mirrors the runtime Evidence plus transfer facts, recorded in
// testdata only.
type labEvidence struct {
	DataPath                              string `json:"data_path"`
	ZeroCopyEvidence                      string `json:"zero_copy_evidence"`
	PessimisticFallbackBytesPerConnection int64  `json:"pessimistic_fallback_bytes_per_connection"`
	Protocol                              string `json:"protocol"`
	Direction                             string `json:"direction"`
	TransferBytes                         int    `json:"transfer_bytes"`
	Result                                string `json:"result"`
}

func TestLabTraceRecordsEvidenceSeparately(t *testing.T) {
	target, stopEcho := startEchoServer(t, "")
	defer stopEcho()
	backend, err := forward.NewBackend(target)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, proxy := startForward(t, backend)

	// Real loopback transfer through the proxy.
	conn, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("lab-trace-"), 64*1024) // 640 KiB
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	reply := readExactly(t, conn, len(payload))
	if !bytes.Equal(reply, payload) {
		t.Fatal("lab trace transfer mismatch")
	}

	runtimeEvidence := proxy.Evidence()
	record := labEvidence{
		DataPath:                              runtimeEvidence.DataPath,
		ZeroCopyEvidence:                      runtimeEvidence.ZeroCopyEvidence,
		PessimisticFallbackBytesPerConnection: runtimeEvidence.PessimisticFallbackBytesPerConnection,
		Protocol:                              "tcp",
		Direction:                             "bidirectional",
		TransferBytes:                         len(payload),
		Result:                                "PASS",
	}

	directory := filepath.Join("testdata")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "lab-evidence.json")
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}

	// The recorded evidence must match the runtime classification exactly
	// and must never contain runtime splice counters.
	readBack, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded labEvidence
	if err := json.Unmarshal(readBack, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != record {
		t.Fatalf("recorded evidence %+v != expected %+v", decoded, record)
	}
	if decoded.DataPath != "go_tcp_copy_splice_eligible" {
		t.Fatalf("lab DataPath = %q, want go_tcp_copy_splice_eligible on Linux", decoded.DataPath)
	}
	if decoded.ZeroCopyEvidence != "eligible" {
		t.Fatalf("lab ZeroCopyEvidence = %q, want eligible", decoded.ZeroCopyEvidence)
	}
	if decoded.PessimisticFallbackBytesPerConnection != 2*32*1024 {
		t.Fatalf("lab pessimistic bytes = %d, want 65536", decoded.PessimisticFallbackBytesPerConnection)
	}
}
