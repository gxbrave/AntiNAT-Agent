// FIX1 RED (F2): DPAPI key-file round trip. protectDPAPI/unprotectDPAPI must
// return a Go-owned copy of the DPAPI output buffer: the old code returned
// unsafe.Slice into the buffer AFTER the deferred windows.LocalFree ran
// (use-after-free on every Windows key-file load/save, P08-QUALITY F2). The
// returned slices must survive any access pattern the caller uses, so this
// test round-trips content and then exercises the protected blob again after
// the first unprotect returned (the DPAPI buffer is long freed by then).
//
// Windows-only: DPAPI is not available on Linux; this file is compiled and
// type-checked by GOOS=windows builds (go vet / go test -c) and runs on a
// Windows host.
//go:build windows

package security

import (
	"bytes"
	"testing"
)

func TestDPAPIProtectUnprotectRoundTrip(t *testing.T) {
	plain := []byte("node key material \x00\x01\x02\xff with binary content")
	protected, err := protectDPAPI(plain)
	if err != nil {
		t.Fatalf("protectDPAPI: %v", err)
	}
	if bytes.Equal(protected, plain) {
		t.Fatal("protectDPAPI returned the plaintext")
	}
	back, err := unprotectDPAPI(protected)
	if err != nil {
		t.Fatalf("unprotectDPAPI: %v", err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatalf("round trip mismatch: got %x want %x", back, plain)
	}
	// The unprotected slice must remain readable and stable after the DPAPI
	// buffer was freed — a second unprotect of the same blob must still
	// yield identical bytes (the first call's LocalFree cannot corrupt a
	// Go-owned copy).
	again, err := unprotectDPAPI(protected)
	if err != nil {
		t.Fatalf("second unprotectDPAPI: %v", err)
	}
	if !bytes.Equal(again, plain) {
		t.Fatalf("second round trip mismatch: got %x want %x", again, plain)
	}
}

func TestDPAPIEmptyBlobRejected(t *testing.T) {
	if _, err := unprotectDPAPI(nil); err == nil {
		t.Fatal("unprotectDPAPI accepted an empty blob")
	}
	if _, err := unprotectDPAPI([]byte{}); err == nil {
		t.Fatal("unprotectDPAPI accepted an empty blob")
	}
}
