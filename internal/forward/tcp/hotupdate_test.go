// Story 4 RED: a hot-updated target must apply to new sessions only — the
// established session keeps talking to its original target while a new
// connection resolves the new snapshot at accept time.
package tcp_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/forward"
)

func TestHotUpdateOldConnectionKeepsOldTarget(t *testing.T) {
	targetA, stopA := startEchoServer(t, "A:")
	defer stopA()
	targetB, stopB := startEchoServer(t, "B:")
	defer stopB()

	backend, err := forward.NewBackend(targetA)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr, _ := startForward(t, backend)

	dialAndEcho := func(name string, target string) {
		t.Helper()
		conn, err := net.Dial("tcp4", proxyAddr)
		if err != nil {
			t.Fatalf("%s dial: %v", name, err)
		}
		defer conn.Close()
		message := fmt.Sprintf("ping-%s", name)
		if _, err := conn.Write([]byte(message)); err != nil {
			t.Fatalf("%s write: %v", name, err)
		}
		want := []byte(target + message)
		if got := readExactly(t, conn, len(want)); !bytes.Equal(got, want) {
			t.Fatalf("%s echo = %q, want %q", name, got, want)
		}
	}

	// Old session pins target A.
	oldConn, err := net.Dial("tcp4", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer oldConn.Close()
	if _, err := oldConn.Write([]byte("ping-old")); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, oldConn, len("A:ping-old")); string(got) != "A:ping-old" {
		t.Fatalf("old session echo = %q, want A:ping-old", got)
	}

	// Hot update: only new sessions must see the new snapshot.
	if err := backend.Update(targetB); err != nil {
		t.Fatalf("Update: %v", err)
	}
	dialAndEcho("new", "B:")

	// The established session is untouched.
	if _, err := oldConn.Write([]byte("ping-old-again")); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, oldConn, len("A:ping-old-again")); string(got) != "A:ping-old-again" {
		t.Fatalf("old session after update = %q, want A:ping-old-again", got)
	}
}
