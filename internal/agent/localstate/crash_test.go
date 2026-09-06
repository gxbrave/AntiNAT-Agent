package localstate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/protocol"
)

// Crash harness: abrupt process exit at each durable-state phase must leave a
// deterministically recoverable store. The helper re-executes this test
// binary, performs the scenario, and exits hard (code 91) exactly where a
// crash would land; the parent then reopens the store and verifies the
// recovered state.

const crashExitCode = 91

func TestCrashHarnessHelper(t *testing.T) {
	if os.Getenv("ANTINAT_CRASH_HELPER") != "1" {
		return
	}
	args := os.Args
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || len(args) != separator+3 {
		os.Exit(92)
	}
	scenario, dir := args[separator+1], args[separator+2]
	switch scenario {
	case "partial-apply-before":
		runPartialApplyCrash(dir, false)
	case "partial-apply-after":
		runPartialApplyCrash(dir, true)
	case "delete-before-stop":
		runDeleteCrash(dir)
	case "decommission-marker":
		runMarkerCrash(dir)
	case "receipt-after":
		runReceiptCrash(dir)
	default:
		os.Exit(93)
	}
	os.Exit(91) // simulate abrupt crash at the designated point
}

func runPartialApplyCrash(dir string, afterCommit bool) {
	store, err := Open(dir)
	if err != nil {
		os.Exit(94)
	}
	defer store.Close()
	seed := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-a", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:80", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
		{ForwardID: "fwd-b", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:80", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
	}}
	if _, err := store.CommitDesired(seed, []ForwardApply{
		{ForwardID: "fwd-a", Outcome: ApplyApplied, Applied: validApplied("fwd-a", 1)},
		{ForwardID: "fwd-b", Outcome: ApplyApplied, Applied: validApplied("fwd-b", 1)},
	}); err != nil {
		os.Exit(94)
	}
	if !afterCommit {
		os.Exit(91) // crash before the next commit
	}
	next := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-a", Protocol: protocol.ProtocolTCP, Target: "10.0.0.1:81", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 2},
		{ForwardID: "fwd-b", Protocol: protocol.ProtocolTCP, Target: "10.0.0.2:90", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 2},
	}}
	if _, err := store.CommitDesired(next, []ForwardApply{
		{ForwardID: "fwd-a", Outcome: ApplyFailed, Err: errors.New("apply failed")},
		{ForwardID: "fwd-b", Outcome: ApplyApplied, Applied: validApplied("fwd-b", 2)},
	}); err != nil {
		os.Exit(94)
	}
	os.Exit(91) // crash after the PARTIAL commit
}

func runDeleteCrash(dir string) {
	store, err := Open(dir)
	if err != nil {
		os.Exit(94)
	}
	defer store.Close()
	seed := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-d", Protocol: protocol.ProtocolTCP, Target: "10.0.0.4:80", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 1},
	}}
	if _, err := store.CommitDesired(seed, []ForwardApply{
		{ForwardID: "fwd-d", Outcome: ApplyApplied, Applied: validApplied("fwd-d", 1)},
	}); err != nil {
		os.Exit(94)
	}
	deleting := protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-d", Protocol: protocol.ProtocolTCP, Target: "10.0.0.4:80", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresenceAbsent, DesiredRevision: 2, DeletionOperationID: "del-op-d"},
	}}
	if _, err := store.CommitDesired(deleting, []ForwardApply{
		{ForwardID: "fwd-d", Outcome: ApplyDeleted},
	}); err != nil {
		os.Exit(94)
	}
	os.Exit(91) // crash after tombstone commit, before the stop side effect
}

func runMarkerCrash(dir string) {
	if err := WriteMarker(dir, MarkerDecommissioning); err != nil {
		os.Exit(94)
	}
	store, err := Open(dir)
	if err != nil {
		os.Exit(94)
	}
	store.Close()
	os.Exit(91) // crash while DECOMMISSIONING, before any Forward stop
}

func runReceiptCrash(dir string) {
	store, err := Open(dir)
	if err != nil {
		os.Exit(94)
	}
	defer store.Close()
	if err := store.AdvanceSession(1, "session-1"); err != nil {
		os.Exit(94)
	}
	if err := store.QueueResult(1, "session-1", "op-r", []byte("deleted")); err != nil {
		os.Exit(94)
	}
	if err := store.ClaimOutbox(1, "session-1", "op-r"); err != nil {
		os.Exit(94)
	}
	if err := store.MarkOutboxSent(1, "session-1", "op-r"); err != nil {
		os.Exit(94)
	}
	if err := store.AcceptSemanticACK(1, "session-1", "op-r"); err != nil {
		os.Exit(94)
	}
	if err := store.AcceptReceipt(1, "session-1", "op-r"); err != nil {
		os.Exit(94)
	}
	os.Exit(91) // crash after the durable receipt
}

func runCrashHelper(t *testing.T, dir, scenario string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestCrashHarnessHelper", "--", scenario, dir)
	cmd.Env = append(os.Environ(), "ANTINAT_CRASH_HELPER=1")
	output, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != crashExitCode {
		t.Fatalf("helper %s: err=%v output=%s", scenario, err, output)
	}
}

func TestCrashPartialApplyRecoversAtomically(t *testing.T) {
	for _, phase := range []string{"partial-apply-before", "partial-apply-after"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			runCrashHelper(t, dir, phase)
			store, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			gotA, ok, err := store.GetAppliedState("fwd-a")
			if err != nil || !ok {
				t.Fatalf("fwd-a applied present=%v err=%v", ok, err)
			}
			gotB, ok, err := store.GetAppliedState("fwd-b")
			if err != nil || !ok {
				t.Fatalf("fwd-b applied present=%v err=%v", ok, err)
			}
			if phase == "partial-apply-before" {
				// Crash before the commit: nothing changed.
				if gotA.DesiredRevision != 1 || gotB.DesiredRevision != 1 {
					t.Fatalf("before-commit recovery a=%d b=%d, want both rev 1", gotA.DesiredRevision, gotB.DesiredRevision)
				}
				return
			}
			// Crash after the PARTIAL commit: fwd-a old retained, fwd-b advanced.
			if gotA.DesiredRevision != 1 {
				t.Fatalf("fwd-a recovered rev = %d, want 1 (failed forward retains old)", gotA.DesiredRevision)
			}
			if gotB.DesiredRevision != 2 {
				t.Fatalf("fwd-b recovered rev = %d, want 2 (sibling advanced)", gotB.DesiredRevision)
			}
			received, ok, err := store.LoadReceivedDesired()
			if err != nil || !ok || received.NodeID != "node-1" || len(received.Forwards) != 2 {
				t.Fatalf("received desired after crash ok=%v err=%v forwards=%d", ok, err, len(received.Forwards))
			}
		})
	}
}

func TestCrashDeleteTombstoneBeforeStopNeverResurrects(t *testing.T) {
	dir := t.TempDir()
	runCrashHelper(t, dir, "delete-before-stop")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// The crash happened after the tombstone commit and before the stop hook:
	// the Forward must be tombstoned, never applied, and never resurrectable.
	if ok, err := store.TombstoneExists("fwd-d"); err != nil || !ok {
		t.Fatalf("tombstone present=%v err=%v, want durable", ok, err)
	}
	if _, ok, err := store.GetAppliedState("fwd-d"); err != nil || ok {
		t.Fatalf("applied present=%v err=%v after delete crash, want absent", ok, err)
	}
	if _, err := store.CommitDesired(protocol.DesiredState{NodeID: "node-1", Forwards: []protocol.ForwardSpec{
		{ForwardID: "fwd-d", Protocol: protocol.ProtocolTCP, Target: "10.0.0.4:80", Strategy: protocol.StrategyDirectV4, Presence: protocol.PresencePresent, DesiredRevision: 9},
	}}, []ForwardApply{
		{ForwardID: "fwd-d", Outcome: ApplyApplied, Applied: validApplied("fwd-d", 9)},
	}); !errors.Is(err, ErrTombstonedForward) {
		t.Fatalf("resurrect after delete crash error = %v, want ErrTombstonedForward", err)
	}
}

func TestCrashDecommissionMarkerSurvives(t *testing.T) {
	dir := t.TempDir()
	runCrashHelper(t, dir, "decommission-marker")
	state, err := LoadMarker(dir)
	if err != nil {
		t.Fatal(err)
	}
	if state != MarkerDecommissioning {
		t.Fatalf("marker after crash = %q, want DECOMMISSIONING", state)
	}
	// The store is still openable under DECOMMISSIONING and carries no torn
	// temp marker files.
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	matches, err := filepath.Glob(filepath.Join(dir, ".antinat-marker-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("leftover marker temp files after crash: %v", matches)
	}
}

func TestCrashAfterReceiptKeepsReceiptTombstone(t *testing.T) {
	dir := t.TempDir()
	runCrashHelper(t, dir, "receipt-after")
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if ok, err := store.ReceiptExists("op-r"); err != nil || !ok {
		t.Fatalf("receipt tombstone present=%v err=%v after crash, want durable", ok, err)
	}
	if store.OutboxContains("op-r") {
		t.Fatal("outbox row resurrected after receipt crash")
	}
	// A replay after the crash cannot resurrect the operation.
	if _, err := store.ResultForOperation(1, "session-1", "op-r"); !errors.Is(err, ErrAlreadyReceipted) {
		t.Fatalf("result lookup after crash error = %v, want ErrAlreadyReceipted", err)
	}
}
