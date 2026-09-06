// P12W Story 1 RED: the Agent localstate store exposes the existing
// mapping_journal bucket as a durable traversal.JournalStore. Put/Get/Delete/
// List/ListByForward round-trip Encode/DecodeJournalRecord, and records
// survive Close+Open with State []byte and Ownership verbatim.
package localstate

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gxbrave/AntiNAT-Agent/internal/traversal"
	bolt "go.etcd.io/bbolt"
)

func TestMappingJournalSatisfiesJournalStore(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var _ traversal.JournalStore = st.MappingJournal()
}

func TestMappingJournalRoundTripAndReopenPreservesState(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	journal := st.MappingJournal()

	record := traversal.JournalRecord{
		ID:              "fwd-1-pcp-abc",
		ForwardID:       "fwd-1",
		OperationID:     "op-detect",
		Mechanism:       traversal.LayerPCP,
		Ownership:       traversal.OwnershipStrong,
		Protocol:        "tcp",
		InternalIP:      "10.0.0.2",
		InternalPort:    48001,
		ExternalIP:      "100.64.0.2",
		ExternalPort:    43111,
		LeaseExpiryUnix: 1893456000,
		Epoch:           3,
		Identity:        "gateway-usn",
		State:           []byte(`{"nonce":"abc123"}`),
		CreatedAtUnix:   1893450000,
		UpdatedAtUnix:   1893456000,
	}
	if err := journal.Put(record); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := journal.Get(record.ID)
	if err != nil || !ok {
		t.Fatalf("Get = ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got.State, record.State) {
		t.Fatalf("State lost: got %q, want %q", got.State, record.State)
	}
	if got.Ownership != record.Ownership || got.Mechanism != record.Mechanism ||
		got.InternalIP != record.InternalIP || got.ExternalPort != record.ExternalPort {
		t.Fatalf("record = %+v, want %+v", got, record)
	}

	// Durability across Close+Open: the State and Ownership bytes must be
	// verbatim, not just semantically equal.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	got, ok, err = st2.MappingJournal().Get(record.ID)
	if err != nil || !ok {
		t.Fatalf("reopen Get = ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got.State, record.State) {
		t.Fatalf("reopen State lost: got %q, want %q", got.State, record.State)
	}
	if got.Ownership != record.Ownership || got.Identity != record.Identity {
		t.Fatalf("reopen record = %+v, want %+v", got, record)
	}
}

func TestMappingJournalListByForwardAndDelete(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	journal := st.MappingJournal()

	records := []traversal.JournalRecord{
		{ID: "fwd-1-pcp-a", ForwardID: "fwd-1", Mechanism: traversal.LayerPCP, Ownership: traversal.OwnershipStrong, Protocol: "tcp"},
		{ID: "fwd-1-natpmp-b", ForwardID: "fwd-1", Mechanism: traversal.LayerNATPMP, Ownership: traversal.OwnershipWeakLease, Protocol: "tcp"},
		{ID: "fwd-2-upnp-c", ForwardID: "fwd-2", Mechanism: traversal.LayerUPnP, Ownership: traversal.OwnershipBestEffort, Protocol: "tcp"},
	}
	for _, record := range records {
		if err := journal.Put(record); err != nil {
			t.Fatalf("Put %s: %v", record.ID, err)
		}
	}

	all, err := journal.List()
	if err != nil || len(all) != len(records) {
		t.Fatalf("List = %d records (%v), want %d", len(all), err, len(records))
	}
	byForward, err := journal.ListByForward("fwd-1")
	if err != nil || len(byForward) != 2 {
		t.Fatalf("ListByForward = %d records (%v), want 2", len(byForward), err)
	}
	for _, record := range byForward {
		if record.ForwardID != "fwd-1" {
			t.Fatalf("ListByForward returned %q", record.ForwardID)
		}
	}

	if err := journal.Delete("fwd-1-natpmp-b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := journal.Get("fwd-1-natpmp-b"); ok {
		t.Fatal("deleted record still present")
	}
	byForward, err = journal.ListByForward("fwd-1")
	if err != nil || len(byForward) != 1 {
		t.Fatalf("ListByForward after delete = %d records (%v), want 1", len(byForward), err)
	}
}

func TestMappingJournalRejectsMalformedBucketRow(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// A malformed row written directly into the mapping_journal bucket must be
	// surfaced by Get as a decode error, not silently skipped or zeroed.
	st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketMapping)).Put([]byte("broken"), []byte("not-json"))
	})
	if _, _, err := st.MappingJournal().Get("broken"); err == nil ||
		!strings.Contains(err.Error(), traversal.ErrJournalDecode.Error()) {
		t.Fatalf("Get on malformed row err = %v, want a decode error", err)
	}
}
