package traversal

import (
	"testing"
	"time"
)

// Story 6 RED: the mapping journal records ownership strength verbatim and
// round-trips durably; the profile carries per-protocol results with honest
// staleness.

// J1: journal records round-trip through the durable encoding with the
// mechanism-private state preserved.
func TestJournalRecordRoundTrip(t *testing.T) {
	record := JournalRecord{
		ID:              "journal-1",
		ForwardID:       "forward-1",
		OperationID:     "op-1",
		Mechanism:       LayerPCP,
		Ownership:       OwnershipStrong,
		Protocol:        "tcp",
		InternalIP:      "10.0.0.2",
		InternalPort:    3111,
		ExternalIP:      "8.8.8.8",
		ExternalPort:    43111,
		LeaseExpiryUnix: time.Now().Add(time.Hour).Unix(),
		Epoch:           3840,
		Identity:        "",
		State:           []byte(`{"nonce":"AAAA"}`),
		CreatedAtUnix:   time.Now().Unix(),
		UpdatedAtUnix:   time.Now().Unix(),
	}

	encoded, err := EncodeJournalRecord(record)
	if err != nil {
		t.Fatalf("EncodeJournalRecord: %v", err)
	}
	decoded, err := DecodeJournalRecord(encoded)
	if err != nil {
		t.Fatalf("DecodeJournalRecord: %v", err)
	}
	if decoded.ID != record.ID || decoded.Mechanism != record.Mechanism ||
		decoded.Ownership != record.Ownership || decoded.ExternalPort != record.ExternalPort ||
		string(decoded.State) != string(record.State) {
		t.Fatalf("round trip mismatch: %+v vs %+v", decoded, record)
	}
}

// J2: the memory journal backs the detector and lab flows: put, get,
// list-by-forward and delete.
func TestMemoryJournalOperations(t *testing.T) {
	journal := NewMemoryJournal()
	record := JournalRecord{ID: "j1", ForwardID: "f1", Mechanism: LayerPCP, Ownership: OwnershipStrong}
	if err := journal.Put(record); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := journal.Get("j1")
	if err != nil || !ok || got.ForwardID != "f1" {
		t.Fatalf("Get = %v/%v/%v", got, ok, err)
	}
	missing := JournalRecord{ID: "j2", ForwardID: "f2", Mechanism: LayerNATPMP, Ownership: OwnershipWeakLease}
	if err := journal.Put(missing); err != nil {
		t.Fatalf("Put j2: %v", err)
	}
	byForward, err := journal.ListByForward("f2")
	if err != nil || len(byForward) != 1 || byForward[0].ID != "j2" {
		t.Fatalf("ListByForward = %v/%v", byForward, err)
	}
	if err := journal.Delete("j1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := journal.Get("j1"); ok {
		t.Fatal("deleted record still present")
	}
}

// J3: a journal record renders the honest ownership classification: the
// strength string is preserved verbatim, never upgraded.
func TestJournalOwnershipVerbatim(t *testing.T) {
	cases := []OwnershipStrength{OwnershipStrong, OwnershipWeakLease, OwnershipBestEffort}
	for _, ownership := range cases {
		record := JournalRecord{ID: "j", Mechanism: LayerUPnP, Ownership: ownership}
		encoded, err := EncodeJournalRecord(record)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		decoded, err := DecodeJournalRecord(encoded)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if decoded.Ownership != ownership {
			t.Fatalf("ownership %q became %q", ownership, decoded.Ownership)
		}
	}
}
