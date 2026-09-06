// Mapping journal (v0.8 §3.4, state-model §2 mapping_journal_ref): the
// durable record of one acquired mapping with its honest ownership
// strength. The Agent persists journal records into the bbolt
// `mapping_journal` bucket (created since schema v1) through the Store
// interface; P14 consumes the records for cleanup and recovery. Nothing may
// record a weaker mechanism as strong ownership: the strength string is
// preserved verbatim.
package traversal

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// JournalRecord is one mapping journal entry.
type JournalRecord struct {
	// ID is the journal record identity (referenced from
	// AppliedForwardState.mapping_journal_ref).
	ID string
	// ForwardID is the owning forward; empty for detection-temp mappings.
	ForwardID string
	// OperationID ties a detection-temp mapping to its operation.
	OperationID  string
	Mechanism    MappingLayerKind
	Ownership    OwnershipStrength
	Protocol     string // "tcp" in v1
	InternalIP   string
	InternalPort uint16
	ExternalIP   string
	ExternalPort uint16
	// LeaseExpiryUnix is the absolute lease deadline (0 = none/unknown).
	LeaseExpiryUnix int64
	Epoch           uint32
	// Identity is the stable gateway identity (UPnP USN, empty otherwise).
	Identity string
	// State is the mechanism-private renewal state (adapter JSON), needed
	// by recovery to renew or release after a restart.
	State []byte
	// CreatedAtUnix / UpdatedAtUnix are wall-clock timestamps for humans;
	// all deadlines are absolute Unix seconds.
	CreatedAtUnix int64
	UpdatedAtUnix int64
}

// Journal encode/decode errors.
var (
	ErrJournalEncode = errors.New("traversal: journal record encode failed")
	ErrJournalDecode = errors.New("traversal: journal record decode failed")
)

// EncodeJournalRecord renders the durable JSON encoding.
func EncodeJournalRecord(record JournalRecord) ([]byte, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJournalEncode, err)
	}
	return encoded, nil
}

// DecodeJournalRecord parses the durable JSON encoding.
func DecodeJournalRecord(encoded []byte) (JournalRecord, error) {
	var record JournalRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return JournalRecord{}, fmt.Errorf("%w: %v", ErrJournalDecode, err)
	}
	return record, nil
}

// JournalStore is the durable journal backing. The agent wiring satisfies
// it with bbolt; the memory implementation serves the detector and labs.
// Implementations must be bounded-latency: the manager invokes Get/Put/Delete
// while holding the acquisition's renewal lock, and a call that blocks forever
// wedges renewal, Release and the status accessors (a hung call cannot be
// forcibly interrupted).
type JournalStore interface {
	Put(record JournalRecord) error
	Get(id string) (JournalRecord, bool, error)
	Delete(id string) error
	List() ([]JournalRecord, error)
	ListByForward(forwardID string) ([]JournalRecord, error)
}

// MemoryJournal is an in-memory JournalStore for detection and lab flows.
type MemoryJournal struct {
	mu      sync.Mutex
	records map[string]JournalRecord
}

// NewMemoryJournal returns an empty in-memory journal.
func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{records: make(map[string]JournalRecord)}
}

// Put inserts or replaces one record.
func (m *MemoryJournal) Put(record JournalRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[record.ID] = record
	return nil
}

// Get returns one record by ID.
func (m *MemoryJournal) Get(id string) (JournalRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.records[id]
	return record, ok, nil
}

// Delete removes one record by ID.
func (m *MemoryJournal) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, id)
	return nil
}

// List returns every record.
func (m *MemoryJournal) List() ([]JournalRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	records := make([]JournalRecord, 0, len(m.records))
	for _, record := range m.records {
		records = append(records, record)
	}
	return records, nil
}

// ListByForward returns the records owned by one forward.
func (m *MemoryJournal) ListByForward(forwardID string) ([]JournalRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var records []JournalRecord
	for _, record := range m.records {
		if record.ForwardID == forwardID {
			records = append(records, record)
		}
	}
	return records, nil
}
