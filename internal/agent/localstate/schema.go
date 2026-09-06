// bbolt schema versioning and migration (docs/state-model.md §9.2 bucket set).
//
// The Agent bbolt database is versioned: Open refuses an unknown future
// schema, a corrupt file, or a locked database, and each migration applies in
// its own transaction so a failed migration leaves the previous version fully
// intact (fail closed).
package localstate

import (
	"encoding/binary"
	"errors"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

// SchemaVersion is the current Agent bbolt schema version. A database
// carrying a higher version is from a newer AntiNAT build and Open fails
// closed with ErrSchemaTooNew rather than risk silent data damage.
const SchemaVersion uint64 = 3

// ErrSchemaTooNew reports a database written by a newer schema than this
// build understands. Opening must fail closed.
var ErrSchemaTooNew = errors.New("localstate: agent bbolt schema is newer than this build")

// Frozen Agent bbolt buckets (v0.8 reviewed plan §9.2). The bucket set is
// pinned by the frozen contract; later plans write into the buckets they own
// and add new buckets only through a schema migration.
const (
	bucketSchema         = "meta/schema"
	bucketControllerPins = "controller_pins"
	bucketEpochs         = "connection_epochs"
	bucketInbox          = "control_inbox"
	bucketOutbox         = "control_outbox"
	bucketDesired        = "received_desired"
	bucketApplied        = "applied_forwards"
	bucketTombstones     = "forward_delete_tombstones"
	bucketActivation     = "activation_recovery"
	bucketMapping        = "mapping_journal"
	bucketHookQueue      = "hook_queue"
	bucketKeyring        = "keyring"
	bucketOperations     = "operation_results"
	// bucketProbeOps (schema v2, P10): durable armed probe operations. The
	// agent persists each outstanding probe operation before answering
	// probe_armed (docs/protocol.md §7.2: durable persistence precedes the
	// RDY1 response), so a crash never loses an armed operation.
	bucketProbeOps = "probe_operations"
	// bucketForwardDeleteIntents (schema v3): reversible, durable deletion
	// fences. Unlike the final tombstone, this row remains until cleanup has
	// completed so restart recovery cannot reopen a Forward in the crash window.
	bucketForwardDeleteIntents = "forward_delete_intents"
)

// allBuckets is the complete frozen bucket set. Schema v1 creates every
// bucket so later plans write into the buckets they own without a schema
// change; any genuinely new bucket requires a migration.
var allBuckets = []string{
	bucketSchema, bucketControllerPins, bucketEpochs, bucketInbox,
	bucketOutbox, bucketDesired, bucketApplied, bucketTombstones,
	bucketActivation, bucketMapping, bucketHookQueue, bucketKeyring,
	bucketOperations,
}

var schemaKeyVersion = []byte("version")

// migration applies one versioned schema change atomically.
type migration struct {
	version uint64
	apply   func(tx *bolt.Tx) error
}

// schemaMigrations lists every migration in version order. Each runs in its
// own bbolt transaction; a failing migration rolls back completely and the
// schema version is never advanced past it.
var schemaMigrations = []migration{
	{version: 1, apply: func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("localstate: create bucket %q: %w", name, err)
			}
		}
		return nil
	}},
	// v2 (P10): durable armed probe operations (docs/protocol.md §7.2).
	// The v1 bucket set is untouched; only the new probe bucket is added.
	{version: 2, apply: func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketProbeOps)); err != nil {
			return fmt.Errorf("localstate: create bucket %q: %w", bucketProbeOps, err)
		}
		return nil
	}},
	// v3: durable, reversible Forward deletion fences. The separate bucket
	// keeps pending lifecycle rows distinct from final tombstones and avoids
	// key namespace collisions with legacy Forward IDs.
	{version: 3, apply: func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucketForwardDeleteIntents)); err != nil {
			return fmt.Errorf("localstate: create bucket %q: %w", bucketForwardDeleteIntents, err)
		}
		return nil
	}},
}

func encodeVersion(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

func decodeVersion(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// readSchemaVersion returns the persisted schema version, or 0 when the
// meta/schema bucket (and thus the version key) does not exist yet.
func readSchemaVersion(tx *bolt.Tx) uint64 {
	b := tx.Bucket([]byte(bucketSchema))
	if b == nil {
		return 0
	}
	return decodeVersion(b.Get(schemaKeyVersion))
}

// migrate applies every migration with version > current, in order, each in
// its own transaction. On the first failure it returns the highest version
// successfully applied and the error; the database is left exactly at that
// version with all earlier data intact.
func migrate(db *bolt.DB, current uint64, ms []migration) (uint64, error) {
	next := current
	for _, m := range ms {
		if m.version <= current {
			continue
		}
		if err := db.Update(func(tx *bolt.Tx) error {
			if err := m.apply(tx); err != nil {
				return err
			}
			b, err := tx.CreateBucketIfNotExists([]byte(bucketSchema))
			if err != nil {
				return err
			}
			return b.Put(schemaKeyVersion, encodeVersion(m.version))
		}); err != nil {
			return next, fmt.Errorf("localstate: migration to schema %d failed (store left at schema %d): %w", m.version, next, err)
		}
		next = m.version
	}
	return next, nil
}
