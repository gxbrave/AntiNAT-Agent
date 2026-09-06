package localstate

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Story 1 RED: unknown future schema, corrupt store, lock contention and
// failed migration must all fail closed. These tests are written against the
// intended API and fail (undefined symbols / missing behavior) before the
// store.go/schema.go GREEN implementation.

func TestOpenUnknownFutureSchemaFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// Write a schema version newer than this build understands, exactly as a
	// future AntiNAT build would leave it, then require Open to fail closed.
	path := filepath.Join(dir, dbFile)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	version := make([]byte, 8)
	binary.BigEndian.PutUint64(version, 999)
	if err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("meta/schema"))
		if err != nil {
			return err
		}
		return b.Put([]byte("version"), version)
	}); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(dir)
	if err == nil {
		store.Close()
		t.Fatal("store with unknown future schema opened successfully; want fail closed")
	}
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("future schema open error = %v, want ErrSchemaTooNew", err)
	}
}

func TestOpenCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(dir, dbFile), 512); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir); err == nil {
		reopened.Close()
		t.Fatal("corrupt bbolt store opened successfully; want fail closed")
	}
}

func TestOpenLockContentionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(dir, WithLockTimeout(100*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(dir, WithLockTimeout(100*time.Millisecond))
	if err == nil {
		second.Close()
		t.Fatal("second opener acquired the exclusive bbolt lock; want fail closed")
	}
}

func TestFailedMigrationFailsClosedAndPreservesOldState(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a bucket that a later, failing migration would rewrite.
	if err := store.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("legacy"))
		if err != nil {
			return err
		}
		return b.Put([]byte("k"), []byte("v"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := bolt.Open(filepath.Join(dir, dbFile), 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	bad := migration{version: SchemaVersion + 1, apply: func(tx *bolt.Tx) error {
		return errors.New("boom: synthetic migration failure")
	}}
	next, err := migrate(db, SchemaVersion, []migration{bad})
	if err == nil {
		t.Fatal("failing migration reported success; want fail closed")
	}
	if next != SchemaVersion {
		t.Fatalf("schema version after failed migration = %d, want %d", next, SchemaVersion)
	}
	// The old state must be intact and the schema version must not advance.
	if err := db.View(func(tx *bolt.Tx) error {
		if got := tx.Bucket([]byte("legacy")).Get([]byte("k")); string(got) != "v" {
			t.Fatalf("legacy data after failed migration = %q, want %q", got, "v")
		}
		raw := tx.Bucket([]byte("meta/schema")).Get([]byte("version"))
		if raw == nil || binary.BigEndian.Uint64(raw) != SchemaVersion {
			t.Fatalf("schema version after failed migration = %v, want %d", raw, SchemaVersion)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
