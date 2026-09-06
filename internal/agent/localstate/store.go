// Agent local bbolt state store (P07).
//
// The store holds the Agent's durable local state: schema metadata, received
// desired state, applied Forward state, forward delete tombstones, the
// durable control inbox/outbox, operation results, and connection-epoch
// fencing. The terminal marker file is deliberately independent of bbolt
// (marker.go) and is loaded first.
package localstate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// dbFile is the bbolt database filename inside the Agent state directory.
const dbFile = "state.db"

// lockTimeoutDefault bounds how long Open waits for the exclusive OS-level
// bbolt file lock before failing closed (single Agent instance per state
// directory).
const lockTimeoutDefault = time.Second

// Options configures Store open behavior.
type Options struct {
	lockTimeout time.Duration
}

// Option mutates Open options.
type Option func(*Options)

// WithLockTimeout bounds the wait for the exclusive bbolt lock. Useful in
// tests to keep lock-contention failures fast; production uses the default.
func WithLockTimeout(d time.Duration) Option {
	return func(o *Options) { o.lockTimeout = d }
}

// Store is a versioned Agent bbolt store. All bbolt access goes through the
// Store methods; the *bolt.DB handle is package-private so journal and apply
// invariants cannot be bypassed from outside the package.
type Store struct {
	dir     string
	db      *bolt.DB
	closeMu sync.Mutex
	closed  bool
}

// Open opens (creating if needed) the Agent state store under dir. It fails
// closed on a corrupt database, a locked database, an unknown future schema,
// or a failed migration. The state directory is created and verified as
// 0700 and the database file as 0600.
func Open(dir string, opts ...Option) (*Store, error) {
	o := Options{lockTimeout: lockTimeoutDefault}
	for _, apply := range opts {
		apply(&o)
	}
	if err := ensurePrivateDirectory(dir); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, dbFile), 0o600, &bolt.Options{
		Timeout: o.lockTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("localstate: open bbolt store at %s: %w", dir, err)
	}
	s := &Store{dir: dir, db: db}
	if err := s.openMigrations(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// openMigrations runs the schema gate: an unknown future schema fails closed;
// otherwise the database is migrated to the current schema.
func (s *Store) openMigrations() error {
	current, err := s.SchemaVersion()
	if err != nil {
		return err
	}
	if current > SchemaVersion {
		return fmt.Errorf("%w: database schema %d, this build supports %d", ErrSchemaTooNew, current, SchemaVersion)
	}
	if _, err := migrate(s.db, current, schemaMigrations); err != nil {
		return err
	}
	return nil
}

// SchemaVersion returns the persisted schema version after Open.
func (s *Store) SchemaVersion() (uint64, error) {
	var version uint64
	err := s.db.View(func(tx *bolt.Tx) error {
		version = readSchemaVersion(tx)
		return nil
	})
	return version, err
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// Close closes the database. Closing is idempotent.
func (s *Store) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed || s.db == nil {
		return nil
	}
	s.closed = true
	err := s.db.Close()
	return err
}

// ensurePrivateDirectory creates dir with mode 0700 and rejects a pre-existing
// path that is not a 0700 directory.
func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("localstate: state directory %s has mode %v, want 0700", path, info.Mode())
	}
	return nil
}

// syncDirectory fsyncs a directory so a rename inside it is durable.
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// errNotExist reports whether err is os.ErrNotExist (or wrapped).
func errNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
