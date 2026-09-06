// Outbox enumeration helper (P08 extension of the declared P07 control
// persistence interface). The journal stores semantic payloads keyed by
// operation id; the transport needs the full pending set to drive the outbox
// pump after reconnect (RequeueOutboxForSession resets rows to PENDING, then
// the pump re-envelopes each one).
package localstate

import bolt "go.etcd.io/bbolt"

// OutboxOperationIDs returns a bounded prefix of operation ids with durable
// outbox rows (any FSM phase). Callers that need to drain the complete set must
// use OutboxOperationIDsAfter in successive keyset pages.
func (s *Store) OutboxOperationIDs() ([]string, error) {
	return s.OutboxOperationIDsLimit(256)
}

// OutboxOperationIDsLimit returns at most limit operation ids in Bolt key order.
// The bounded API is intentional: an outbox can be larger than one transport
// batch, so the transport pump must not mistake this prefix for the whole set.
func (s *Store) OutboxOperationIDsLimit(limit int) ([]string, error) {
	return s.OutboxOperationIDsAfter("", limit)
}

// OutboxOperationIDsAfter returns one bounded keyset page strictly after after.
// An empty after starts at the first key. Pages are stable under deletion and
// permit the caller to make eventual progress without an unbounded read.
func (s *Store) OutboxOperationIDsAfter(after string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 256
	}
	var ids []string
	err := s.db.View(func(tx *bolt.Tx) error {
		cursor := tx.Bucket([]byte(bucketOutbox)).Cursor()
		var key []byte
		if after == "" {
			key, _ = cursor.First()
		} else {
			key, _ = cursor.Seek([]byte(after))
			if key != nil && string(key) <= after {
				key, _ = cursor.Next()
			}
		}
		for ; key != nil && len(ids) < limit; key, _ = cursor.Next() {
			ids = append(ids, string(key))
		}
		return nil
	})
	return ids, err
}
