// P10 probe orchestration adapter (docs/protocol.md §7).
//
// P05 declares that P10 may add a probe orchestration adapter file in this
// package through the frozen protocol surface; this file is that adapter.
// It contains only derivation helpers that both the controller and the
// agent must compute from data they already hold — no wire format changes
// and no frozen fixture edits.
package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// ActivationID deterministically derives the 16-byte activation identifier
// for a forward at a spec revision. Both the controller and the agent can
// compute it from data they already hold, so the ARM1 activation field is
// verifiable without extra wire state (P10).
func ActivationID(forwardID string, specRevision uint64) [16]byte {
	var buf bytes.Buffer
	buf.WriteString("antinat-activation-v1\x00")
	buf.WriteString(forwardID)
	buf.WriteByte(0)
	var rev [8]byte
	binary.BigEndian.PutUint64(rev[:], specRevision)
	buf.Write(rev[:])
	sum := sha256.Sum256(buf.Bytes())
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}
