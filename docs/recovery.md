# AntiNAT Recovery and Lifecycle Operations

> Operator-facing recovery documentation for the v1.0-beta lifecycle: Forward
> deletion, node decommission, key rotation, backup/restore, and uninstall.
> This file is owned by plan 14 (14-lifecycle-rotation-recovery); the behavior
> it describes is implemented by the Agent reconcile layer and the Controller
> lifecycle/recovery services.

## 1. Forward deletion

Deleting a Forward is an explicit `ABSENT` desired record carrying a
`deletion_operation_id`. The Agent:

1. persists the deletion intent and a durable tombstone **before** any stop
   side effect (tombstone-before-stop);
2. stops the listener and releases the data-plane lease — for gateway Forwards
   this deletes the PCP/NAT-PMP/UPnP mapping, its journal record and the
   shared-port listener **together**;
3. records a durable result and ACKs; the Controller's durable receipt is what
   eventually garbage-collects the tombstone.

An old Controller snapshot or a rollback **never resurrects** a deleted
Forward: the durable tombstone and delete fence are the authority over any
replayed PRESENT record. If the Agent is offline the Forward shows
`DELETE_PENDING_OFFLINE`; the Controller never claims the remote endpoint is
stopped until the durable receipt exists.

## 2. Node decommission

Normal and force decommission follow the terminal marker FSM
`ACTIVE -> DECOMMISSIONING -> DECOMMISSIONED -> CLEANUP_ONLY`.

Ordering invariants (state-model §3.4, v0.8 §7.3):

- The `DECOMMISSIONING` marker is written with fsync + rename + parent-fsync
  **before** any Forward stops, and the shared reconcile latch engages at the
  same instant so no concurrent desired-apply can start a new actor.
- All Forward listeners, gateway mappings and journal records are stopped next.
- `DECOMMISSIONED` is written after every Forward LKG, hook secret and job row
  is cleared. The cleanup tombstone keeps every **allowed** Agent key hash and
  credential version across a rotation overlap so no secret survives
  decommission and none is ever re-admitted.
- The decommission ACK carries a minimal node identity and operation result so
  an ACK loss is retryable without retaining any Forward secret.

Force delete works for offline nodes: the Controller persists the cleanup
tombstone (`remote_cleanup_confirmed=false`) and removes the node from the
regular UI immediately, but the old key can **never** receive new desired or
secrets (the enqueue guard refuses it), and the never-reconnected state remains
unconfirmed until the bounded decommission ACK arrives. After the deadline the
Agent records `DROPPED_DUE_TO_DECOMMISSION` — decommission/uninstall is bounded
best-effort, never a permanent at-least-once promise.

## 3. Key rotation

Every Controller signing key, Agent key, Controller master encryption key, hook
encryption key and probe pinned key rotates through the durable operation FSM

```
PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED
```

The rotation certificate is **signed by the old key** and binds the old/new
key IDs, public keys, generation, not-before window and the overlap deadline.
An Agent accepts the new pin only for a valid certificate from its currently
pinned key carrying a **strictly higher** generation (anti-downgrade), fsyncs
the successor pin, then ACKs.

- An offline Agent that never ACKs blocks a normal retire. Force retire
  fast-forwards the journal and then **requires manual re-pin/re-enroll**.
- Rotation is mutually exclusive with backup/restore (and coordinated with
  decommission/force delete) via one process-safe controller-state reservation
  held across each barrier check and its filesystem/SQLite side effect. The
  backup barrier refuses a backup while any rotation is non-terminal, and
  restore refuses while the live controller has a non-terminal rotation. A
  A controller startup/retry path can reconcile PREPARED operations: missing or
  corrupt staged successor material is removed with the PREPARED journal row
  while the old signer remains active, so the operation can be retried safely.
  The caller invokes `lifecycle.ReconcilePreparedRotations` before announcing
  successors; P14 exposes that bounded reconciliation seam rather than adding
  a second controller composition path.
- Ciphertext records carry `key_id`; master/hook rotation writes with the new
  key first, rewraps in the background, re-validates every record and only then
  retires the old key.

## 4. Backup / restore anti-rollback

Backups are a `VACUUM INTO` snapshot plus a manifest containing the Controller
instance id, schema/protocol version, the desired/deletion/tombstone
high-water, the **current key IDs**, per-file hashes/permissions, and creation
time (v0.8 §7.4).

Restore is a staged, verified, operator-gated switch:

1. The backup is verified (manifest hashes + ACL, SQLite `quick_check` +
   `foreign_key_check`, keys, and the manifest high-water against the backup
   contents). A key mismatch, a bit flip, a missing key-id set, a manifest whose
   high-water does not match the backup database contents (tampering), a backup
   whose deletion/tombstone/node-revision high-water is older than the live
   store (a pre-deletion rollback), or an in-flight key rotation **all fail
   closed**.
2. The database is staged to a temp file, integrity-checked, then atomically
   switched over the live database file.
3. The Controller enters `RESTORE_RECONCILIATION`: web sessions are revoked,
   unused enrollment tokens are invalidated, and every node is **quarantined** —
   no automatic desired/delete/probe/rotation is dispatched (automatic probe
   dispatch is suspended until reauthorization). This is why restoring an old
   snapshot can never silently resurrect a Forward or deletion the operator has
   already made.

   The restore/reconcile machinery is code-complete and crash-safe, but the
   **operator flow** that advances a restore operation from
   `RESTORE_RECONCILIATION` to `AUTHORIZED` and that reauthorizes each
   quarantined node is wired by the **P15 operator API**. The lifecycle surfaces
   `lifecycle.FinalizeRestore` and `lifecycle.ReauthorizeNode` exist as the
   library entry points that P15's API is expected to call; no shipped P14
   artifact exposes an in-artifact operator flow for them. Until the P15 API
   ships, advancing `RESTORE_RECONCILIATION -> AUTHORIZED` and clearing a node's
   quarantine flag requires direct controller-database/store access (or a
   P15-provided surface). Until BOTH an `AUTHORIZED` restore operation AND a
   cleared per-node quarantine flag exist, every automatic
   desired/delete/probe/rotation is refused — and the outbox pump re-checks this
   gate at delivery time, requeueing rows enqueued before the restore with a
   bounded backoff so they are never silently delivered.
4. Agents that receive a restore-reconcile enter `RECOVERY_QUARANTINE`: they
   do **not** auto-restore LKG listeners until the Controller issues a recovery
   authorization. The current terminal/uninstall marker on disk is **never**
   overwritten by an old backup — the quarantine marker refuses to exist over a
   `DECOMMISSIONED` marker.

Threat-model note: if an attacker holds the old Controller signing key and a
complete backup, a pure-software Agent cannot perfectly distinguish a
legitimate disaster recovery from a malicious rollback. Strong anti-rollback
requires external WORM/TPM/HSM storage or out-of-band human approval.

## 5. Agent uninstall notice

Uninstall is a bounded best-effort notice, not a silent remote stop promise:

- **Online**: the Agent queues `node_uninstall_notice` for a durable Controller
  receipt (bounded at-least-once).
- **Offline**: the outcome is `UNKNOWN`; the operator must treat the node's
  Controller-side state as unconfirmed.

The local terminal marker always prevents any LKG recovery afterward,
regardless of whether the notice reached the Controller.

## 6. Data-plane journal recovery (operators)

The Agent keeps a durable mapping journal (bbolt `mapping_journal`). On
restart, recovery:

- reopens every durable applied Forward that is not delete-fenced;
- reacquires the gateway mapping, **decodes the adapter-private State** back to
  the typed renewal/delete authority, and refreshes the applied record's
  journal reference at the same revision (never moving SpecRevision);
- evacuates orphaned/superseded journal records: their mapping is released
  through the owning adapter, then the record is deleted with applied/tombstone
  adjacency in one bbolt transaction. Records whose State cannot be decoded are
  **retained** and surfaced — a live gateway mapping is never released on a
  guess.