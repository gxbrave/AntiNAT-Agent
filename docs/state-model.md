# AntiNAT State and Lifecycle Contract (FROZEN)

> Status: **FROZEN at P04**. This document is a normative contract consumed by
> later Coding AIs without reinterpretation. Any change requires a versioned
> contract revision and orchestrator approval.
>
> Schema version: `antinat.contracts/state-model/v1`.
> Fixtures: `test/contracts/testdata/state-model/**`, validated by
> `go test ./test/contracts/... -count=1 -v`.

## 1. Orthogonal activation states

Every Forward activation holds **one value per independent axis**. A UI may
compute aggregate status, but an aggregate is never a protocol fact and cannot
replace an axis value. The axes and their exact enums are frozen:

| Axis | Values |
|---|---|
| `control_state` | `ONLINE`, `OFFLINE` |
| `listener_state` | `STOPPED`, `STARTING`, `READY`, `ERROR` |
| `mapping_state` | `NOT_REQUIRED`, `ACQUIRING`, `FIRST_HOP_MAPPED`, `PUBLIC_CANDIDATE`, `LOST`, `ERROR` |
| `keepalive_state` | `NOT_REQUIRED`, `HEALTHY`, `DEGRADED`, `LOST` |
| `wan_reachability_state` | `NOT_TESTED`, `PROBING`, `OPEN_FROM_VANTAGE`, `REJECTED`, `TIMEOUT`, `NO_INDEPENDENT_VANTAGE`, `PROBE_INFRA_UNAVAILABLE`, `UNKNOWN` |
| `return_path_state` | `NOT_TESTED`, `VERIFIED`, `FAILED`, `UNKNOWN` |
| `target_health_state` | `PASS`, `FAIL`, `SKIPPED`, `UNSUPPORTED`, `UNKNOWN` |
| `publication_state` | `NONE`, `PUBLISHED_VERIFIED`, `PUBLISHED_UNVERIFIED`, `STALE`, `UNPUBLISHED` |
| `data_plane_state` | `STOPPED`, `READY`, `DEGRADED`, `ERROR` |

Rules:

- A complete snapshot has exactly one value for every axis.
- `PUBLISHED_VERIFIED` requires `wan_reachability_state=OPEN_FROM_VANTAGE` and
  `return_path_state=VERIFIED`.
- `PUBLISHED_UNVERIFIED` must never claim `OPEN_FROM_VANTAGE`.
- `FIRST_HOP_MAPPED` is never a verified public endpoint; only
  `OPEN_FROM_VANTAGE` may drive a verified publication.

## 2. AppliedForwardState

The durable Agent LKG record for a Forward (bbolt bucket `applied_forwards`).
It never persists a directly-restorable verified health: after a process
restart the activation recovers to `RECOVERING`/`UNVERIFIED_AFTER_RESTART` and
must be re-probed before any publication.

| Field | Type | Rule |
|---|---|---|
| `forward_id` | string | non-empty |
| `spec_revision` | uint64 | |
| `desired_revision` | uint64 | >= `spec_revision` |
| `actual_bind_host` / `actual_bind_port` | string / uint16 | concrete bind tuple, port != 0 |
| `assigned_gateway_port` | uint16 | optional |
| `public_port` | uint16 | optional |
| `strategy` | string | one of `direct-v4`, `manual-static-v4`, `explicit-gateway`, `stun-only`, `auto` |
| `layer_version` | uint64 | |
| `activation_recovery_descriptor` | string | |
| `mapping_journal_ref` | string | optional |
| `hook_definition_version` / `hook_secret_version` | uint64 | optional |
| `applied_at_unix` | int64 | > 0 |

## 3. Durable control FSMs

Transitions require their **exact predecessor** (single step). A semantic ACK
does not permit GC; only a durable receipt does.

### 3.1 Outbox (Controller and Agent)

```text
PENDING -> CLAIMED -> SENT -> SEMANTIC_ACKED -> RECEIPTED -> GC
```

- `SENT` means only that the socket write happened.
- The receiving side persists the semantic result, then sends the ACK.
- The sending side persists the ACK, returns `message_receipt`/
  `operation_complete`, and GCs only after the durable receipt.

Illegal transitions (pinned by fixtures): `SENT -> GC`, `PENDING -> SENT`,
`SEMANTIC_ACKED -> GC`, any backward move, any move out of `GC`.

### 3.2 Inbox / Operation

```text
RECEIVED -> INTENT_PERSISTED -> APPLYING -> APPLIED | NACKED
```

- Delete/decommission/rotation/restore persist intent before any external side
  effect.
- Old-epoch ACKs are rejected; the new session re-signs the same semantic
  result without repeating the side effect.

Illegal transitions: `RECEIVED -> APPLIED`, `APPLIED -> NACKED`, and any skip
over `INTENT_PERSISTED` or `APPLYING`.

### 3.3 Key rotation

```text
PREPARED -> ANNOUNCED -> ACKED -> ACTIVE -> RETIRED
```

- The rotation certificate (signed by the old key) binds old/new key IDs,
  public keys, generation, not-before, and overlap deadline.
- The Agent fsyncs the new pin set before ACK and persists the highest
  generation to prevent downgrade.
- Offline/un-ACKed nodes block normal retire; force-retire requires manual
  repin/re-enroll.

Illegal transition: `PREPARED -> ACTIVE` (pinned).

### 3.4 Decommission

```text
ACTIVE -> DECOMMISSIONING -> DECOMMISSIONED -> CLEANUP_ONLY
```

- The terminal marker and reconcile share one exclusive latch; after the
  marker starts, no concurrent desired apply may start a new actor.
- `DECOMMISSIONING` is written first (temp write + fsync + rename + parent
  fsync), then all Forwards stop, then LKG/secrets are cleaned, then
  `DECOMMISSIONED`.
- ACK loss keeps only the minimal node private identity, operation result, and
  ACK outbox until Controller durable receipt — never Forward LKG/secrets.
- `CLEANUP_ONLY` is the only session allowed for a force-deleted node.

Illegal transition: `ACTIVE -> DECOMMISSIONED` (pinned).

### 3.5 Restore

```text
RESTORED -> RECOVERY_QUARANTINE -> RECONCILING -> AUTHORIZED
```

- A restored Agent enters `RECOVERY_QUARANTINE` and does not auto-recover LKG
  listeners; it must receive Controller recovery authorization.
- The Controller enters reconciliation: invalidates web sessions, unused
  enroll tokens, and probe operations; quarantines nodes; raises revisions
  above Agent high-water; merges deletion facts; never auto-revives
  post-backup-deleted resources.
- The current disk terminal/uninstall marker can never be overwritten by an
  older backup.

Illegal transition: `RESTORED -> AUTHORIZED` (pinned).

## 4. Explicit deletion and tombstones

- A full snapshot's missing Forward never implies deletion. Deletion is only
  an explicit `desired_presence=ABSENT` plus a `deletion_operation_id`.
- The Agent writes `forward_delete_tombstone` in the same bbolt transaction
  before stopping the listener/connections/sessions.
- The tombstone is GC'd only after the Controller's durable receipt/high-water
  is sufficient.
- When the Agent is offline, the UI shows `DELETE_PENDING_OFFLINE`; the
  Controller never claims the remote side has stopped.

## 5. Publication revocation

On any local evidence of lease loss, STUN TCP disconnect, observed endpoint
change, route/interface change, or resume from suspend:

1. Atomically mark the old publication `STALE`/`UNPUBLISHED`.
2. Persist a local `EndpointDeactivated` event.
3. Then attempt remap/reprobe.
4. Force-publish uses `PUBLISHED_UNVERIFIED` plus an
   `UnverifiedEndpointPublished` audit event, never a normal
   `EndpointActivated/Changed`.

## 6. Backup / restore anti-rollback

- Backup manifests carry backup/controller instance ID, schema/protocol
  version, desired/deletion/tombstone high-water, current key IDs, per-file
  hash/permissions, and Agent marker/outbox high-water.
- Restore verifies hashes, ACLs, SQLite integrity, keys, and bbolt before an
  atomic switch, then enters `RESTORE_RECONCILIATION` (Controller) or
  `RECOVERY_QUARANTINE` (Agent).
- Software-only anti-rollback limits are explicit in the threat model.

## 7. Fixture summary

`test/contracts/testdata/state-model/**` pins:

- allowed and rejected single-step transitions for all five FSMs (including
  illegal skips and backward moves);
- complete valid/invalid orthogonal snapshots (missing axis, illegal value);
- publication truth invariants;
- valid/invalid `AppliedForwardState` records.

Every fixture in this directory is additionally SHA-256 pinned in
`test/contracts/manifest.json`, so a silent byte-level edit that preserves the
validation outcome is still detected by the manifest gate.
