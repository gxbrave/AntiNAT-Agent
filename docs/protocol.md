# AntiNAT Protocol Contract (FROZEN)

> Status: **FROZEN at P04**. This document is a normative contract consumed by
> later Coding AIs without reinterpretation. Any change requires a versioned
> contract revision and orchestrator approval.
>
> Contract schema versions in this document:
> - Control envelope: `antinat.contracts/control-envelope/v1`
> - Enrollment transcript: `antinat.contracts/enrollment/v1`
> - Probe frame: `antinat.contracts/probe-frame/v1` (Story 2)
>
> Golden byte vectors live under `internal/protocol/testdata/**` and are
> validated by `go test ./test/contracts/... -count=1 -v`.

## 1. Scope

This contract freezes the machine-readable wire format for:

1. The normative control envelope (Controller ↔ Agent signed control frames).
2. The enrollment transcript (EnrollChallenge / EnrollRequest / EnrollResult).
3. The probe wire frames (Story 2): `ARM1` arm, `RDY1` armed, `WAN1` provider
   challenge frame, `ACK1` same-path acknowledgement, `RCT1` control receipt.
4. The strict JSON payload rules shared by all JSON payloads.

It does **not** specify a production parser implementation, server, store, or
UI. Later plans implement parsers that must accept exactly the valid golden
vectors and reject exactly the invalid vectors at the frozen rejection stage.

## 2. Conventions

- All integers are unsigned big-endian.
- All length prefixes are uint32 big-endian, in bytes.
- `||` denotes byte concatenation.
- Ed25519 signatures are 64 bytes.
- `sha256(x)` is the 32-byte SHA-256 digest.
- All lengths and caps below are normative and non-negotiable.

## 3. Normative control envelope

### 3.1 Frame layout

Every control frame is exactly:

```text
[0:4]    magic              ASCII "ANAT"
[4:5]    wire_version       uint8 = 1
[5:9]    header_len         uint32 BE
[9:13]   payload_len        uint32 BE
[13:13+h] protected_header_bytes
[13+h:13+h+p] raw_payload_bytes
[13+h+p:13+h+p+64] signature (Ed25519)
```

Normative caps:

| Constant | Value |
|---|---|
| `maxHeaderBytes` | 4096 |
| `maxPayloadBytes` | 65536 |
| `maxJSONDepth` | 16 |
| `wireVersion` | 1 |

Framing validation order (all must hold before any payload decode):

1. `len(frame) >= 13 + 64`.
2. `frame[0:4] == "ANAT"`.
3. `frame[4] == 1`.
4. `0 < header_len <= maxHeaderBytes`.
5. `payload_len <= maxPayloadBytes`.
6. `len(frame) == 13 + header_len + payload_len + 64`.

### 3.2 Protected header

The protected header is a fixed ordered list of **exactly 14** length-prefixed
fields (uint32 BE length + raw bytes). No JSON map serialization is permitted.

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `protocol_domain` | utf8 `"AntiNAT-Control-v1"` | 1..255 |
| 2 | `controller_instance_id` | raw | 16 |
| 3 | `node_id` | raw | 16 |
| 4 | `controller_key_id` | utf8 | 1..255 |
| 5 | `agent_credential_version` | uint32 BE | 4 |
| 6 | `connection_epoch` | uint64 BE | 8 |
| 7 | `session_id` | utf8 | 1..255 |
| 8 | `direction` | 1 byte: `0x01` C2A, `0x02` A2C | 1 |
| 9 | `sequence` | uint64 BE | 8 |
| 10 | `message_id` | raw | 16 |
| 11 | `message_type` | utf8 | 1..255 |
| 12 | `schema_version` | uint32 BE | 4 |
| 13 | `payload_length` | uint64 BE | 8 |
| 14 | `payload_sha256` | raw | 32 |

Header validation order:

1. All 14 fields must be present; the header must contain no trailing bytes.
2. Fixed-size fields must have their exact sizes.
3. `protocol_domain == "AntiNAT-Control-v1"`.
4. `payload_length == payload_len` (frame field).
5. `sha256(payload) == payload_sha256`.
6. `direction` is `0x01` or `0x02`.
7. `agent_credential_version != 0`.

### 3.3 Signature

```text
signature_input = protocol_domain_bytes || protected_header_bytes || payload_sha256_bytes
signature       = Ed25519.Sign(peer_private_key, signature_input)
```

Verification uses the pinned peer public key (Controller verifies with the
Agent's key, Agent verifies with the Controller's key). A wrong key, a stale
epoch/session, a tampered header, or a tampered payload hash all fail closed
before any payload decode.

### 3.4 Strict JSON payload rules

JSON payloads (when present) are validated with a strict decoder before any
semantic use:

1. The payload must be a single JSON object (no arrays at top level, no
   trailing garbage).
2. Duplicate keys are rejected.
3. Unknown fields are rejected against the per-message schema.
4. Nesting depth is bounded at 16.
5. All numbers must be finite integers within the int64 range, excluding
   int64 min (`-9223372036854775808`); fractional and exponential forms are
   rejected.
6. Payload size is bounded by `maxPayloadBytes`.

### 3.5 Message dedup semantics

- Same `message_id` + same `message_type` + same payload hash: cached result
  returned.
- Same `message_id` + different type or hash: fail-closed session conflict,
  audited, connection treated as compromised/stale.

### 3.6 Normative message types

| `message_type` | Direction | Purpose |
|---|---|---|
| `desired` | C2A | Desired Forward/node state (JSON payload) |
| `desired_result` | A2C | Result of applying desired state |
| `forward_delete` | C2A | Explicit deletion command (carries `deletion_operation_id`) |
| `forward_delete_ack` | A2C | Acknowledgment of deletion |
| `node_decommission` | C2A | Node decommission command |
| `node_decommission_ack` | A2C | Decommission acknowledgment |
| `message_receipt` | A2C | Durable receipt for an outbox message |
| `operation_complete` | A2C | Operation completion result |
| `probe_arm` | C2A | Probe arming (never carries the challenge) |
| `probe_armed` | A2C | Durable probe armed response |
| `probe_ingress_receipt` | A2C | Signed control receipt for a provider frame |
| `probe_result` | A2C | Probe outcome result |
| `key_rotation_prepare` / `key_rotation_ack` / `key_rotation_commit` | both | Key rotation FSM |
| `restore_reconcile` / `restore_result` | both | Restore reconciliation |
| `heartbeat` | A2C | Heartbeat/status/traffic |
| `status` | A2C | Status snapshot |

## 4. Enrollment transcript

The enrollment transcript is three signed messages. All use the domain
`"AntiNAT-Enroll-v1"` and canonical length-prefixed field encoding (uint32 BE
length + raw bytes), never JSON maps.

### 4.1 EnrollChallenge (Controller → Agent, signed by pinned Controller key)

Fields (in order):

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `controller_instance_id` | raw | 16 |
| 2 | `controller_key_id` | utf8 | 1..255 |
| 3 | `node_id` | raw | 16 |
| 4 | `server_nonce` | raw | 32 |
| 5 | `protocol_versions` | utf8, `"1"` | 1..255 |
| 6 | `expiry_unix` | uint64 BE | 8 |

Signature input: `"AntiNAT-Enroll-v1" || canonical_fields`.

### 4.2 EnrollRequest (Agent → Controller, signed by the new Agent key)

The signature is the possession proof. Fields (in order):

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `challenge_hash` | sha256 of the canonical EnrollChallenge | 32 |
| 2 | `agent_nonce` | raw | 32 |
| 3 | `agent_public_key` | Ed25519 public key | 32 |
| 4 | `agent_credential_version` | uint32 BE, non-zero | 4 |
| 5 | `token` | utf8, 1..256 bytes | 1..256 |
| 6 | `capability_hash` | sha256 | 32 |

Signature input: `"AntiNAT-Enroll-v1" || canonical_fields`, verified against
`agent_public_key` (self-possessed key).

Validation:

1. The `challenge_hash` must equal the server-issued challenge hash.
2. Token length must be within 1..256.
3. `agent_credential_version` must be non-zero.
4. Signature must verify against the presented `agent_public_key`.

### 4.3 EnrollResult (Controller → Agent, signed by Controller signing key)

Fields (in order):

| # | Field | Encoding | Size |
|---|---|---|---|
| 1 | `controller_instance_id` | raw | 16 |
| 2 | `controller_key_id` | utf8 | 1..255 |
| 3 | `node_id` | raw | 16 |
| 4 | `agent_public_key_hash` | sha256 of agent public key | 32 |
| 5 | `agent_credential_version` | uint32 BE, non-zero | 4 |
| 6 | `enrollment_result_id` | raw | 16 |
| 7 | `expiry_unix` | uint64 BE | 8 |

Signature input: `"AntiNAT-Enroll-v1" || canonical_fields`.

### 4.4 Enrollment rules

1. Token consumption, credential binding, and enrollment result ID are
   committed in a single SQLite transaction.
2. If the EnrollResult response is lost, the same node + same key + valid
   possession proof returns the original binding result (idempotent).
3. A different key on a registered node fails uniformly and is audited;
   ordinary enrollment tokens cannot rebind a registered node's key.
4. Tokens never appear in generated commands, shell history, argv, env,
   service units, config, or logs. Interactive installs read tokens from a
   hidden TTY prompt; non-interactive installs accept only `--token-fd` or a
   strict-ACL `--token-file`, deleted after consumption.

## 5. Fixture schema summary

All fixture files are JSON and carry a `schema` field:

- Control envelope: `antinat.contracts/control-envelope/v1` with `frame_hex`,
  `verifier` (`agent`|`controller`), `public_key_hex`, `expect`
  (`valid`|`invalid`), `reject_stage`
  (`framing`|`header`|`consistency`|`signature`|`payload_json`), and header
  expectations.
- Enrollment: `antinat.contracts/enrollment/v1` with `kind`
  (`challenge`|`request`|`result`), `message_hex`, `expect`, `reject_reason`
  (`malformed`|`domain`|`challenge`|`signature`), plus semantic expectations.

Test keys are deterministic, published TEST-ONLY fixture keys (seeds `0x11`,
`0x22`, `0x33`); they are never real credentials.

## 6. Versioning and change control

- Frozen at P04 commit. The SHA-256 of this file and every fixture is recorded
  in `test/contracts/manifest.json`.
- A contract revision requires a proposal, orchestrator approval, and a new
  schema version (`/v2`); old vectors remain valid for their schema version.

## 7. Probe wire and operation contract

Two-phase arm + provider-hidden challenge, same-path Agent signature, and
signed control receipt. The arm never contains the provider challenge; the
provider introduces the challenge only at WAN ingress. All frames are fixed
binary (never JSON) with the magics below.

| Magic | Frame | Signed by | Direction |
|---|---|---|---|
| `ARM1` | probe arm | Controller | control channel → Agent |
| `RDY1` | probe armed | Agent (node key) | control channel → Controller |
| `WAN1` | provider frame | Provider | WAN ingress → Agent |
| `ACK1` | same-path ACK | Agent (node key) | WAN ingress → Provider |
| `RCT1` | control receipt | Agent (node key) | control channel → Controller |

Length-prefixed fields use a 1-byte length prefix (fields are <= 255 bytes).
All multi-byte integers are big-endian.

### 7.1 ProbeArm (`ARM1`, Controller → Agent)

| Field | Encoding | Size |
|---|---|---|
| magic | `"ARM1"` | 4 |
| `probe_id` | raw | 16 |
| `provider_id` | raw | 16 |
| `provider_public_key` | Ed25519 | 32 |
| `expected_source_ip` | IPv4 | 4 |
| `activation` | raw | 16 |
| `endpoint` | 1-byte length + utf8 IPv4:port | 1..256 |
| `ttl_ms` | uint64 BE, 0 < ttl <= 24h | 8 |
| `expiry_opaque` | raw (opaque) | 16 |

The arm is delivered inside a signed control envelope (Section 3), so the
Controller signature lives at the envelope layer. The arm payload itself must
**never** contain the challenge or any per-probe secret material (anti-oracle).
`endpoint` must be a concrete global IPv4 literal and port; hostnames, IPv6,
private (RFC 1918), loopback, link-local (unicast and multicast), multicast,
and unspecified addresses are rejected. IANA documentation ranges (TEST-NET,
e.g. `198.51.100.7`) are global unicast and are the addresses used by the
golden vectors.

### 7.2 ProbeArmed (`RDY1`, Agent → Controller)

| Field | Encoding | Size |
|---|---|---|
| magic | `"RDY1"` | 4 |
| `arm_digest` | sha256 of the canonical ARM1 | 32 |
| signature | Ed25519 over `RDY1 || arm_digest` | 64 |

The Agent persists the outstanding operation with a monotonic deadline derived
from `ttl_ms` and returns `probe_armed` only after durable persistence. The
Controller requests the provider only after it persists `probe_armed`.

### 7.3 ProviderFrame (`WAN1`, Provider → Agent)

| Field | Encoding | Size |
|---|---|---|
| magic | `"WAN1"` | 4 |
| `arm_digest` | sha256 of the canonical ARM1 | 32 |
| `probe_id` | raw | 16 |
| `provider_id` | raw | 16 |
| `activation` | raw | 16 |
| `endpoint` | 1-byte length + utf8 IPv4:port | 1..256 |
| `expiry_opaque` | raw | 16 |
| `challenge` | raw | 32 |
| signature | Ed25519 over the above fields | 64 |

The provider signs the full WAN frame and introduces the challenge only at
ingress. The Agent accepts the frame only when every field matches the armed
operation and the signature verifies against the arm's `provider_public_key`.

### 7.4 ProbeACK (`ACK1`, Agent → Provider, same path)

| Field | Encoding | Size |
|---|---|---|
| magic | `"ACK1"` | 4 |
| `arm_digest` | sha256 of the canonical ARM1 | 32 |
| `challenge_hash` | sha256 of the challenge | 32 |
| signature | Ed25519 over `ACK1 || arm_digest || challenge_hash` | 64 |

TCP: returned on the accepted ingress connection. UDP: returned through the
original ingress socket from the exact published IPv4:port, no larger than the
request. The ACK proves the WAN ingress/return path.

### 7.5 ProbeReceipt (`RCT1`, Agent → Controller)

| Field | Encoding | Size |
|---|---|---|
| magic | `"RCT1"` | 4 |
| `arm_digest` | sha256 of the canonical ARM1 | 32 |
| `challenge_hash` | sha256 of the challenge | 32 |
| `provider_id` | raw | 16 |
| signature | Ed25519 over `RCT1 || arm_digest || challenge_hash || provider_id` | 64 |

The control receipt is `Sign(node_key, RCT1 || arm_digest || challenge_hash ||
provider_id)`, matching the RCT1 layout above. It is sent over the signed
control channel.

### 7.6 Outcome and anti-oracle rules

- The Controller records `OPEN_FROM_VANTAGE` + `RETURN_PATH_VERIFIED` only
  after joining the provider result, the same-path ACK, and the Agent control
  receipt for the same probe ID, activation, endpoint, challenge hash, opaque
  expiry, and TTL window.
- A control-only malicious Agent that guesses a challenge cannot satisfy the
  join.
- Every failed ingress (wrong source, wrong activation, wrong provider, wrong
  endpoint, wrong opaque expiry, bad signature, expired TTL, replay) returns
  the same generic `REJECTED`/`DROPPED` outcome with zero authenticated
  material. No timing/detail leakage distinguishes victim behavior.
- A probe ID is consumed exactly once. Consumed IDs enter a bounded replay
  cache (TTL window) keyed by digest: re-arm of the same ID with the same
  material is a replay rejection; different material is an ID conflict.
- TTL semantics: the Agent uses a monotonic deadline from `ttl_ms`; the
  provider and Controller use their own trusted clocks to verify the absolute
  opaque expiry. The Controller aggregates bilateral results only within the
  operation deadline.
- Probe state, replay state, and attempt budgets are bounded and expirable.

### 7.7 TCP and UDP golden vectors

`internal/protocol/testdata/probe-frame/**` pins:

- ARM1/RDY1/WAN1/ACK1/RCT1 valid golden frames (TCP and UDP transports share
  the same canonical bytes; the transport differs only in how the stream is
  framed: TCP uses a bounded stream reader with a deadline, UDP uses the
  single-socket demux).
- Invalid structural vectors (bad magic, truncated, zero/over-cap TTL,
  hostname endpoint, wrong key, wrong digest).
- Full operation transcripts that run the frozen probe state machine:
  ingress-ok (accepted once, replayed rejected, ACK+receipt join), wrong
  source/activation/provider, expired TTL, and replay/conflict.

## 8. Outcome registry

The probe operation outcome registry is the frozen enum of possible probe
results. The Controller persists exactly one of these per probe operation:

| Outcome | Meaning |
|---|---|
| `ARMED` | Agent durably armed the operation (persisted `probe_armed`) |
| `ACCEPTED` | Agent accepted the provider frame at ingress and returned ACK |
| `REJECTED` | Ingress was rejected for any reason (generic, no detail leak) |
| `DROPPED` | Ingress was dropped without a response (malformed/overflow) |
| `OPEN_FROM_VANTAGE` | Controller joined provider result + ACK + receipt |
| `TIMEOUT` | No valid ingress before the operation deadline |
| `NO_INDEPENDENT_VANTAGE` | No independent vantage is configured for this node |
| `PROBE_INFRA_UNAVAILABLE` | Probe infrastructure unavailable |
| `UNKNOWN` | No terminal outcome recorded |

`OPEN_FROM_VANTAGE` is the only outcome that may drive a verified publication.
