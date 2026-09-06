# AntiNAT Error Code Contract (FROZEN)

> Status: **FROZEN at P04**. Schema version: `antinat.contracts/error-codes/v1`.
> Every API error response carries `code`, `message`, and `request_id`; the
> `code` must be one of the codes below. HTTP status is fixed per code.

## 1. Conventions

- Error body: `{"code": string, "message": string, "request_id": string,
  "details": object?}`.
- Status codes `428 Precondition Required`, `412 Precondition Failed`, and
  `409 Conflict` have the exact semantics in this registry.
- Never expose stack traces, SQL, internal paths, or secrets in `message` or
  `details`.

## 2. Registry

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `BAD_REQUEST` | Malformed request (syntax, unknown field) |
| 400 | `VALIDATION_ERROR` | Request fails schema validation |
| 400 | `INVALID_PAGINATION` | Page/page_size/cursor out of range |
| 401 | `UNAUTHENTICATED` | No valid session |
| 403 | `FORBIDDEN` | Authenticated but not permitted |
| 404 | `NOT_FOUND` | Resource not found |
| 409 | `CONFLICT` | Port or state conflict (resource-level) |
| 409 | `IDEMPOTENCY_CONFLICT` | Idempotency-Key reused with a different request |
| 409 | `REVISION_CONFLICT` | Desired revision conflicts with current |
| 412 | `PRECONDITION_FAILED` | If-Match ETag does not match current revision |
| 413 | `PAYLOAD_TOO_LARGE` | Request body exceeds the API payload cap |
| 422 | `UNPROCESSABLE_ENTITY` | Semantically invalid but schema-valid payload |
| 428 | `PRECONDITION_REQUIRED` | If-Match ETag required but missing |
| 429 | `RATE_LIMITED` | Per-principal rate limit exceeded |
| 500 | `INTERNAL_ERROR` | Unexpected server error |
| 501 | `NOT_IMPLEMENTED` | Capability not implemented in this build |
| 503 | `UNAVAILABLE` | Service not ready (startup/reconciliation) |

## 3. Operation polling

Deletion, decommission, force-cutover, retry, and detection endpoints return
`202` with an `Operation` object:

| Field | Meaning |
|---|---|
| `operation_id` | Durable operation ID |
| `state` | Frozen lifecycle state (see docs/state-model.md §3) |
| `remote_cleanup_confirmed` | false until the remote Agent confirms |
| `detail` | Human-readable progress, never a stack trace |

Polling: `GET /api/v1/forward-deletions/{operation_id}` and
`GET /api/v1/node-deletions/{operation_id}`. A completed operation returns a
terminal state; an expired/unknown operation returns `404 NOT_FOUND`.

## 4. Idempotency

- All creates require `Idempotency-Key` (8..128 chars).
- The key binds route, principal, request hash, and the stored response/status.
- Same key + same request hash → the stored response is replayed (200/201).
- Same key + different request hash → `409 IDEMPOTENCY_CONFLICT`.
- Keys expire after a frozen TTL; expiry is an audit event.

## 5. ETag / If-Match

- Every resource mutation (PATCH/PUT/DELETE) requires `If-Match`.
- Missing header → `428 PRECONDITION_REQUIRED`.
- Mismatched ETag → `412 PRECONDITION_FAILED`.
- Port/state conflicts → `409 CONFLICT`.

## 6. Pagination

- `page` (>=1), `page_size` (1..200), optional `sort` and `filter`.
- Streams and audit use an opaque `cursor`/`next_cursor`.
- Out-of-range values → `400 INVALID_PAGINATION`.

## 7. SSE event cursor

- `GET /api/v1/events` is `text/event-stream` backed by the durable
  `admin_events` table (monotonically ordered IDs), not in-memory broadcast.
- Each event carries `id`; the client may resume with `Last-Event-ID`.
- `Cache-Control: no-cache`; reconnects resume from the cursor without gaps.

## 8. Force-publish

- `POST /api/v1/forwards/{id}/force-publish` publishes as
  `PUBLISHED_UNVERIFIED` and emits the distinct audit event
  `UnverifiedEndpointPublished`. It never emits a normal
  `EndpointActivated/Changed` and never claims `OPEN_FROM_VANTAGE`.

## 9. Coverage rule

`api/openapi.yaml` must reference only codes in this registry, and every code
in this registry must be reachable by at least one OpenAPI response. The
validator enforces this bidirectionally.
