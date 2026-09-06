# ADR-0002: Evidence-backed v1 scope and capability statuses

- Status: accepted
- Date: 2026-08-09
- Owners: gxbrave

## Decision

v1.0-beta is limited to IPv4 Forward ingress/targets, an IPv4/IPv6-capable
control plane, and evidence-backed capability reporting. Direct, manual,
explicit-gateway, and STUN strategies are separate layers. A local bind,
public-IP lookup, or STUN mapping creates at most a `PUBLIC_CANDIDATE`.

Only an authenticated independent WAN probe matching the activation, endpoint,
TTL, challenge, and same-path receipt may produce `OPEN_FROM_VANTAGE` and a
verified publication. Missing real infrastructure is a limitation, not a
successful result.

## Rationale

NAT mappings do not prove inbound reachability. The previous product intent was
broader than what a single local observation can establish. Separating facts
prevents stale or unverified endpoints from being presented as usable.

## Consequences

The support matrix must use `ga`, `beta`, `experimental`, `build-only`, or
`unsupported`. Unsupported features are not silently exposed. IPv6 data-plane,
Controller relay, arbitrary NAT guarantees, macOS, and Windows containers are
out of scope for this release.
