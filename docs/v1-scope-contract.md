# AntiNAT v1.0-beta scope contract

Status: frozen by P01 bootstrap
Date: 2026-08-09
Repository owner: gxbrave

This document is the product-boundary contract for the v1.0-beta workstream.
It is intentionally about externally observable scope and claims; P04 owns the
wire, state, API, and installer contract documents.

## Architecture boundary

AntiNAT has two fault domains:

- Controller: management UI/API, desired state, authentication, health,
  authenticated Agent control channel, and bounded WAN-probe coordination.
- Agent: durable local state, socket ownership, mapping/traversal attempts,
  endpoint publication, and forwarding to the configured target.

The Controller MUST NOT carry user business payloads. A future relay is a
separate product role and is not a v1 capability.

## Connectivity and publication truth

A local bind is not a public endpoint. A mapping response is not proof of
reachability. The following facts remain separate:

- `PUBLIC_CANDIDATE`: a candidate endpoint exists from direct, manual, mapping,
  or STUN evidence;
- `OPEN_FROM_VANTAGE`: a named independent probe vantage completed the
  authenticated provider-hidden challenge and same-path ACK;
- `PUBLISHED_VERIFIED`: listener readiness, unexpired candidate, and the
  independent authenticated probe all match the same activation;
- `target_health=PASS`: the Agent can reach its local target;
- `application_e2e=PASS`: an independent client received and validated a real
  application response through the Agent.

`controller-local` is not an independent vantage by default. If the required
remote resource is absent, the result is `NO_INDEPENDENT_VANTAGE`,
`PROBE_INFRA_UNAVAILABLE`, or another explicit limitation. It must not be
promoted to verified by guessing a public IP.

## Data-plane and update semantics

- v1 Forward ingress and targets are IPv4-only. The control plane may accept
  IPv4 and IPv6 connections.
- Each Forward has a stable ID and each activation has its own generation.
- Normal target/spec updates do not tear down unrelated Forwards. Existing
  sessions retain their original target path; new sessions use the new target.
- A Forward delete is an immediate-stop operation: listener, active TCP, and
  UDP sessions stop, mapping cleanup is attempted, and the deletion fact is
  durable before acknowledgement.
- Rate/statistics changes use `NEW_SESSIONS_ONLY`. Any forced disconnect must be
  explicit and must report the compatibility consequence.
- On restart, recovered listeners are `UNVERIFIED_AFTER_RESTART` until a new
  independent probe. Old verified state is never restored as fact.

## Scope status vocabulary

Release documentation uses exactly these statuses:

- `ga`: release-quality evidence on the named platform and version;
- `beta`: usable for the declared beta scope with known limitations;
- `experimental`: available for investigation, not a general support claim;
- `build-only`: compilation or packaging is tested, runtime support is not;
- `unsupported`: excluded from this release.

A status is not evidence by itself. The support matrix records the gate and
whether P01 has any current implementation evidence.

## Security and provenance boundary

The repository is Apache-2.0. Natter is a principles-only reference from the
original product note; its GPL-3.0 source and derived implementation are not
copied. Enrollment tokens are secrets and must not be embedded in shell history,
argv, environment, service definitions, or ordinary logs. Probe challenges are
provider-hidden until the Agent receives the authenticated ingress frame.

## Change control

P01 freezes this boundary on 2026-08-09 for the Agent module
`github.com/gxbrave/AntiNAT-Agent`, owned by `gxbrave`. Scope changes require a
reviewed ADR, updated traceability/support documents, affected contract hashes,
and explicit approval before implementation. P04 owns later machine-readable
protocol/state/API revisions; P01 must not silently edit them.

## Explicit non-goals

v1 does not promise arbitrary-NAT reachability, Controller relay, IPv6 Forward
data plane, macOS, Windows containers, RBAC/HA, unattended upgrades, arbitrary
local shell execution, built-in DDNS providers, kernel fast paths, or formal
2 Gbps / `<1 ms` GA SLOs.
