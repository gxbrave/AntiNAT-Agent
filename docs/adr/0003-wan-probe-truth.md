# ADR-0003: Provider-hidden WAN probe and publication truth

- Status: accepted
- Date: 2026-08-09
- Owners: gxbrave

## Decision

WAN verification is a two-stage arm/armed operation. The Controller sends the
Agent the operation identity, provider identity/key, exact endpoint, source
policy, and TTL, but not the provider challenge. The provider creates a random
signed challenge only after the Agent has durably acknowledged `probe_armed`.

The Agent accepts only the authenticated provider frame on the exact ingress
path, returns an authenticated same-path ACK, and sends a signed ingress receipt
through the control channel. The Controller joins the provider result and the
Agent receipt for the same operation before publishing `OPEN_FROM_VANTAGE`.

## Rationale

This prevents a pre-shared challenge from becoming a scan oracle and separates
control-channel receipt from proof that the published path received traffic.

## Consequences

A plain TCP connect, bare accept, UDP send, local control ACK, or provider
response without the matching Agent receipt is not a successful probe. Probe
operations require bounded TTL, rate, concurrency, and replay state. A local
Controller vantage is not independent unless explicitly registered and
verified.
