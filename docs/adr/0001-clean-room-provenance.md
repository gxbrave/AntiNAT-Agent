# ADR-0001: Clean-room provenance and Apache-2.0 licensing

- Status: accepted
- Date: 2026-08-09
- Owners: gxbrave

## Decision

AntiNAT is an independent Apache-2.0 implementation. `antinat.txt` names Natter
as a conceptual networking reference only. The repository may use public
protocol specifications and independently written tests, but it must not copy,
translate, adapt, or otherwise derive implementation code from Natter's
GPL-3.0 source.

## Rationale

The product is intended for Apache-2.0 distribution. Keeping the reference at
the level of principles and protocol behavior preserves license compatibility
and makes the implementation auditable from first principles.

## Consequences

Every future contributor must retain source attribution in design notes without
importing third-party implementation. A provenance review is required when a
new dependency or copied fixture is proposed. The root `LICENSE` is Apache
License 2.0 and the README states the clean-room boundary.
