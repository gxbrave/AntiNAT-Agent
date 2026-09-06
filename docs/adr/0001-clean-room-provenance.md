# ADR-0001: Clean-room provenance and GPL-3.0 licensing

- Status: accepted
- Date: 2026-08-09
- Owners: gxbrave

## Decision

AntiNAT is an independent GPL-3.0 implementation. The original product
requirements name Natter as a conceptual networking reference only. The
repository may use public protocol specifications and independently written
tests, but it does not include, copy, translate, adapt, or otherwise derive
implementation code from Natter's source.

## Rationale

The product is distributed under GPL-3.0. Keeping the reference at the level
of principles and protocol behavior keeps the implementation auditable from
first principles and avoids presenting another project's source as part of
AntiNAT.

## Consequences

Every future contributor must retain source attribution in design notes without
importing third-party implementation. A provenance review is required when a
new dependency or copied fixture is proposed. The root `LICENSE` is GPL-3.0
and the README states the clean-room boundary.
