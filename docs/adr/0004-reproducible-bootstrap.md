# ADR-0004: Reproducible Go toolchain, CI, and evidence

- Status: accepted
- Date: 2026-08-09
- Owners: gxbrave

## Decision

The module path is `github.com/gxbrave/AntiNAT-Agent`. The repository declares
`go 1.26.0` with `toolchain go1.26.6`, the fixed patch version used by the
release lane after the P19 vulnerability gate identified reachable standard
library fixes in Go 1.26.5. CI pins action references by commit SHA,
uses read-only permissions, fixed job timeouts, artifact retention, and separate
`pr-fast`, `pr-integration`, and `windows-pr` lanes.

Agent builds are validated by the repository CI with unit tests, race tests,
vet, and Linux amd64 plus Windows amd64 cross-build checks. Controller-backed
release evidence is maintained in the integrated Controller repository.

## Rationale

A clean bootstrap must be reproducible without a dependency graph or network
service. Exact toolchain/action pins and machine-readable evidence keep later
release claims tied to the artifact actually tested.

## Consequences

Go module changes require an explicit reviewed update to this ADR and CI image.
Fork pull requests never receive secrets or privileged execution. A missing
artifact digest or unpinned action blocks integration rather than being waived.
