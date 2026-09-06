# AntiNAT Beta Release Policy

This policy governs the `v1.0.0-beta.N` release channel. A release is an
immutable set of bytes, not a source tag followed by a later rebuild.

## Build identity

The release runner requires a clean Linux amd64 checkout and records the full
Git commit, tree, Go toolchain, version, and UTC build time. It builds the
candidate set exactly once with `-trimpath` and `-buildvcs=false`. The manifest
contains a lowercase SHA-256 for every shipped file except the manifest and
its detached signature. `checksums.txt` binds the same set independently.

After the build, tests may inspect the candidate but must not replace or
rebuild any file under `release/`. The evidence record stores the SHA-256 of
the exact manifest, and every gate repeats that digest.

## Trust and signing

The production trust root is `release-key-2026`, pinned in
`deploy/trust/release-ed25519.pub`. The private Ed25519 key is supplied only
to a protected release environment. It must never be committed, placed in an
artifact, passed in argv, or written to ordinary logs.

An unsigned bundle is a useful local candidate and is reported as
`SUPPORTED_WITH_LIMITS`; it is never promotion evidence. A non-production
trust root is accepted only with an explicit test-mode verifier invocation.

## Promotion

Promotion requires all required gates to be `PASS`, a verified detached
signature, and an approval recorded by the protected `antinat-release`
environment. The promotion job downloads the candidate bundle and signs the
already-built manifest. It does not rebuild binaries or images. The workflow
creates the immutable version tag and GitHub release only after the
promotion-grade verifier succeeds.

Missing WAN vantage, native platform, registry, SBOM tooling, vulnerability
scanner, or soak infrastructure lowers the candidate status and stays in the
known-limit list. Loopback, fake-server, netns, cross-build, and local image
evidence cannot promote a runtime capability.

## Release contents

The release directory may contain Linux amd64 and Windows amd64 binaries,
the supported arm64 build-only subset, `manifest.json`, `manifest.sig`,
`checksums.txt`, `sbom.cdx.json`, and `source.json`. Installers consume the
manifest and verify its signature and artifact digests before copying a file.
OCI images require a registry manifest digest plus SBOM and signature evidence;
a local image ID is not sufficient.
