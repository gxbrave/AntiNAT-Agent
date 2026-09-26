# Changelog

## v1.0.0-beta.3

- Published signed Linux amd64 and Windows amd64 Agent artifacts with the
  manifest, installer scripts, and pinned release trust root.
- Hardened bootstrap cleanup and forwarding runtime state reporting.
- Kept public-WAN, native Windows, arm64, OpenRC, and long-running soak claims
  outside the verified scope.

## Unreleased beta candidate

- Published the standalone Agent source and build pipeline extracted from the
  integrated AntiNAT beta candidate.
- Included durable local state, signed enrollment/control sessions, forwarding,
  traversal strategies, Linux service files, and a non-root container image.

The source is not a `v1.0.0-beta.1` binary release. It remains
`SUPPORTED_WITH_LIMITS` until the required external network, platform, signing,
and soak evidence is supplied and independently approved.
