# Release trust root

`release-ed25519.pub` is the pinned public verification key for the example
release channel (`trust_root=release-key-2026`). The corresponding private key
is never stored in this repository. Production release automation supplies the
private key out of band and publishes `manifest.json` plus its detached
`manifest.sig` before uploading artifacts.

The installer uses this root and the fixed `release-key-2026` identifier in
production. Test harnesses may replace both values only while
`ANTINAT_TEST_MODE=1`; production callers cannot select a verification key or
identifier through the environment. It never uses a checksum downloaded from
the same untrusted URL as a trust anchor.
