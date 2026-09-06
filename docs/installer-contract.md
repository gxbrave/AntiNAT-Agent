# AntiNAT Installer and Compatibility Contract (FROZEN)

> Status: **FROZEN at P04**. Schema versions:
> `antinat.contracts/installer/v1`, `antinat.contracts/compat/v1`.
> Fixtures: `test/fixtures/installer-contract/**`, `test/fixtures/compat/**`,
> validated by `go test ./test/contracts/... -count=1 -v`.

## 1. Security deployment flow

1. The UI renders an install command that contains **no secret**.
2. The enrollment token is displayed separately and once.
3. The installer reads the token from a hidden TTY prompt (interactive
   default), or non-interactively only from `--token-fd <n>` or a strict-ACL
   `--token-file <path>` (mode exactly 0600).
4. The token is consumed and its file securely deleted after use.
5. Tests must prove no token literal appears in shell/PowerShell history,
   `ps`, service units, environment, config, or logs.

A convenience mode embedding the token in a one-line command is **not** part
of v1 and must never be claimed as leak-free.

## 2. Installer CLI surface

Verbs: `install`, `uninstall`, `purge`, `upgrade`.

Flags (frozen):

| Flag | Meaning |
|---|---|
| `--controller-endpoint` | Administrator-confirmed Controller endpoint |
| `--bind-interface` | Interface to bind the data plane to |
| `--install-dir` | Install directory |
| `--service-name` | Service unit name |
| `--log-level` | Log level |
| `--auto-update` | Auto-update policy |
| `--github-proxy` | GitHub proxy for artifact downloads |
| `--detection-scheduler` | Initial detection scheduler spec |
| `--platform` | `linux` \| `windows` \| `docker` |
| `--token-fd` | Non-interactive token via open file descriptor |
| `--token-file` | Non-interactive token via strict-ACL file (0600) |
| `--version` / `--help` | Metadata |

**Forbidden**: any flag or positional argument carrying a literal token
(`--token`, `--token-value`, `-t`). The token is never in argv.

Token input must be exactly one of: interactive TTY (default), `--token-fd`,
or `--token-file`. `--token-file` requires mode exactly 0600.

## 3. Frozen Linux paths and service (primary target)

| Key | Value |
|---|---|
| `install_dir` | `/opt/antinat` |
| `binary` | `/opt/antinat/bin/antinat-agent` |
| `data_dir` | `/var/lib/antinat` |
| `config` | `/etc/antinat/agent.conf` |
| `state_marker` | `/var/lib/antinat/agent.marker` |
| `log_dir` | `/var/log/antinat` |
| `service` | `antinat-agent.service` |
| `user` / `group` | `antinat` / `antinat` |

Windows and other platforms use their own documented layouts; the Linux
systemd path is the primary release gate.

## 4. Exit code registry

| Code | Meaning |
|---|---|
| 0 | SUCCESS |
| 1 | GENERIC_FAILURE |
| 2 | USAGE_ERROR |
| 3 | TOKEN_INPUT_FAILURE |
| 4 | ARTIFACT_VERIFICATION_FAILURE |
| 5 | PATH_OR_SERVICE_CONFLICT |
| 6 | ROLLBACK_PERFORMED |
| 7 | PURGE_COMPLETE |
| 8 | UPGRADE_BLOCKED_MIGRATION_FAILURE |

`ROLLBACK_PERFORMED` reports that a failed upgrade was rolled back to the
previous version; a second run must find no residue.

## 5. Artifact trust

- The release manifest is frozen with `schema_version=1` and a per-artifact
  lowercase sha256 hex map.
- A detached signature covers the manifest; the trust root is a pinned
  public key ID (out-of-band distributed), **never** a checksum from the same
  untrusted URL used to download the artifacts.
- Bootstrap downloads the pinned manifest + artifacts, verifies the signature,
  then verifies each artifact checksum before execution.
- Any verification failure exits with code 4 and leaves the system unchanged.

## 6. N/N-1 compatibility

- `current_version - previous_version` must be 0 or 1: schema/control upgrade
  must not skip an intermediate version.
- N-1 stores and control traffic must be readable by N; destructive schema
  changes are deferred one version (expand/contract).
- Upgrade freezes state modifications and command acceptance, creates a
  consistent snapshot of SQLite/bbolt/keys/config/binary, and restores the
  whole set if migration or health checks fail.
- After restore: DB integrity, admin login, Agent reconnect, and a real
  Forward smoke must pass.

## 7. Purge semantics

- Online Agent: send a signed uninstall notice and wait for a bounded receipt;
  an offline Agent must not be treated as uninstalled automatically.
- Controller purge first performs a normal decommission of the remote node;
  offline nodes require warning/export/explicit force.
- The ownership manifest has root/SYSTEM ACL + HMAC + installation ID.
- A missing/corrupt manifest deletes only compile-time allowlisted owned
  resources; deletion is handle-relative (dirfd/openat2/O_NOFOLLOW on Linux,
  open handle + reparse checks on Windows).
- Offline purge defines export/force semantics for an unusable Controller,
  corrupted DB, or lost admin credentials.
- A second run reports no residue and must never delete user reverse proxies,
  TLS, or external files.

## 8. Fixture summary

`test/fixtures/installer-contract/**` pins CLI shape (valid + forbidden token
in argv + unknown long and short flags + bare value-less `--token-fd`/
`--token-file`), token input rules (tty/fd/file, 0600 enforcement,
exactly-one rule), frozen paths, exit codes, artifact-manifest trust rules,
and purge states.

`test/fixtures/compat/**` pins N/N-1 schema-version pairs: same-version and
one-step upgrades are valid; skipped versions and regressions are rejected.
