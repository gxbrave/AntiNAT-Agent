# AntiNAT v1 requirements traceability

Status date: 2026-08-09
Owner: gxbrave
Source of product intent: the original AntiNAT product requirements
The Agent implementation follows the shared protocol, state, and support
contracts published in this repository.

This document records the clean-room translation from the original intent to
the v1.0-beta boundary. `frozen` means the requirement has a written v1
interpretation; it does not mean the implementation or release evidence exists.
A later plan may implement a row only after its dependency contracts and gates
are complete.

## Traceability matrix

| Source intent | v1 interpretation | Status | Owning plan / evidence gate |
|---|---|---|---|
| Controller + Agent split; Controller manages, Agent forwards | Controller carries management/control data only. Agent owns local sockets and user payloads. | frozen | P04/P05 contracts; P10 walking-skeleton E2E |
| NAT hole punching and forwarding | Direct/manual/explicit-gateway/STUN are separate capability paths. Failure is a truthful capability result. | frozen | P02/P11/P12 real-network evidence |
| Controller must not proxy customer traffic | No user-payload relay, buffering, or fallback in Controller. | frozen | P05/P10 security review |
| Keep existing forwards alive during edits | Stable `forward_id`; target edits affect new sessions only; deletion is the explicit immediate-stop exception. | frozen | P04 state contract; P14 lifecycle tests |
| Rate limiting and detailed statistics | v1 semantics are `NEW_SESSIONS_ONLY`; optional `disconnect_existing` is explicit and visible. | frozen | P15 API/state tests |
| IPv4 and IPv6 support | Control plane may be dual-stack. v1 Forward ingress and target are IPv4-only; IPv6 data plane is v2. | frozen | P04 protocol contract; P10/P19 evidence |
| Low overhead / zero-copy preference | Linux TCP is only `splice-eligible` when the declared conditions hold. No runtime zero-copy claim without lab evidence. | frozen | P03 data-path spike; P19 release evidence |
| Custom destination IP or hostname | Targets are validated and resolved according to the later protocol/state contract; Controller stores desired state, Agent connects locally. | frozen | P04/P07/P09 tests |
| DDNS/custom scripts | v1 webhook plus sandboxed JS only if the platform isolation gate passes. Arbitrary local shell is excluded. | frozen | P03/P16 sandbox evidence |
| Install Controller, Agent, or both | Linux systemd is the primary beta path. Other platforms require their own install, upgrade, rollback, and purge evidence. | frozen | P18 installer evidence |
| Display public IP from a public service | A service response is only an unverified diagnostic candidate. It never proves reachability or chooses a Controller endpoint automatically. | frozen | P01 ADR-0002; P10 probe tests |
| One-click deployment command with token | Installation command and enrollment secret are separate. TTY input is hidden; non-interactive input requires a protected file descriptor or 0600 file. | frozen | P04 installer contract; P18 security evidence |
| Natter as reference | Principles may inform design; Natter source or copied implementation may not enter this GPL-3.0 repository. | frozen | P01 ADR-0001; license review |
| High concurrency and lightweight operation | A performance claim is release evidence, not a design assertion. No 2 Gbps, `<1 ms`, or zero-copy SLO is advertised in v1.0-beta. | frozen | P03 spike; P19 exact-artifact benchmark |
| x64 and arm support | Linux amd64 is the primary target. Linux arm64 is evidence-gated; Windows amd64 and Docker have separate status gates. | frozen | `docs/support-matrix.md`; P18/P19 |

## Explicit v1 non-goals

The following are deliberately outside this release boundary: arbitrary-NAT
reachability guarantees, Controller relay, IPv6 Forward data plane, macOS,
Windows containers, RBAC/HA, unattended upgrades, arbitrary shell execution,
built-in DDNS providers, kernel nft fast paths, and formal GA performance SLOs.

## Evidence and change control

A passing build, cross-build, fake server, local socket bind, STUN mapping, or
public-IP lookup is not evidence for a broader capability. Each later plan must
record the exact command, a positive integer `timeout` in seconds, non-empty
`os`, artifact digest, result, and retained logs/state/pcap where applicable
using `test/evidence/schema.json`.

Evidence `timeout` is a positive JSON number whose mathematical value is an
integer; integral spellings such as `600`, `600.0`, and `6e2` are equivalent
and valid, while fractional values are invalid. `plan` is exactly three
characters (`PNN`), `commit_sha` is exactly 40 lowercase hexadecimal
characters, and `artifact_digest` is exactly `sha256:` plus 64 lowercase
hexadecimal characters; trailing line terminators are invalid. RFC3339
timestamps must be calendar-valid with a non-zero four-digit year and accept
the standards-permitted lowercase `t`/`z` markers, but their numeric offset
must have an hour from `00` through `23` and a minute from `00` through `59`.
Required `command` and `os` values, and every `evidence_paths` entry, must
contain at least one non-whitespace character; the C0 separators U+001C
through U+001F are treated as whitespace. The canonical Go validator and the
schema parity harness enforce these same rules.

To change a frozen row, propose a new ADR or a reviewed contract revision with:

1. the affected source-intent row and current behavior;
2. security, compatibility, and migration impact;
3. tests and real infrastructure required to prove the change;
4. an explicit approver and date;
5. updates to this matrix and the support matrix in the same change.

No child plan may silently broaden a frozen requirement.
