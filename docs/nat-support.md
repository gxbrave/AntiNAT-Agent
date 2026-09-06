# NAT and Connectivity Support

AntiNAT publishes an endpoint only after the listener, activation generation,
unexpired candidate, and authenticated independent probe agree. A local bind,
STUN mapping, gateway lease, or hairpin result is not proof of public
reachability.

## Strategy status

| Strategy or layer | Beta status | Evidence boundary |
|---|---|---|
| Direct IPv4 TCP/UDP | `beta` on Linux amd64 when the independent probe gate passes | Local walking-skeleton evidence is not public-WAN evidence |
| Manual static endpoint | `beta` with explicit operator endpoint and independent probe | It does not infer reachability from a configured address |
| STUN-only | `experimental` | Candidate mapping is `PUBLIC_CANDIDATE` until a matching probe |
| PCP / NAT-PMP / UPnP | `experimental` | Adapter and daemon evidence is retained per layer; CPE coverage is not universal |
| IPv6 Forward data plane | `unsupported` | Outside the v1 contract |
| Controller payload relay | `unsupported` | The Controller never carries user business payload |

## NAT classifications

The product does not guess a NAT type from a timeout. `OPEN_FROM_VANTAGE`,
`REJECTED`, `TIMEOUT`, `NO_INDEPENDENT_VANTAGE`,
`PROBE_INFRA_UNAVAILABLE`, and `UNKNOWN` remain distinct outcomes. A timeout
can be a diagnostic observation but cannot be relabeled as filtering proof.

The following environments remain explicitly limited until their named gates
run on real hosts:

- Linux arm64: build-only evidence from the P18 subset; no runtime promotion.
- Windows amd64: cross-build and parser evidence; no native service or data
  path promotion.
- OpenRC: generated service and isolated installer tests; no native host
  lifecycle promotion.
- Docker: local amd64 image/static checks; no registry digest, SBOM/signature,
  or production host-network promotion.
- Public WAN and real CPE: no independent vantage or router inventory is
  provisioned in the current project inputs.

The UI and release documents must use the same status vocabulary as
`docs/v1-scope-contract.md`: `ga`, `beta`, `experimental`, `build-only`, and
`unsupported`.
