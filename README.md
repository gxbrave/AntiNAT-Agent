# AntiNAT Agent

AntiNAT Agent is the standalone data-plane client for the AntiNAT Controller.
It owns local sockets, NAT traversal attempts, forwarding, durable local
state, enrollment, and the signed Controller control session. The Controller
repository is `github.com/gxbrave/AntiNAT-Agent`.

## Build and test

The module path is `github.com/gxbrave/AntiNAT-Agent` and the validated Go
toolchain is Go 1.26.6.

```bash
GOWORK=off make check
GOWORK=off make build
./bin/antinat-agent version
```

Run the Agent with a Controller endpoint and node identity:

```bash
./bin/antinat-agent \
  --endpoint https://controller.example \
  --node node-1 \
  --state ./var/agent
```

Enrollment accepts a one-time token from a 0600 file or a protected file
descriptor. The Controller public key pin is supplied with `--pin` or
`ANTINAT_PIN`.

## Included components

- `internal/agent`: enrollment, control sessions, reconciliation, recovery,
  lifecycle, and durable local state.
- `internal/forward`: TCP and UDP forwarding.
- `internal/traversal`: direct, STUN, PCP, NAT-PMP, and UPnP strategies.
- `internal/protocol`: signed control and probe frames.
- `internal/security`: node keys, key rotation, and frame protection.
- `deploy/` and `docker/`: Linux service and container integration.

Controller-backed end-to-end tests remain in the integrated Controller
repository; this repository contains the Agent unit and protocol test suite
needed for independent Agent builds.

## Support limits

The current candidate is `SUPPORTED_WITH_LIMITS`. Local Linux amd64 build and
test evidence is available. Independent public-WAN, real CPE/router, native
Windows, native arm64/OpenRC, and long-duration soak evidence is not available
for this source snapshot. See `docs/support-matrix.md` and
`docs/nat-support.md` for the exact boundaries.

AntiNAT Agent is distributed under the Apache License 2.0.
