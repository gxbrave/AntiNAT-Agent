# AntiNAT Agent

[中文说明](README.md)

AntiNAT Agent is the standalone data-plane process for AntiNAT. It runs inside the target network, owns local listeners, tries NAT traversal and port mappings, forwards TCP/UDP traffic, and receives desired state from the Controller over a protected control channel.

The Controller project is [gxbrave/AntiNAT](https://github.com/gxbrave/AntiNAT). The Controller manages nodes, forwarding rules, authentication, and reachability evidence; the Agent does not route business traffic through the Controller.

## What It Does

- Apply Controller forwarding configuration to local TCP/UDP listeners and sessions.
- Try direct, STUN, PCP, NAT-PMP, and UPnP mapping or traversal paths.
- Persist node identity, keys, mappings, and recovery information across restarts.
- Protect enrollment, heartbeats, configuration sync, and status reporting with signed frames and node identity.
- Provide Linux service integration and Docker state/enrollment helper scripts.

## Getting Started

### Requirements

- Linux amd64 is the most complete runtime target.
- Go 1.26.6, or a CI-compatible Go version.
- Source builds need Go and common Unix tools; service installation needs root privileges.

### Option 1: Installer script

The installer downloads the Agent manifest and artifacts from a release, verifies the pinned trust root, signature, and SHA-256 digests, and then installs the service. Enrollment tokens are read from a hidden TTY or a `0600` file/file descriptor. Never put a token directly in command-line arguments.

There is no published GitHub Release for this repository yet. Once a matching release exists, run this from a clone of the repository:

```bash
sudo env ANTINAT_RELEASE_BASE_URL="https://github.com/gxbrave/AntiNAT-Agent/releases/download/<version>" \
  bash scripts/install.sh install \
  --controller-endpoint https://your-controller.example
```

For networks that need a GitHub mirror, use `ghfast.top` as the URL prefix:

```bash
sudo env ANTINAT_RELEASE_BASE_URL="https://ghfast.top/https://github.com/gxbrave/AntiNAT-Agent/releases/download/<version>" \
  bash scripts/install.sh install \
  --controller-endpoint https://your-controller.example
```

Set `ANTINAT_RELEASE_BASE_URL` for this URL-prefix mirror. `--github-proxy` is for a real HTTP(S) proxy server and is a different option. The installer currently targets Linux amd64; see [`docs/installer-contract.md`](docs/installer-contract.md) for the CLI and security rules.

After the Controller issues a one-time token for the node, enter it when prompted. The lifecycle commands are:

```bash
sudo bash scripts/install.sh upgrade
sudo bash scripts/install.sh uninstall
sudo bash scripts/install.sh purge
```

### Option 2: Build from source

```bash
git clone https://github.com/gxbrave/AntiNAT-Agent.git
cd AntiNAT-Agent
GOWORK=off make check
GOWORK=off make build
./bin/antinat-agent version
```

Create a node in the Controller and obtain its one-time enrollment token, node ID, and Controller public-key pin. Store the token in a `0600` file and start the Agent:

```bash
chmod 600 ./var/enrollment.token
./bin/antinat-agent \
  --endpoint https://your-controller.example \
  --node <node-id> \
  --token-file ./var/enrollment.token \
  --pin <64-hex-character-controller-public-key> \
  --state ./var/agent
```

After enrollment succeeds, the Agent consumes the one-time token. With an existing local enrollment, omit `--token-file` and `--pin`:

```bash
./bin/antinat-agent \
  --endpoint https://your-controller.example \
  --node <node-id> \
  --state ./var/agent
```

The same values can be supplied through `ANTINAT_ENDPOINT`, `ANTINAT_NODE`, `ANTINAT_TOKEN_FILE`, `ANTINAT_PIN`, and `ANTINAT_STATE`.

### Useful options

- `--stun-servers`: comma-separated `stun+tcp://` endpoints.
- `--auto-order`: an explicit automatic strategy order such as `explicit-gateway,direct-v4,stun-only`.
- `--token-fd`: read the token from a protected file descriptor for automation.
- `--state`: local state directory, defaulting to `./var/agent`.

## Support Limits

The current candidate is `SUPPORTED_WITH_LIMITS`:

- Linux amd64 builds, package tests, race tests, and local protocol tests are the most complete.
- Windows amd64 has cross-build and installer compilation checks, not a full Windows runtime claim.
- Native arm64/OpenRC, real public WAN and CPE/router evidence, and long-running soak evidence are still missing.
- The Agent cannot promise reachability through every NAT. IPv6 is available for the control connection; the forwarding data plane is currently IPv4-only.

## Directory Guide

- `internal/agent`: enrollment, control sessions, local state, recovery, and lifecycle.
- `internal/forward`: TCP/UDP forwarding.
- `internal/traversal`: direct, STUN, PCP, NAT-PMP, and UPnP strategies.
- `internal/protocol`: signed control and probe frames.
- `internal/security`: node keys, rotation, and frame protection.
- `deploy/` and `docker/`: service files, containers, and enrollment helpers.
- `docs/nat-support.md`: NAT capability and limitation details.

## Implementation

The Agent owns the data plane. The Controller sends desired state and probe work; the Agent performs local listening, mapping, traversal, target connections, and forwarding. The control session uses node identity and signed protocol frames. Changes enter a durable local reconciler before they are applied, so restarts and network interruptions do not silently discard state.

Each forward has a stable ID and an activation generation. Ordinary target edits affect new connections, while deletion is the explicit immediate-stop operation. Probe results are stored separately from local listeners and STUN addresses; only an authenticated independent probe can promote a candidate endpoint to a publishable result.

The installer treats the release manifest as a trust boundary: it verifies the signature and SHA-256 values before copying binaries, installing services, and writing the ownership record. Tokens are used only during enrollment and are not placed in argv, service files, or ordinary logs.

## Tests

```bash
GOWORK=off go test ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
GOWORK=off make cross-build
```

See [`docs/support-matrix.md`](docs/support-matrix.md) for the complete evidence and platform limits.

## License

This project is released under the [GPL-3.0](LICENSE).
