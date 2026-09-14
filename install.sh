#!/usr/bin/env bash
# Parameterized Agent bootstrap, called by a Controller-generated command.
set -euo pipefail
fail() { printf 'antinat agent bootstrap: %s\n' "$*" >&2; exit 2; }
case "${1:-}" in
    --help|-h) printf '%s\n' 'Usage: install.sh [install] --controller-endpoint URL [installer flags]' 'Required environment: ANTINAT_NODE_ID, ANTINAT_CONTROLLER_PIN' 'Enrollment token: hidden TTY, --token-file PATH (0600), or --token-fd FD.'; exit 0 ;;
    install) shift ;;
esac
args=("$@")
endpoint=''
while (($#)); do
    case "$1" in
        --controller-endpoint) (($# >= 2)) || fail 'missing endpoint'; endpoint="$2"; shift 2 ;;
        --bind-interface|--install-dir|--service-name|--log-level|--auto-update|--github-proxy|--detection-scheduler|--platform|--token-fd|--token-file)
            (($# >= 2)) || fail "missing value for $1"; shift 2 ;;
        *) fail "unsupported argument: $1" ;;
    esac
done
[[ -n "$endpoint" ]] || fail 'Controller-generated --controller-endpoint is required'
[[ -n "${ANTINAT_NODE_ID:-}" ]] || fail 'Controller-generated ANTINAT_NODE_ID is required'
[[ "${ANTINAT_CONTROLLER_PIN:-}" =~ ^[0-9a-f]{64}$ ]] || fail 'Controller-generated ANTINAT_CONTROLLER_PIN must be 64 lowercase hex characters'
# Never inherit the Controller bootstrap role when installing the local Agent.
export ANTINAT_ROLE=agent
release_version="${ANTINAT_AGENT_RELEASE_VERSION:-v1.0.0-beta.2}"
[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || fail 'invalid Agent release version'
release_base_url="${ANTINAT_AGENT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT-Agent/releases/download/$release_version}"
[[ "$release_base_url" != *"@"* && "$release_base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || fail 'invalid Agent release URL'
export ANTINAT_RELEASE_BASE_URL="$release_base_url"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/antinat-agent-installer.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
mkdir -p -- "$tmp_dir/scripts" "$tmp_dir/deploy/trust"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$ANTINAT_RELEASE_BASE_URL/libinstall.sh" -o "$tmp_dir/scripts/libinstall.sh"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "$ANTINAT_RELEASE_BASE_URL/release-ed25519.pub" -o "$tmp_dir/deploy/trust/release-ed25519.pub"
# shellcheck source=/dev/null
source "$tmp_dir/scripts/libinstall.sh"
installer_run install "${args[@]}"
