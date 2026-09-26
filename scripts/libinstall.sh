#!/usr/bin/env bash

# Shared implementation for install.sh. This file intentionally uses arrays
# and direct command invocations; no user-controlled value is ever passed to
# eval or to a shell command string.

set -euo pipefail

INSTALLER_VERSION="1"
INSTALLER_SCHEMA_VERSION=3
INSTALLER_SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

INSTALLER_EXIT_SUCCESS=0
INSTALLER_EXIT_GENERIC=1
INSTALLER_EXIT_USAGE=2
INSTALLER_EXIT_TOKEN=3
INSTALLER_EXIT_ARTIFACT=4
INSTALLER_EXIT_CONFLICT=5
INSTALLER_EXIT_ROLLBACK=6
INSTALLER_EXIT_PURGE=7
INSTALLER_EXIT_MIGRATION=8

INSTALLER_COMMAND=""
INSTALLER_PLATFORM="linux"
INSTALLER_ENDPOINT=""
INSTALLER_BIND_INTERFACE=""
INSTALLER_DIR="/opt/antinat"
INSTALLER_SERVICE_NAME="antinat-agent.service"
INSTALLER_SERVICE_MANAGER=""
INSTALLER_LOG_LEVEL="info"
INSTALLER_AUTO_UPDATE="disabled"
INSTALLER_GITHUB_PROXY=""
INSTALLER_SCHEDULER="sequential"
INSTALLER_TOKEN_FD=""
INSTALLER_TOKEN_FILE=""
INSTALLER_TOKEN_TMP=""
INSTALLER_TOKEN_IDENTITY_TMP=""
INSTALLER_TOKEN_STAGE_DIR=""
INSTALLER_TOKEN_SOURCE_CONSUMED=0
INSTALLER_HELP_REQUESTED=0
INSTALLER_VERSION_REQUESTED=0
INSTALLER_PURGE_KEEP_OTHER=0
INSTALLER_AGENT_REENABLE=0
INSTALLER_CONTROLLER_REENABLE=0
INSTALLER_AGENT_WAS_ACTIVE=0
INSTALLER_CONTROLLER_WAS_ACTIVE=0
INSTALLER_AGENT_WAS_ENABLED=0
INSTALLER_CONTROLLER_WAS_ENABLED=0
INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL=0
INSTALLER_SCHEMA_BACKUP=""
INSTALLER_INSTALL_SNAPSHOT=""
INSTALLER_UPGRADE_LOCK_FD=""

INSTALLER_TEST_ROOT="${ANTINAT_TEST_ROOT:-}"
INSTALLER_ROLE="${ANTINAT_ROLE:-agent}"

installer_role_has_agent() {
    [[ "$INSTALLER_ROLE" == agent || "$INSTALLER_ROLE" == both ]]
}

installer_role_has_controller() {
    [[ "$INSTALLER_ROLE" == controller || "$INSTALLER_ROLE" == both ]]
}

installer_die() {
    local code="$1"
    shift
    printf 'antinat installer: %s\n' "$*" >&2
    return "$code"
}

installer_usage() {
    cat >&2 <<'EOF'
Usage: install.sh {install|uninstall|purge|upgrade} [flags]

Frozen flags:
  --controller-endpoint URL --bind-interface NAME --install-dir PATH
  --service-name NAME --log-level LEVEL --auto-update POLICY
  --github-proxy URL --detection-scheduler MODE --platform linux|windows|docker
  --token-fd FD | --token-file PATH

Tokens are read from a hidden TTY by default. Literal --token arguments are
not accepted.
EOF
}

installer_logical_path() {
    local logical="$1"
    if [[ -n "$INSTALLER_TEST_ROOT" ]]; then
        printf '%s%s' "${INSTALLER_TEST_ROOT%/}" "$logical"
    else
        printf '%s' "$logical"
    fi
}

installer_init_paths() {
    INSTALLER_INSTALL_DIR=$(installer_logical_path /opt/antinat)
    INSTALLER_BIN_DIR=$(installer_logical_path /opt/antinat/bin)
    INSTALLER_AGENT_BINARY=$(installer_logical_path /opt/antinat/bin/antinat-agent)
    INSTALLER_CONTROLLER_BINARY=$(installer_logical_path /opt/antinat/bin/antinat-controller)
    INSTALLER_HOOK_BINARY=$(installer_logical_path /opt/antinat/bin/antinat-hook-runner)
    INSTALLER_DATA_DIR=$(installer_logical_path /var/lib/antinat)
    INSTALLER_CONFIG=$(installer_logical_path /etc/antinat/agent.conf)
    INSTALLER_LOG_DIR=$(installer_logical_path /var/log/antinat)
    INSTALLER_SERVICE_DIR=$(installer_logical_path /etc/systemd/system)
    INSTALLER_OPENRC_DIR=$(installer_logical_path /etc/init.d)
    INSTALLER_AGENT_UNIT=$(installer_logical_path "/etc/systemd/system/${INSTALLER_SERVICE_NAME}")
    INSTALLER_CONTROLLER_UNIT=$(installer_logical_path /etc/systemd/system/antinat-controller.service)
    INSTALLER_CONTROLLER_KEY_DIR=$(installer_logical_path /var/lib/antinat/controller-keys)
    INSTALLER_OWNERSHIP_MANIFEST=$(installer_logical_path /var/lib/antinat/ownership-manifest.json)
    INSTALLER_OWNERSHIP_KEY=$(installer_logical_path /var/lib/antinat/ownership.key)
    INSTALLER_BACKUP_DIR=$(installer_logical_path /var/lib/antinat/backups)
    INSTALLER_SCHEMA_FILE=$(installer_logical_path /var/lib/antinat/schema.version)
    INSTALLER_SERVICE_MANAGER="${ANTINAT_SERVICE_MANAGER:-}"
    if [[ -z "$INSTALLER_SERVICE_MANAGER" ]]; then
        if [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]]; then
            INSTALLER_SERVICE_MANAGER=systemd
        elif command -v systemctl >/dev/null 2>&1; then
            INSTALLER_SERVICE_MANAGER=systemd
        elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
            INSTALLER_SERVICE_MANAGER=openrc
        else
            INSTALLER_SERVICE_MANAGER=systemd
        fi
    fi
    [[ "$INSTALLER_SERVICE_MANAGER" == systemd || "$INSTALLER_SERVICE_MANAGER" == openrc ]] || return "$INSTALLER_EXIT_USAGE"
    INSTALLER_AGENT_REENABLE=0
    INSTALLER_CONTROLLER_REENABLE=0
    INSTALLER_AGENT_WAS_ACTIVE=0
    INSTALLER_CONTROLLER_WAS_ACTIVE=0
    INSTALLER_AGENT_WAS_ENABLED=0
    INSTALLER_CONTROLLER_WAS_ENABLED=0
    INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL=0
    INSTALLER_SCHEMA_BACKUP=""
    INSTALLER_INSTALL_SNAPSHOT=""
}

installer_parse_args() {
    if (($# == 0)); then
        installer_usage
        return "$INSTALLER_EXIT_USAGE"
    fi
    INSTALLER_COMMAND="$1"
    shift
    case "$INSTALLER_COMMAND" in
        install|uninstall|purge|upgrade) ;;
        --help)
            INSTALLER_COMMAND=""
            INSTALLER_HELP_REQUESTED=1
            ;;
        --version)
            INSTALLER_COMMAND=""
            INSTALLER_VERSION_REQUESTED=1
            ;;
        *)
            installer_usage
            return "$INSTALLER_EXIT_USAGE"
            ;;
    esac

    while (($# > 0)); do
        local raw="$1"
        local name="$raw"
        local value=""
        local has_value=0
        shift
        if [[ "$raw" == *=* ]]; then
            name="${raw%%=*}"
            value="${raw#*=}"
            has_value=1
        fi
        case "$name" in
            --help)
                ((has_value == 0)) || return "$INSTALLER_EXIT_USAGE"
                INSTALLER_HELP_REQUESTED=1
                ;;
            --version)
                ((has_value == 0)) || return "$INSTALLER_EXIT_USAGE"
                INSTALLER_VERSION_REQUESTED=1
                ;;
            --controller-endpoint|--bind-interface|--install-dir|--service-name|--log-level|--auto-update|--github-proxy|--detection-scheduler|--platform|--token-fd|--token-file)
                if ((has_value == 0)); then
                    (($# > 0)) || return "$INSTALLER_EXIT_USAGE"
                    [[ "$1" != -* ]] || return "$INSTALLER_EXIT_USAGE"
                    value="$1"
                    shift
                fi
                [[ -n "$value" ]] || return "$INSTALLER_EXIT_USAGE"
                case "$name" in
                    --controller-endpoint) INSTALLER_ENDPOINT="$value" ;;
                    --bind-interface) INSTALLER_BIND_INTERFACE="$value" ;;
                    --install-dir) INSTALLER_DIR="$value" ;;
                    --service-name) INSTALLER_SERVICE_NAME="$value" ;;
                    --log-level) INSTALLER_LOG_LEVEL="$value" ;;
                    --auto-update) INSTALLER_AUTO_UPDATE="$value" ;;
                    --github-proxy) INSTALLER_GITHUB_PROXY="$value" ;;
                    --detection-scheduler) INSTALLER_SCHEDULER="$value" ;;
                    --platform) INSTALLER_PLATFORM="$value" ;;
                    --token-fd) INSTALLER_TOKEN_FD="$value" ;;
                    --token-file) INSTALLER_TOKEN_FILE="$value" ;;
                esac
                ;;
            --token|--token-value|-t|--token-*)
                return "$INSTALLER_EXIT_USAGE"
                ;;
            -*|*)
                return "$INSTALLER_EXIT_USAGE"
                ;;
        esac
    done

    if ((INSTALLER_HELP_REQUESTED != 0 && INSTALLER_VERSION_REQUESTED != 0)); then
        return "$INSTALLER_EXIT_USAGE"
    fi
    # A metadata request may not be used to bypass token-input validation. This
    # keeps a literal or protected token argument rejected even when --help is
    # present.
    if [[ -z "$INSTALLER_COMMAND" && (-n "$INSTALLER_TOKEN_FD" || -n "$INSTALLER_TOKEN_FILE") ]]; then
        return "$INSTALLER_EXIT_USAGE"
    fi
    if ((INSTALLER_HELP_REQUESTED != 0)); then
        installer_usage
        return 0
    fi
    if ((INSTALLER_VERSION_REQUESTED != 0)); then
        printf 'antinat-installer %s\n' "$INSTALLER_VERSION"
        return 0
    fi
    [[ -n "$INSTALLER_COMMAND" ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_PLATFORM" == linux ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_DIR" == /opt/antinat ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_SERVICE_NAME" == antinat-agent.service ]] || return "$INSTALLER_EXIT_USAGE"
    [[ "$INSTALLER_ROLE" == agent || "$INSTALLER_ROLE" == controller || "$INSTALLER_ROLE" == both ]] || return "$INSTALLER_EXIT_USAGE"
    if [[ -n "$INSTALLER_TOKEN_FD" && -n "$INSTALLER_TOKEN_FILE" ]]; then
        return "$INSTALLER_EXIT_TOKEN"
    fi
    if [[ -n "$INSTALLER_TOKEN_FD" ]]; then
        [[ "$INSTALLER_TOKEN_FD" =~ ^[3-9][0-9]*$ ]] || return "$INSTALLER_EXIT_TOKEN"
    fi
    if [[ "$INSTALLER_COMMAND" == install && ("$INSTALLER_ROLE" == agent || "$INSTALLER_ROLE" == both) && -z "$INSTALLER_ENDPOINT" && "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
        return "$INSTALLER_EXIT_USAGE"
    fi
    installer_validate_text "$INSTALLER_ENDPOINT" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$INSTALLER_BIND_INTERFACE" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$INSTALLER_GITHUB_PROXY" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$INSTALLER_SCHEDULER" || return "$INSTALLER_EXIT_USAGE"
    case "$INSTALLER_LOG_LEVEL" in
        debug|info|warn|error) ;;
        *) return "$INSTALLER_EXIT_USAGE" ;;
    esac
    case "$INSTALLER_AUTO_UPDATE" in
        disabled|manual|stable|enabled) ;;
        *) return "$INSTALLER_EXIT_USAGE" ;;
    esac
    case "$INSTALLER_SCHEDULER" in
        sequential|parallel) ;;
        *) return "$INSTALLER_EXIT_USAGE" ;;
    esac
    if [[ -n "${ANTINAT_TEST_FAIL_POINT:-}" ]]; then
        [[ "${ANTINAT_TEST_MODE:-0}" == 1 && -n "$INSTALLER_TEST_ROOT" ]] || return "$INSTALLER_EXIT_USAGE"
        case "$ANTINAT_TEST_FAIL_POINT" in
            enrollment|write|complete_journal) ;;
            *) return "$INSTALLER_EXIT_USAGE" ;;
        esac
    fi
    if [[ -n "$INSTALLER_GITHUB_PROXY" && ("$INSTALLER_GITHUB_PROXY" == *"@"* || ! "$INSTALLER_GITHUB_PROXY" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$) ]]; then
        return "$INSTALLER_EXIT_USAGE"
    fi
    return 0
}

installer_validate_text() {
    local value="$1"
    # Bash strings cannot contain NUL bytes; reject the control characters
    # that can be represented in a shell variable.
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]]
}

installer_validate_endpoint() {
    local endpoint="$1"
    [[ "$endpoint" =~ ^https?://[^[:space:]/?#]+(:[0-9]+)?([/][^[:space:]?#]*)?$ ]] || return 1
    [[ "$endpoint" != *"@"* && "$endpoint" != *"?"* && "$endpoint" != *"#"* ]] || return 1
    # Enrollment carries the one-time token in the request body. Plain HTTP is
    # allowed for the Controller-generated local enrollment endpoint only;
    # remote controllers must use TLS before any token is read.
    if [[ "$endpoint" == http://* ]]; then
        [[ "$endpoint" =~ ^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?([/][^[:space:]?#]*)?$ ]] || return 1
    fi
}

installer_require_tools() {
    local tool
    for tool in awk chmod cp curl find flock getent groupadd head hostname id install jq mktemp mv od openssl python3 readlink rm rmdir sha256sum sleep stat sync timeout tr uname useradd wc; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            installer_die "$INSTALLER_EXIT_GENERIC" "required tool $tool is unavailable" || true
            return "$INSTALLER_EXIT_GENERIC"
        fi
    done
}

installer_require_privileges() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    if [[ "$(id -u)" != 0 ]]; then
        installer_die "$INSTALLER_EXIT_GENERIC" "the installer must run as root" || true
        return "$INSTALLER_EXIT_GENERIC"
    fi
}

installer_require_linux_amd64() {
    local machine
    machine=$(uname -m 2>/dev/null) || return "$INSTALLER_EXIT_ARTIFACT"
    case "$machine" in
        x86_64|amd64) ;;
        *)
            installer_die "$INSTALLER_EXIT_ARTIFACT" "Linux installer supports amd64 only; detected $machine" || true
            return "$INSTALLER_EXIT_ARTIFACT"
            ;;
    esac
}

installer_fetch_release() {
    if [[ -n "${ANTINAT_ARTIFACT_DIR:-}" ]]; then
        INSTALLER_ARTIFACT_DIR="$ANTINAT_ARTIFACT_DIR"
        INSTALLER_MANIFEST_FILE="${ANTINAT_MANIFEST_FILE:-$INSTALLER_ARTIFACT_DIR/manifest.json}"
        INSTALLER_SIGNATURE_FILE="${ANTINAT_SIGNATURE_FILE:-$INSTALLER_ARTIFACT_DIR/manifest.sig}"
        return 0
    fi
    local base_url="${ANTINAT_RELEASE_BASE_URL:-https://github.com/gxbrave/AntiNAT-Agent/releases/download/v1.0.0-beta.3}"
    [[ "$base_url" != *"@"* && "$base_url" =~ ^https://[^[:space:]/?#]+(/[^[:space:]?#]*)?$ ]] || return "$INSTALLER_EXIT_ARTIFACT"
    local scratch
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/antinat-release.XXXXXX") || return "$INSTALLER_EXIT_ARTIFACT"
    INSTALLER_ARTIFACT_DIR="$scratch"
    INSTALLER_MANIFEST_FILE="$scratch/manifest.json"
    INSTALLER_SIGNATURE_FILE="$scratch/manifest.sig"
    local -a curl_options=(--fail --silent --show-error --location --proto '=https' --tlsv1.2)
    if [[ -n "$INSTALLER_GITHUB_PROXY" ]]; then
        curl_options+=(--proxy "$INSTALLER_GITHUB_PROXY")
    fi
    curl "${curl_options[@]}" --max-time 60 "$base_url/manifest.json" -o "$INSTALLER_MANIFEST_FILE" || return "$INSTALLER_EXIT_ARTIFACT"
    curl "${curl_options[@]}" --max-time 60 "$base_url/manifest.sig" -o "$INSTALLER_SIGNATURE_FILE" || return "$INSTALLER_EXIT_ARTIFACT"
    local artifact
    while IFS= read -r artifact; do
        [[ -n "$artifact" ]] || continue
        [[ "$artifact" != */* ]] && artifact="${artifact##*/}"
        curl "${curl_options[@]}" --connect-timeout 20 --max-time 600 --retry 2 \
            "$base_url/$artifact" -o "$scratch/${artifact##*/}" || return "$INSTALLER_EXIT_ARTIFACT"
    done < <(jq -r '.artifacts | keys[]' "$INSTALLER_MANIFEST_FILE")
    return 0
}

installer_verify_artifacts() {
    local trust_root="$INSTALLER_SCRIPT_DIR/../deploy/trust/release-ed25519.pub"
    local trust_root_id="release-key-2026"
    if [[ "${ANTINAT_TEST_MODE:-0}" == 1 ]]; then
        trust_root="${ANTINAT_TRUST_ROOT_FILE:-$trust_root}"
        trust_root_id="${ANTINAT_TRUST_ROOT_ID:-$trust_root_id}"
    elif [[ -n "${ANTINAT_TRUST_ROOT_FILE:-}" || -n "${ANTINAT_TRUST_ROOT_ID:-}" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release trust root overrides are only allowed in test mode" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ ! -d "$INSTALLER_ARTIFACT_DIR" || -L "$INSTALLER_ARTIFACT_DIR" || "$(readlink -f -- "$INSTALLER_ARTIFACT_DIR" 2>/dev/null)" != "$INSTALLER_ARTIFACT_DIR" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact directory is not a private canonical directory" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    # A caller-supplied release directory is an input boundary. Requiring a
    # root-owned, non-writable directory makes the signed manifest and the
    # bytes selected from it immutable to an unprivileged local process after
    # verification. Downloads created by mktemp already satisfy this rule.
    local artifact_mode artifact_owner
    artifact_mode=$(stat -c '%a' -- "$INSTALLER_ARTIFACT_DIR") || return "$INSTALLER_EXIT_ARTIFACT"
    artifact_owner=$(stat -c '%u' -- "$INSTALLER_ARTIFACT_DIR") || return "$INSTALLER_EXIT_ARTIFACT"
    [[ "$artifact_owner" == 0 && "$artifact_mode" == 700 ]] || {
        installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact directory must be root-owned and mode 0700" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    }
    if [[ ! -r "$trust_root" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "pinned release trust root is unavailable" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ ! -r "$INSTALLER_MANIFEST_FILE" || ! -r "$INSTALLER_SIGNATURE_FILE" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest or detached signature is missing" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if ! jq -e 'type == "object" and ((keys - ["schema_version", "release", "artifacts", "trust_root", "signature_algorithm"]) | length == 0)' "$INSTALLER_MANIFEST_FILE" >/dev/null; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest has unknown fields" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ "$(jq -r '.schema_version // empty' "$INSTALLER_MANIFEST_FILE")" != 1 ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "unsupported release manifest schema" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ "$(jq -r '.signature_algorithm // "ed25519"' "$INSTALLER_MANIFEST_FILE")" != ed25519 ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "unsupported release signature algorithm" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if [[ "$(jq -r '.trust_root // empty' "$INSTALLER_MANIFEST_FILE")" != "$trust_root_id" ]]; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest trust root is not pinned" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if ! jq -e '.trust_root | type == "string" and length > 0' "$INSTALLER_MANIFEST_FILE" >/dev/null || \
        ! jq -e '.artifacts | type == "object" and length > 0' "$INSTALLER_MANIFEST_FILE" >/dev/null; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "release manifest has no artifacts" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi
    if ! openssl pkeyutl -verify -pubin -inkey "$trust_root" -rawin -in "$INSTALLER_MANIFEST_FILE" -sigfile "$INSTALLER_SIGNATURE_FILE" >/dev/null 2>&1; then
        installer_die "$INSTALLER_EXIT_ARTIFACT" "detached release manifest signature failed" || true
        return "$INSTALLER_EXIT_ARTIFACT"
    fi

    local name digest path actual leaf
    declare -A seen_artifact_leaves=()
    while IFS=$'\t' read -r name digest; do
        if [[ ! "$name" =~ ^[A-Za-z0-9._/-]+$ || "$name" == /* || "$name" == *"//"* || "$name" =~ (^|/)\.\.?(/|$) ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "unsafe artifact name" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        leaf="${name##*/}"
        if [[ -z "$leaf" || -n "${seen_artifact_leaves[$leaf]+present}" ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact names collide after extraction" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        seen_artifact_leaves["$leaf"]=1
        if [[ ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact digest is not lowercase SHA-256" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        path="$INSTALLER_ARTIFACT_DIR/$leaf"
        if [[ ! -f "$path" || -L "$path" ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact is missing" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
        actual=$(sha256sum -- "$path" | awk '{print $1}')
        if [[ "$actual" != "$digest" ]]; then
            installer_die "$INSTALLER_EXIT_ARTIFACT" "artifact digest mismatch" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
    done < <(jq -r '.artifacts | to_entries[] | [.key,.value] | @tsv' "$INSTALLER_MANIFEST_FILE")
}

installer_find_artifact_name() {
    local suffix="$1" name count=0 match=""
    while IFS= read -r name; do
        [[ -n "$name" ]] || continue
        count=$((count + 1))
        match="$name"
    done < <(jq -r --arg suffix "$suffix" '.artifacts | keys[] | select(endswith($suffix))' "$INSTALLER_MANIFEST_FILE")
    [[ "$count" == 1 ]] || return 1
    printf '%s\n' "$match"
}

installer_find_artifact() {
    local suffix="$1" name
    name=$(installer_find_artifact_name "$suffix") || return 1
    printf '%s/%s' "$INSTALLER_ARTIFACT_DIR" "${name##*/}"
}

installer_read_token_file_bound() {
    local source="$1" destination="$2" identity="$3"
    python3 - "$source" "$destination" "$identity" <<'PY'
import os
import stat
import sys

source, destination, identity = sys.argv[1:]
parent = os.path.dirname(source) or "."
name = os.path.basename(source)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o7777) != 0o600 or
                st.st_uid != os.geteuid() or st.st_nlink != 1):
            raise OSError("token source is not a private owner-only file")
        data = bytearray()
        while len(data) <= 4096:
            chunk = os.read(fd, 4097 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > 4096:
            raise OSError("token source exceeds size limit")
        out_fd = os.open(destination, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            view = memoryview(data)
            while view:
                written = os.write(out_fd, view)
                view = view[written:]
            os.fsync(out_fd)
        finally:
            os.close(out_fd)
        meta_fd = os.open(identity, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(meta_fd, f"{st.st_dev} {st.st_ino}\n".encode("ascii"))
            os.fsync(meta_fd)
        finally:
            os.close(meta_fd)
    finally:
        os.close(fd)
finally:
    os.close(parent_fd)
PY
}

installer_consume_token_file_bound() {
    local source="$1" identity="$2"
    python3 - "$source" "$identity" <<'PY'
import os
import stat
import sys

source, identity = sys.argv[1:]
identity_fd = os.open(identity, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    identity_stat = os.fstat(identity_fd)
    if (not stat.S_ISREG(identity_stat.st_mode) or
            (identity_stat.st_mode & 0o7777) != 0o600 or
            identity_stat.st_uid != os.geteuid() or identity_stat.st_nlink != 1):
        raise OSError("token identity record is not a private owner-only file")
    fields = os.read(identity_fd, 128).split()
finally:
    os.close(identity_fd)
if len(fields) != 2:
    raise OSError("token identity record is invalid")
expected_dev, expected_ino = int(fields[0]), int(fields[1])
parent = os.path.dirname(source) or "."
name = os.path.basename(source)
parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISREG(st.st_mode) or (st.st_mode & 0o7777) != 0o600 or
            st.st_uid != os.geteuid() or st.st_nlink != 1 or
            st.st_dev != expected_dev or st.st_ino != expected_ino):
        raise OSError("token file was replaced before consumption")
    os.unlink(name, dir_fd=parent_fd)
    os.fsync(parent_fd)
finally:
    os.close(parent_fd)
PY
}

installer_read_token() {
    local token_tmp_dir="$INSTALLER_DATA_DIR"
    mkdir -p -- "$token_tmp_dir"
    chmod 700 -- "$token_tmp_dir"
    local token_stage_root
    token_stage_root=$(installer_logical_path /run/antinat) || return "$INSTALLER_EXIT_TOKEN"
    mkdir -p -- "$token_stage_root" || return "$INSTALLER_EXIT_TOKEN"
    chmod 700 -- "$token_stage_root" || return "$INSTALLER_EXIT_TOKEN"
    installer_chown root:root "$token_stage_root" || return "$INSTALLER_EXIT_TOKEN"
    INSTALLER_TOKEN_STAGE_DIR=$(mktemp -d "$token_stage_root/install.XXXXXX") || return "$INSTALLER_EXIT_TOKEN"
    chmod 700 -- "$INSTALLER_TOKEN_STAGE_DIR" || return "$INSTALLER_EXIT_TOKEN"
    installer_chown root:root "$INSTALLER_TOKEN_STAGE_DIR" || return "$INSTALLER_EXIT_TOKEN"
    INSTALLER_TOKEN_TMP=$(mktemp "$INSTALLER_TOKEN_STAGE_DIR/token.XXXXXX") || return "$INSTALLER_EXIT_TOKEN"
    chmod 600 -- "$INSTALLER_TOKEN_TMP"
    INSTALLER_TOKEN_IDENTITY_TMP=""
    if [[ -n "$INSTALLER_TOKEN_FD" ]]; then
        # The descriptor is read directly; its contents are never placed in
        # argv or an environment variable.
        head -c 4097 <&"$INSTALLER_TOKEN_FD" >"$INSTALLER_TOKEN_TMP" || return "$INSTALLER_EXIT_TOKEN"
    elif [[ -n "$INSTALLER_TOKEN_FILE" ]]; then
        INSTALLER_TOKEN_IDENTITY_TMP=$(mktemp "$INSTALLER_TOKEN_STAGE_DIR/identity.XXXXXX") || return "$INSTALLER_EXIT_TOKEN"
        chmod 600 -- "$INSTALLER_TOKEN_IDENTITY_TMP"
        installer_read_token_file_bound "$INSTALLER_TOKEN_FILE" "$INSTALLER_TOKEN_TMP" "$INSTALLER_TOKEN_IDENTITY_TMP" || return "$INSTALLER_EXIT_TOKEN"
    else
        local tty=/dev/tty token
        [[ -r "$tty" && -w "$tty" ]] || return "$INSTALLER_EXIT_TOKEN"
        printf 'Enrollment token: ' >"$tty"
        IFS= read -r -s token <"$tty" || return "$INSTALLER_EXIT_TOKEN"
        printf '\n' >"$tty"
        printf '%s\n' "$token" >"$INSTALLER_TOKEN_TMP"
    fi
    [[ "$(wc -c <"$INSTALLER_TOKEN_TMP")" -le 4096 ]] || return "$INSTALLER_EXIT_TOKEN"
    [[ -s "$INSTALLER_TOKEN_TMP" ]] || return "$INSTALLER_EXIT_TOKEN"
    # The token is copied in a root-only staging directory. Publish it into
    # the Agent data directory only after all root-side reads are complete;
    # the final rename never follows a service-user symlink.
    local published_token
    published_token=$(mktemp "$token_tmp_dir/.enrollment-token.XXXXXX") || return "$INSTALLER_EXIT_TOKEN"
    rm -f -- "$published_token"
    mv -f -- "$INSTALLER_TOKEN_TMP" "$published_token" || return "$INSTALLER_EXIT_TOKEN"
    INSTALLER_TOKEN_TMP="$published_token"
    # The service runs as antinat and must be able to read/delete this one-time
    # file. The root-only identity record remains outside the service path.
    installer_chown antinat:antinat "$INSTALLER_TOKEN_TMP" || return "$INSTALLER_EXIT_TOKEN"
}

installer_cleanup_token() {
    if [[ -n "$INSTALLER_TOKEN_TMP" && -e "$INSTALLER_TOKEN_TMP" ]]; then
        rm -f -- "$INSTALLER_TOKEN_TMP"
    fi
    if [[ -n "$INSTALLER_TOKEN_IDENTITY_TMP" ]]; then
        rm -f -- "$INSTALLER_TOKEN_IDENTITY_TMP"
    fi
    INSTALLER_TOKEN_TMP=""
    INSTALLER_TOKEN_IDENTITY_TMP=""
    if [[ -n "$INSTALLER_TOKEN_STAGE_DIR" ]]; then
        rmdir -- "$INSTALLER_TOKEN_STAGE_DIR" 2>/dev/null || true
    fi
    INSTALLER_TOKEN_STAGE_DIR=""
}

installer_consume_source_token() {
    [[ -n "$INSTALLER_TOKEN_FILE" && "$INSTALLER_TOKEN_SOURCE_CONSUMED" == 0 ]] || return 0
    [[ -n "$INSTALLER_TOKEN_IDENTITY_TMP" && -f "$INSTALLER_TOKEN_IDENTITY_TMP" ]] || return "$INSTALLER_EXIT_TOKEN"
    installer_consume_token_file_bound "$INSTALLER_TOKEN_FILE" "$INSTALLER_TOKEN_IDENTITY_TMP" || return "$INSTALLER_EXIT_TOKEN"
    INSTALLER_TOKEN_SOURCE_CONSUMED=1
}

installer_atomic_copy() {
    local source="$1" destination="$2" mode="$3"
    [[ -f "$source" && ! -L "$source" ]] || return 1
    mkdir -p -- "$(dirname -- "$destination")"
    local temporary
    temporary=$(mktemp "$(dirname -- "$destination")/.antinat-copy.XXXXXX") || return 1
    chmod "$mode" -- "$temporary"
    if ! cp -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod "$mode" -- "$temporary"
    mv -f -- "$temporary" "$destination"
}

installer_atomic_copy_verified() {
    local source="$1" destination="$2" mode="$3" expected="$4"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || return 1
    mkdir -p -- "$(dirname -- "$destination")"
    python3 - "$source" "$destination" "$mode" "$expected" <<'PY'
import hashlib
import os
import stat
import sys
import tempfile

source, destination, mode, expected = sys.argv[1:]
source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
temporary_path = None
try:
    source_stat = os.fstat(source_fd)
    if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
        raise OSError("artifact is not a private regular file")
    parent = os.path.dirname(destination) or "."
    destination_fd, temporary_path = tempfile.mkstemp(prefix=".antinat-copy-", dir=parent)
    try:
        os.fchmod(destination_fd, int(mode, 8))
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        if digest.hexdigest() != expected:
            raise OSError("artifact digest changed during copy")
        if os.fstat(source_fd).st_ino != source_stat.st_ino or os.fstat(source_fd).st_dev != source_stat.st_dev:
            raise OSError("artifact identity changed during copy")
        os.fsync(destination_fd)
    finally:
        os.close(destination_fd)
    os.replace(temporary_path, destination)
    temporary_path = None
    directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    os.close(source_fd)
    if temporary_path is not None:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass
PY
}

installer_copy_artifact() {
    local suffix="$1" destination="$2" mode="$3" name expected
    name=$(installer_find_artifact_name "$suffix") || return 1
    [[ -n "$name" ]] || return 1
    expected=$(jq -r --arg name "$name" '.artifacts[$name]' "$INSTALLER_MANIFEST_FILE")
    installer_atomic_copy_verified "$INSTALLER_ARTIFACT_DIR/${name##*/}" "$destination" "$mode" "$expected"
}

installer_test_fail_at() {
    [[ "${ANTINAT_TEST_MODE:-0}" == 1 && -n "$INSTALLER_TEST_ROOT" && "${ANTINAT_TEST_FAIL_POINT:-}" == "$1" ]]
}

installer_write_config() {
    local token_file="${1:-}"
    local node_id="${ANTINAT_NODE_ID:-}"
    if [[ -z "$node_id" ]]; then
        node_id=$(hostname 2>/dev/null || printf 'antinat-node')
    fi
    if ((${#node_id} > 16)); then
        node_id=$(printf '%s' "$node_id" | sha256sum | awk '{print substr($1,1,16)}')
    fi
    installer_validate_endpoint "$INSTALLER_ENDPOINT" || return "$INSTALLER_EXIT_USAGE"
    installer_validate_text "$node_id" || return "$INSTALLER_EXIT_USAGE"
    mkdir -p -- "$(dirname -- "$INSTALLER_CONFIG")"
    chmod 750 -- "$(dirname -- "$INSTALLER_CONFIG")"
    local temporary
    temporary=$(mktemp "$(dirname -- "$INSTALLER_CONFIG")/.agent-conf.XXXXXX") || return 1
    chmod 600 -- "$temporary"
    {
        printf "ANTINAT_ENDPOINT='%s'\n" "${INSTALLER_ENDPOINT//\'/\'\\\'\'}"
        printf "ANTINAT_NODE='%s'\n" "${node_id//\'/\'\\\'\'}"
        printf "ANTINAT_STATE='%s'\n" "${INSTALLER_DATA_DIR//\'/\'\\\'\'}"
        if [[ -n "${ANTINAT_CONTROLLER_PIN:-}" ]]; then
            printf "ANTINAT_PIN='%s'\n" "${ANTINAT_CONTROLLER_PIN//\'/\'\\\'\'}"
        fi
        if [[ -n "$token_file" ]]; then
            printf "ANTINAT_TOKEN_FILE='%s'\n" "${token_file//\'/\'\\\'\'}"
        fi
        if [[ -n "$INSTALLER_GITHUB_PROXY" ]]; then
            printf "ANTINAT_GITHUB_PROXY='%s'\n" "${INSTALLER_GITHUB_PROXY//\'/\'\\\'\'}"
        fi
        printf "ANTINAT_BIND_INTERFACE='%s'\n" "${INSTALLER_BIND_INTERFACE//\'/\'\\\'\'}"
        printf "ANTINAT_LOG_LEVEL='%s'\n" "${INSTALLER_LOG_LEVEL//\'/\'\\\'\'}"
        printf "ANTINAT_AUTO_UPDATE='%s'\n" "${INSTALLER_AUTO_UPDATE//\'/\'\\\'\'}"
        printf "ANTINAT_DETECTION_SCHEDULER='%s'\n" "${INSTALLER_SCHEDULER//\'/\'\\\'\'}"
        if [[ -n "${ANTINAT_STUN_SERVERS:-}" ]]; then
            printf "ANTINAT_STUN_SERVERS='%s'\n" "${ANTINAT_STUN_SERVERS//\'/\'\\\'\'}"
        fi
        if [[ -n "${ANTINAT_AUTO_ORDER:-}" ]]; then
            printf "ANTINAT_AUTO_ORDER='%s'\n" "${ANTINAT_AUTO_ORDER//\'/\'\\\'\'}"
        fi
    } >"$temporary"
    mv -f -- "$temporary" "$INSTALLER_CONFIG"
    chmod 600 -- "$INSTALLER_CONFIG"
    installer_chown root:root "$INSTALLER_CONFIG"
}

installer_create_user() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    if ! getent group antinat >/dev/null 2>&1; then
        groupadd --system antinat
    fi
    if ! id antinat >/dev/null 2>&1; then
        useradd --system --gid antinat --home-dir /var/lib/antinat --shell /usr/sbin/nologin antinat
    fi
}

installer_write_schema_version() {
    local temporary
    installer_test_fail_at write && return 1
    mkdir -p -- "$INSTALLER_DATA_DIR"
    if [[ -e "$INSTALLER_SCHEMA_FILE" || -L "$INSTALLER_SCHEMA_FILE" ]]; then
        [[ -f "$INSTALLER_SCHEMA_FILE" && ! -L "$INSTALLER_SCHEMA_FILE" ]] || return 1
    fi
    temporary=$(mktemp "$INSTALLER_DATA_DIR/.schema-version.XXXXXX") || return 1
    chmod 600 -- "$temporary"
    if ! printf '%s\n' "$INSTALLER_SCHEMA_VERSION" >"$temporary" || ! mv -f -- "$temporary" "$INSTALLER_SCHEMA_FILE"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 600 -- "$INSTALLER_SCHEMA_FILE"
    installer_chown antinat:antinat "$INSTALLER_SCHEMA_FILE"
}

installer_backup_schema_for_install() {
    INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL=0
    INSTALLER_SCHEMA_BACKUP=""
    if [[ ! -e "$INSTALLER_SCHEMA_FILE" && ! -L "$INSTALLER_SCHEMA_FILE" ]]; then
        return 0
    fi
    INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL=1
    [[ -f "$INSTALLER_SCHEMA_FILE" && ! -L "$INSTALLER_SCHEMA_FILE" ]] || return 1
    INSTALLER_SCHEMA_BACKUP=$(mktemp "$INSTALLER_DATA_DIR/.schema-rollback.XXXXXX") || return 1
    chmod 600 -- "$INSTALLER_SCHEMA_BACKUP"
    if ! cp -p -- "$INSTALLER_SCHEMA_FILE" "$INSTALLER_SCHEMA_BACKUP"; then
        rm -f -- "$INSTALLER_SCHEMA_BACKUP"
        INSTALLER_SCHEMA_BACKUP=""
        return 1
    fi
    INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL=1
}

installer_cleanup_schema_backup() {
    if [[ -n "$INSTALLER_SCHEMA_BACKUP" ]]; then
        rm -f -- "$INSTALLER_SCHEMA_BACKUP"
    fi
    INSTALLER_SCHEMA_BACKUP=""
}

installer_restore_install_schema() {
    if [[ "$INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL" == 1 ]]; then
        [[ -n "$INSTALLER_SCHEMA_BACKUP" && -f "$INSTALLER_SCHEMA_BACKUP" && ! -L "$INSTALLER_SCHEMA_BACKUP" ]] || return 1
        local temporary
        temporary=$(mktemp "$INSTALLER_DATA_DIR/.schema-restore.XXXXXX") || return 1
        if ! cp -p -- "$INSTALLER_SCHEMA_BACKUP" "$temporary" || ! mv -f -- "$temporary" "$INSTALLER_SCHEMA_FILE"; then
            rm -f -- "$temporary"
            return 1
        fi
    else
        installer_safe_remove "$INSTALLER_DATA_DIR" schema.version || return 1
    fi
}

installer_validate_upgrade_version() {
    local previous_text previous_version marker_size
    if [[ ! -e "$INSTALLER_SCHEMA_FILE" && ! -L "$INSTALLER_SCHEMA_FILE" ]]; then
        # Releases before the marker was introduced are treated as N-1. This
        # is the only compatibility assumption made for legacy installs.
        previous_version=$((INSTALLER_SCHEMA_VERSION - 1))
    else
        [[ -f "$INSTALLER_SCHEMA_FILE" && ! -L "$INSTALLER_SCHEMA_FILE" ]] || {
            installer_die "$INSTALLER_EXIT_MIGRATION" "schema version marker is unsafe" || true
            return "$INSTALLER_EXIT_MIGRATION"
        }
        marker_size=$(stat -c '%s' -- "$INSTALLER_SCHEMA_FILE") || return "$INSTALLER_EXIT_MIGRATION"
        if ((marker_size > 64)); then
            installer_die "$INSTALLER_EXIT_MIGRATION" "schema version marker is too large" || true
            return "$INSTALLER_EXIT_MIGRATION"
        fi
        previous_text=$(<"$INSTALLER_SCHEMA_FILE") || return "$INSTALLER_EXIT_MIGRATION"
        [[ "$previous_text" =~ ^[1-9][0-9]*$ ]] || {
            installer_die "$INSTALLER_EXIT_MIGRATION" "schema version marker is invalid" || true
            return "$INSTALLER_EXIT_MIGRATION"
        }
        previous_version="$previous_text"
    fi
    if [[ "$previous_version" != "$INSTALLER_SCHEMA_VERSION" && "$previous_version" != "$((INSTALLER_SCHEMA_VERSION - 1))" ]]; then
        installer_die "$INSTALLER_EXIT_MIGRATION" "schema upgrade from $previous_version to $INSTALLER_SCHEMA_VERSION is not N/N-1 compatible" || true
        return "$INSTALLER_EXIT_MIGRATION"
    fi
}

installer_install_unit() {
    local source="$1" destination="$2"
    [[ -r "$source" ]] || return 1
    mkdir -p -- "$(dirname -- "$destination")"
    installer_atomic_copy "$source" "$destination" 644
}

installer_find_service_source() {
    local unit="$1" candidate
    if [[ -n "${ANTINAT_SYSTEMD_DIR:-}" ]]; then
        candidate="$ANTINAT_SYSTEMD_DIR/$unit"
        if [[ -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    for candidate in \
        "$INSTALLER_SCRIPT_DIR/../deploy/systemd/$unit" \
        "$INSTALLER_SCRIPT_DIR/systemd/$unit" \
        "/usr/share/antinat/systemd/$unit"; do
        if [[ -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

installer_find_openrc_source() {
    local service="$1" candidate
    if [[ -n "${ANTINAT_OPENRC_DIR:-}" ]]; then
        candidate="$ANTINAT_OPENRC_DIR/$service"
        if [[ -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    for candidate in \
        "$INSTALLER_SCRIPT_DIR/../deploy/openrc/$service" \
        "$INSTALLER_SCRIPT_DIR/openrc/$service" \
        "/usr/share/antinat/openrc/$service"; do
        if [[ -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

installer_install_embedded_unit() {
    local unit="$1" destination="$2" temporary
    temporary=$(mktemp "${TMPDIR:-/tmp}/antinat-unit.XXXXXX") || return 1
    case "$unit" in
        antinat-agent.service)
            {
                printf '%s\n' '[Unit]' 'Description=AntiNAT Agent' \
                    'Wants=network-online.target' 'After=network-online.target'
                printf '%s\n' '' '[Service]' 'Type=simple' 'User=antinat' \
                    'Group=antinat' 'EnvironmentFile=-/etc/antinat/agent.conf' \
                    'ExecStart=/opt/antinat/bin/antinat-agent' \
                    'WorkingDirectory=/var/lib/antinat' 'Restart=on-failure' \
                    'RestartSec=5s' 'TimeoutStopSec=15s' 'UMask=0077' \
                    'NoNewPrivileges=true' 'PrivateTmp=true' 'ProtectHome=true' \
                    'ProtectSystem=strict' 'CapabilityBoundingSet=' \
                    'AmbientCapabilities=' 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
                    'ReadWritePaths=/var/lib/antinat /var/log/antinat'
                printf '%s\n' '' '[Install]' 'WantedBy=multi-user.target'
            } >"$temporary"
            ;;
        antinat-controller.service)
            {
                printf '%s\n' '[Unit]' 'Description=AntiNAT Controller' \
                    'Wants=network-online.target' 'After=network-online.target'
                printf '%s\n' '' '[Service]' 'Type=simple' 'User=antinat' \
                    'Group=antinat' \
                    'ExecStart=/opt/antinat/bin/antinat-controller -listen 127.0.0.1:3111 -store /var/lib/antinat/controller.db -keydir /var/lib/antinat/controller-keys' \
                    'WorkingDirectory=/var/lib/antinat' 'Restart=on-failure' \
                    'RestartSec=5s' 'TimeoutStopSec=15s' 'UMask=0077' \
                    'NoNewPrivileges=true' 'PrivateTmp=true' 'ProtectHome=true' \
                    'ProtectSystem=strict' 'CapabilityBoundingSet=' \
                    'AmbientCapabilities=' 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' \
                    'ReadWritePaths=/var/lib/antinat /var/log/antinat'
                printf '%s\n' '' '[Install]' 'WantedBy=multi-user.target'
            } >"$temporary"
            ;;
        *)
            rm -f -- "$temporary"
            return 1
            ;;
    esac
    if ! installer_atomic_copy "$temporary" "$destination" 644; then
        rm -f -- "$temporary"
        return 1
    fi
    rm -f -- "$temporary"
}

installer_install_service_unit() {
    local unit="$1" destination="$2" source
    if source=$(installer_find_service_source "$unit"); then
        installer_install_unit "$source" "$destination"
    else
        installer_install_embedded_unit "$unit" "$destination"
    fi
}

installer_install_openrc_service() {
    local service="$1" destination="$INSTALLER_OPENRC_DIR/$1" source
    if source=$(installer_find_openrc_source "$service"); then
        installer_atomic_copy "$source" "$destination" 755
        return
    fi
    return 1
}

installer_openrc() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    local action="$1" service="$2"
    case "$action" in
        start|stop|restart)
            rc-service "$service" "$action"
            ;;
        add|del)
            rc-update "$action" "$service" default
            ;;
        *)
            return 2
            ;;
    esac
}

installer_systemctl() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    systemctl "$@"
}

installer_systemd_unit_present() {
    local unit="$1"
    if [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]]; then
        [[ -e "$INSTALLER_SERVICE_DIR/$unit" || "$unit" == "$INSTALLER_SERVICE_NAME" && -e "$INSTALLER_AGENT_UNIT" ]]
        return
    fi
    systemctl cat "$unit" >/dev/null 2>&1
}

installer_chown() {
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    chown "$@"
}

installer_ownership_resource_role() {
    local root="$1" path="$2"
    case "$root:$path" in
        "$INSTALLER_INSTALL_DIR:bin/antinat-agent"|\
        "$INSTALLER_INSTALL_DIR:bin/antinat-hook-runner"|\
        "$INSTALLER_DATA_DIR:state.db"|\
        "$INSTALLER_DATA_DIR:node.key"|\
        "$INSTALLER_DATA_DIR:.key.lock"|\
        "$INSTALLER_DATA_DIR:.lifecycle.lock"|\
        "$INSTALLER_DATA_DIR:detection.profile"|\
        "$INSTALLER_DATA_DIR:.enrollment-token"|\
        "$INSTALLER_DATA_DIR:terminal.marker"|\
        "$INSTALLER_DATA_DIR:agent.marker"|\
        "$(dirname -- "$INSTALLER_CONFIG"):agent.conf"|\
        "$INSTALLER_SERVICE_DIR:$INSTALLER_SERVICE_NAME"|\
        "$INSTALLER_OPENRC_DIR:antinat-agent")
            printf 'agent\n'
            return 0
            ;;
        "$INSTALLER_INSTALL_DIR:bin/antinat-controller"|\
        "$INSTALLER_DATA_DIR:controller.db"|\
        "$INSTALLER_DATA_DIR:controller.db-wal"|\
        "$INSTALLER_DATA_DIR:controller.db-shm"|\
        "$INSTALLER_DATA_DIR:controller-keys"|\
        "$INSTALLER_SERVICE_DIR:antinat-controller.service"|\
        "$INSTALLER_OPENRC_DIR:antinat-controller")
            printf 'controller\n'
            return 0
            ;;
        "$INSTALLER_DATA_DIR:backups"|\
        "$INSTALLER_DATA_DIR:.upgrade.lock"|\
        "$INSTALLER_DATA_DIR:schema.version"|\
        "$(dirname -- "$INSTALLER_LOG_DIR"):$(basename -- "$INSTALLER_LOG_DIR")"|\
        "$INSTALLER_DATA_DIR:ownership-manifest.json"|\
        "$INSTALLER_DATA_DIR:ownership.key")
            printf 'shared\n'
            return 0
            ;;
    esac
    printf 'unknown\n'
    return 1
}

installer_manifest_validate() {
    [[ -f "$INSTALLER_OWNERSHIP_MANIFEST" && ! -L "$INSTALLER_OWNERSHIP_MANIFEST" ]] || return 1
    [[ -f "$INSTALLER_OWNERSHIP_KEY" && ! -L "$INSTALLER_OWNERSHIP_KEY" ]] || return 1
    local mode owner links
    mode=$(stat -c '%a' -- "$INSTALLER_OWNERSHIP_KEY") || return 1
    owner=$(stat -c '%u' -- "$INSTALLER_OWNERSHIP_KEY") || return 1
    links=$(stat -c '%h' -- "$INSTALLER_OWNERSHIP_KEY") || return 1
    [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || return 1
    mode=$(stat -c '%a' -- "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    owner=$(stat -c '%u' -- "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    links=$(stat -c '%h' -- "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    [[ "$mode" == 600 && "$owner" == "$(id -u)" && "$links" == 1 ]] || return 1
    if ! jq -e 'type == "object" and ((keys - ["schema_version", "installation_id", "resources", "hmac"]) | length == 0) and .schema_version == 1 and (.installation_id | type == "string" and test("^[A-Za-z0-9._-]+$")) and (.resources | type == "array" and length > 0 and all(.[]; type == "object" and ((keys - ["root", "path"]) | length == 0) and (.root | type == "string") and (.path | type == "string"))) and (.hmac | type == "string" and test("^[0-9a-f]{64}$"))' "$INSTALLER_OWNERSHIP_MANIFEST" >/dev/null; then
        return 1
    fi
    local key_hex expected payload actual root path role
    key_hex=$(od -An -v -tx1 "$INSTALLER_OWNERSHIP_KEY" | tr -d ' \n') || return 1
    payload=$(jq -c '{schema_version,installation_id,resources}' "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    expected=$(jq -r '.hmac // empty' "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    actual=$(printf '%s' "$payload" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" | awk '{print $NF}') || return 1
    [[ "$expected" == "$actual" ]] || return 1
    while IFS=$'\t' read -r root path; do
        role=$(installer_ownership_resource_role "$root" "$path") || true
        [[ "$role" != unknown ]] || return 1
    done < <(jq -r '.resources[] | [.root,.path] | @tsv' "$INSTALLER_OWNERSHIP_MANIFEST")
}

installer_write_ownership_manifest() {
    local installation_id="$1" resources="$2"
    local key_hex payload mac manifest temporary
    key_hex=$(od -An -v -tx1 "$INSTALLER_OWNERSHIP_KEY" | tr -d ' \n') || return 1
    payload=$(jq -cn --arg id "$installation_id" --argjson resources "$resources" \
        '{schema_version:1,installation_id:$id,resources:$resources}') || return 1
    mac=$(printf '%s' "$payload" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$key_hex" | awk '{print $NF}') || return 1
    manifest=$(printf '%s' "$payload" | jq -c --arg hmac "$mac" '. + {hmac:$hmac}') || return 1
    temporary=$(mktemp "$(dirname -- "$INSTALLER_OWNERSHIP_MANIFEST")/.ownership-manifest.XXXXXX") || return 1
    chmod 600 -- "$temporary"
    if ! printf '%s\n' "$manifest" >"$temporary" || ! mv -f -- "$temporary" "$INSTALLER_OWNERSHIP_MANIFEST"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 600 -- "$INSTALLER_OWNERSHIP_MANIFEST"
    installer_chown root:root "$INSTALLER_OWNERSHIP_MANIFEST"
}

installer_make_ownership_manifest() {
    local installation_id resources='[]'
    mkdir -p -- "$INSTALLER_DATA_DIR"
    chmod 700 -- "$INSTALLER_DATA_DIR"
    if [[ -e "$INSTALLER_OWNERSHIP_KEY" || -L "$INSTALLER_OWNERSHIP_KEY" ]]; then
        [[ -f "$INSTALLER_OWNERSHIP_KEY" && ! -L "$INSTALLER_OWNERSHIP_KEY" ]] || return 1
    else
        head -c 32 /dev/urandom >"$INSTALLER_OWNERSHIP_KEY"
    fi
    chmod 600 -- "$INSTALLER_OWNERSHIP_KEY"
    if [[ -e "$INSTALLER_OWNERSHIP_MANIFEST" ]]; then
        installer_manifest_validate || return 1
        installation_id=$(jq -r '.installation_id' "$INSTALLER_OWNERSHIP_MANIFEST")
        resources=$(jq -c '.resources' "$INSTALLER_OWNERSHIP_MANIFEST")
    else
        installation_id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    fi
    if installer_role_has_agent; then
        resources=$(jq -c \
            --arg root "$INSTALLER_INSTALL_DIR" \
            --arg data "$INSTALLER_DATA_DIR" \
            --arg config "$(dirname -- "$INSTALLER_CONFIG")" \
            --arg service "$INSTALLER_SERVICE_DIR" \
            --arg openrc "$INSTALLER_OPENRC_DIR" \
            --arg manager "$INSTALLER_SERVICE_MANAGER" \
            '$ARGS.positional as $r | . + [
              {root:$root,path:"bin/antinat-agent"},
              {root:$root,path:"bin/antinat-hook-runner"},
              {root:$data,path:"state.db"},
              {root:$data,path:"node.key"},
              {root:$data,path:".key.lock"},
              {root:$data,path:".lifecycle.lock"},
              {root:$data,path:"detection.profile"},
              {root:$data,path:".enrollment-token"},
              {root:$data,path:"terminal.marker"},
              {root:$data,path:"agent.marker"},
              {root:$config,path:"agent.conf"},
              (if $manager == "systemd" then {root:$service,path:"antinat-agent.service"} else {root:$openrc,path:"antinat-agent"} end)
            ] | unique_by([.root,.path])' <<<"$resources")
    fi
    if installer_role_has_controller; then
        resources=$(jq -c \
            --arg root "$INSTALLER_INSTALL_DIR" \
            --arg data "$INSTALLER_DATA_DIR" \
            --arg service "$INSTALLER_SERVICE_DIR" \
            --arg openrc "$INSTALLER_OPENRC_DIR" \
            --arg manager "$INSTALLER_SERVICE_MANAGER" \
            '. + [
              {root:$root,path:"bin/antinat-controller"},
              {root:$data,path:"controller.db"},
              {root:$data,path:"controller.db-wal"},
              {root:$data,path:"controller.db-shm"},
              {root:$data,path:"controller-keys"},
              (if $manager == "systemd" then {root:$service,path:"antinat-controller.service"} else {root:$openrc,path:"antinat-controller"} end)
            ] | unique_by([.root,.path])' <<<"$resources")
    fi
    resources=$(jq -c \
        --arg data "$INSTALLER_DATA_DIR" \
        --arg backup "$INSTALLER_BACKUP_DIR" \
        --arg logroot "$(dirname -- "$INSTALLER_LOG_DIR")" \
        --arg logname "$(basename -- "$INSTALLER_LOG_DIR")" \
        --arg service "$INSTALLER_SERVICE_DIR" \
        --arg openrc "$INSTALLER_OPENRC_DIR" \
        --arg manager "$INSTALLER_SERVICE_MANAGER" \
        '. + [
          {root:$data,path:"backups"},
          {root:$data,path:".upgrade.lock"},
          {root:$logroot,path:$logname},
          {root:$data,path:"schema.version"},
          {root:$data,path:"ownership-manifest.json"},
          {root:$data,path:"ownership.key"}
        ] | unique_by([.root,.path])' <<<"$resources")
    installer_write_ownership_manifest "$installation_id" "$resources"
}

installer_prepare_dirs() {
    mkdir -p -- "$INSTALLER_BIN_DIR" "$INSTALLER_DATA_DIR" "$INSTALLER_LOG_DIR" \
        "$(dirname -- "$INSTALLER_CONFIG")"
    if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
        mkdir -p -- "$INSTALLER_SERVICE_DIR"
    else
        mkdir -p -- "$INSTALLER_OPENRC_DIR"
    fi
    if installer_role_has_controller; then
        mkdir -p -- "$INSTALLER_CONTROLLER_KEY_DIR"
        chmod 700 -- "$INSTALLER_CONTROLLER_KEY_DIR"
        installer_chown antinat:antinat "$INSTALLER_CONTROLLER_KEY_DIR"
    fi
    chmod 755 -- "$INSTALLER_INSTALL_DIR" "$INSTALLER_BIN_DIR" "$INSTALLER_LOG_DIR"
    if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
        chmod 755 -- "$INSTALLER_SERVICE_DIR"
    else
        chmod 755 -- "$INSTALLER_OPENRC_DIR"
    fi
    chmod 700 -- "$INSTALLER_DATA_DIR"
    chmod 750 -- "$(dirname -- "$INSTALLER_CONFIG")"
    installer_chown antinat:antinat "$INSTALLER_DATA_DIR" "$INSTALLER_LOG_DIR"
}

installer_install_files() {
    if installer_role_has_agent; then
        if installer_copy_artifact "antinat-agent-linux-amd64" "$INSTALLER_AGENT_BINARY" 755; then
            :
        else
            installer_die "$INSTALLER_EXIT_ARTIFACT" "Linux Agent artifact is missing" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
    fi
    installer_write_schema_version || return "$INSTALLER_EXIT_GENERIC"
    if installer_role_has_controller; then
        if installer_copy_artifact "antinat-controller-linux-amd64" "$INSTALLER_CONTROLLER_BINARY" 755; then
            :
        else
            installer_die "$INSTALLER_EXIT_ARTIFACT" "Linux Controller artifact is missing" || true
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
    fi
    if installer_role_has_agent && jq -e --arg suffix "antinat-hook-runner-linux-amd64" '.artifacts | keys[] | select(endswith($suffix))' "$INSTALLER_MANIFEST_FILE" >/dev/null; then
        if installer_copy_artifact "antinat-hook-runner-linux-amd64" "$INSTALLER_HOOK_BINARY" 755; then
            :
        else
            return "$INSTALLER_EXIT_ARTIFACT"
        fi
    fi
}

installer_install_services() {
    if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
        if installer_role_has_controller; then
            installer_install_service_unit antinat-controller.service "$INSTALLER_CONTROLLER_UNIT" || return 1
        fi
        if installer_role_has_agent; then
            installer_install_service_unit antinat-agent.service "$INSTALLER_AGENT_UNIT" || return 1
        fi
        installer_systemctl daemon-reload
        if installer_role_has_controller; then
            installer_systemctl enable --now antinat-controller.service || return 1
        fi
        if installer_role_has_agent; then
            installer_systemctl enable --now "$INSTALLER_SERVICE_NAME" || return 1
        fi
        return 0
    fi
    if installer_role_has_controller; then
        installer_install_openrc_service antinat-controller || return 1
        installer_openrc add antinat-controller || return 1
    fi
    if installer_role_has_agent; then
        installer_install_openrc_service antinat-agent || return 1
        installer_openrc add antinat-agent || return 1
    fi
    if installer_role_has_controller; then
        installer_openrc start antinat-controller || return 1
    fi
    if installer_role_has_agent; then
        installer_openrc start antinat-agent || return 1
    fi
}

installer_start_services() {
    if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
        installer_systemctl daemon-reload || return 1
        if installer_role_has_controller && installer_systemd_unit_present antinat-controller.service; then
            if [[ "$INSTALLER_CONTROLLER_REENABLE" == 1 ]]; then
                installer_systemctl enable antinat-controller.service || return 1
            fi
            if [[ "$INSTALLER_CONTROLLER_WAS_ACTIVE" == 1 ]]; then
                installer_systemctl start antinat-controller.service || return 1
            fi
        fi
        if installer_role_has_agent && installer_systemd_unit_present "$INSTALLER_SERVICE_NAME"; then
            if [[ "$INSTALLER_AGENT_REENABLE" == 1 ]]; then
                installer_systemctl enable "$INSTALLER_SERVICE_NAME" || return 1
            fi
            if [[ "$INSTALLER_AGENT_WAS_ACTIVE" == 1 ]]; then
                installer_systemctl start "$INSTALLER_SERVICE_NAME" || return 1
            fi
        fi
        return 0
    fi
    if installer_role_has_controller && [[ -e "$INSTALLER_OPENRC_DIR/antinat-controller" ]]; then
        if [[ "$INSTALLER_CONTROLLER_WAS_ENABLED" == 1 ]]; then
            installer_openrc add antinat-controller || return 1
        fi
        if [[ "$INSTALLER_CONTROLLER_WAS_ACTIVE" == 1 ]]; then
            installer_openrc start antinat-controller || return 1
        fi
    fi
    if installer_role_has_agent && [[ -e "$INSTALLER_OPENRC_DIR/antinat-agent" ]]; then
        if [[ "$INSTALLER_AGENT_WAS_ENABLED" == 1 ]]; then
            installer_openrc add antinat-agent || return 1
        fi
        if [[ "$INSTALLER_AGENT_WAS_ACTIVE" == 1 ]]; then
            installer_openrc start antinat-agent || return 1
        fi
    fi
}

installer_wait_for_token_consumption() {
    [[ -n "$INSTALLER_TOKEN_TMP" ]] || return 0
    installer_test_fail_at enrollment && return "$INSTALLER_EXIT_TOKEN"
    [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    local i
    for ((i=0; i<30; i++)); do
        [[ ! -e "$INSTALLER_TOKEN_TMP" ]] && { installer_consume_source_token; return 0; }
        sleep 1
    done
    # Enrollment has not been proven. Preserve the source token and report a
    # token failure; the service can be inspected and retried by the operator.
    return "$INSTALLER_EXIT_TOKEN"
}

installer_conflict() {
    [[ "$INSTALLER_COMMAND" == install ]] || return 1
    if installer_role_has_agent && [[ -e "$INSTALLER_AGENT_BINARY" || -e "$INSTALLER_AGENT_UNIT" ]]; then
        return 0
    fi
    if installer_role_has_controller && [[ -e "$INSTALLER_CONTROLLER_BINARY" || -e "$INSTALLER_CONTROLLER_UNIT" ]]; then
        return 0
    fi
    return 1
}

installer_controller_port_available() {
    python3 - <<'PY'
import socket

try:
    connection = socket.create_connection(("127.0.0.1", 3111), timeout=0.25)
except OSError:
    raise SystemExit(0)
else:
    connection.close()
    raise SystemExit(1)
PY
}

installer_begin_install_transaction() {
    local snapshot
    snapshot=$(mktemp -d "${TMPDIR:-/tmp}/antinat-install.XXXXXX") || return 1
    chmod 700 -- "$snapshot"
    installer_chown root:root "$snapshot"
    INSTALLER_INSTALL_SNAPSHOT="$snapshot"
    if ! installer_snapshot_files "$snapshot" installer_install_resource_list || \
        ! installer_snapshot_install_directories "$snapshot"; then
        rm -rf -- "$snapshot"
        INSTALLER_INSTALL_SNAPSHOT=""
        return 1
    fi
}

installer_cleanup_install_snapshot() {
    local snapshot="$INSTALLER_INSTALL_SNAPSHOT"
    [[ -n "$snapshot" ]] || return 0
    installer_assert_private_metadata_dir "$snapshot" || return 1
    rm -rf -- "$snapshot" || return 1
    INSTALLER_INSTALL_SNAPSHOT=""
}

installer_install() {
    if installer_role_has_agent && ! installer_validate_endpoint "$INSTALLER_ENDPOINT"; then
        installer_die "$INSTALLER_EXIT_USAGE" "controller endpoint must be an http(s) URL without credentials, query or fragment" || true
        return "$INSTALLER_EXIT_USAGE"
    fi
    installer_require_linux_amd64 || return "$INSTALLER_EXIT_ARTIFACT"
    installer_init_paths
    installer_require_tools
    installer_fetch_release || return "$INSTALLER_EXIT_ARTIFACT"
    installer_verify_artifacts
    if installer_conflict; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "AntiNAT is already installed; use upgrade" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    if installer_role_has_controller && ! installer_controller_port_available; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "Controller listen port 127.0.0.1:3111 is already in use" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    if ! installer_begin_install_transaction; then
        return "$INSTALLER_EXIT_GENERIC"
    fi
    installer_create_user || {
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    }
    installer_prepare_dirs || {
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    }
    if ! installer_backup_schema_for_install; then
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    fi
    if installer_role_has_agent && [[ -n "$INSTALLER_TOKEN_FD" || -n "$INSTALLER_TOKEN_FILE" || "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
        installer_read_token || {
            installer_cleanup_token
            installer_rollback_new_install
            return "$INSTALLER_EXIT_TOKEN"
        }
    fi
    if installer_install_files; then
        :
    else
        local install_status=$?
        installer_cleanup_token
        installer_rollback_new_install
        return "${install_status:-$INSTALLER_EXIT_GENERIC}"
    fi
    local token_for_service="${INSTALLER_TOKEN_TMP:-}"
    if installer_role_has_agent; then
        installer_write_config "$token_for_service" || {
            installer_cleanup_token
            installer_rollback_new_install
            return "$INSTALLER_EXIT_GENERIC"
        }
    fi
    installer_install_services || {
        installer_cleanup_token
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    }
    if installer_role_has_agent; then
        installer_wait_for_token_consumption || {
            installer_cleanup_token
            installer_rollback_new_install
            return "$INSTALLER_EXIT_TOKEN"
        }
        if [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]]; then
            installer_consume_source_token || {
                installer_cleanup_token
                installer_rollback_new_install
                return "$INSTALLER_EXIT_TOKEN"
            }
        fi
        if [[ -n "$INSTALLER_TOKEN_TMP" ]]; then
            # The one-time path is only needed until enrollment commits. Keeping
            # it in the service environment would make every later restart try
            # to enroll against a file that the Agent already consumed.
            installer_write_config "" || {
                installer_cleanup_token
                installer_rollback_new_install
                return "$INSTALLER_EXIT_GENERIC"
            }
            if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
                installer_systemctl daemon-reload || true
            fi
        fi
    fi
    installer_cleanup_token
    if ! installer_make_ownership_manifest; then
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    fi
    installer_cleanup_schema_backup
    if installer_role_has_agent; then
        if ! chmod 600 -- "$INSTALLER_CONFIG" || ! installer_chown root:root "$INSTALLER_CONFIG"; then
            installer_rollback_new_install
            return "$INSTALLER_EXIT_GENERIC"
        fi
    fi
    # The manifest and HMAC key are installer authority, not Agent state. Keep
    # both root-owned so an Agent cannot authorize its own purge.
    if ! installer_chown root:root "$INSTALLER_OWNERSHIP_MANIFEST" "$INSTALLER_OWNERSHIP_KEY"; then
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    fi
    if ! installer_cleanup_install_snapshot; then
        installer_rollback_new_install
        return "$INSTALLER_EXIT_GENERIC"
    fi
    printf 'antinat installer: install complete\n'
}

installer_stop_service() {
    local failed=0
    if [[ "$INSTALLER_SERVICE_MANAGER" == openrc ]]; then
        if [[ -z "$INSTALLER_TEST_ROOT" && "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
            if installer_role_has_agent && [[ -e "$INSTALLER_OPENRC_DIR/antinat-agent" ]]; then
                if rc-service antinat-agent status >/dev/null 2>&1; then INSTALLER_AGENT_WAS_ACTIVE=1; fi
                if rc-update show default 2>/dev/null | awk '$1 == "antinat-agent" || $2 == "antinat-agent" { found=1 } END { exit !found }'; then
                    INSTALLER_AGENT_WAS_ENABLED=1
                fi
            fi
            if installer_role_has_controller && [[ -e "$INSTALLER_OPENRC_DIR/antinat-controller" ]]; then
                if rc-service antinat-controller status >/dev/null 2>&1; then INSTALLER_CONTROLLER_WAS_ACTIVE=1; fi
                if rc-update show default 2>/dev/null | awk '$1 == "antinat-controller" || $2 == "antinat-controller" { found=1 } END { exit !found }'; then
                    INSTALLER_CONTROLLER_WAS_ENABLED=1
                fi
            fi
        fi
        if installer_role_has_agent && [[ -e "$INSTALLER_OPENRC_DIR/antinat-agent" ]]; then
            installer_openrc stop antinat-agent || failed=1
            installer_openrc del antinat-agent || failed=1
        fi
        if installer_role_has_controller && [[ -e "$INSTALLER_OPENRC_DIR/antinat-controller" ]]; then
            installer_openrc stop antinat-controller || failed=1
            installer_openrc del antinat-controller || failed=1
        fi
    else
        local unit was_active was_enabled
        local units=()
        installer_role_has_agent && units+=("$INSTALLER_SERVICE_NAME")
        installer_role_has_controller && units+=(antinat-controller.service)
        for unit in "${units[@]}"; do
            if installer_systemd_unit_present "$unit"; then
                if [[ -n "$INSTALLER_TEST_ROOT" || "${ANTINAT_TEST_MODE:-0}" == 1 ]]; then
                    installer_systemctl stop "$unit" || failed=1
                    installer_systemctl disable "$unit" || failed=1
                else
                    was_active=0
                    was_enabled=0
                    if systemctl is-active --quiet "$unit"; then
                        was_active=1
                    fi
                    if systemctl is-enabled --quiet "$unit"; then
                        was_enabled=1
                    fi
                    if [[ "$unit" == "$INSTALLER_SERVICE_NAME" ]]; then
                        INSTALLER_AGENT_WAS_ACTIVE="$was_active"
                        INSTALLER_AGENT_WAS_ENABLED="$was_enabled"
                    elif [[ "$unit" == antinat-controller.service ]]; then
                        INSTALLER_CONTROLLER_WAS_ACTIVE="$was_active"
                        INSTALLER_CONTROLLER_WAS_ENABLED="$was_enabled"
                    fi
                    if ((was_active != 0)); then
                        systemctl stop "$unit" || failed=1
                    fi
                    if ((was_enabled != 0)); then
                        if [[ "$unit" == "$INSTALLER_SERVICE_NAME" ]]; then
                            INSTALLER_AGENT_REENABLE=1
                        elif [[ "$unit" == antinat-controller.service ]]; then
                            INSTALLER_CONTROLLER_REENABLE=1
                        fi
                        systemctl disable "$unit" || failed=1
                    fi
                fi
            fi
        done
        installer_systemctl daemon-reload || failed=1
    fi
    return "$failed"
}

installer_quiesce_services() {
    local failed=0
    if [[ "$INSTALLER_SERVICE_MANAGER" == openrc ]]; then
        if installer_role_has_agent && [[ -e "$INSTALLER_OPENRC_DIR/antinat-agent" ]]; then
            installer_openrc stop antinat-agent || failed=1
        fi
        if installer_role_has_controller && [[ -e "$INSTALLER_OPENRC_DIR/antinat-controller" ]]; then
            installer_openrc stop antinat-controller || failed=1
        fi
    else
        local unit
        local units=()
        installer_role_has_agent && units+=("$INSTALLER_SERVICE_NAME")
        installer_role_has_controller && units+=(antinat-controller.service)
        for unit in "${units[@]}"; do
            if installer_systemd_unit_present "$unit"; then
                installer_systemctl stop "$unit" || failed=1
            fi
        done
    fi
    return "$failed"
}

installer_remote_uninstall_notice() {
    # The running Agent owns the signed notice/receipt protocol. It accepts
    # only root peers on its private state-directory socket and returns success
    # only after the Controller's durable receipt reaches local state.
    [[ "${ANTINAT_TEST_MODE:-0}" == 1 ]] && return 0
    local action="${1:-uninstall}" operation_id socket response export_path
    [[ "$action" == uninstall || "$action" == purge ]] || return 1
    installer_role_has_agent || return 0
    # This root-only emergency override deliberately skips Controller delivery.
    # It is used when the Agent cannot provide a durable receipt and the
    # operator has explicitly accepted the offline decommission obligation.
    [[ "${ANTINAT_FORCE_OFFLINE_PURGE:-0}" == 1 ]] && return 0
    operation_id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    [[ "$operation_id" =~ ^[0-9a-f]{32}$ ]] || return 1
    socket="$INSTALLER_DATA_DIR/uninstall.sock"
    if [[ -S "$socket" && ! -L "$socket" ]]; then
        command -v curl >/dev/null 2>&1 || return 1
        command -v jq >/dev/null 2>&1 || return 1
        response=$(curl --fail --silent --show-error --max-time 35 \
            --unix-socket "$socket" \
            -H 'Content-Type: application/json' \
            --data-binary "{\"operation_id\":\"$operation_id\"}" \
            http://localhost/v1/uninstall-notice) || return 1
        jq -e --arg operation_id "$operation_id" \
            'type == "object" and keys == ["operation_id", "status"] and .operation_id == $operation_id and .status == "RECEIPTED"' \
            <<<"$response" >/dev/null || return 1
        return 0
    fi
    export_path="${ANTINAT_OFFLINE_EXPORT_FILE:-}"
    if [[ -n "$export_path" ]]; then
        umask 077
        printf '{"operation_id":"%s","status":"UNKNOWN","requested_action":"%s","action":"operator_review_required"}\n' "$operation_id" "$action" >"$export_path" || return 1
        printf 'antinat installer: offline uninstall notice exported; Controller decommission is still required\n' >&2
    fi
    return 1
}

installer_uninstall() {
    installer_init_paths
    installer_remote_uninstall_notice || return "$INSTALLER_EXIT_GENERIC"
    installer_stop_service || return "$INSTALLER_EXIT_GENERIC"
    if installer_role_has_agent; then
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-agent || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$INSTALLER_SERVICE_DIR" "$INSTALLER_SERVICE_NAME" || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$INSTALLER_OPENRC_DIR" antinat-agent || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$(dirname -- "$INSTALLER_CONFIG")" agent.conf || return "$INSTALLER_EXIT_GENERIC"
    fi
    if installer_role_has_controller; then
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-controller || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-controller.service || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$INSTALLER_OPENRC_DIR" antinat-controller || return "$INSTALLER_EXIT_GENERIC"
    fi
    printf 'antinat installer: service and executable files removed; state retained\n'
}

installer_safe_remove() {
    local root="$1" relative="$2"
    [[ "$root" == /* && "$relative" != /* && "$relative" != *".."* && "$relative" != *"\\"* ]] || return 1
    # Python's dir_fd APIs map directly to openat/unlinkat. The complete tree
    # is preflighted before the first unlink, and every component is opened
    # with O_NOFOLLOW, so a reparse/symlink replacement fails closed.
    python3 - "$root" "$relative" <<'PY'
import errno
import os
import stat
import sys

root, relative = sys.argv[1:]
parts = relative.split('/')
if not parts or any(not p or p in ('.', '..') for p in parts):
    raise OSError("unsafe ownership path")
if not os.path.isabs(root) or '\\' in relative:
    raise OSError("unsafe ownership path")

def open_child(parent, name):
    return os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent)

def inspect_at(parent, names):
    try:
        st = os.stat(names[0], dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise OSError("owned tree contains a link or special file")
    if len(names) > 1:
        if not stat.S_ISDIR(st.st_mode):
            raise OSError("owned parent is not a directory")
        child = open_child(parent, names[0])
        try:
            return inspect_at(child, names[1:])
        finally:
            os.close(child)
    if stat.S_ISDIR(st.st_mode):
        child = open_child(parent, names[0])
        try:
            for name in os.listdir(child):
                inspect_at(child, [name])
        finally:
            os.close(child)
    return True

def remove_at(parent, names):
    try:
        st = os.stat(names[0], dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise OSError("owned tree changed to a link or special file")
    if len(names) > 1:
        child = open_child(parent, names[0])
        try:
            removed = remove_at(child, names[1:])
        finally:
            os.close(child)
        return removed
    if stat.S_ISDIR(st.st_mode):
        child = open_child(parent, names[0])
        try:
            for name in os.listdir(child):
                remove_at(child, [name])
        finally:
            os.close(child)
        os.rmdir(names[0], dir_fd=parent)
    else:
        os.unlink(names[0], dir_fd=parent)
    return True

try:
    root_fd = os.open(root, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY)
except FileNotFoundError:
    raise SystemExit(0)
try:
    if inspect_at(root_fd, parts):
        remove_at(root_fd, parts)
    os.fsync(root_fd)
finally:
    os.close(root_fd)
PY
}

installer_rollback_new_install() {
    local failed=0
    installer_stop_service || failed=1
    if [[ -n "$INSTALLER_INSTALL_SNAPSHOT" ]]; then
        installer_cleanup_schema_backup
        if installer_restore_snapshot "$INSTALLER_INSTALL_SNAPSHOT" && \
            installer_restore_install_directories "$INSTALLER_INSTALL_SNAPSHOT"; then
            installer_cleanup_install_snapshot || failed=1
        else
            printf 'antinat installer: install rollback snapshot retained at %s\n' "$INSTALLER_INSTALL_SNAPSHOT" >&2
            failed=1
        fi
        rmdir -- "$INSTALLER_BIN_DIR" 2>/dev/null || true
        rmdir -- "$INSTALLER_INSTALL_DIR" 2>/dev/null || true
        rmdir -- "$INSTALLER_SERVICE_DIR" 2>/dev/null || true
        rmdir -- "$INSTALLER_OPENRC_DIR" 2>/dev/null || true
        rmdir -- "$(dirname -- "$INSTALLER_CONFIG")" 2>/dev/null || true
        rmdir -- "$INSTALLER_DATA_DIR" 2>/dev/null || true
        rmdir -- "$INSTALLER_LOG_DIR" 2>/dev/null || true
        return "$failed"
    fi
    if installer_role_has_agent; then
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-agent || true
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner || true
        installer_safe_remove "$INSTALLER_DATA_DIR" state.db || true
        installer_safe_remove "$INSTALLER_DATA_DIR" node.key || true
        installer_safe_remove "$INSTALLER_DATA_DIR" terminal.marker || true
        installer_safe_remove "$INSTALLER_DATA_DIR" agent.marker || true
        installer_safe_remove "$(dirname -- "$INSTALLER_CONFIG")" agent.conf || true
        installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-agent.service || true
        installer_safe_remove "$INSTALLER_OPENRC_DIR" antinat-agent || true
    fi
    if installer_role_has_controller; then
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-controller || true
        installer_safe_remove "$INSTALLER_DATA_DIR" controller.db || true
        installer_safe_remove "$INSTALLER_DATA_DIR" controller.db-wal || true
        installer_safe_remove "$INSTALLER_DATA_DIR" controller.db-shm || true
        installer_safe_remove "$INSTALLER_DATA_DIR" controller-keys || true
        installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-controller.service || true
        installer_safe_remove "$INSTALLER_OPENRC_DIR" antinat-controller || true
    fi
    # A failed role install must not destroy shared ownership state or a schema
    # marker that belongs to a role already installed on the same host.
    if [[ ! -e "$INSTALLER_INSTALL_DIR/bin/antinat-agent" && ! -e "$INSTALLER_INSTALL_DIR/bin/antinat-controller" ]]; then
        installer_safe_remove "$INSTALLER_DATA_DIR" ownership-manifest.json || true
        installer_safe_remove "$INSTALLER_DATA_DIR" ownership.key || true
    fi
    if [[ "$INSTALLER_SCHEMA_EXISTED_BEFORE_INSTALL" == 1 ]]; then
        # If the backup could not be created, no install resource has been
        # written yet; preserve the existing marker in that failure case.
        if [[ -n "$INSTALLER_SCHEMA_BACKUP" ]]; then
            installer_restore_install_schema || failed=1
        fi
    else
        installer_safe_remove "$INSTALLER_DATA_DIR" schema.version || true
    fi
    installer_cleanup_schema_backup
    rmdir -- "$INSTALLER_BIN_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_INSTALL_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_SERVICE_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_OPENRC_DIR" 2>/dev/null || true
    rmdir -- "$(dirname -- "$INSTALLER_CONFIG")" 2>/dev/null || true
    rmdir -- "$INSTALLER_DATA_DIR" 2>/dev/null || true
    return "$failed"
}

installer_fallback_purge() {
    if installer_role_has_agent; then
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-agent || return 1
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" terminal.marker || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" agent.marker || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" state.db || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" node.key || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" .key.lock || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" .lifecycle.lock || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" detection.profile || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" .enrollment-token || return 1
        installer_safe_remove "$(dirname -- "$INSTALLER_CONFIG")" agent.conf || return 1
        installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-agent.service || return 1
        installer_safe_remove "$INSTALLER_OPENRC_DIR" antinat-agent || return 1
    fi
    if installer_role_has_controller; then
        installer_safe_remove "$INSTALLER_INSTALL_DIR" bin/antinat-controller || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" controller.db || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" controller.db-wal || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" controller.db-shm || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" controller-keys || return 1
        installer_safe_remove "$INSTALLER_SERVICE_DIR" antinat-controller.service || return 1
        installer_safe_remove "$INSTALLER_OPENRC_DIR" antinat-controller || return 1
    fi
    if [[ ! -e "$INSTALLER_INSTALL_DIR/bin/antinat-agent" && ! -e "$INSTALLER_INSTALL_DIR/bin/antinat-controller" ]]; then
        installer_safe_remove "$INSTALLER_DATA_DIR" schema.version || return 1
    fi
    installer_safe_remove "$INSTALLER_DATA_DIR" .upgrade.lock || return 1
    installer_safe_remove "$(dirname -- "$INSTALLER_LOG_DIR")" "$(basename -- "$INSTALLER_LOG_DIR")" || return 1
}

installer_manifest_purge() {
    installer_manifest_validate || return 1
    local installation_id resources remaining='[]' root path class keep_other=0 remove
    installation_id=$(jq -r '.installation_id' "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    resources=$(jq -c '.resources' "$INSTALLER_OWNERSHIP_MANIFEST") || return 1
    while IFS=$'\t' read -r root path; do
        class=$(installer_ownership_resource_role "$root" "$path") || true
        if [[ "$class" == agent ]] && ! installer_role_has_agent; then
            keep_other=1
        elif [[ "$class" == controller ]] && ! installer_role_has_controller; then
            keep_other=1
        fi
    done < <(jq -r '.resources[] | [.root,.path] | @tsv' "$INSTALLER_OWNERSHIP_MANIFEST")
    while IFS=$'\t' read -r root path; do
        class=$(installer_ownership_resource_role "$root" "$path") || true
        remove=0
        if [[ "$class" == agent ]] && installer_role_has_agent; then
            remove=1
        elif [[ "$class" == controller ]] && installer_role_has_controller; then
            remove=1
        elif [[ "$class" == shared && "$keep_other" == 0 ]]; then
            remove=1
        fi
        if [[ "$remove" == 1 ]]; then
            if [[ "$class" != shared || ("$path" != ownership-manifest.json && "$path" != ownership.key) ]]; then
                installer_safe_remove "$root" "$path" || return 1
            fi
        else
            remaining=$(jq -c --arg root "$root" --arg path "$path" '. + [{root:$root,path:$path}]' <<<"$remaining") || return 1
        fi
    done < <(jq -r '.resources[] | [.root,.path] | @tsv' "$INSTALLER_OWNERSHIP_MANIFEST")
    if [[ "$keep_other" == 1 ]]; then
        installer_write_ownership_manifest "$installation_id" "$remaining" || return 1
    else
        installer_safe_remove "$INSTALLER_DATA_DIR" ownership.key || return 1
        installer_safe_remove "$INSTALLER_DATA_DIR" ownership-manifest.json || return 1
    fi
    INSTALLER_PURGE_KEEP_OTHER="$keep_other"
}

installer_purge() {
    installer_init_paths
    installer_remote_uninstall_notice purge || return "$INSTALLER_EXIT_GENERIC"
    installer_stop_service || return "$INSTALLER_EXIT_GENERIC"
    local used_manifest=1
    INSTALLER_PURGE_KEEP_OTHER=0
    if ! installer_manifest_purge; then
        used_manifest=0
        printf 'antinat installer: ownership manifest unavailable or invalid; using compile-time allowlist only\n' >&2
        installer_fallback_purge || return "$INSTALLER_EXIT_GENERIC"
    fi
    if installer_role_has_agent; then
        # Existing signed ownership manifests predate these Agent runtime files.
        installer_safe_remove "$INSTALLER_DATA_DIR" detection.profile || return "$INSTALLER_EXIT_GENERIC"
        installer_safe_remove "$INSTALLER_DATA_DIR" .enrollment-token || return "$INSTALLER_EXIT_GENERIC"
    fi
    # Empty parent directories are safe to remove only when they contain no
    # user files. Never use recursive deletion for these shared parents.
    rmdir -- "$INSTALLER_BIN_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_INSTALL_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_SERVICE_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_OPENRC_DIR" 2>/dev/null || true
    rmdir -- "$(dirname -- "$INSTALLER_CONFIG")" 2>/dev/null || true
    rmdir -- "$INSTALLER_DATA_DIR" 2>/dev/null || true
    rmdir -- "$INSTALLER_LOG_DIR" 2>/dev/null || true
    if ((used_manifest == 0)); then
        printf 'antinat installer: remote decommission status is unknown; verify Controller-side purge separately\n' >&2
        printf 'antinat installer: purge complete; allowlisted role resources removed, ownership metadata retained because the manifest was not authenticated\n'
    elif ((INSTALLER_PURGE_KEEP_OTHER == 1)); then
        printf 'antinat installer: current role purge complete; another role and shared ownership state remain\n'
    else
        printf 'antinat installer: purge complete; no owned residue remains\n'
    fi
    return "$INSTALLER_EXIT_PURGE"
}

installer_snapshot_copy() {
    local source="$1" destination="$2"
    mkdir -p -- "$(dirname -- "$destination")"
    python3 - "$source" "$destination" <<'PY'
import os
import stat
import sys
import tempfile

source, destination = sys.argv[1:]

def reject(st):
    if stat.S_ISLNK(st.st_mode) or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
        raise OSError("snapshot resource contains a link or special file")

def copy_entry(source_parent, source_name, destination_parent, destination_name):
    source_stat = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
    reject(source_stat)
    mode = stat.S_IMODE(source_stat.st_mode)
    if stat.S_ISDIR(source_stat.st_mode):
        os.mkdir(destination_name, mode=mode, dir_fd=destination_parent)
        source_dir = os.open(source_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=source_parent)
        destination_dir = os.open(destination_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=destination_parent)
        try:
            for child in os.listdir(source_dir):
                copy_entry(source_dir, child, destination_dir, child)
            os.fsync(destination_dir)
        finally:
            os.close(source_dir)
            os.close(destination_dir)
        return
    source_fd = os.open(source_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=source_parent)
    temporary_path = None
    temporary_fd = -1
    try:
        current = os.fstat(source_fd)
        if not stat.S_ISREG(current.st_mode):
            raise OSError("snapshot source changed to a non-regular file")
        temporary_fd, temporary_path = tempfile.mkstemp(prefix=".antinat-snapshot-", dir=os.path.dirname(os.path.abspath(destination)))
        os.fchmod(temporary_fd, mode)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_fd, view)
                view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        staged_path = os.path.join(os.path.dirname(os.path.abspath(destination)), os.path.basename(temporary_path))
        os.replace(staged_path, destination_name, dst_dir_fd=destination_parent)
        temporary_path = None
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        os.close(source_fd)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass

source_stat = os.lstat(source)
reject(source_stat)
destination_parent_path = os.path.dirname(destination) or "."
destination_name = os.path.basename(destination)
destination_parent = os.open(destination_parent_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    if stat.S_ISDIR(source_stat.st_mode):
        os.mkdir(destination_name, mode=stat.S_IMODE(source_stat.st_mode), dir_fd=destination_parent)
        source_parent = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        destination_dir = os.open(destination_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=destination_parent)
        try:
            for child in os.listdir(source_parent):
                copy_entry(source_parent, child, destination_dir, child)
            os.fsync(destination_dir)
        finally:
            os.close(source_parent)
            os.close(destination_dir)
    else:
        source_parent = os.open(os.path.dirname(source) or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            copy_entry(source_parent, os.path.basename(source), destination_parent, destination_name)
        finally:
            os.close(source_parent)
    os.fsync(destination_parent)
finally:
    os.close(destination_parent)
PY
}

installer_assert_private_metadata_dir() {
    local path="$1"
    [[ -d "$path" && ! -L "$path" ]] || return 1
    local metadata mode owner links
    metadata=$(stat -c '%a:%u:%h' -- "$path" 2>/dev/null) || return 1
    IFS=: read -r mode owner links <<<"$metadata"
    [[ "$mode" == 700 && "$owner" == 0 && "$links" =~ ^[0-9]+$ && "$links" -ge 2 ]]
}

installer_assert_private_metadata_file() {
    local path="$1"
    [[ -f "$path" && ! -L "$path" ]] || return 1
    [[ "$(stat -c '%a:%u:%h' -- "$path" 2>/dev/null)" == 600:0:1 ]] || return 1
}

installer_snapshot_matches() {
    local current="$1" backup="$2"
    python3 - "$current" "$backup" <<'PY'
import hashlib
import os
import stat
import sys

left, right = sys.argv[1:]

def compare(a, b):
    sa, sb = os.lstat(a), os.lstat(b)
    if stat.S_IMODE(sa.st_mode) != stat.S_IMODE(sb.st_mode) or stat.S_ISLNK(sa.st_mode) or stat.S_ISLNK(sb.st_mode):
        return False
    if stat.S_ISREG(sa.st_mode) != stat.S_ISREG(sb.st_mode) or stat.S_ISDIR(sa.st_mode) != stat.S_ISDIR(sb.st_mode):
        return False
    if stat.S_ISREG(sa.st_mode):
        digest_a, digest_b = hashlib.sha256(), hashlib.sha256()
        with open(a, "rb", buffering=0) as fa, open(b, "rb", buffering=0) as fb:
            while True:
                ca, cb = fa.read(1024 * 1024), fb.read(1024 * 1024)
                if ca != cb:
                    return False
                if not ca:
                    break
                digest_a.update(ca)
                digest_b.update(cb)
        return digest_a.digest() == digest_b.digest()
    if not stat.S_ISDIR(sa.st_mode):
        return False
    names_a, names_b = sorted(os.listdir(a)), sorted(os.listdir(b))
    return names_a == names_b and all(compare(os.path.join(a, n), os.path.join(b, n)) for n in names_a)

raise SystemExit(0 if compare(left, right) else 1)
PY
}

installer_snapshot_files() {
    local backup="$1" resource_list="${2:-installer_upgrade_resource_list}"
    mkdir -p -- "$backup"
    chmod 700 -- "$backup"
    installer_chown root:root "$backup"
    local metadata_tmp="$backup/.snapshot.tsv.tmp" metadata="$backup/snapshot.tsv"
    : >"$metadata_tmp"
    chmod 600 -- "$metadata_tmp"
    local root relative source destination kind mode uid gid index=0
    while IFS=$'\t' read -r root relative; do
        source="$root/$relative"
        if [[ -e "$source" || -L "$source" ]]; then
            [[ ! -L "$source" ]] || return 1
            if [[ -d "$source" ]]; then
                kind=directory
            elif [[ -f "$source" ]]; then
                kind=file
            else
                return 1
            fi
            mode=$(stat -c '%a' -- "$source") || return 1
            uid=$(stat -c '%u' -- "$source") || return 1
            gid=$(stat -c '%g' -- "$source") || return 1
            destination="$backup/file-$index"
            installer_snapshot_copy "$source" "$destination" || return 1
            printf '1\t%s\t%s\t%s\t%s\t%s\t%s\tfile-%s\n' "$kind" "$root" "$relative" "$mode" "$uid" "$gid" "$index" >>"$metadata_tmp"
        else
            printf '0\tnone\t%s\t%s\t-\t-\t-\t-\n' "$root" "$relative" >>"$metadata_tmp"
        fi
        index=$((index + 1))
    done < <("$resource_list")
    mv -f -- "$metadata_tmp" "$metadata"
    chmod 600 -- "$metadata"
    installer_chown root:root "$metadata"
}

installer_install_resource_list() {
    installer_upgrade_resource_list
    printf '%s\t%s\n' "$(dirname -- "$INSTALLER_LOG_DIR")" "$(basename -- "$INSTALLER_LOG_DIR")"
}

installer_install_directory_list() {
    printf '%s\n' "$INSTALLER_BIN_DIR"
    printf '%s\n' "$INSTALLER_INSTALL_DIR"
    printf '%s\n' "$INSTALLER_DATA_DIR"
    printf '%s\n' "$INSTALLER_LOG_DIR"
    printf '%s\n' "$(dirname -- "$INSTALLER_CONFIG")"
    if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
        printf '%s\n' "$INSTALLER_SERVICE_DIR"
    else
        printf '%s\n' "$INSTALLER_OPENRC_DIR"
    fi
}

installer_snapshot_install_directories() {
    local backup="$1"
    local metadata="$backup/directories.tsv" temporary="$backup/.directories.tsv.tmp"
    local path mode uid gid
    : >"$temporary"
    chmod 600 -- "$temporary"
    while IFS= read -r path; do
        if [[ -e "$path" || -L "$path" ]]; then
            [[ -d "$path" && ! -L "$path" ]] || return 1
            mode=$(stat -c '%a' -- "$path") || return 1
            uid=$(stat -c '%u' -- "$path") || return 1
            gid=$(stat -c '%g' -- "$path") || return 1
            printf '1\t%s\t%s\t%s\t%s\n' "$mode" "$uid" "$gid" "$path" >>"$temporary"
        else
            printf '0\t-\t-\t-\t%s\n' "$path" >>"$temporary"
        fi
    done < <(installer_install_directory_list)
    mv -f -- "$temporary" "$metadata"
    chmod 600 -- "$metadata"
    installer_chown root:root "$metadata"
}

installer_restore_install_directories() {
    local backup="$1" present mode uid gid path extra failed=0
    installer_assert_private_metadata_file "$backup/directories.tsv" || return 1
    while IFS=$'\t' read -r present mode uid gid path extra; do
        [[ -z "${extra:-}" && "$path" == /* && "$path" != *$'\n'* ]] || return 1
        if [[ "$present" == 0 ]]; then
            [[ "$mode" == - && "$uid" == - && "$gid" == - ]] || return 1
            if [[ -e "$path" || -L "$path" ]]; then
                [[ -d "$path" && ! -L "$path" ]] || { failed=1; continue; }
                rmdir -- "$path" 2>/dev/null || failed=1
            fi
            continue
        fi
        [[ "$present" == 1 && "$mode" =~ ^[0-7]{3,4}$ && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return 1
        [[ -d "$path" && ! -L "$path" ]] || { failed=1; continue; }
        chmod "$mode" -- "$path" || failed=1
        installer_chown "$uid:$gid" "$path" || failed=1
    done <"$backup/directories.tsv"
    return "$failed"
}

installer_upgrade_resource_list() {
    if installer_role_has_agent; then
        printf '%s\t%s\n' "$INSTALLER_INSTALL_DIR" bin/antinat-agent
        printf '%s\t%s\n' "$INSTALLER_INSTALL_DIR" bin/antinat-hook-runner
        printf '%s\t%s\n' "$(dirname -- "$INSTALLER_CONFIG")" agent.conf
        if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
            printf '%s\t%s\n' "$INSTALLER_SERVICE_DIR" antinat-agent.service
        else
            printf '%s\t%s\n' "$INSTALLER_OPENRC_DIR" antinat-agent
        fi
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" state.db
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" node.key
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" .key.lock
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" .lifecycle.lock
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" terminal.marker
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" agent.marker
    fi
    if installer_role_has_controller; then
        printf '%s\t%s\n' "$INSTALLER_INSTALL_DIR" bin/antinat-controller
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" controller.db
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" controller.db-wal
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" controller.db-shm
        printf '%s\t%s\n' "$INSTALLER_DATA_DIR" controller-keys
        if [[ "$INSTALLER_SERVICE_MANAGER" == systemd ]]; then
            printf '%s\t%s\n' "$INSTALLER_SERVICE_DIR" antinat-controller.service
        else
            printf '%s\t%s\n' "$INSTALLER_OPENRC_DIR" antinat-controller
        fi
    fi
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" schema.version
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" .upgrade.lock
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" ownership-manifest.json
    printf '%s\t%s\n' "$INSTALLER_DATA_DIR" ownership.key
}

installer_verify_snapshot_state() {
    local backup="$1" present kind root relative mode uid gid backup_name extra current
    installer_assert_private_metadata_dir "$backup" || return 1
    installer_assert_private_metadata_file "$backup/snapshot.tsv" || return 1
    while IFS=$'\t' read -r present kind root relative mode uid gid backup_name extra; do
        [[ -z "${extra:-}" ]] || return 1
        current="$root/$relative"
        if [[ "$present" == 0 ]]; then
            [[ "$kind" == none && "$mode" == - && "$uid" == - && "$gid" == - && "$backup_name" == - ]] || return 1
            [[ ! -e "$current" && ! -L "$current" ]] || return 1
            continue
        fi
        [[ "$backup_name" =~ ^file-[0-9]+$ ]] || return 1
        [[ -e "$current" && ! -L "$current" && -e "$backup/$backup_name" && ! -L "$backup/$backup_name" ]] || return 1
        if [[ "$kind" == directory ]]; then
            [[ -d "$current" ]] || return 1
        elif [[ "$kind" == file ]]; then
            [[ -f "$current" ]] || return 1
        else
            return 1
        fi
        [[ "$(stat -c '%a' -- "$current")" == "$mode" ]] || return 1
        [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return 1
        [[ "$(stat -c '%u:%g' -- "$current")" == "$uid:$gid" ]] || return 1
        installer_snapshot_matches "$current" "$backup/$backup_name" || return 1
        if [[ "$kind" == directory ]]; then
            installer_verify_snapshot_ownership "$current" "$uid" "$gid" || return 1
        fi
    done <"$backup/snapshot.tsv"
}

installer_verify_snapshot_ownership() {
    local path="$1" uid="$2" gid="$3"
    python3 - "$path" "$uid" "$gid" <<'PY'
import os
import stat
import sys

path, expected_uid, expected_gid = sys.argv[1:]
expected_uid, expected_gid = int(expected_uid), int(expected_gid)
for root, directories, files in os.walk(path, followlinks=False):
    for name in directories + files:
        child = os.path.join(root, name)
        info = os.lstat(child)
        if stat.S_ISLNK(info.st_mode) or info.st_uid != expected_uid or info.st_gid != expected_gid:
            raise SystemExit(1)
raise SystemExit(0)
PY
}

installer_restore_snapshot() {
    local backup="$1"
    local present kind root relative mode uid gid backup_name extra source destination
    installer_verify_snapshot_state "$backup" 2>/dev/null && return 0
    [[ -f "$backup/snapshot.tsv" && ! -L "$backup/snapshot.tsv" ]] || return 1
    while IFS=$'\t' read -r present kind root relative mode uid gid backup_name extra; do
        [[ -z "${extra:-}" ]] || return 1
        source="$root/$relative"
        destination="$backup/$backup_name"
        if [[ "$present" == 0 ]]; then
            [[ "$kind" == none && "$mode" == - && "$uid" == - && "$gid" == - && "$backup_name" == - ]] || return 1
            installer_safe_remove "$root" "$relative" || return 1
        elif [[ "$kind" == directory ]]; then
            [[ -d "$destination" && ! -L "$destination" ]] || return 1
            installer_safe_remove "$root" "$relative" || return 1
            installer_snapshot_copy "$destination" "$source" || return 1
            installer_chown -R "$uid:$gid" "$source" || return 1
        elif [[ "$kind" == file ]]; then
            [[ -f "$destination" && ! -L "$destination" ]] || return 1
            installer_atomic_copy "$destination" "$source" "$mode" || return 1
            installer_chown "$uid:$gid" "$source" || return 1
        else
            return 1
        fi
    done <"$backup/snapshot.tsv"
    installer_verify_snapshot_state "$backup"
}

installer_upgrade_journal_write() {
    local backup="$1" state="$2" completed="${3:-[]}" error_message="${4:-}"
    local temporary journal agent_active=false controller_active=false agent_enabled=false controller_enabled=false
    installer_assert_private_metadata_dir "$backup" || return 1
    installer_assert_private_metadata_file "$backup/snapshot.tsv" || return 1
    jq -e 'type == "array" and all(.[]; type == "string")' <<<"$completed" >/dev/null || return 1
    [[ "$INSTALLER_AGENT_WAS_ACTIVE" == 1 ]] && agent_active=true
    [[ "$INSTALLER_CONTROLLER_WAS_ACTIVE" == 1 ]] && controller_active=true
    [[ "$INSTALLER_AGENT_WAS_ENABLED" == 1 ]] && agent_enabled=true
    [[ "$INSTALLER_CONTROLLER_WAS_ENABLED" == 1 ]] && controller_enabled=true
    temporary=$(mktemp "$backup/.transaction.XXXXXX") || return 1
    chmod 600 -- "$temporary"
    installer_chown root:root "$temporary"
    if ! journal=$(jq -cn \
        --arg schema "antinat.shell-upgrade/v1" \
        --arg live "$INSTALLER_INSTALL_DIR" \
        --arg backup "$backup" \
        --arg state "$state" \
        --arg error "$error_message" \
        --argjson agent_active "$agent_active" \
        --argjson controller_active "$controller_active" \
        --argjson agent_enabled "$agent_enabled" \
        --argjson controller_enabled "$controller_enabled" \
        --argjson completed "$completed" \
        '{schema:$schema,live_root:$live,backup_path:$backup,snapshot:"snapshot.tsv",state:$state,completed:$completed,agent_was_active:$agent_active,controller_was_active:$controller_active,agent_was_enabled:$agent_enabled,controller_was_enabled:$controller_enabled} + (if $error == "" then {} else {error:$error} end)'); then
        rm -f -- "$temporary"
        return 1
    fi
    if ! printf '%s\n' "$journal" >"$temporary" || ! mv -f -- "$temporary" "$backup/transaction.json"; then
        rm -f -- "$temporary"
        return 1
    fi
    chmod 600 -- "$backup/transaction.json"
    installer_chown root:root "$backup/transaction.json"
    sync -d "$backup" 2>/dev/null || sync
}

installer_upgrade_resource_allowed() {
    local root="$1" relative="$2" allowed_root allowed_relative
    while IFS=$'\t' read -r allowed_root allowed_relative; do
        if [[ "$root" == "$allowed_root" && "$relative" == "$allowed_relative" ]]; then
            return 0
        fi
    done < <(installer_upgrade_resource_list)
    return 1
}

installer_validate_upgrade_snapshot_inputs() {
    local backup="$1" present kind root relative mode uid gid backup_name extra key backup_path
    installer_assert_private_metadata_dir "$backup" || return 1
    installer_assert_private_metadata_file "$backup/snapshot.tsv" || return 1
    declare -A expected_resources=() seen_resources=() seen_backups=()
    while IFS=$'\t' read -r root relative; do
        [[ -n "$root" && -n "$relative" ]] || return 1
        key="${root}"$'\t'"${relative}"
        expected_resources["$key"]=1
    done < <(installer_upgrade_resource_list)
    local expected_count=${#expected_resources[@]} seen_count=0
    while IFS=$'\t' read -r present kind root relative mode uid gid backup_name extra; do
        [[ -z "${extra:-}" ]] || return 1
        [[ "$present" == 0 || "$present" == 1 ]] || return 1
        key="${root}"$'\t'"${relative}"
        [[ -n "${expected_resources[$key]+present}" && -z "${seen_resources[$key]+present}" ]] || return 1
        seen_resources["$key"]=1
        seen_count=$((seen_count + 1))
        [[ "$relative" != /* && "$relative" != *".."* && "$relative" != *"\\"* ]] || return 1
        if [[ "$present" == 1 ]]; then
            [[ "$kind" == file || "$kind" == directory ]] || return 1
            [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
            [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || return 1
            [[ "$backup_name" =~ ^file-[0-9]+$ ]] || return 1
            [[ -z "${seen_backups[$backup_name]+present}" ]] || return 1
            seen_backups["$backup_name"]=1
            backup_path="$backup/$backup_name"
            [[ -e "$backup_path" && ! -L "$backup_path" ]] || return 1
            if [[ "$kind" == directory ]]; then
                [[ -d "$backup_path" ]] || return 1
            else
                [[ -f "$backup_path" ]] || return 1
            fi
        else
            [[ "$kind" == none && "$mode" == - && "$uid" == - && "$gid" == - && "$backup_name" == - ]] || return 1
        fi
    done <"$backup/snapshot.tsv"
    [[ "$seen_count" == "$expected_count" ]] || return 1
    for key in "${!expected_resources[@]}"; do
        [[ -n "${seen_resources[$key]+present}" ]] || return 1
    done
}

installer_recover_interrupted_upgrades() {
    [[ -d "$INSTALLER_BACKUP_DIR" && ! -L "$INSTALLER_BACKUP_DIR" ]] || return 0
    local candidate journal state live backup snapshot
    for candidate in "$INSTALLER_BACKUP_DIR"/upgrade.*; do
        [[ -d "$candidate" && ! -L "$candidate" ]] || continue
        installer_assert_private_metadata_dir "$candidate" || return 1
        journal="$candidate/transaction.json"
        [[ -f "$journal" && ! -L "$journal" ]] || continue
        installer_assert_private_metadata_file "$journal" || return 1
        if ! jq -e 'type == "object" and ((keys - ["schema","live_root","backup_path","snapshot","state","completed","agent_was_active","controller_was_active","agent_was_enabled","controller_was_enabled","error"]) | length == 0) and .schema == "antinat.shell-upgrade/v1" and (.completed | type == "array" and all(.[]; type == "string")) and (.agent_was_active | type == "boolean") and (.controller_was_active | type == "boolean") and (.agent_was_enabled | type == "boolean") and (.controller_was_enabled | type == "boolean")' "$journal" >/dev/null; then
            return 1
        fi
        live=$(jq -r '.live_root' "$journal") || return 1
        backup=$(jq -r '.backup_path' "$journal") || return 1
        snapshot=$(jq -r '.snapshot' "$journal") || return 1
        [[ "$live" == "$INSTALLER_INSTALL_DIR" && "$backup" == "$candidate" && "$snapshot" == snapshot.tsv ]] || return 1
        state=$(jq -r '.state' "$journal") || return 1
        case "$state" in
            complete|rolled_back|recovered) continue ;;
            snapshot_ready|promoting|promoted|migrating|health_checking|rollback_in_progress) ;;
            *) return 1 ;;
        esac
        if [[ "$(jq -r '.agent_was_active' "$journal")" == true ]]; then INSTALLER_AGENT_WAS_ACTIVE=1; else INSTALLER_AGENT_WAS_ACTIVE=0; fi
        if [[ "$(jq -r '.controller_was_active' "$journal")" == true ]]; then INSTALLER_CONTROLLER_WAS_ACTIVE=1; else INSTALLER_CONTROLLER_WAS_ACTIVE=0; fi
        if [[ "$(jq -r '.agent_was_enabled' "$journal")" == true ]]; then INSTALLER_AGENT_WAS_ENABLED=1; INSTALLER_AGENT_REENABLE=1; else INSTALLER_AGENT_WAS_ENABLED=0; INSTALLER_AGENT_REENABLE=0; fi
        if [[ "$(jq -r '.controller_was_enabled' "$journal")" == true ]]; then INSTALLER_CONTROLLER_WAS_ENABLED=1; INSTALLER_CONTROLLER_REENABLE=1; else INSTALLER_CONTROLLER_WAS_ENABLED=0; INSTALLER_CONTROLLER_REENABLE=0; fi
        installer_validate_upgrade_snapshot_inputs "$candidate" || return 1
        installer_restore_snapshot "$candidate" || return 1
        installer_verify_snapshot_state "$candidate" || return 1
        installer_upgrade_journal_write "$candidate" recovered "$(jq -c '.completed' "$journal")" 'interrupted upgrade restored before retry' || return 1
    done
}

installer_acquire_upgrade_lock() {
    local lock="$INSTALLER_DATA_DIR/.upgrade.lock" fd
    mkdir -p -- "$INSTALLER_DATA_DIR"
    exec {fd}>>"$lock" || return 1
    chmod 600 -- "$lock" || { exec {fd}>&-; return 1; }
    installer_chown root:root "$lock" || { exec {fd}>&-; return 1; }
    if ! flock -n "$fd"; then
        exec {fd}>&-
        return 1
    fi
    printf '%s\n' 'upgrade advisory barrier' >&"$fd"
    INSTALLER_UPGRADE_LOCK_FD="$fd"
}

installer_release_upgrade_lock() {
    if [[ -n "$INSTALLER_UPGRADE_LOCK_FD" ]]; then
        local fd="$INSTALLER_UPGRADE_LOCK_FD"
        flock -u "$fd" 2>/dev/null || true
        exec {fd}>&-
        INSTALLER_UPGRADE_LOCK_FD=""
    fi
}

installer_upgrade() {
    installer_init_paths
    installer_require_linux_amd64 || return "$INSTALLER_EXIT_ARTIFACT"
    installer_validate_upgrade_version || return $?
    installer_require_tools
    installer_fetch_release || return "$INSTALLER_EXIT_ARTIFACT"
    installer_verify_artifacts
    if installer_role_has_agent && [[ ! -e "$INSTALLER_AGENT_BINARY" ]] || \
        installer_role_has_controller && [[ ! -e "$INSTALLER_CONTROLLER_BINARY" ]]; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "cannot upgrade an installation that is not present" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    mkdir -p -- "$INSTALLER_BACKUP_DIR"
    chmod 700 -- "$INSTALLER_BACKUP_DIR"
    installer_chown root:root "$INSTALLER_BACKUP_DIR"
    if ! installer_acquire_upgrade_lock; then
        installer_die "$INSTALLER_EXIT_CONFLICT" "another upgrade is already running" || true
        return "$INSTALLER_EXIT_CONFLICT"
    fi
    local backup
    backup=$(mktemp -d "$INSTALLER_BACKUP_DIR/upgrade.XXXXXX") || { installer_release_upgrade_lock; return "$INSTALLER_EXIT_GENERIC"; }
    chmod 700 -- "$backup"
    installer_chown root:root "$backup"
    local failed=0 rollback_failed=0
    installer_stop_service || failed=1
    if ((failed == 0)); then
        installer_recover_interrupted_upgrades || failed=1
    fi
    if ((failed == 0)); then
        installer_snapshot_files "$backup" || failed=1
        installer_verify_snapshot_state "$backup" || failed=1
        installer_upgrade_journal_write "$backup" snapshot_ready '[]' || failed=1
    fi
    local completed='[]'
    if ((failed == 0)); then
        installer_upgrade_journal_write "$backup" promoting "$completed" || failed=1
        if installer_role_has_agent; then
            if installer_copy_artifact "antinat-agent-linux-amd64" "$INSTALLER_AGENT_BINARY" 755; then
                completed=$(jq -c '. + ["bin/antinat-agent"]' <<<"$completed")
                installer_upgrade_journal_write "$backup" promoting "$completed" || failed=1
            else
                failed=1
            fi
        fi
        if ((failed == 0)) && installer_role_has_controller; then
            if installer_copy_artifact "antinat-controller-linux-amd64" "$INSTALLER_CONTROLLER_BINARY" 755; then
                completed=$(jq -c '. + ["bin/antinat-controller"]' <<<"$completed")
                installer_upgrade_journal_write "$backup" promoting "$completed" || failed=1
            else
                failed=1
            fi
        fi
        if ((failed == 0)); then
            if installer_write_schema_version; then
                completed=$(jq -c '. + ["schema.version"]' <<<"$completed")
                installer_upgrade_journal_write "$backup" promoted "$completed" || failed=1
            else
                failed=1
            fi
        fi
        if [[ "${ANTINAT_FAIL_MIGRATION:-0}" == 1 ]]; then
            installer_upgrade_journal_write "$backup" migrating "$completed" 'migration failed' || failed=1
            failed=1
        fi
        if ((failed == 0)); then
            installer_upgrade_journal_write "$backup" health_checking "$completed" || failed=1
        fi
        if ((failed == 0)); then
            installer_start_services || failed=1
        fi
        if ((failed == 0 && "${ANTINAT_FORCE_HEALTH_FAIL:-0}" == 1)); then
            failed=1
        fi
        if ((failed == 0)) && installer_role_has_controller && [[ -z "$INSTALLER_TEST_ROOT" ]] && [[ "${ANTINAT_TEST_MODE:-0}" != 1 ]]; then
            curl --fail --silent --show-error --max-time 10 http://127.0.0.1:3111/readyz >/dev/null || failed=1
        fi
    fi
    if ((failed != 0)); then
        installer_upgrade_journal_write "$backup" rollback_in_progress "$completed" 'upgrade failed; restoring snapshot' || rollback_failed=1
        # A failed health check can leave the newly promoted services running.
        # Quiesce them before restoring executable and mutable state bytes;
        # otherwise Controller writes race the snapshot verification and the
        # old binaries are not actually the processes serving after rollback.
        installer_quiesce_services || rollback_failed=1
        if ((rollback_failed == 0)); then
            installer_restore_snapshot "$backup" || rollback_failed=1
        fi
        if ((rollback_failed == 0)); then
            installer_verify_snapshot_state "$backup" || rollback_failed=1
        fi
        installer_start_services || rollback_failed=1
        if ((rollback_failed == 0)); then
            installer_upgrade_journal_write "$backup" rolled_back "$completed" 'previous version restored' || rollback_failed=1
        else
            installer_upgrade_journal_write "$backup" rollback_failed "$completed" 'rollback could not be verified' || true
        fi
        installer_release_upgrade_lock
        if ((rollback_failed != 0)); then
            printf 'antinat installer: upgrade failed; rollback could not be verified\n' >&2
        else
            printf 'antinat installer: upgrade failed; previous version restored\n' >&2
        fi
        return "$INSTALLER_EXIT_ROLLBACK"
    fi
    installer_cleanup_schema_backup
    if installer_test_fail_at complete_journal || ! installer_upgrade_journal_write "$backup" complete "$completed"; then
        rollback_failed=0
        installer_upgrade_journal_write "$backup" rollback_in_progress "$completed" 'upgrade completion journal failed; restoring snapshot' || rollback_failed=1
        installer_quiesce_services || rollback_failed=1
        if ((rollback_failed == 0)); then
            installer_restore_snapshot "$backup" || rollback_failed=1
        fi
        if ((rollback_failed == 0)); then
            installer_verify_snapshot_state "$backup" || rollback_failed=1
        fi
        installer_start_services || rollback_failed=1
        if ((rollback_failed == 0)); then
            installer_upgrade_journal_write "$backup" rolled_back "$completed" 'previous version restored after journal failure' || rollback_failed=1
        else
            installer_upgrade_journal_write "$backup" rollback_failed "$completed" 'rollback could not be verified after journal failure' || true
        fi
        installer_release_upgrade_lock
        return "$INSTALLER_EXIT_ROLLBACK"
    fi
    installer_release_upgrade_lock
    printf 'antinat installer: upgrade complete\n'
}

installer_run() {
    installer_parse_args "$@" || return $?
    if [[ -n "$INSTALLER_COMMAND" ]]; then
        installer_require_privileges || return $?
    fi
    case "$INSTALLER_COMMAND" in
        install) installer_install ;;
        uninstall) installer_uninstall ;;
        purge) installer_purge ;;
        upgrade) installer_upgrade ;;
    esac
}
