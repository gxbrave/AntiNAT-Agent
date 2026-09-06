#!/bin/sh
set -eu

# Docker secrets are read-only mounts. Stage one copy in the private state
# volume so the Agent can consume and delete it using its normal 0600 token
# path, without putting the token in argv, the environment, or an image layer.
state_dir=${ANTINAT_STATE:-/var/lib/antinat}
secret_file=${ANTINAT_DOCKER_TOKEN_FILE:-/run/secrets/antinat_enrollment_token}
staged_file="$state_dir/.enrollment-token"
complete_file="$state_dir/.enrollment-complete"
agent_bin=/opt/antinat/bin/antinat-agent
if [ "${ANTINAT_TEST_MODE:-0}" = 1 ] && [ -n "${ANTINAT_DOCKER_AGENT_BIN:-}" ]; then
    agent_bin=$ANTINAT_DOCKER_AGENT_BIN
fi
child_pid=

die() {
    printf '%s\n' "antinat docker entrypoint: $*" >&2
    exit 1
}

if [ -L "$state_dir" ] || [ ! -d "$state_dir" ]; then
    die 'state directory is not a private directory'
fi
if ! chmod 700 "$state_dir"; then
    die 'could not restrict state directory permissions'
fi
if [ -L "$complete_file" ]; then
    die 'enrollment completion marker is a symlink'
fi

if [ -e "$complete_file" ]; then
    if [ ! -f "$complete_file" ]; then
        die 'enrollment completion marker is not a regular file'
    fi
    exec "$agent_bin" "$@"
fi

if [ -L "$staged_file" ]; then
    die 'staged enrollment token is a symlink'
fi
if [ ! -e "$staged_file" ]; then
    if [ -L "$secret_file" ] || [ ! -f "$secret_file" ]; then
        die 'a Docker enrollment secret is required for the first start'
    fi
    umask 077
    temporary=$(mktemp "$state_dir/.enrollment-token.XXXXXX") || die 'could not create staged enrollment token'
    if ! cp "$secret_file" "$temporary" || ! chmod 600 "$temporary"; then
        rm -f -- "$temporary"
        die 'could not stage enrollment secret'
    fi
    if ! mv -f -- "$temporary" "$staged_file"; then
        rm -f -- "$temporary"
        die 'could not publish staged enrollment secret'
    fi
fi

if [ ! -f "$staged_file" ]; then
    die 'staged enrollment token is not a regular file'
fi

write_completion_marker() {
    if [ -e "$complete_file" ]; then
        [ ! -L "$complete_file" ] && [ -f "$complete_file" ] || die 'enrollment completion marker is not a regular file'
        return
    fi
    umask 077
    marker_temporary=$(mktemp "$state_dir/.enrollment-complete.XXXXXX") || die 'could not create enrollment completion marker'
    if ! printf '%s\n' enrolled >"$marker_temporary" || ! chmod 600 "$marker_temporary"; then
        rm -f -- "$marker_temporary"
        die 'could not write enrollment completion marker'
    fi
    if ! mv -f -- "$marker_temporary" "$complete_file"; then
        rm -f -- "$marker_temporary"
        die 'could not publish enrollment completion marker'
    fi
}

forward_signal() {
    if [ -n "${child_pid:-}" ]; then
        kill -"$1" "$child_pid" 2>/dev/null || true
    else
        exit 128
    fi
}

on_exit() {
    if [ -n "${child_pid:-}" ] && kill -0 "$child_pid" 2>/dev/null; then
        kill -TERM "$child_pid" 2>/dev/null || true
    fi
}

trap 'forward_signal TERM' TERM
trap 'forward_signal INT' INT
trap 'forward_signal HUP' HUP
trap on_exit EXIT

enrollment_consumed=0
"$agent_bin" "$@" --token-file "$staged_file" &
child_pid=$!
while kill -0 "$child_pid" 2>/dev/null; do
    if [ ! -e "$staged_file" ] && [ ! -L "$staged_file" ]; then
        # A normal Agent is long-running, so its successful exit cannot be the
        # enrollment acknowledgement. Token consumption while it is still
        # alive is the durable handoff point. The successful-exit path below
        # remains as a fallback for short-lived Agents that race this poll.
        if kill -0 "$child_pid" 2>/dev/null; then
            write_completion_marker
            enrollment_consumed=1
            break
        fi
    fi
    sleep 1
done

if wait "$child_pid"; then
    child_status=0
else
    child_status=$?
fi
if [ "$child_status" -eq 0 ] && [ "$enrollment_consumed" -eq 0 ] && [ ! -e "$staged_file" ] && [ ! -L "$staged_file" ]; then
    write_completion_marker
fi
exit "$child_status"
