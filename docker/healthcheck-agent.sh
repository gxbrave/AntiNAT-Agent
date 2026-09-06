#!/bin/sh
set -eu
agent_is_alive() {
    pid=$1
    [ -r "/proc/$pid/cmdline" ] || return 1
    cmdline=$(tr '\000' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
    case "$cmdline" in
        */antinat-agent*|antinat-agent*) kill -0 "$pid" 2>/dev/null; return ;;
    esac
    return 1
}

# The enrollment wrapper is PID 1 on first start and the Agent becomes PID 1
# after the completion marker is written. Check the actual Agent process in
# both states so wrapper liveness cannot mask a dead child.
agent_is_alive 1 && exit 0
if [ -r /proc/1/task/1/children ]; then
    for pid in $(cat /proc/1/task/1/children 2>/dev/null); do
        agent_is_alive "$pid" && exit 0
    done
fi
exit 1
