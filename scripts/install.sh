#!/usr/bin/env bash

set -euo pipefail
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=scripts/libinstall.sh
source "$script_dir/libinstall.sh"

installer_run "$@"
