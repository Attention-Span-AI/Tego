#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


set -euo pipefail
here="$(/usr/bin/dirname "$0")"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
: "${DIR:?}" "${TEGO:?}" "${CONTRACT:?}" "${IN_RUN:?}" "${IN_USE_SUDO:?}"
# Setup can fail before any launcher or agent executes. Keep the checked result
# unknown so agent.sh can still retain diagnostics and its evidence inventory.
printf 'unknown\n' >"$DIR/state/agent-exit"
verify_binary
# The product requires the status parent to belong to the actual launcher.
# Root status is read back through the checked collector only after teardown.
[ ! -e "$DIR/status" ] && [ ! -L "$DIR/status" ] || exit 125
if [ "$IN_USE_SUDO" = true ]; then
  /usr/bin/sudo -n -- /usr/bin/install -d -m 0700 -o 0 -g 0 "$DIR/status" || exit 125
else
  /usr/bin/mkdir -m 0700 "$DIR/status" || exit 125
fi
# A fresh unpredictable marker is held only by this parent. Agent output drains
# before command processing resumes. File-command paths are outside grants.
marker="$(/usr/bin/od -An -N32 -tx1 /dev/urandom | /usr/bin/tr -d ' \n')"
printf '::stop-commands::%s\n' "$marker"
rc=0
/usr/bin/python3 -I "$here/launch.py" || rc=$?
printf '\n::%s::\n' "$marker"
printf '%s\n' "$rc" >"$DIR/state/agent-exit"
out exit-code "$rc"
