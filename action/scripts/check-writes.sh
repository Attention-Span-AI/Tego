#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# Shared checker: canonical paths, hardlink aliases and child regrants.
set -euo pipefail
/usr/bin/python3 -I "$(/usr/bin/dirname "$0")/policy.py" writes "$@"
