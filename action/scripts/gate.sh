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
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(/usr/bin/dirname "$0")/lib.sh"
if [ "${PREPARE_EXIT:-0}" = 211 ]; then exit 211; fi
code="${AGENT_EXIT:-}"
if [ "${EVIDENCE_EXIT:-0}" != 0 ] || [ -z "${RUN_ID:-}" ] || [ "${VERIFIED:-}" != true ]; then
  printf 'Evidence could not be checked; agent exit: %s; evidence exit: %s\n' "${code:-not started}" "${EVIDENCE_EXIT:-unknown}" >&2
  exit 125
fi
[[ "$code" =~ ^[0-9]+$ ]] && [ "$code" -le 255 ] || exit 125
if [ "$code" != 0 ]; then exit "$code"; fi
if [ "${REFUSALS:-0}" != 0 ] && [ "${IN_ON_REFUSAL:-warn}" = fail ]; then exit 1; fi
