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
: "${DIR:?}"
ev="$DIR/evidence"
marker="$(/usr/bin/python3 -I "$here/identity.py" | /usr/bin/jq -r .marker)"
if [ "${RECEIPT_FAILURE:-false}" = true ]; then
  /usr/bin/mkdir -p "$ev"
  /usr/bin/jq -nr --arg marker "$marker" --arg commit "${GITHUB_SHA:-unavailable}" '
    def safe: tostring | gsub("[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]"; "?") | gsub("`"; "\u0027");
    $marker, "### No checked receipt for commit `\($commit | safe)`",
    "Evidence verification failed. An earlier receipt does not describe this commit. This report is not signed."' >"$ev/receipt.md"
  out markdown "$ev/receipt.md"
  exit 0
fi
compile="$ev/compile.json"
[ -s "$compile" ] || compile=/dev/null
/usr/bin/jq -nr --slurpfile r "$ev/receipt.json" --slurpfile v "$ev/verify.json" \
  --slurpfile s "$ev/run_start.json" --slurpfile c "$compile" --slurpfile m "$ev/tego-ci.json" \
  --slurpfile tierlines "$here/../tier-lines.json" --arg ws "${WORKSPACE:-}" \
  --arg marker "$marker" --arg commit "${GITHUB_SHA:-unavailable}" --arg unsigned_reason "${UNSIGNED_REASON:-disabled: no signing request was selected for this report phase}" \
  -f "$here/../render.jq" >"$ev/receipt.md"
out markdown "$ev/receipt.md"
