#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# A refusal is itself reported, even when no run directory was made.
set -euo pipefail
here="$(/usr/bin/dirname "$0")"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
: "${DIR:?}"
marker="$(/usr/bin/python3 -I "$here/identity.py" | /usr/bin/jq -r .marker)"
tier=unknown
code=125
if [ -f "$DIR/state/tier-wanted" ]; then tier="$(/usr/bin/cat "$DIR/state/tier-wanted")"; fi
if [ -f "$DIR/state/prepare-exit" ]; then code="$(/usr/bin/cat "$DIR/state/prepare-exit")"; fi
if [ "$code" = 211 ]; then
  /usr/bin/jq -nr --arg marker "$marker" --arg tier "$tier" \
    'def safe: tostring | gsub("[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]"; "?") | gsub("`"; "\u0027");
     $marker, "### No receipt: this runner cannot provide tier `\($tier | safe)`.",
     "The agent did not start. This report is not signed. Keep doctor.json from the diagnostic artifact.",
     "Hosted-runner tier support has not been measured for this workflow. Review the requested tier and runner image."' >"$DIR/evidence/receipt.md"
else
  printf '%s\n### No receipt: evidence collection could not finish.\nThe report is not signed. Review the job log and diagnostic artifact.\n' "$marker" >"$DIR/evidence/receipt.md"
fi
# Do not copy generic doctor fix advice (GRUB or root) into a hosted-runner display.
if [ -s "$DIR/evidence/doctor.json" ]; then
  /usr/bin/jq -r --arg tier "$tier" '(.missing[$tier] // [])[0:8][] | tostring | gsub("[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]"; "?") | @json | "- Missing for requested tier: `" + gsub("`"; "\u0027") + "`"' \
    "$DIR/evidence/doctor.json" >>"$DIR/evidence/receipt.md"
fi
out markdown "$DIR/evidence/receipt.md"
# Every display names the fresh event commit, even when no receipt exists.
/usr/bin/jq -nr --arg commit "${GITHUB_SHA:-unavailable}" '
  $commit | gsub("[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]"; "?") | gsub("`"; "\u0027") |
  "\n| Event commit | `\(.)` |"' >>"$DIR/evidence/receipt.md"
