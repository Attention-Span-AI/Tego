#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


#
# post.sh: puts the receipt where people look. Always the job summary. On a pull request, one comment the action
# creates once and then edits in place (found by the marker on the receipt's first line). Optionally a check run.
# A comment or check that GitHub refuses (a fork's read-only token, a missing permission) is a warning, never a
# failure: the job summary and the artifact still hold the receipt.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(/usr/bin/dirname "$0")/lib.sh"

: "${DIR:?}" "${MD:?}"
[ -s "$MD" ] || die "no receipt to post"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
	/usr/bin/cat "$MD" >>"$GITHUB_STEP_SUMMARY"
fi

limit=60000 # GitHub refuses a comment body over 65536 characters
body="$DIR/state/comment.md"
/usr/bin/mkdir -p "$DIR/state"
body_bytes="$(/usr/bin/wc -c <"$MD")"
if [ "$body_bytes" -gt "$limit" ]; then
	{
		/usr/bin/python3 -I - "$MD" "$limit" <<'PYTRUNC'
import sys
from pathlib import Path
print(Path(sys.argv[1]).read_bytes()[:int(sys.argv[2])].decode('utf-8', errors='ignore'), end='')
PYTRUNC
		printf '\n\n**Cut here: the full receipt is in the job summary.**\n'
	} >"$body"
else
	/usr/bin/cp "$MD" "$body"
fi

if [ "${DO_COMMENT:-false}" = true ]; then
	[[ "${PR_NUMBER:-}" =~ ^[0-9]+$ ]] || die "internal: no pull request number"
	[ -x /usr/bin/gh ] || die "gh is not on this runner"
	repo="${GITHUB_REPOSITORY:?}"
	marker="$(/usr/bin/head -n 1 "$MD")"
	id=""
	if /usr/bin/gh api --paginate "repos/$repo/issues/$PR_NUMBER/comments" >"$DIR/state/comments.json" 2>"$DIR/state/gh.err"; then
		id="$(/usr/bin/jq -s -r --arg m "$marker" '[add[]? | select(.user.login == "github-actions[bot]" and .user.type == "Bot" and ((.body // "") | startswith($m))) | .id] | last // empty' "$DIR/state/comments.json")"
	fi
	payload="$(/usr/bin/jq -n --rawfile b "$body" '{body: $b}')"
	posted=false
	if [ -n "$id" ] && printf '%s' "$payload" | /usr/bin/gh api -X PATCH "repos/$repo/issues/comments/$id" --input - >/dev/null 2>>"$DIR/state/gh.err"; then
		posted=true
		note "updated the receipt comment on #$PR_NUMBER"
	elif printf '%s' "$payload" | /usr/bin/gh api -X POST "repos/$repo/issues/$PR_NUMBER/comments" --input - >/dev/null 2>>"$DIR/state/gh.err"; then
		posted=true
		note "posted the receipt comment on #$PR_NUMBER"
	fi
	if [ "$posted" != true ]; then
		warn "could not comment on #$PR_NUMBER (a pull request from a fork gets a read-only token; otherwise grant pull-requests: write). The receipt is in the job summary. "
	fi
fi

if [ "${DO_CHECK:-false}" = true ]; then
	repo="${GITHUB_REPOSITORY:?}"
	sha="$(/usr/bin/jq -r '.pull_request.head.sha // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)"
	[ -n "$sha" ] || sha="${GITHUB_SHA:?}"
	conclusion=success
	title="Tego: no refusals recorded"
	if [ "${VERIFIED:-}" != true ]; then
		conclusion=failure
		title="Tego: the record did not verify"
	elif [ "${REFUSALS:-0}" != 0 ]; then
		title="Tego: ${REFUSALS} refused"
		conclusion=neutral
		[ "${IN_ON_REFUSAL:-warn}" = fail ] && conclusion=failure
	fi
	if ! /usr/bin/jq -n --rawfile b "$body" --arg sha "$sha" --arg c "$conclusion" --arg t "$title" \
		'{name: "Tego receipt", head_sha: $sha, status: "completed", conclusion: $c, output: {title: $t, summary: $b}}' |
		/usr/bin/gh api -X POST "repos/$repo/check-runs" --input - >/dev/null 2>>"$DIR/state/gh.err"; then
		warn "could not post a check run (grant checks: write). "
	fi
fi
