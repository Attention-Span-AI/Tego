#!/bin/bash -p
# SPDX-License-Identifier: Apache-2.0
export PATH=/usr/bin:/bin
unset BASH_ENV ENV PROMPT_COMMAND CDPATH GLOBIGNORE
if [ "${1:-}" = --tego-ci-clean ]; then
  shift
else
  exec /usr/bin/python3 -I "$(/usr/bin/dirname "$0")/environment.py" "$0" "$@"
fi


# Eligible signing displays use authenticated metadata. No OIDC requests.
set -euo pipefail
here="$(/usr/bin/dirname "$0")"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$here/lib.sh"
[ "${GITHUB_SERVER_URL:-}" = https://github.com ] || die 'only github.com is supported'
[ "${GITHUB_EVENT_NAME:-}" != pull_request_target ] || { echo 'pull_request_target is refused before launch' >&2; exit 125; }
[ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || { echo 'the agent job must not have OIDC authority' >&2; exit 125; }
case "${IN_USE_SUDO:?}" in true | false) ;; *) exit 125 ;; esac
case "${IN_ON_REFUSAL:?}" in warn | fail) ;; *) exit 125 ;; esac
case "${IN_COMMENT:-false}" in auto | true | false) ;; *) exit 125 ;; esac
case "${IN_SIGN:-auto}" in auto | true | false) ;; *) exit 125 ;; esac
: "${DIR:?}" "${GITHUB_WORKSPACE:?}"
for tool in curl jq sha256sum systemd-run git python3 gh; do [ -x "/usr/bin/$tool" ] || exit 125; done
if /usr/bin/git -C "$GITHUB_WORKSPACE" config --includes --get-regexp '^http\..*\.extraheader$' >/dev/null 2>&1; then
  die 'checkout credentials are persisted; set persist-credentials: false'
fi
export VISIBILITY=unknown IS_FORK=unknown
pr=''
repo="${GITHUB_REPOSITORY:?}"
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || exit 125
if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
  pr="$(/usr/bin/jq -r '.number' "${GITHUB_EVENT_PATH:?}")"
  [[ "$pr" =~ ^[1-9][0-9]*$ ]] || exit 125
fi
case "${IN_SIGN:-auto}:${GITHUB_EVENT_NAME:-}" in
  false:*) ;; # Comments still use the event's PR number, without policy lookups.
  *:push | *:schedule | *:workflow_dispatch | *:pull_request)
    if /usr/bin/gh api "repos/$repo" >"$DIR/state/repository.json" 2>"$DIR/state/api-error"; then
      VISIBILITY="$(/usr/bin/jq -er --arg repo "$repo" '
        if (.full_name | type) == "string" and (.full_name | ascii_downcase) == ($repo | ascii_downcase) and
           (.id | type) == "number" and .id > 0 and
           (.visibility == "public" or .visibility == "private" or .visibility == "internal")
        then .visibility else "unknown" end' "$DIR/state/repository.json" 2>>"$DIR/state/api-error")" || VISIBILITY=unknown
    fi
    if [ -n "$pr" ] && /usr/bin/gh api "repos/$repo/pulls/$pr" >"$DIR/state/pull.json" 2>>"$DIR/state/api-error"; then
      IS_FORK="$(/usr/bin/jq -nr --slurpfile p "$DIR/state/pull.json" --slurpfile r "$DIR/state/repository.json" '
        if ($p | length) != 1 or ($r | length) != 1 or
           ($p[0].head.repo.id | type) != "number" or ($r[0].id | type) != "number" or
           ($p[0].base.repo.id != $r[0].id)
        then "unknown" else ($p[0].head.repo.id != $r[0].id | tostring) end' 2>>"$DIR/state/api-error")" || IS_FORK=unknown
    fi
    ;;
esac
/usr/bin/python3 -I "$here/eligibility.py" >"$DIR/evidence/eligibility.json"
comment=false
case "${IN_COMMENT:-false}" in
  true) [ -n "$pr" ] || exit 125; comment=true ;;
  auto) [ -z "$pr" ] || comment=true ;;
esac
out comment "$comment"
out pr "$pr"
reason="$(/usr/bin/jq -er .reason "$DIR/evidence/eligibility.json")"
out unsigned-reason "$reason"
