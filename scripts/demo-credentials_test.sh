#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise the real command printers with synthetic logins and a stand-in engine.
# No agent, server, user manager or real ledger is started.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
demo=$here/../examples/supply-chain-demo/demo.sh
t=$(mktemp -d "${TMPDIR:-/tmp}/demo-credentials.XXXXXX")
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/bin" "$t/stage/without/proj" "$t/stage/with/proj"
: >"$t/stage/with/claude-code.filled.yaml"
cat >"$t/bin/tego" <<'EOF'
#!/bin/sh
# Confirm the executed command still receives the exact login, without printing it.
printf '%s' "${CLAUDE_CODE_OAUTH_TOKEN:-}${ANTHROPIC_API_KEY:-}" >"${HOME%/home}/received"
printf 'tego %s: r-abc-123-456\nRan 1 test\nOK\n' "$1"
EOF
printf '#!/bin/sh\nexit 0\n' >"$t/bin/claude"
chmod +x "$t/bin/tego" "$t/bin/claude"
fail=0
for login in CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY; do
	for ending in plain newline newlines only-newlines; do
		# Spaces, quotes, shell metacharacters and '=' must remain one executed word.
		canary="SYNTHETIC_${login}_CANARY space'\"=\$() *"
		canary+=$'\nSYNTHETIC_LOGIN_SECOND_LINE'
		case $ending in
			newline) canary+=$'\n' ;;
			newlines) canary+=$'\n\n' ;;
			only-newlines) canary=$'\n\n' ;;
		esac
		printf '%s' "$canary" >"$t/expected"
		# Test all demo quoting helpers without executing the demos.
		for kit in supply-chain-demo live-modes-demo demo; do
			quote=shq
			[ "$kit" != demo ] || quote=q
			awk -v fn="$quote()" '$1 == fn && $2 == "{" {copy=1} copy {print} copy && /}$/ {exit}' \
				"$here/../examples/$kit/demo.sh" >"$t/shq.sh"
			# shellcheck disable=SC2016 # Expanded by the child shell.
			sh -c '. "$1"; quoted=$("$3" "$2"); eval "set -- $quoted"; [ "$#" = 1 ] || exit 1; printf %s "$1"' \
				sh "$t/shq.sh" "$canary" "$quote" >"$t/quoted"
			if ! cmp -s "$t/expected" "$t/quoted"; then
				echo "FAIL: $kit $quote changes $login ending=$ending"; fail=1
			fi
		done
		for quiet in 0 1; do
			for cmd in backup left right; do
				rm -f "$t/stage/without/received" "$t/stage/with/received"
				rc=0
				env -i "PATH=$t/bin:$PATH" "HOME=$t" "DEMO_STAGE=$t/stage" \
					"DEMO_CONFIG=$t/config.yaml" "DEMO_LEDGER=$t/ledger" DEMO_AGENT=claude DEMO_FORCE=1 \
					"DEMO_QUIET=$quiet" "TEGO=$t/bin/tego" "$login=$canary" \
					sh "$demo" "$cmd" >"$t/out" 2>"$t/err" || rc=$?
				if grep -qE -- "SYNTHETIC_${login}_CANARY|SYNTHETIC_LOGIN_SECOND_LINE" "$t/out" "$t/err"; then
					echo "FAIL: $cmd quiet=$quiet ending=$ending prints $login on stdout/stderr"; fail=1
				elif ! grep -qF "$login=..." "$t/out"; then
					echo "FAIL: $cmd quiet=$quiet did not print a redacted command (exit $rc)"; fail=1
				else
					echo "ok: $cmd quiet=$quiet ending=$ending redacts $login on stdout/stderr"
				fi
				case $cmd in backup) sides='without with' ;; left) sides=without ;; right) sides=with ;; esac
				for side in $sides; do
					if ! cmp -s "$t/expected" "$t/stage/$side/received"; then
						echo "FAIL: $cmd did not pass the intact $login ending=$ending to $side"; fail=1
					fi
				done
			done
		done
	done
done
exit "$fail"
