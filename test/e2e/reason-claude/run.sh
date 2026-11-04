#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — tego's reason channel end to end with the REAL Claude Code (README.md, "End to end"). Each scenario is one
# `tego run` of `claude -p` at tier landlock under contract.yaml: no network but the forwarder, a dummy key, and the
# model stub (test/workloads/model-stub/server.py --log-content) behind the forwarder. report.py e2e then reads the
# stub's log and the run's ledger and prints PASS or FAIL per check:
#   a  a Write outside the workspace       the next request carries that refusal (ledger: write-outside-contract), target, rule
#   c  a Bash `git push` (exec.deny)       ... that refusal (ledger: exec-not-allowed) and its rule
#   d  both, as one turn's two tool_use blocks: the next request lists both, no later request repeats either
#   e  an allowed Write                     the next request carries no tego text
#   f  scenario c with --bare, and with CLAUDE_CODE_SIMPLE=1: bare mode runs no hook (RESULTS.md R2), so tego refuses
#      the run with exit 125 before it starts, and no request reaches the model
#   p  scenario a with the project's .claude/settings.json turning the hook off (disableAllHooks, CLAUDE_CODE_SIMPLE
#      and CLAUDE_CODE_SAFE_MODE in its env): tego's file outranks it, so the refusal still reaches the next request
#   v  scenario a with the command's own --settings holding a value Claude Code's schema rejects (cleanupPeriodDays
#      "soon"), which tego merges as given: whether the merged file's hook still runs (ADR 0063 (8))
#   h  one interactive session (test/poc/interactive-claude/drive.py, mode reason) with the assertion of a
# The next request of a, c, d and e, normalised, must equal testdata/next-request.golden, which the CI twin
# (fakeclaude/e2e_integration_test.go) holds fakeclaude to on every CI run, so that drift between the stand-in and the
# real binary shows.
#
# Usage: run.sh [a c d e f p v h ...]    default: all of them
#        CLAUDE=<path to claude>  TEGO_BIN=<tego built with -tags tegotesthooks>  ROOT=<dir> (kept)  KEEP=1
#        WRITE_GOLDEN=1 rewrites the golden's entries from this run (the real binary is the reference)
# Exit 0 when every check passed, 1 on a FAIL, 2 when a tool is missing, 77 (SKIP) when no claude is installed.
# Durable files (machine config, ledger, chain anchor, own log and HOME) are under $ROOT. The short per-run
# %R runtime is under a private temporary base in /run/user/<uid> and removed at script exit. HOME is $ROOT/home. The contract denies the
# agent the account's own configuration (Claude Code reads the passwd-database home's ~/.claude whatever HOME says), and the real ~/.tego is
# listed before and after.
set -uo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../.." && pwd)
poc=$repo/test/poc/interactive-claude
claude=${CLAUDE:-$(command -v claude || true)}
if [ -z "$claude" ] || [ ! -x "$claude" ]; then
	echo "SKIP  reason-claude end to end: no claude on PATH (CLAUDE=<path> names one)"
	exit 77
fi
for t in python3 openssl; do command -v "$t" >/dev/null || { echo "run.sh: needs $t" >&2; exit 2; }; done
scenarios=${*:-a c d e f p v h}
root=${ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/tego-reason-e2e-XXXXXX")}
mkdir -p "$root" && chmod 755 "$root"
root=$(cd "$root" && pwd)
stub_pid=
runtime_base=
cleanup() {
	[ -n "$stub_pid" ] && kill "$stub_pid" 2>/dev/null
	[ -z "$runtime_base" ] || rm -rf "$runtime_base"
	[ "${KEEP:-0}" = 1 ] || [ -n "${ROOT:-}" ] || rm -rf "$root"
}
trap cleanup EXIT
fail=0
check() { # check <0|1> <what>
	if [ "$1" = 0 ]; then echo "PASS  $2"; else echo "FAIL  $2"; fail=1; fi
}
section() { printf '\n==== %s\n' "$1"; }

# --- tego, as drive.py expects it: files under $root/state, short per-run runtime under the login base ---
mkdir -p "$root/bin" && chmod 755 "$root/bin"
if [ -n "${TEGO_BIN:-}" ]; then
	cp "$TEGO_BIN" "$root/bin/tego"
else
	(cd "$repo" && CGO_ENABLED=0 go build -tags=tegotesthooks -o "$root/bin/tego" ./cmd/tego) || exit 2
fi
bin=$root/bin/tego
# A product build would anchor these runs in the invoking user's own ~/.tego/chain.log; only the test build has the
# variable's name in it.
grep -aq TEGO_TEST_CHAIN_ANCHOR "$bin" || { echo "run.sh: $bin is not built with -tags tegotesthooks" >&2; exit 2; }
state=$root/state
mkdir -p "$state/runs" "$state/ownlog" && chmod 755 "$state"
printf 'version: 0\nledger_root: %s\nstop_grace: 3s\n' "$state/runs" >"$state/config.yaml" && chmod 600 "$state/config.yaml"
# A short private base keeps %R within 103 bytes and never sweeps the user's normal runtime.
runtime_base=$(mktemp -d "/run/user/$(id -u)/tXXXXXX") || exit 2
chmod 700 "$runtime_base"
printf '%s\n' "$runtime_base" >"$state/runtime"
export TEGO_CONFIG=$state/config.yaml TEGO_TEST_CHAIN_ANCHOR=$state/chain.log TEGO_TEST_OWN_LOG_HOME=$state/ownlog
export XDG_RUNTIME_DIR=$runtime_base SSL_CERT_FILE=$root/stub/cert.pem
real_home=$(getent passwd "$(id -u)" | cut -d: -f6)
tego_home_listing() { [ -d "$real_home/.tego" ] && find "$real_home/.tego" -printf '%p %s %T@\n' 2>/dev/null | sort; }
tego_home_listing >"$root/tego-home-before.txt"
isolation=()
for p in .claude .claude.json .codex .config/anthropic .tego; do [ -e "$real_home/$p" ] && isolation+=("$real_home/$p"); done
deny=""
for p in "${isolation[@]}"; do deny="$deny\"$p\", "; done

mkdir -p "$root/stub" && chmod 755 "$root/stub"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
	-keyout "$root/stub/key.pem" -out "$root/stub/cert.pem" -subj /CN=127.0.0.1 \
	-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" -addext "keyUsage=critical,digitalSignature,keyCertSign" \
	-addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1 || { echo "run.sh: openssl could not make a certificate" >&2; exit 2; }
chmod 644 "$root/stub/cert.pem"
KEY="sk-ant-api03-OFFLINE-DUMMY-NOT-A-REAL-KEY-00000000000000000000"

# layout <stub script> [extra contract line]: a fresh workspace, home, stub and contract (drive.py's layout).
layout() {
	local port
	ws=$root/ws
	rm -rf "${ws:?}" "${root:?}/home" "$root/outside" "$root/contract" "$state/runs"
	mkdir -p "$ws/work" "$ws/bin" "$ws/.claude-state/tmp" "$root/home" "$root/outside" "$root/contract" "$state/runs"
	chmod 755 "$ws" "$root/home" "$root/outside" "$root/contract"
	cp "$poc/git" "$ws/bin/git"
	# Claude Code's first-run record (no credential): without it, its first act is a check against api.anthropic.com.
	# The workspace is recorded trusted, so the interactive session (h) never meets the trust dialog, which the driver
	# lost to a race once in two runs (RESULTS.md R6).
	printf '{"hasCompletedOnboarding": true, "theme": "dark", "projects": {"%s": {"hasTrustDialogAccepted": true}}}\n' "$ws" \
		>"$ws/.claude-state/.claude.json"
	sed "s#@W@#$ws#g; s#@OUT@#$root/outside#g" "$1" >"$root/stub/script.json"
	if [ -n "$stub_pid" ]; then kill "$stub_pid" 2>/dev/null; wait "$stub_pid" 2>/dev/null; fi
	: >"$root/stub/requests.log"
	rm -f "$root/stub/stub.port"
	python3 -I "$repo/test/workloads/model-stub/server.py" --cert "$root/stub/cert.pem" --key "$root/stub/key.pem" \
		--ready "$root/stub/stub.port" --log "$root/stub/requests.log" --log-content --script "$root/stub/script.json" 2>"$root/stub/stub.err" &
	stub_pid=$!
	for _ in $(seq 1 100); do [ -s "$root/stub/stub.port" ] && break; sleep 0.1; done
	port=$(cat "$root/stub/stub.port")
	sed "s#@STUB_PORT@#$port#; s#@ROOT@#$root#g; s#^@DENY_READ@\$#  deny_read: [${deny%, }]#" "$here/contract.yaml" >"$root/contract/agent.yaml"
	[ -z "${2:-}" ] || sed -i "s#^  set:\$#  set:\n    $2#" "$root/contract/agent.yaml"
	chmod 644 "$root/contract/agent.yaml"
}
ledger() { find "$state/runs" -mindepth 2 -maxdepth 2 -name events.jsonl | head -1; }
# claude_p <args...>: claude -p under tego run, from the workspace, in an environment built from nothing.
claude_p() {
	(cd "$ws" && env -i PATH="$ws/bin:$(dirname "$claude"):/usr/bin:/bin" HOME="$root/home" LANG=C.UTF-8 \
		XDG_RUNTIME_DIR="$runtime_base" SSL_CERT_FILE="$SSL_CERT_FILE" TEGO_CONFIG="$TEGO_CONFIG" \
		TEGO_TEST_CHAIN_ANCHOR="$TEGO_TEST_CHAIN_ANCHOR" TEGO_TEST_OWN_LOG_HOME="$TEGO_TEST_OWN_LOG_HOME" ANTHROPIC_API_KEY="$KEY" \
		timeout 300 "$bin" run "$root/contract/agent.yaml" -- claude -p --permission-mode bypassPermissions "$@" \
		"Carry out the scripted steps." >"$root/claude.out" 2>"$root/claude.err")
}
report() { # report <scenario> [golden args...]
	local args=() p
	for p in "${isolation[@]}"; do args+=(--isolation "$p"); done
	python3 -I "$here/report.py" e2e "$root/stub/requests.log" --ledger "$(ledger)" --scenario "$1" \
		--sub "$ws=@W@" --sub "$root/outside=@OUT@" --sub "$root=@ROOT@" --sub "$real_home=@REALHOME@" "${args[@]}" "${@:2}"
}
golden_args() {
	if [ "${WRITE_GOLDEN:-0}" = 1 ]; then echo --golden "$here/testdata/next-request.golden" --write-golden
	else echo --golden "$here/testdata/next-request.golden"; fi
}

section "Claude Code"
layout "$here/testdata/stub-e.json"
(cd "$ws" && env -i PATH="$(dirname "$claude"):/usr/bin:/bin" HOME="$root/home" CLAUDE_CONFIG_DIR="$ws/.claude-state" \
	DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 timeout 30 "$claude" --version 2>&1 | head -1 | sed 's/^/version: /')
echo "tego: $("$bin" version 2>/dev/null | head -1)"

for s in $scenarios; do
	case $s in
	a | c | d | e)
		section "$s. claude -p, scenario $s"
		layout "$here/testdata/stub-$s.json"
		claude_p
		check "$?" "tego run of claude -p exited 0 (scenario $s)"
		# shellcheck disable=SC2046 # two or three words, on purpose
		report "$s" $(golden_args) || fail=1
		;;
	f)
		for how in --bare "CLAUDE_CODE_SIMPLE: \"1\""; do
			section "f. scenario c, bare ($how)"
			if [ "$how" = --bare ]; then layout "$here/testdata/stub-c.json"; claude_p --bare
			else layout "$here/testdata/stub-c.json" "$how"; claude_p; fi
			rc=$?
			check "$([ "$rc" = 125 ] && echo 0 || echo 1)" "tego refused the bare run with exit 125 ($how; exit $rc)"
			check "$(grep -q 'drop --bare and CLAUDE_CODE_SIMPLE, or set harness: none' "$root/claude.err" && echo 0 || echo 1)" \
				"... saying what to do instead"
			check "$([ ! -s "$root/stub/requests.log" ] && [ -z "$(ledger)" ] && echo 0 || echo 1)" \
				"... before run_start: no ledger, no request reached the model"
		done
		;;
	p)
		section "p. scenario a, the project's settings turning the hook off"
		layout "$here/testdata/stub-a.json"
		mkdir -p "$ws/.claude"
		printf '{"disableAllHooks": true, "env": {"CLAUDE_CODE_SIMPLE": "1", "CLAUDE_CODE_SAFE_MODE": "1"}}\n' >"$ws/.claude/settings.json"
		claude_p
		check "$?" "tego run of claude -p exited 0 (scenario p)"
		report a || fail=1
		;;
	v)
		section "v. scenario a, the command's own --settings holding an invalid value"
		layout "$here/testdata/stub-a.json"
		claude_p --settings '{"cleanupPeriodDays": "soon"}'
		check "$?" "tego run of claude -p exited 0 (scenario v)"
		# Measured with 2.1.310 (RESULTS.md R9): Claude Code drops the whole file, tego's hook with it, while run_start
		# says provisioned. Held as the known behaviour, so a release that keeps the hook (or tego refusing the run)
		# shows here as a FAIL to re-measure.
		check "$(grep -q 'settings files did not load' "$root/claude.err" && echo 0 || echo 1)" \
			"Claude Code says the merged settings file did not load (one invalid value of the user's drops it all)"
		check "$(grep -qE "Tego refused |Tego, this run's access control" "$root/stub/requests.log" && echo 1 || echo 0)" \
			"... so no hook ran and no refusal reached the model (KNOWN, R9: the run still says provisioned)"
		;;
	h)
		section "h. one interactive session (drive.py reason)"
		layout "$poc/stub-script.json"
		(cd "$ws" && PATH="$(dirname "$claude"):$PATH" python3 -I "$poc/drive.py" "$root" reason) | grep -E '^(PASS|FAIL)'
		check "${PIPESTATUS[0]}" "the driver's own checks"
		report a || fail=1
		;;
	*) echo "run.sh: unknown scenario $s" >&2; exit 2 ;;
	esac
done

tego_home_listing >"$root/tego-home-after.txt"
cmp -s "$root/tego-home-before.txt" "$root/tego-home-after.txt"
check "$?" "the real ~/.tego is unchanged (listing before and after)"
echo "directory: $root"
[ "$fail" = 0 ]
