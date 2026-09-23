#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt7-two-agents.sh — kill test 7 (P0-DESIGN §10 "7 two agents (Claude Agent SDK via forwarder; a
# system-Python agent via uprobes)"; §12 acceptance item 1; docs/FEATURES.md "Kill test 7": "two
# agents complete a real local task under `examples/agents/*.yaml`, each with at least one `refused`
# event and no code change: (a) a Claude Agent SDK (Python) agent with `capture: forwarder` and
# `env.set: {CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"}`; every model request is `ssl_request
# source=forwarder`; a deliberate direct connect to `api.anthropic.com:443` is `refused`; the gap
# line reads `capture: uprobe unavailable (static BoringSSL, no symbols); forwarder active`; (b) one
# open-source Python agent on system Python + the Anthropic SDK with `capture: uprobe`.").
#
# What it attacks: that tego runs two real, unmodified agent harnesses end to end — one whose TLS
# it cannot see into (forced through the forwarder) and one whose TLS it can (captured by uprobes) —
# and that a real refusal fires in both.
#
# Both halves talk to the local model stand-in (test/workloads/model-stub) instead of the vendor, so no
# key is spent and no upstream decides the verdict. Each contract is the shipped example with only its
# model endpoint moved, from api.anthropic.com:443 to the stand-in; the stand-in's script is the task.
#
# (a) runs at tier landlock, as the invoking user (started as root under sudo, it runs as SUDO_UID). The
# agent is test/workloads/claude-sdk, the Claude Agent SDK's own query() loop, on this machine's python3
# with the SDK test/e2e/pydeps.sh --claude-sdk installed, which bundles the Claude Code binary it drives.
# The contract is examples/agents/claude-agent-sdk.yaml; the SDK is copied to ./.deps, where the contract
# expects it. The forwarder trusts the stand-in's certificate through SSL_CERT_FILE in tego's own
# environment; the agent is not given it and never needs it. The task: read ./in, write ./out/summary.md,
# finish; then the agent connects straight to the model host, which must fail in the agent and be a
# refused event (R38). Every request the stand-in answered must be an ssl_request with source=forwarder
# and a parsed ssl_response. Part a-cli runs the same Claude Code as `claude -p` under
# examples/agents/claude-code.yaml (P0-DESIGN §12.3's `claude -p` agent): the example's own command must
# complete the task, and a write the task asks for outside the contract must be refused. Part a-gap looks
# for FEATURES' gap line, "capture: uprobe unavailable (static BoringSSL, no symbols); forwarder active":
# tego does not print it yet, and until it does the part is a named skip with that condition, never a
# pass. Half (a) at tier cgroup is not run: a root tier-cgroup run does not start its agent on the kernel
# matrix yet, which half (b) reports on its own.
#
# (b) needs root under sudo, for tier $KT7_TIER (default cgroup; the kernel matrix runs it at bpflsm as well
# where bpf is an active LSM, TIER3-PLAN T11). The agent is test/workloads/python-anthropic, the SDK's own
# tool-use loop, on this machine's python3 with the Anthropic SDK test/e2e/pydeps.sh installed (KT_PYDEPS).
# Its contract is examples/agents/anthropic-sdk-python.yaml; the stand-in's certificate is trusted through
# SSL_CERT_FILE. The task: list ./in, write ./out/summary.md, then ask for a write outside the contract,
# which must be refused, then finish. Every model request the stand-in answered must be an ssl_request with
# source=ssl — read by the uprobes on the system libssl, which is what "via uprobes" means — with a parsed
# ssl_response.
#
# Halves: `kt7-two-agents.sh [a] [b]` (default both). Exit 0 when every half that ran passed, 1 when one
# failed, 2 when none could run — see test/e2e/lib.sh. Each half and part prints a KT-HALF line.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

failed=0
ran=0
result() { # half verdict text
	kt_half kt7 "$1" "$2" "${*:3}"
	case "$2" in
	PASS) ran=1 ;;
	FAIL) ran=1; failed=1 ;;
	esac
}

repo="$(kt_repo_root)"
tego="$(kt_ensure_tego)"

# --- (a) Claude Code through the forwarder, at tier landlock -------------------------------------------

# a_setup prepares one part's work directory for Claude Code, and sets W to it: ./in with two files, ./out
# and ./.claude-state for the agent to write, the stand-in's certificate, and the stand-in itself answering
# the JSON script on stdin, which may name the directory as @W@. The stand-in's port is in $W/stub.port and
# its request log in $W/stub-requests.log. It sets a variable rather than printing the path because the
# stand-in it starts would hold a $(...) open until it exits.
a_setup() {
	W="$(kt_workdir)"
	mkdir -p "$W/in" "$W/out" "$W/.claude-state"
	printf 'alpha: the first file\n' >"$W/in/a.txt"
	printf 'beta: the second file\n' >"$W/in/b.txt"
	sed "s#@W@#$W#g" >"$W/script.json"
	kt_tls_cert "$W" || return 1
	kt_model_stub "$W" "$W/script.json" || return 1
}

# a_contract writes one of the shipped examples into <dir>/agent.yaml with its model endpoint moved to the
# stand-in, and fails when the example no longer names the endpoint where this test moves it.
a_contract() {
	local example="$1" w="$2" port
	port="$(cat "$w/stub.port")"
	sed -e "s/host: api\.anthropic\.com, port: 443/host: \"127.0.0.1\", port: $port/" \
		"$repo/examples/agents/$example" >"$w/agent.yaml"
	grep -q "port: $port" "$w/agent.yaml"
}

# a_compiles compiles $1/agent.yaml as the run will, from $1 with the PATH $2. It returns 0 when it compiles,
# 2 with the tool named when the example names a tool this machine lacks (exec-not-on-path: the kernel-matrix
# guest's base image has no git of its own), which is the machine's gap and not the example's, and 1
# otherwise, with compile's first error on stdout. Tego's own state (machine config, ledger, chain anchor) is in
# $1.tego, beside the work directory and not in it: the chain anchor's directory is tego's own (agent-contract R10),
# so the example's write entry ./out/ inside it would be a contradiction and the example would not compile.
a_compiles() {
	local w="$1" path="$2" out
	out="$(cd "$w" && PATH="$path" TEGO_CONFIG="$w.tego/config.yaml" "$tego" compile agent.yaml --offline 2>&1 >/dev/null)" && return 0
	if grep -q '\[exec-not-on-path\]' <<<"$out"; then
		grep '\[exec-not-on-path\]' <<<"$out" | head -1 | sed 's/^error: [^ ]* //'
		return 2
	fi
	grep -E '^error:' <<<"$out" | head -1
	return 1
}

# a_forwarded judges "every model request is ssl_request source=forwarder" for one run: as many
# ssl_request events as the stand-in answered requests, none from another source, and a parsed 200
# response for each. It prints what was wrong, or nothing.
a_forwarded() {
	local run="$1" w="$2" nstub
	nstub="$(grep -c . "$w/stub-requests.log")"
	if [ "$nstub" = 0 ]; then
		echo "the stand-in answered no model request"
	else
		kt_forwarded_problem "$run/events.jsonl" "$nstub"
	fi
}

# half_a is kill test 7 (a) itself: the Claude Agent SDK agent under examples/agents/claude-agent-sdk.yaml.
half_a() {
	local w port rc run why refused
	a_setup <<-'EOF' || { result a SKIP "the model stand-in could not start (openssl or python3)"; return; }
	[
	 [{"type": "tool_use", "name": "Read", "input": {"file_path": "@W@/in/a.txt"}},
	  {"type": "tool_use", "name": "Read", "input": {"file_path": "@W@/in/b.txt"}}],
	 [{"type": "tool_use", "name": "Write", "input": {"file_path": "@W@/out/summary.md", "content": "# Summary\n\nTwo files: alpha and beta.\n"}}],
	 [{"type": "text", "text": "Wrote out/summary.md."}]
	]
	EOF
	w="$W"
	port="$(cat "$w/stub.port")"
	cp -al "$sdk" "$w/.deps"
	cp "$repo/test/workloads/claude-sdk/agent.py" "$w/agent.py"
	a_contract claude-agent-sdk.yaml "$w" ||
		{ result a FAIL "examples/agents/claude-agent-sdk.yaml no longer names api.anthropic.com:443 where this test moves it"; return; }
	mkdir -m 700 "$w.tego" && kt_config "$w.tego" >/dev/null
	why="$(a_compiles "$w" "$PATH")"
	case $? in
	0) ;;
	2) result a SKIP "examples/agents/claude-agent-sdk.yaml names a tool this machine lacks: $why"; return ;;
	*) result a FAIL "examples/agents/claude-agent-sdk.yaml does not compile here: $why"; return ;;
	esac
	(cd "$w" && TEGO_CONFIG="$w.tego/config.yaml" SSL_CERT_FILE="$w/cert.pem" ANTHROPIC_API_KEY=sk-ant-stub \
		PYTHONPATH="$w/.deps" kt_run "$tego" run agent.yaml --tier landlock --offline -- \
		python3 agent.py --direct "127.0.0.1:$port" "Summarize the files in ./in into ./out/summary.md") \
		</dev/null >"$w/run.out" 2>"$w/run.err"
	rc=$?
	cp "$w/run.err" "$KT_ROOT/a.run.err"
	run="$(kt_rundir "$w.tego")"
	[ -z "$run" ] || kt_save_fixture "kt7-a-landlock" "$run"
	if [ "$rc" != 0 ] || [ -z "$run" ]; then
		result a FAIL "tego run exited $rc: $(kt_err_line "$w/run.err") (agent: $(grep -E '^result|^direct' "$w/run.out" | tr '\n' ' '))"
		return
	fi
	if [ ! -s "$w/out/summary.md" ]; then
		result a FAIL "the SDK agent did not write out/summary.md, the task's output: $(grep -E '^result|^direct' "$w/run.out" | tr '\n' ' ')"
		return
	fi
	if ! grep -q "^result success: Wrote out/summary.md" "$w/run.out"; then
		result a FAIL "the SDK reported no successful result: $(tail -3 "$w/run.out" | tr '\n' ' ')"
		return
	fi
	why="$(a_forwarded "$run" "$w")"
	if [ -n "$why" ]; then
		result a FAIL "$why"
		return
	fi
	refused="$(jq -r --arg t "127.0.0.1:$port" 'select(.kind == "refused" and .target == $t) | .reason' "$run/events.jsonl" | head -1)"
	if ! grep -q "^direct connect refused" "$w/run.out"; then
		result a FAIL "the direct connect to the model host around the forwarder did not fail as refused: $(grep '^direct' "$w/run.out")"
	elif [ "$refused" != net-not-allowed ]; then
		result a FAIL "the direct connect failed in the agent, but no refused event names 127.0.0.1:$port with reason net-not-allowed (found: ${refused:-none})"
	else
		result a PASS "tier landlock: the Claude Agent SDK agent completed its task under examples/agents/claude-agent-sdk.yaml; all $(grep -c . "$w/stub-requests.log") model requests are ssl_request source=forwarder with parsed responses; the direct connect to the model host was refused ($(sed -n 's/^direct connect refused (errno \(.*\))$/\1/p' "$w/run.out"), reason=$refused)"
	fi
}

# half_a_cli is §12.3's `claude -p` agent: the same Claude Code under examples/agents/claude-code.yaml, run
# with that example's own command.
half_a_cli() {
	local w rc run why cmd refused argv
	a_setup <<-'EOF' || { result a-cli SKIP "the model stand-in could not start (openssl or python3)"; return; }
	[
	 [{"type": "tool_use", "name": "Read", "input": {"file_path": "@W@/in/a.txt"}},
	  {"type": "tool_use", "name": "Read", "input": {"file_path": "@W@/in/b.txt"}}],
	 [{"type": "tool_use", "name": "Write", "input": {"file_path": "@W@/out/summary.md", "content": "# Summary\n\nTwo files: alpha and beta.\n"}}],
	 [{"type": "tool_use", "name": "Write", "input": {"file_path": "@W@/leak.txt", "content": "outside the contract"}}],
	 [{"type": "text", "text": "Wrote out/summary.md."}]
	]
	EOF
	w="$W"
	mkdir -p "$w/bin"
	# A hard link, not a symbolic one: Claude Code starts itself again by the path the kernel reports for
	# its own executable, and that has to be the path the contract's `claude` resolved to.
	ln "$sdk/claude_agent_sdk/_bundled/claude" "$w/bin/claude"
	a_contract claude-code.yaml "$w" ||
		{ result a-cli FAIL "examples/agents/claude-code.yaml no longer names api.anthropic.com:443 where this test moves it"; return; }
	# The example's own command, read from the file: this part checks that it completes the task.
	cmd="$(python3 -c 'import json, re, sys; print("\n".join(json.loads(re.search(r"^command:\s*(\[.*?\])", open(sys.argv[1]).read(), re.S | re.M).group(1))))' "$w/agent.yaml")" ||
		{ result a-cli FAIL "examples/agents/claude-code.yaml has no command this test can read"; return; }
	mapfile -t argv <<<"$cmd"
	mkdir -m 700 "$w.tego" && kt_config "$w.tego" >/dev/null
	why="$(a_compiles "$w" "$w/bin:$PATH")"
	case $? in
	0) ;;
	2) result a-cli SKIP "examples/agents/claude-code.yaml names a tool this machine lacks: $why"; return ;;
	*) result a-cli FAIL "examples/agents/claude-code.yaml does not compile here: $why"; return ;;
	esac
	(cd "$w" && PATH="$w/bin:$PATH" TEGO_CONFIG="$w.tego/config.yaml" SSL_CERT_FILE="$w/cert.pem" \
		ANTHROPIC_API_KEY=sk-ant-stub kt_run "$tego" run agent.yaml --tier landlock --offline -- "${argv[@]}") \
		</dev/null >"$w/run.out" 2>"$w/run.err"
	rc=$?
	run="$(kt_rundir "$w.tego")"
	[ -z "$run" ] || kt_save_fixture "kt7-a-cli-landlock" "$run"
	if [ "$rc" != 0 ] || [ -z "$run" ]; then
		result a-cli FAIL "tego run exited $rc: $(kt_err_line "$w/run.err")"
		return
	fi
	if [ ! -s "$w/out/summary.md" ]; then
		result a-cli FAIL "\`${argv[*]}\` did not write out/summary.md, the task's output (its last words: $(tail -3 "$w/run.out" | tr '\n' ' '))"
		return
	fi
	if ! grep -q "Wrote out/summary.md" "$w/run.out"; then
		result a-cli FAIL "\`${argv[*]}\` did not finish the conversation: $(tail -3 "$w/run.out" | tr '\n' ' ')"
		return
	fi
	why="$(a_forwarded "$run" "$w")"
	if [ -n "$why" ]; then
		result a-cli FAIL "$why"
		return
	fi
	# Claude Code writes a file through a temporary one beside it, leak.txt.tmp.<pid>.<hex>, and names the
	# directory as /proc/self/fd/<n>, so the refusal is found by the file's name; the PASS line quotes the
	# target the ledger recorded.
	refused="$(jq -r 'select(.kind == "refused" and .reason == "write-outside-contract" and ((.target // "") | split("/") | last | startswith("leak.txt"))) | .target' "$run/events.jsonl" | head -1)"
	if [ -e "$w/leak.txt" ]; then
		result a-cli FAIL "the write outside the contract happened: $w/leak.txt exists"
	elif [ -z "$refused" ]; then
		result a-cli FAIL "leak.txt was not written, but no refused event with reason write-outside-contract names it"
	else
		result a-cli PASS "tier landlock: \`${argv[*]}\` completed its task under examples/agents/claude-code.yaml; every model request is ssl_request source=forwarder with a parsed response; the write outside the contract was refused (target as recorded: $refused)"
	fi
}

# half_a_gap looks for the gap line FEATURES names in the stderr of half (a)'s run.
half_a_gap() {
	local want="capture: uprobe unavailable (static BoringSSL, no symbols); forwarder active" line
	[ -f "$KT_ROOT/a.run.err" ] || { result a-gap SKIP "half (a) did not run, so there is no run to read the gap line from"; return; }
	line="$(grep -F "forwarder active" "$KT_ROOT/a.run.err" | head -1)"
	if [ -z "$line" ]; then
		result a-gap SKIP "not built: tego prints no capture line for a forwarder run; FEATURES wants \"$want\", which needs the static-TLS detection of Claude Code's binary (ACCEPT-12.3, I3)"
	elif grep -qF "$want" <<<"$line"; then
		result a-gap PASS "$line"
	else
		result a-gap FAIL "the gap line reads \"$line\", FEATURES wants \"$want\""
	fi
}

run_a() {
	local py
	if ! py="$(kt_pydeps --claude-sdk)"; then
		for part in a a-cli a-gap; do
			result "$part" SKIP "the Claude Agent SDK (test/e2e/pydeps.sh --claude-sdk) is not cached here and cannot be fetched; the kernel-matrix guest carries it only with VM_KT7A=1"
		done
		return
	fi
	if ! reason="$(kt_tier_available "$tego" landlock)"; then
		for part in a a-cli a-gap; do result "$part" SKIP "tier landlock unavailable: $reason"; done
		return
	fi
	# One copy per script, on the file system of the work directories, so each part links to it instead of
	# copying 270 MB: a path under the invoking user's home would name the account in a saved fixture.
	sdk="$KT_ROOT/claude-sdk-site"
	cp -r "$py/claude-sdk-site" "$sdk"
	chmod -R go+rX "$sdk"
	half_a
	half_a_cli
	half_a_gap
}

# --- (b) a system-Python agent on the Anthropic SDK via uprobes -------------------------------------
half_b() {
	local py work port rundir nq nr nother nstub refused src tier="${KT7_TIER:-cgroup}" part=b
	# A second tier is a part of its own, so a row running half (b) at both tiers reports each once.
	[ "$tier" = cgroup ] || part="b-$tier"
	if ! kt_sudo_user; then
		result "$part" SKIP "needs root under sudo for tier $tier (CAP_BPF to load and attach the uprobes)"
		return
	fi
	if ! reason="$(kt_tier_available "$tego" "$tier")"; then
		result "$part" SKIP "tier $tier unavailable: $reason"
		return
	fi
	if ! py="$(kt_pydeps)"; then
		result "$part" SKIP "the Anthropic SDK is not cached and cannot be fetched (test/e2e/pydeps.sh)"
		return
	fi
	work="$(kt_workdir)"
	cp -r "$py/anthropic-site" "$work/site"
	chmod -R go+rX "$work/site"
	kt_tls_cert "$work" || { result "$part" SKIP "openssl could not make a certificate for the model stand-in"; return; }
	mkdir -p "$work/in" "$work/out"
	printf 'alpha: the first file\n' >"$work/in/a.txt"
	printf 'beta: the second file\n' >"$work/in/b.txt"
	chmod -R go+rX "$work/in"
	kt_agent_owns "$work/out"
	cat >"$work/script.json" <<-EOF
	[
	 [{"type": "tool_use", "name": "list_dir", "input": {"path": "in"}}],
	 [{"type": "tool_use", "name": "read_file", "input": {"path": "in/a.txt"}}],
	 [{"type": "tool_use", "name": "write_file", "input": {"path": "out/summary.md", "content": "# Summary\\n\\nTwo files: alpha and beta.\\n"}}],
	 [{"type": "tool_use", "name": "write_file", "input": {"path": "$work/leak.txt", "content": "outside the contract"}}],
	 [{"type": "text", "text": "Wrote out/summary.md; the second write was refused."}]
	]
	EOF
	kt_model_stub "$work" "$work/script.json" || { result "$part" FAIL "the model stand-in did not start: $(cat "$work/stub.err")"; return; }
	port="$KT_STUB_PORT"
	cp "$repo/test/workloads/python-anthropic/agent.py" "$work/agent.py"
	# The shipped contract, with only its model endpoint moved to the stand-in.
	sed -e "s/api\.anthropic\.com:443/127.0.0.1:$port/g" \
		-e "s/host: api\.anthropic\.com, port: 443/host: \"127.0.0.1\", port: $port/" \
		"$repo/examples/agents/anthropic-sdk-python.yaml" >"$work/agent.yaml"
	if ! { grep -q "127.0.0.1:$port" "$work/agent.yaml" && grep -q "port: $port" "$work/agent.yaml"; }; then
		result "$part" FAIL "examples/agents/anthropic-sdk-python.yaml no longer names api.anthropic.com:443 where this test moves it"
		return
	fi
	kt_config "$work" >/dev/null
	(cd "$work" && TEGO_CONFIG="$work/config.yaml" SSL_CERT_FILE="$work/cert.pem" ANTHROPIC_API_KEY=stub \
		ANTHROPIC_BASE_URL="https://127.0.0.1:$port" PYTHONPATH="$work/site" \
		kt_run "$tego" run agent.yaml --tier "$tier" --offline -- python3 agent.py "Summarize the files in ./in into ./out/summary.md") \
		>"$work/run.out" 2>"$work/run.err"
	rc=$?
	rundir="$(kt_rundir "$work")"
	[ -z "$rundir" ] || kt_save_fixture "kt7-b-$tier" "$rundir"
	nstub="$(grep -c . "$KT_STUB_LOG")"
	if [ "$rc" != 0 ] || [ -z "$rundir" ]; then
		result "$part" FAIL "tego run exited $rc: $(kt_err_line "$work/run.err")"
		return
	fi
	if ! grep -q "^final: Wrote out/summary.md" "$work/run.out" || [ ! -s "$work/out/summary.md" ]; then
		result "$part" FAIL "the agent did not complete its task: $(tail -3 "$work/run.out" | tr '\n' ' ')"
		return
	fi
	refused="$(jq -r --arg p "$work/leak.txt" 'select(.kind == "refused" and .target == $p) | .reason' "$rundir/events.jsonl" | head -1)"
	if [ -z "$refused" ] || [ -e "$work/leak.txt" ]; then
		result "$part" FAIL "the write outside the contract was not refused on the ledger (agent said: $(grep leak "$work/run.out"))"
		return
	fi
	read -r nq nr nother <<<"$(jq -rs '
		[.[] | select(.kind == "ssl_request")] as $q
		| [.[] | select(.kind == "ssl_response" and (.parser_version // "") != "")] as $r
		| "\($q | length) \($r | length) \([$q[] | select(.source != "ssl")] | length)"' "$rundir/events.jsonl")"
	src="$(jq -r 'select(.kind == "ssl_request") | .source' "$rundir/events.jsonl" | sort | uniq -c | tr -s ' ' | paste -sd, -)"
	if [ "$nother" != 0 ] || [ "$nq" != "$nstub" ]; then
		why=""
		case "$src" in
		*forwarder*) why="; the SDK's requests went through the forwarder, whose listener tego named in ANTHROPIC_BASE_URL although the contract asks for capture: uprobe" ;;
		esac
		result "$part" FAIL "the stand-in answered $nstub model requests; the ledger holds $nq ssl_request (sources:${src:- none}), and every one must be read by the uprobes (source=ssl)$why"
		return
	fi
	if [ "$nr" != "$nstub" ]; then
		result "$part" FAIL "$nr of $nstub ssl_response events parsed"
		return
	fi
	result "$part" PASS "the Anthropic SDK agent completed its task under examples/agents/anthropic-sdk-python.yaml; $nq of $nstub model requests read by the uprobes with parsed responses; the write outside was refused (reason=$refused)"
}
halves=("$@")
[ "${#halves[@]}" -gt 0 ] || halves=(a b)
for h in "${halves[@]}"; do
	case "$h" in
	a)
		if ! kt_am_root; then
			run_a
		elif kt_sudo_user && command -v setpriv >/dev/null 2>&1; then
			# Half (a) is the invoking user's: the half runs as the user sudo names, from this script.
			home="$(getent passwd "$SUDO_UID" | cut -d: -f6)"
			ua="$(kt_workdir)/a.out"
			setpriv --reuid="$SUDO_UID" --regid="${SUDO_GID:-$SUDO_UID}" --clear-groups \
				env -u SUDO_UID -u SUDO_GID -u SUDO_USER -u SUDO_COMMAND HOME="${home:-/}" USER="${SUDO_USER:-}" \
				TEGO_BIN="$tego" TMPDIR=/tmp "$0" a >"$ua" 2>&1
			cat "$ua"
			n=0
			while read -r _ _ part verdict _; do
				n=$((n + 1))
				case "$verdict" in
				PASS) ran=1 ;;
				FAIL) ran=1; failed=1 ;;
				esac
			done < <(grep '^KT-HALF kt7 ' "$ua")
			[ "$n" -gt 0 ] || result a FAIL "the user half printed no result: $(tail -2 "$ua" | tr '\n' ' ')"
		else
			result a SKIP "runs as the invoking user; this is root with no SUDO_UID (or no setpriv) to become that user"
		fi
		;;
	b) half_b ;;
	*) echo "usage: $0 [a] [b]" >&2; exit 2 ;;
	esac
done

[ "$failed" = 0 ] || kt_fail "a half of kill test 7 failed (KT-HALF lines above)"
[ "$ran" = 1 ] || kt_skip "neither half of kill test 7 could run here (KT-HALF lines above)"
kt_pass "every half of kill test 7 that could run here passed (KT-HALF lines above name any that could not)"
