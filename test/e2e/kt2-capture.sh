#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt2-capture.sh — kill test 2 (P0-DESIGN §10 "2 capture (95% of pairs, gaps explained)"; §12
# acceptance item 1; docs/FEATURES.md "R8 / kill test 2": "uprobe path (system Python + OpenSSL,
# HTTP/1.1): on a 20-step run at least 95% of model request/response pairs are
# `ssl_request`/`ssl_response` events whose response parsed, and every missing pair is explained by
# a `gap what=capture` event or the `count` of a `gap what=record`. Forwarder path (Claude Code,
# Agent SDK, Codex): every model request is `ssl_request source=forwarder`, and every direct connect
# to the model host is `refused`, by host in tiers 2 and 3, by port in tier 1.").
#
# What it attacks: that model traffic is captured completely (uprobe path) or, when it cannot be
# (bundled-TLS agents), that every real model call still goes through the forwarder and any attempt
# to skip it is refused rather than leaking out uncaptured.
#
# Both halves run the same 20-step agent (test/workloads/python-steps) against the same local model
# stand-in (test/workloads/model-stub), an HTTPS endpoint the run trusts through SSL_CERT_FILE, so
# neither needs an API key or spends anything, and neither can be made to pass by a flaky upstream.
#   forwarder half: `capture: forwarder`; the agent talks to the forwarder's loopback listener, and
#     after its 20 steps connects straight to the model host. Every request must be an ssl_request
#     with source=forwarder and a parsed ssl_response, and the direct connect must fail in the agent
#     and be a refused net event in the ledger. It runs at $KT_TIER (default: cgroup as root under
#     sudo, else landlock).
#   uprobe half: `capture: uprobe` at tier cgroup, root only. The agent talks TLS itself through the
#     system libssl; at least 19 of its 20 exchanges must be ssl_request/ssl_response pairs with
#     source=ssl whose response parsed, and every missing pair must be covered by a capture gap or a
#     record gap's count.
#
# An earlier version of this script ran the forwarder pair check through `go test` and never wrote the
# uprobe half. Both now run here against the real binary, on any machine with python3 and openssl, the
# kernel-matrix guest included.
#
# Exit 0 when every half that could run passed (each prints a KT-HALF line; a skipped half is named,
# never counted as a pass), 1 when one failed, 2 when none could run — see test/e2e/lib.sh.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
kt2_pairs_jq="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/kt2-pairs.jq"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

STEPS=20
NEED=$(((STEPS * 95 + 99) / 100)) # R8: at least 95% of the pairs; 19 of 20

tego="$(kt_ensure_tego)"
command -v python3 >/dev/null 2>&1 || kt_skip "python3 is not on PATH: both halves run a system-Python agent"
if kt_am_root && ! kt_sudo_user; then
	kt_skip "running as root without SUDO_UID: a root tego run drops the agent to the sudo user and has none here"
fi

work="$(kt_workdir)"
kt_tls_cert "$work" || kt_skip "openssl could not make a certificate for the local model stand-in"
kt_model_stub "$work" || kt_skip "the local model stand-in did not start: $(cat "$work/stub.err" 2>/dev/null)"
port="$KT_STUB_PORT"
agent="$(kt_repo_root)/test/workloads/python-steps/agent.py"
kt_note "model stand-in on https://127.0.0.1:$port"

failed=0
ran=0
result() { # half verdict text
	kt_half kt2 "$1" "$2" "${*:3}"
	case "$2" in
	PASS) ran=1 ;;
	FAIL) ran=1; failed=1 ;;
	esac
}

# run_half writes a contract for one half into its own directory and runs the agent under it; it
# prints the run directory. $1 half name, $2 tier, $3 the contract's capture/net/env block.
run_half() {
	local half="$1" tier="$2" body="$3" dir out url=-
	# The uprobe half's agent speaks TLS to the stand-in itself; the forwarder half's reads the listener
	# tego hands it in ANTHROPIC_BASE_URL ("-").
	[ "$half" != uprobe ] || url="https://127.0.0.1:$port"
	dir="$work/$half"
	out="$dir/out"
	mkdir -p "$out"
	chmod 755 "$dir"
	kt_agent_owns "$out"
	kt_config "$dir" >/dev/null
	cat >"$dir/agent.yaml" <<-EOF
	version: 0
	name: kt2-$half
	command: ["python3", "$agent"]
	models:
	  - { provider: anthropic, host: "127.0.0.1", port: $port }
	fs:
	  write: ["$out/"]
	exec:
	  allow: ["python3"]
	limits:
	  pids: 64
	  wall: 120s
	record: summary
	$body
	EOF
	(cd "$dir" && TEGO_CONFIG="$dir/config.yaml" SSL_CERT_FILE="$work/cert.pem" DIRECT="127.0.0.1:$port" \
		kt_run "$tego" run agent.yaml --tier "$tier" --offline -- python3 "$agent" "$url" "$STEPS") \
		>"$dir/run.out" 2>"$dir/run.err"
	echo $? >"$dir/exit"
	kt_rundir "$dir"
}

# pairs prints "<requests> <parsed responses> <requests from another source> <capture gaps> <record gap
# count> <pairs>" for one ledger (test/e2e/kt2-pairs.jq). A pair is a request line with a parsed response
# that names it by request_seq, not a smaller-of-two count that a duplicated event could inflate.
pairs() {
	jq -rs --arg src "$2" -f "$kt2_pairs_jq" "$1/events.jsonl"
}

# --- forwarder half ------------------------------------------------------------------------------
ftier="${KT_TIER:-$(kt_sudo_user && echo cgroup || echo landlock)}"
if ! reason="$(kt_tier_available "$tego" "$ftier")"; then
	result forwarder SKIP "tier $ftier unavailable: $reason"
else
	kt_note "forwarder half: $STEPS steps through the forwarder at tier $ftier, then a direct connect to the model host"
	# The contract has no net: section, as this half's contract always had. R38 makes the forwarder's
	# port the only route to a declared model host once capture: forwarder is active, so the direct
	# connect has to be refused whether or not the contract says anything else about the network.
	rundir="$(run_half forwarder "$ftier" 'capture: forwarder
env:
  pass: ["PATH", "HOME", "DIRECT"]')"
	d="$work/forwarder"
	[ -z "$rundir" ] || kt_save_fixture "kt2-forwarder-$ftier" "$rundir"
	if [ "$(cat "$d/exit")" != 0 ] || [ -z "$rundir" ]; then
		result forwarder FAIL "tego run exited $(cat "$d/exit"): $(kt_err_line "$d/run.err")"
	elif ! grep -q "steps=$STEPS ok=$STEPS" "$d/run.out"; then
		result forwarder FAIL "the agent did not complete its $STEPS model calls through the forwarder: $(tail -3 "$d/run.out")"
	else
		fwd_problem="$(kt_forwarded_problem "$rundir/events.jsonl" "$STEPS")"
		refused="$(jq -r --arg t "127.0.0.1:$port" 'select(.kind == "refused" and .target == $t) | .reason' \
			"$rundir/events.jsonl" | head -1)"
		if [ -n "$fwd_problem" ]; then
			result forwarder FAIL "$fwd_problem (for $STEPS model calls)"
		elif ! grep -q "direct connect refused" "$d/run.out"; then
			result forwarder FAIL "a direct connect to the model host around the forwarder succeeded: $(grep direct "$d/run.out")"
		elif [ -z "$refused" ]; then
			result forwarder FAIL "the direct connect failed in the agent but no refused event names 127.0.0.1:$port"
		else
			result forwarder PASS "tier $ftier: $STEPS of $STEPS requests are ssl_request source=forwarder with a parsed response; the direct connect was refused (reason=$refused)"
		fi
	fi
fi

# --- uprobe half -----------------------------------------------------------------------------------
if ! kt_sudo_user; then
	result uprobe SKIP "needs root under sudo for tier cgroup (CAP_BPF to load and attach the uprobes)"
elif ! reason="$(kt_tier_available "$tego" cgroup)"; then
	result uprobe SKIP "tier cgroup unavailable: $reason"
else
	kt_note "uprobe half: $STEPS steps over the system libssl at tier cgroup"
	rundir="$(run_half uprobe cgroup "capture: uprobe
net:
  allow: [\"127.0.0.1:$port\"]
env:
  pass: [\"PATH\", \"HOME\"]
  set: { SSL_CERT_FILE: \"$work/cert.pem\" }")"
	d="$work/uprobe"
	[ -z "$rundir" ] || kt_save_fixture "kt2-uprobe-cgroup" "$rundir"
	if [ "$(cat "$d/exit")" != 0 ] || [ -z "$rundir" ]; then
		result uprobe FAIL "tego run exited $(cat "$d/exit"): $(kt_err_line "$d/run.err")"
	elif ! grep -q "steps=$STEPS ok=$STEPS" "$d/run.out"; then
		result uprobe FAIL "the agent did not complete its $STEPS model calls: $(tail -3 "$d/run.out")"
	else
		read -r nq nr nother ncg nrg got <<<"$(pairs "$rundir" ssl)"
		missing=$((STEPS - got))
		explained=$((ncg + nrg))
		gaps="$(jq -r 'select(.kind == "gap") | "\(.what):\(.why)\(if .binary then " " + .binary else "" end)"' \
			"$rundir/events.jsonl" | sort | uniq -c | tr -s ' ' | paste -sd, -)"
		if [ "$nother" != 0 ]; then
			result uprobe FAIL "$nother ssl_request events did not come from the uprobes (source != ssl)"
		elif [ "$nq" -gt "$STEPS" ] || [ "$nr" -gt "$STEPS" ]; then
			result uprobe FAIL "$nq ssl_request and $nr parsed ssl_response events for $STEPS model calls: an exchange was captured more than once"
		elif [ "$got" -lt "$NEED" ]; then
			result uprobe FAIL "$got of $STEPS pairs captured and parsed ($nq requests, $nr parsed responses, matched by request_seq), R8 needs $NEED; gaps: ${gaps:-none}"
		elif [ "$missing" -gt "$explained" ]; then
			result uprobe FAIL "$missing pairs missing but only $explained explained by capture gaps or record gap counts (gaps: ${gaps:-none})"
		else
			result uprobe PASS "$got of $STEPS pairs captured from the system libssl with parsed responses; $missing missing, $explained explained"
		fi
	fi
fi

[ "$failed" = 0 ] || kt_fail "a half of kill test 2 failed (KT-HALF lines above)"
[ "$ran" = 1 ] || kt_skip "neither half of kill test 2 could run here (KT-HALF lines above)"
kt_pass "every half of kill test 2 that could run here passed (KT-HALF lines above name any that could not)"
