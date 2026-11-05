#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# kt4-ordinary.sh — kill test 4 (P0-DESIGN §10 "4 ordinary work (19/20)"; §12 acceptance item 1;
# docs/FEATURES.md "R18 / kill test 4": "ordinary work (`pip install` + `pytest`, `npm install`,
# `go build`) unbroken under `examples/profiles/base/python-dev` with `record: summary` in every tier
# the machine allows: nineteen of twenty runs exit 0 and emit no `refused` event whose target the
# profile declares; broken = non-zero exit, wall time over 2× the median of five runs outside `tego`,
# or a `refused` event naming a declared path, host or exec.").
#
# What it attacks: that enforcement does not get in the way of work the contract actually allows.
#
# The three kinds of work R18 names, each under a contract that extends base/python-dev and adds only
# its own write directories and the tools it runs:
#   pip  — test/workloads/build/python/run.sh: `pip install` of the §9 build workload's pinned
#          requirements from a local wheelhouse, then `pytest` over its tests (test/e2e/pydeps.sh
#          fetches the wheels and pip once; no index is on the clock). Ordinary work uses
#          site-packages at root tiers and target at landlock. The original --target ./target under
#          a broad writable parent is a checked C55 limit at root tiers, with a tested remedy;
#   npm  — `npm install` of test/workloads/npm-agent, a local zero-registry dependency;
#   go   — `go build` of test/workloads/build/cpu in a module of its own, offline, with a build cache
#          the five baseline runs warm, as a developer's cache is.
# Each is exact and repeatable on any box, including one with no network, so the 2×-median bound
# measures tego's own cost and not a registry's latency. A kind whose tool is missing here is a named
# skip, never a pass.
#
# Tiers: $KT4_TIERS, default "landlock", plus "cgroup", and "bpflsm", when run as root under sudo and doctor allows each.
# Exit 0 when every (kind, tier) that ran passed, 1 when one failed, 2 when none could run; one
# KT-HALF line per (kind, tier) — see test/e2e/lib.sh.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/e2e/lib.sh
. "$repo_root/e2e/lib.sh"
kt_need_jq

KT4_RUNS="${KT4_RUNS:-20}"     # R18: "nineteen of twenty runs"
KT4_BASE_RUNS=5                # R18: "the median of five runs outside tego"
KT4_THRESHOLD=$(((KT4_RUNS * 19 + 19) / 20)) # ceil(0.95 * KT4_RUNS); 19 at the spec's own N=20

tego="$(kt_ensure_tego)"
repo="$(kt_repo_root)"
if kt_am_root && ! kt_sudo_user; then
	kt_skip "running as root without SUDO_UID: a root tego run drops the agent to the sudo user and has none here"
fi

tiers="${KT4_TIERS:-landlock}"
if [ -z "${KT4_TIERS:-}" ] && kt_sudo_user && kt_tier_available "$tego" cgroup >/dev/null; then
	tiers="landlock cgroup"
	# Tier bpflsm, the decision plane in LSM mode, where the boot allows it (TIER3-PLAN §9: kill test 4 at bpflsm).
	if kt_tier_available "$tego" bpflsm >/dev/null; then
		tiers="$tiers bpflsm"
	fi
fi
kinds="${KT4_KINDS:-pip npm go}"

failed=0
ran=0
result() { # part verdict text
	kt_half kt4 "$1" "$2" "${*:3}"
	case "$2" in
	PASS) ran=1 ;;
	FAIL) ran=1; failed=1 ;;
	esac
}

# kt4_timer is the shell that times one run: `bash -c "$kt4_timer" <file> <command...>` runs the command and
# writes its wall time in ms to <file>. The time is taken inside whatever bounds the run, around the command
# itself, because kt_run's bound is timeout(1), and uutils' timeout notices its command's exit only on a 100 ms
# poll: where the host's timeout is uutils' (Ubuntu 25.10's), and so in that host's kernel-matrix guests, timed
# around kt_run every run under tego was up to 100 ms longer than it was, and no baseline run was, since the
# baseline is not bounded (found in a re-acceptance run; test/e2e/kt4_test.sh).
# The baseline is timed by the same shell, so both sides of R18's 2x bound are measured alike. The shell traps
# SIGTERM instead of dying of it, so when the bound signals the run's process group it goes on waiting for
# tego, and the bound still returns when tego does; a trapped signal is reset to its default across exec, so
# the command starts with the dispositions it had without this shell.
# shellcheck disable=SC2016 # the timing shell expands it, with the output file as $0
kt4_timer='trap : TERM; t0=$(date +%s%N); "$@"; rc=$?; t1=$(date +%s%N); echo $(((t1 - t0) / 1000000)) >"$0"; exit "$rc"'

median() {
	# stdin: one integer per line.
	sort -n | awk '{a[NR]=$1} END {if (NR==0) {print 0} else if (NR%2==1) {print a[(NR+1)/2]} else {print int((a[NR/2]+a[NR/2+1])/2)}}'
}

# prepare_<kind> sets up one kind's work directory and sets: cmd (the argv, run from cwd), cwd, reset
# (a command that returns the tree to its state before one run), execs (the exec.allow entries beyond the
# profile's) and envset (extra env.set pairs). It prints a reason and returns 2 when the kind cannot run
# here. run_kind calls them by name ("prepare_$kind"), which shellcheck cannot follow.
# shellcheck disable=SC2329
prepare_pip() {
	local py dest="${1:-target}"
	# shellcheck disable=SC2119 # pydeps.sh's default cache, not this function's arguments
	py="$(kt_pydeps)" || { echo "the pip bootstrap and wheelhouse are not cached and cannot be fetched (test/e2e/pydeps.sh)"; return 2; }
	cp -r "$py/pip-bootstrap" "$py/wheelhouse" "$work/"
	chmod -R go+rX "$work/pip-bootstrap" "$work/wheelhouse"
	# The original target case stays in check_pip_limit. The ordinary root-tier destination
	# stays within name coverage; it does not claim the target restriction has been fixed.
	pip_target="$W/$dest"
	cmd=(bash "$repo/test/workloads/build/python/run.sh" "$work/wheelhouse" "$work/pip-bootstrap" "$pip_target" "$W/tmp")
	cwd="$W"
	# pip installs markupsafe's _speedups extension into target/, and pytest imports it: at the tiers a decision
	# plane decides, a PROT_EXEC map of native code under a write entry needs an exec.allow entry covering it
	# (ADR 0027), or the import falls back to pure Python. The directory is kept between runs (only emptied) so the
	# entry names a path that exists when the contract compiles.
	# pip builds each package under its TMPDIR (tmp/) and then renames the tree into target/. A rename that gains a
	# right the destination alone grants is refused (Landlock's REFER rule, which tier 3's plane keeps: SEMANTICS
	# §2), and target/'s exec.allow is such a right, so tmp/ is named in exec.allow too: without it every package's
	# move was refused rename-outside-contract (pip then copies), and each run counted as broken (2026-10-24). Both are kept between runs, only emptied, for the same reason.
	mkdir -p "$pip_target" "$W/tmp"
	reset="find '$pip_target' '$W/tmp' -mindepth 1 -delete"
	# dirname and mkdir are named as they are, hard links of one multi-call binary on a uutils host (Ubuntu 25.10)
	# included: the plane keys an exec row per link (enforce-plane §6 E15), so each listed link runs.
	execs="\"bash\", \"dirname\", \"mkdir\", \"$pip_target/\", \"$W/tmp/\""
	envset=""
}

# shellcheck disable=SC2329
prepare_npm() {
	command -v npm >/dev/null 2>&1 || { echo "npm is not on PATH"; return 2; }
	command -v node >/dev/null 2>&1 || { echo "node is not on PATH (npm's own #!/usr/bin/env node needs it)"; return 2; }
	cp -r "$repo/test/workloads/npm-agent" "$work/npm-agent-src"
	chmod -R go+rX "$work/npm-agent-src"
	mkdir -p "$W/consumer"
	cat >"$W/consumer/package.json" <<-EOF
	{"name":"kt4-consumer","version":"1.0.0","private":true,"dependencies":{"tego-npm-agent":"file:$work/npm-agent-src"}}
	EOF
	cmd=(npm install --no-audit --no-fund --offline --prefix "$W/consumer")
	cwd="$W/consumer"
	reset="rm -rf '$W/consumer/node_modules' '$W/consumer/package-lock.json'"
	execs='"npm"'
	envset="npm_config_cache: \"$W/cache\", npm_config_update_notifier: \"false\""
}

# shellcheck disable=SC2329
prepare_go() {
	local goroot
	command -v go >/dev/null 2>&1 || { echo "go is not on PATH"; return 2; }
	goroot="$(go env GOROOT)"
	mkdir -p "$W/src"
	cp "$repo/test/workloads/build/cpu/main.go" "$W/src/"
	printf 'module kt4cpu\n\ngo 1.21\n' >"$W/src/go.mod"
	cmd=(go build -o "$W/bin/cpu" .)
	cwd="$W/src"
	reset="rm -rf '$W/bin'"
	# go runs its compiler and linker from GOROOT/pkg/tool, which a directory entry covers.
	execs="\"go\", \"$goroot/pkg/tool/\""
	envset="GOCACHE: \"$W/gocache\", GOPATH: \"$W/gopath\", GOFLAGS: \"-mod=mod\", GOPROXY: \"off\", GOTOOLCHAIN: \"local\", CGO_ENABLED: \"0\", GOTELEMETRY: \"off\""
}

# Explicit write entries grant access; they do not add built-in name scopes (ADR 0043 D10).
write_contract() {
	local kind="$1" extra_writes=""
	if [ "$kind" = pip ] && [ "${2:-scoped}" != broad ]; then
		extra_writes="\"$W/tmp/\", \"$pip_target/\""
	fi
	cat >"$work/agent.yaml" <<-EOF
	version: 0
	name: kt4-$kind
	extends: base/python-dev
	command: [$(printf '"%s", ' "${cmd[@]}" | sed 's/, $//')]
	fs:
	  write: ["$W/"${extra_writes:+, $extra_writes}]
	exec:
	  allow: [$execs]
	env:
	  set: { HOME: "$W/agent-home", TMPDIR: "$W/tmp"${envset:+, $envset} }
	limits:
	  wall: 300s
	EOF

}

# C55: keep the original broad-parent contract visible beside R18's ordinary case. Pip's copy
# fallback is successful work with recorded refusals, not an R18 pass. The remedy uses a cwd root.
check_pip_limit() {
	local tier="$1" rundir rc from to
	work="$(kt_workdir)"
	W="$work/write"
	mkdir -p "$W/agent-home" "$W/tmp" "$W/cache"
	if ! prepare_pip >"$work/why"; then
		result "pip-limit-$tier" SKIP "$(cat "$work/why")"
		return
	fi
	kt_agent_owns "$W"
	kt_config "$work" >/dev/null
	write_contract pip broad
	(cd "$cwd" && TEGO_CONFIG="$work/config.yaml" kt_run "$tego" run "$work/agent.yaml" --tier "$tier" --offline -- "${cmd[@]}") >"$work/limit.log" 2>&1
	rc=$?
	rundir="$(kt_rundir "$work")"
	if [ "$rc" != 0 ] || [ -z "$rundir" ] || ! jq -e -s --arg tmp "$W/tmp/" \
		'any(.[]; .kind == "refused" and .reason == "rename-outside-contract" and (.rule | endswith("/**/.env]")) and (.target | startswith($tmp)))' "$rundir/events.jsonl" >/dev/null; then
		result "pip-limit-$tier" FAIL "broad-parent pip must exit 0 by copying and record its name-coverage rename refusal (exit $rc)"
		return
	fi
	if ! grep -Fq 'lose protected-name coverage' "$rundir/last-refusal.json" ||
		! grep -Fq 'launch working directory' "$rundir/last-refusal.json"; then
		result "pip-limit-$tier" FAIL "the refusal does not explain coverage loss and the contract remedy"
		return
	fi
	if ! TEGO_CONFIG="$work/config.yaml" "$tego" learn "$rundir" >"$work/learn.yaml" 2>"$work/learn.err" ||
		! grep -Fq 'fs.write: ["./tmp/", "./target/"]' "$work/learn.yaml" || ! grep -Fq 'same exec.allow' "$work/learn.yaml" || ! grep -Fq 'cd target' "$work/learn.yaml"; then
		result "pip-limit-$tier" FAIL "tego learn does not give the tested contract change"
		return
	fi
	kt_note "C55 $tier: $(jq -r .text "$rundir/last-refusal.json")"
	kt_save_fixture "kt4-pip-limit-$tier" "$rundir"

	# A directory containing a protected name cannot escape through the excluded target directory,
	# even though the broad write grants both ends. Use a real syscall, not mv's copy fallback.
	from="$W/tmp/protected"; to="$W/target/escaped"
	mkdir -p "$from"
	printf 'KT4_FIXTURE=protected\n' >"$from/.env"
	kt_agent_owns "$W"
	rm -rf "$work/runs"
	(cd "$cwd" && TEGO_CONFIG="$work/config.yaml" kt_run "$tego" run "$work/agent.yaml" --tier "$tier" --offline -- \
		python3 -c 'import os,sys; os.rename(sys.argv[1], sys.argv[2])' "$from" "$to") >"$work/move.log" 2>&1
	rc=$?
	rundir="$(kt_rundir "$work")"
	if [ "$rc" != 1 ] || [ ! -f "$from/.env" ] || [ -e "$to" ] || [ -z "$rundir" ] ||
		! jq -e -s --arg src "$from" 'any(.[]; .kind == "refused" and .target == $src and .reason == "rename-outside-contract" and (.rule | startswith("fs.deny_read[")))' "$rundir/events.jsonl" >/dev/null; then
		result "name-move-$tier" FAIL "a writable-to-writable directory move lost protected-name coverage (exit $rc)"
		return
	fi
	kt_note "D5 $tier: $(jq -c --arg src "$from" 'select(.kind == "refused" and .target == $src)' "$rundir/events.jsonl")"
	kt_save_fixture "kt4-name-move-$tier" "$rundir"
	result "name-move-$tier" PASS "directory containing .env stayed at its source; rename out of name protection refused"

	# Apply precisely the guidance above, keeping all other grants. No deny_read waiver is involved.
	eval "$reset"
	rm -rf "$work/runs"
	write_contract pip
	cwd="$W/target" # C55 remedy: target is the launch cwd, not an added write-root scope.
	(cd "$cwd" && TEGO_CONFIG="$work/config.yaml" kt_run "$tego" run "$work/agent.yaml" --tier "$tier" --offline -- "${cmd[@]}") >"$work/remedy.log" 2>&1
	rc=$?
	rundir="$(kt_rundir "$work")"
	if [ "$rc" != 0 ] || [ -z "$rundir" ] || ! jq -e -s --arg w "$W/" \
		'all(.[]; .kind != "refused" or ((.target // "") | startswith($w) | not))' "$rundir/events.jsonl" >/dev/null; then
		result "pip-limit-$tier" FAIL "explicit staging/target writes and launching from target did not remedy pip's refusal (exit $rc)"
		return
	fi

	result "pip-limit-$tier" PASS "broad-parent refusal explained; learn's explicit writes plus target-cwd remedy ran pip without a declared-path refusal"
}

# run_kind runs one kind at one tier: five baseline runs outside tego, then KT4_RUNS under it.
run_kind() {
	local kind="$1" tier="$2" base_times=() base_median budget_ms i rc wall rundir pass_count=0
	local failures=() walls=() target d bad_refusal declared
	work="$(kt_workdir)"
	W="$work/write"
	# Go probes telemetry below HOME; a synthetic /home/ component would trip
	# kt_save_fixture's guard against exporting account paths.
	mkdir -p "$W/agent-home" "$W/tmp" "$W/cache"
	# Called in this shell, not in a $(...), so the variables it sets survive; a skip's reason goes to a file.
	local prep=()
	# Landlock permits the original target workload. At root tiers it remains an explicit limit.
	[ "$kind" != pip ] || [ "$tier" = landlock ] || prep=(site-packages)
	if ! "prepare_$kind" "${prep[@]}" >"$work/why"; then
		result "$kind-$tier" SKIP "$(cat "$work/why")"
		return
	fi
	kt_agent_owns "$W"
	kt_config "$work" >/dev/null
	write_contract "$kind"
	# The baseline runs as the agent will: as the user a root run drops to, with the same environment.
	local as_agent=()
	! kt_sudo_user || as_agent=(setpriv --reuid="$SUDO_UID" --regid="${SUDO_GID:-$SUDO_UID}" --clear-groups)
	local goenv=()
	[ "$kind" != go ] || goenv=(GOCACHE="$W/gocache" GOPATH="$W/gopath" GOFLAGS=-mod=mod GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0 GOTELEMETRY=off)
	for i in $(seq 1 "$KT4_BASE_RUNS"); do
		eval "$reset"
		rm -f "$work/wall"
		(cd "$cwd" && bash -c "$kt4_timer" "$work/wall" "${as_agent[@]}" env HOME="$W/agent-home" TMPDIR="$W/tmp" PYTHONDONTWRITEBYTECODE=1 \
			npm_config_cache="$W/cache" npm_config_update_notifier=false "${goenv[@]}" "${cmd[@]}") >"$work/base.log" 2>&1
		rc=$?
		if [ "$rc" -ne 0 ]; then
			result "$kind-$tier" FAIL "baseline run $i outside tego exited $rc — the workload itself is broken here, not tego: $(tail -2 "$work/base.log" | tr '\n' ' ')"
			return
		fi
		base_times+=("$(cat "$work/wall")")
	done
	base_median="$(printf '%s\n' "${base_times[@]}" | median)"
	budget_ms="$((base_median * 2))"
	# A run ten times the baseline is broken whatever it does next; bounding it there keeps a launcher that
	# hangs from holding the kill test for kt_run's default bound twenty times over.
	local KT_RUN_TIMEOUT=$((base_median * 10 / 1000 + 60))
	kt_note "$kind at tier $tier: baseline median ${base_median}ms, budget ${budget_ms}ms (2x, R18)"

	# What the contract declares, for R18's "a refused event naming a declared path, host or exec": every
	# write, exec and net entry of the contract as compiled, the profile's merged in, so a path the profile
	# alone declares (its /dev/null) counts as much as the contract's own. Compiled rather than read from
	# the two files, because compile is what resolves an exec name to the path a refusal would name.
	# An empty entry would match every target below, so none is kept.
	mapfile -t declared < <(cd "$cwd" && TEGO_CONFIG="$work/config.yaml" "$tego" compile "$work/agent.yaml" --offline --json 2>"$work/compile.err" |
		jq -r '([.fs[] | select(.kind == "write") | .path] + [.exec[] | .path, .raw] + [.net[] | .raw])[]
			| select(. != null) | rtrimstr("/") | select(. != "")')
	if [ "${#declared[@]}" = 0 ]; then
		result "$kind-$tier" FAIL "tego compile of the kill test's contract named nothing it declares: $(kt_err_line "$work/compile.err")"
		return
	fi
	for i in $(seq 1 "$KT4_RUNS"); do
		# Once more runs have broken than R18 forgives, the verdict cannot change: the rest are not run.
		if [ "${#failures[@]}" -gt $((KT4_RUNS - KT4_THRESHOLD)) ]; then
			failures+=("runs $i-$KT4_RUNS not run: ${#failures[@]} broken already decide the verdict")
			break
		fi
		eval "$reset"
		rm -rf "$work/runs"
		rm -f "$work/wall"
		(cd "$cwd" && TEGO_CONFIG="$work/config.yaml" kt_run bash -c "$kt4_timer" "$work/wall" \
			"$tego" run "$work/agent.yaml" --tier "$tier" --offline -- "${cmd[@]}") >"$work/run.log" 2>&1
		rc=$?
		# No time written means kt_run's SIGKILL, ten seconds past the bound, killed the timing shell with tego:
		# the run counts as lasting the whole bound, and its exit status already makes it broken.
		wall="$(cat "$work/wall" 2>/dev/null || echo $((KT_RUN_TIMEOUT * 1000)))"
		walls+=("$wall")
		[ "$i" != 1 ] || [ -z "$(kt_rundir "$work")" ] || kt_save_fixture "kt4-$kind-$tier" "$(kt_rundir "$work")"
		if [ "$rc" -ne 0 ]; then
			failures+=("run $i: exit $rc ($(kt_err_line "$work/run.log"))")
			continue
		fi
		if [ "$wall" -gt "$budget_ms" ]; then
			failures+=("run $i: wall ${wall}ms over the ${budget_ms}ms budget")
			continue
		fi
		rundir="$(kt_rundir "$work")"
		if [ -z "$rundir" ]; then
			failures+=("run $i: exit 0 but no run directory")
			continue
		fi
		if ! kt_ledger_valid "$rundir/events.jsonl"; then
			failures+=("run $i: the ledger has a line that is not JSON (the refused-target scan would stop there)")
			continue
		fi
		bad_refusal=""
		while IFS= read -r target; do
			[ -n "$target" ] || continue
			for d in "${declared[@]}"; do
				case "$target" in
				"$d" | "$d"/* | */"$d") bad_refusal="$target (declared: $d)" ;;
				esac
			done
		done < <(jq -r 'select(.kind == "refused") | .target // empty' "$rundir/events.jsonl" 2>/dev/null)
		if [ -n "$bad_refusal" ]; then
			failures+=("run $i: refused a declared target: $bad_refusal")
			continue
		fi
		pass_count=$((pass_count + 1))
	done
	for d in "${failures[@]:-}"; do
		[ -n "$d" ] && kt_note "  $kind/$tier $d"
	done
	local timing
	timing="baseline median ${base_median}ms, under tego median $(printf '%s\n' "${walls[@]}" | median)ms, budget ${budget_ms}ms"
	if [ "$pass_count" -ge "$KT4_THRESHOLD" ]; then
		result "$kind-$tier" PASS "$pass_count of $KT4_RUNS runs unbroken ($timing)"
	else
		result "$kind-$tier" FAIL "$pass_count of $KT4_RUNS runs unbroken, R18 needs $KT4_THRESHOLD ($timing); first: ${failures[0]:-}"
	fi
}

for tier in $tiers; do
	if ! reason="$(kt_tier_available "$tego" "$tier")"; then
		for kind in $kinds; do result "$kind-$tier" SKIP "tier $tier unavailable: $reason"; done
		continue
	fi
	for kind in $kinds; do
		run_kind "$kind" "$tier"
		[ "$kind" != pip ] || [ "$tier" = landlock ] || check_pip_limit "$tier"
	done
done

[ "$failed" = 0 ] || kt_fail "ordinary work was broken under tego (KT-HALF lines above)"
[ "$ran" = 1 ] || kt_skip "none of R18's kinds of work could run here (KT-HALF lines above)"
kt_pass "every kind of ordinary work that could run here was unbroken in at least $KT4_THRESHOLD of $KT4_RUNS runs (KT-HALF lines above)"
