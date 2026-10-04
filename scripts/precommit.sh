#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# precommit.sh — `make precommit` and .githooks/pre-commit: CI's build-test job, run here before a commit, so a
# commit that job would fail is not made.
#
# The steps, in build-test's order: gofmt over the Go files git tracks or would add; go vet untagged, with
# -tags integration, with -tags tegobpf, and with both as CI vets them; golangci-lint with .golangci.yml, then
# again with its build-tags line emptied and unused off (the files the tags leave out, as CI's second lint run);
# the SPDX check; shellcheck over the tracked scripts when it is installed; scripts/check-skiplists.sh;
# scripts/check-exits.sh (limits-check-doctor-cli.md I6, I9); scripts/check-fd.sh (ADR 0023's descriptor rules and
# ratchet, with the total held to the merge base with master when there is one); tools/rulecheck (ADR 0030: rule IDs unique in each
# spec, no dangling reference; then its -strict count, report only); tools/isocheck (no test harness can write the
# invoking user's ~/.tego or ~/.bash_history: identity-config.md R27); the unit
# tests and the unprivileged integration tests, each as JSON through scripts/skipgate.sh with its list. go test's
# own exit status is checked beside the gate's, since skipgate.sh judges skips and exits 0 over a failed test.
# Every go test step, in either mode, runs with -count=1 (gated-test.sh adds it too): go test's cache rechecks only
# the files the test process itself opens, so a test whose verdict comes from a go build, go list or a built binary it
# runs (the link gate, the binary-closure suites) replayed a stale pass.
# bpf-objects (scripts/check-bpf-objects.sh: `make gen` in a clean copy must reproduce internal/bpf) runs only when
# bpf/ or internal/bpf/ differs from origin/master or has uncommitted changes, or when TEGO_PRECOMMIT_BPF=1.
# Then the script self-tests build-test runs (install, coverage, bench-gate, timing-budgets, skipgate, release and
# the harness tests, and precommit_test.sh, which holds this list to ci.yml's), and actionlint when it is installed.
# govulncheck is not run: it needs the network. The absolute timing budgets themselves are not run here: they need
# an idle machine (`make budgets`, scripts/timing-budgets.sh; CI's bench-gate job), and the gated tests hold them to
# their unit-gate ceilings.
# The tests run in this user's systemd user manager (scripts/in-user-manager.sh), as CI's do.
#
# Every step runs, and the script reports each one's result (with its duration) and fails if any failed.
#
# Steps run concurrently (scripts/precommit-runner.sh), in three phases: the static checks (the lint job, the
# longest, started first), then the unit tests followed in the same job by the tegotesthooks tests (go test -p sized
# to the job budget), then the integration tests alone. At most TEGO_PRECOMMIT_JOBS jobs run at once; the default is
# min(nproc/2, memory/2 GB) and never below 1, the memory being the lower of MemAvailable and what each of this
# process's cgroups has left (memory.max less memory.current without its inactive page cache: the gate's slice is
# shared). TEGO_PRECOMMIT_JOBS=1 runs every step one after another in the order above. Each step's output is kept apart and printed in that fixed order,
# with its duration, whatever finished first; a step that is killed, or never reported, is a failure.
#
# Modes (docs/OPERATIONS.md, "Precommit modes"): with no TEGO_PRECOMMIT_SINCE, the full gate above, which every
# master merge runs. With TEGO_PRECOMMIT_SINCE=<rev> (`make precommit-affected BASE=<rev>`), the change-scoped
# check for in-between runs: tools/affected compares the tree with the merge base of HEAD and <rev> and prints what
# it selects and why; a global input (go.mod, the gate's scripts and lists, tools/, internal/testutil/, ...) runs
# the full gate; Markdown alone runs the docs gate (rulecheck, check-spdx, the tests that read Markdown); anything
# else runs gofmt, the vets and lints over the affected packages, check-spdx, check-licenses, check-skiplists,
# check-exits, check-fd, rulecheck, isocheck, shellcheck over the changed scripts and the selected tests through the
# same skip lists. It is never a replacement for the full gate. The verdict line says which mode passed: only the
# full gate prints "precommit: every step passed"; `make precommit` and the commit hook clear TEGO_PRECOMMIT_SINCE.
#
# Usage: scripts/precommit.sh   (from anywhere in the checkout; enable the hook with
#   `git config core.hooksPath .githooks`)
# Environment: TEGO_PRECOMMIT_JOBS (jobs at once), TEGO_PRECOMMIT_SINCE (the scoped mode's base revision),
#   TEGO_PRECOMMIT_BPF=1 (force the bpf-objects step), GO (go), GOLANGCI_LINT (golangci-lint), SHELLCHECK
#   (shellcheck), ACTIONLINT (actionlint).
# Exit: 0 when every step passed, 1 when one failed, 2 on a bad TEGO_PRECOMMIT_JOBS.
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
GO="${GO:-go}"
LINT="${GOLANGCI_LINT:-golangci-lint}"
SHELLCHECK="${SHELLCHECK:-shellcheck}"
ACTIONLINT="${ACTIONLINT:-actionlint}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-precommit.XXXXXX")"
# shellcheck source=scripts/precommit-runner.sh
. ./scripts/precommit-runner.sh
# A step still running when the script ends (an interrupt) is stopped with it, and so is what it started.
trap 'pc_stop; rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM
# shellcheck disable=SC2034 # read by the sourced runner
PC_TMP="$tmp"

# default_jobs: min(nproc/2, GB/2), GB being MemAvailable or the least any of this process's cgroups has left
# (memory.max less memory.current: a VM or another gate in the same slice holds part of it). inactive_file is taken
# off memory.current, as MemAvailable counts it: the page cache of the builds before this gate stays charged to the
# slice, and counted as used it turned a parallel gate into a serial one with nothing else running.
# PC_SYSROOT: a tree holding proc/meminfo and sys/fs/cgroup in place of the real ones (precommit_test.sh's fixture).
default_jobs() {
	local n gb cg lim cur cache free j root="${PC_SYSROOT:-}/sys/fs/cgroup"
	n="$(nproc 2>/dev/null || echo 2)"
	gb="$(awk '/^MemAvailable:/{print int($2/1048576)}' "${PC_SYSROOT:-}/proc/meminfo" 2>/dev/null)"
	gb="${gb:-2}"
	cg="$(sed -n 's/^0:://p' /proc/self/cgroup 2>/dev/null)"
	while [ -n "$cg" ]; do
		lim="$(cat "$root$cg/memory.max" 2>/dev/null)"
		cur="$(cat "$root$cg/memory.current" 2>/dev/null)"
		cache="$(awk '$1 == "inactive_file" { print $2 }' "$root$cg/memory.stat" 2>/dev/null)"
		case "$cur" in '' | *[!0-9]*) cur=0 ;; esac
		case "$cache" in '' | *[!0-9]*) cache=0 ;; esac
		cur=$((cache < cur ? cur - cache : 0))
		case "$lim" in '' | max | *[!0-9]*) ;; *)
			free=$((lim > cur ? lim - cur : 0))
			[ $((free / 1073741824)) -lt "$gb" ] && gb=$((free / 1073741824))
			;;
		esac
		[ "$cg" != / ] || break
		cg="$(dirname "$cg")"
	done
	j=$((n / 2))
	[ $((gb / 2)) -ge "$j" ] || j=$((gb / 2))
	[ "$j" -ge 1 ] || j=1
	echo "$j"
}
PC_JOBS="${TEGO_PRECOMMIT_JOBS:-$(default_jobs)}"
case "$PC_JOBS" in '' | *[!0-9]* | 0)
	echo "precommit: TEGO_PRECOMMIT_JOBS must be a positive integer, not '$PC_JOBS'" >&2
	exit 2
	;;
esac
# go test -p for the test passes: the job budget (the tegotesthooks pass runs after the unit pass, in its job, so the
# timing tests do not share the machine with it). JOBS=1 leaves go test's own default.
test_p=()
[ "$PC_JOBS" -le 1 ] || test_p=(-p "$PC_JOBS")
# The lint job (both golangci-lint runs and the script self-tests, about 4 min) starts before the vets.
# shellcheck disable=SC2034 # read by the sourced runner
PC_FIRST=lint

gofmt_clean() { ./scripts/gofmt-clean.sh; }
govet() {
	local tags=$1
	shift
	if [ "$tags" = - ]; then "$GO" vet "$@"; else "$GO" vet -tags "$tags" "$@"; fi
}
lint_tagged() { "$LINT" run --config .golangci.yml "$@"; }
lint_untagged() { GOLANGCI_LINT="$LINT" ./scripts/lint-untagged.sh "$@"; }
shellcheck_all() {
	# The tree's own files, not the index's (a deletion not yet staged would fail here), and the hook, which has no .sh.
	{ ./scripts/tree-files.sh | grep -zE '\.sh$'; printf '.githooks/pre-commit\0'; } | xargs -0 "$SHELLCHECK" -e SC1091
}
shellcheck_files() { "$SHELLCHECK" -e SC1091 "$@"; }
check_spdx() { ./scripts/check-spdx.sh; }
check_licenses() { GO="$GO" ./scripts/check-licenses.sh; }
check_skiplists() { ./scripts/check-skiplists.sh; }
check_exits() { GO="$GO" ./scripts/check-exits.sh; }
rulecheck() { "$GO" run ./tools/rulecheck; }
# Report only, never a failure: the rules no Test/Fuzz doc comment or t.Run name cites (rulecheck -strict).
rulecheck_strict() { "$GO" run ./tools/rulecheck -strict 2>&1 | sed -n 's/^rulecheck: strict: //p'; }
isocheck() { "$GO" run ./tools/isocheck; }
bpf_objects() { ./scripts/check-bpf-objects.sh --worktree; }
actionlint_run() { "$ACTIONLINT"; }
# script_tests: the shell self-tests build-test runs (make release-test, install-test, skipgate-test, coverage-test,
# bench-gate-test, budgets-test and harness-test, and the vm helpers' own).
script_tests() {
	local t st=0
	# The python helpers some self-tests run leave no __pycache__ in the tree.
	export PYTHONDONTWRITEBYTECODE=1
	for t in scripts/install_test.sh scripts/install-maze_test.sh scripts/coverage_test.sh scripts/bench-gate_test.sh scripts/timing-budgets_test.sh scripts/check-spdx_test.sh scripts/check-licenses_test.sh scripts/scrub-capture_test.sh scripts/fuzz-corpus_test.sh scripts/deadcode-report_test.sh scripts/skipgate_test.sh \
		scripts/check-skiplists_test.sh scripts/release_test.sh scripts/check-control-pin_test.sh scripts/bpf-toolchain_test.sh scripts/tree-files_test.sh \
		scripts/precommit_test.sh scripts/check-bpf-objects_test.sh scripts/fd-churn_test.sh scripts/check-fd_test.sh scripts/check-edgelint_test.sh test/vm/kvm-step_test.sh test/vm/python-pkgs_test.sh test/vm/fetch-kernel_test.sh \
		test/e2e/lib_test.sh test/e2e/pydeps_test.sh test/e2e/kt4_test.sh test/e2e/kt5_test.sh test/e2e/kt2_pairs_test.sh test/e2e/m0_demo_test.sh test/e2e/overhead/kt3_test.sh test/e2e/overhead/bench_test.sh test/e2e/overhead/run_test.sh \
		test/vm/matrix_test.sh test/vm/root-suites_test.sh test/vm/doctor-refusal_test.sh test/vm/doctor-facts_test.sh test/vm/perf_test.sh \
		test/vm/guarded-run_test.sh test/vm/bounded-run_test.sh test/vm/fwd-run_test.sh test/vm/kvm-modules_test.sh test/vm/kvm-files_test.sh test/vm/kvm-cleanup_test.sh test/vm/tier2-pairs_test.sh test/vm/pairs_test.sh \
		test/vm/kvm-run_test.sh; do
		"./$t" >"$tmp/script-test.out" 2>&1 || { echo "$t failed:"; cat "$tmp/script-test.out"; st=1; }
	done
	return "$st"
}
# gated NAME LIST CGO_ENABLED ARGS...: go test -json ARGS through skipgate.sh LIST; fails on go test's status or
# the gate's. The integration tests build cgo-free, as CI's step and the shipped binary do. -count=1 on every test
# step: a cached pass is replayed when the test binary and the files it opened are unchanged, though a go build or
# go list it ran would now read a different tree (the header).
gated_unit() { GO="$GO" ./scripts/gated-test.sh test/unit-skips.txt "$("$GO" env CGO_ENABLED)" -count=1 "${test_p[@]}" "$@"; }
gated_integration() { GO="$GO" ./scripts/gated-test.sh test/integration-skips.txt 0 -count=1 "${test_p[@]}" -tags integration "$@"; }
hooks_test() { "$GO" test -count=1 "${test_p[@]}" -tags tegotesthooks "$@"; }
# check_fd: ADR 0023 A9 holds the baseline's total to the merge base with master (the gate runs
# locally); a checkout with no master checks everything but the total, and says so.
check_fd() {
	local base
	if base="$(git merge-base HEAD master 2>/dev/null)"; then
		GO="$GO" ./scripts/check-fd.sh --base "$base"
	else
		echo "check-fd: no master to take a merge base from; the baseline's total is not compared"
		GO="$GO" ./scripts/check-fd.sh
	fi
}
# bpf_touched: bpf/ or internal/bpf/ differs from origin/master (HEAD when there is none), committed or not, or
# holds untracked files.
bpf_touched() {
	local base=origin/master
	git rev-parse -q --verify "$base" >/dev/null || base=HEAD
	! git diff --quiet "$base" -- bpf internal/bpf || git status --porcelain --untracked-files=all -- bpf internal/bpf | grep -q '^??'
}

# add_full: the full gate's steps, in build-test's order. The two golangci-lint runs and the script self-tests share
# a job (golangci-lint refuses a second instance while one holds its lock, and check-fd_test.sh and
# check-edgelint_test.sh run it), as do rulecheck and its report.
add_full() {
	pc_add static gofmt "gofmt" step gofmt_clean
	pc_add static vet "go vet" step govet - ./...
	pc_add static vet-i "go vet -tags integration" step govet integration ./...
	pc_add static vet-b "go vet -tags tegobpf" step govet tegobpf ./...
	pc_add static vet-ib "go vet -tags 'integration tegobpf'" step govet integration,tegobpf ./...
	pc_add static lint "golangci-lint" step lint_tagged ./...
	pc_add static lint "golangci-lint (the files the tags leave out)" step lint_untagged
	pc_add static spdx "check-spdx" step check_spdx
	pc_add static licenses "check-licenses" step check_licenses
	if command -v "$SHELLCHECK" >/dev/null; then
		pc_add static shellcheck "shellcheck" step shellcheck_all
	else
		pc_add static - "shellcheck" note "not installed (CI's scripts-and-workflows job runs it)"
	fi
	pc_add static skiplists "check-skiplists" step check_skiplists
	pc_add static exits "check-exits" step check_exits
	pc_add static fd "check-fd (ADR 0023 descriptor ownership)" step check_fd
	pc_add static rulecheck "rulecheck" step rulecheck
	pc_add static isocheck "isocheck (harnesses keep out of ~/.tego)" step isocheck
	pc_add static rulecheck "rulecheck -strict (report only)" report rulecheck_strict
	if [ "${TEGO_PRECOMMIT_BPF:-}" = 1 ] || bpf_touched; then
		pc_add static bpf "bpf-objects (make gen reproduces internal/bpf)" step bpf_objects
	else
		pc_add static - "bpf-objects" note "skipped: bpf/, internal/bpf/ match origin/master (TEGO_PRECOMMIT_BPF=1 forces)"
	fi
	pc_add static lint "script self-tests" step script_tests
	if command -v "$ACTIONLINT" >/dev/null; then
		pc_add static actionlint "actionlint" step actionlint_run
	else
		pc_add static - "actionlint" note "not installed (CI's scripts-and-workflows job runs it)"
	fi
	pc_add tests unit "unit tests (test/unit-skips.txt)" step gated_unit ./...
	# In the unit job, after the unit pass: beside it, the unit pass's timing tests (rulesview's InForce) ran slow.
	# precommit_test.sh holds this list to the directories with tegotesthooks test files.
	pc_add tests unit "unit tests (-tags tegotesthooks)" step hooks_test ./internal/bpf/ ./internal/cli/ ./internal/platform/sys/ ./internal/runtime/enforce/ ./internal/runtime/enforce/landlock/
	pc_add integration integration "integration tests (test/integration-skips.txt)" step gated_integration ./...
}

# add_scoped PLAN: the steps tools/affected's plan selects (mode scoped or docs). A build's test and run lines share
# one job, and the tegotesthooks lines the unit job, so no more test binaries run at once than in the full gate.
add_scoped() {
	local plan=$1 mode kind tags rest label
	local -a words run
	mode="$(sed -n 's/^mode //p' "$plan")"
	if [ "$mode" = scoped ]; then
		pc_add static gofmt "gofmt" step gofmt_clean
	fi
	while read -r kind tags rest; do
		read -ra words <<<"$rest"
		case "$kind" in
		vet) pc_add static "vet-$tags" "go vet [$tags] (${#words[@]} affected)" step govet "$tags" "${words[@]}" ;;
		lint)
			# The plan's lint line has no tags field: every word is a directory.
			words=("$tags" "${words[@]}")
			pc_add static lint "golangci-lint (${#words[@]} affected)" step lint_tagged "${words[@]}"
			pc_add static lint "golangci-lint, untagged files (${#words[@]} affected)" step lint_untagged "${words[@]}"
			;;
		shell)
			words=("$tags" "${words[@]}")
			if command -v "$SHELLCHECK" >/dev/null; then
				pc_add static shellcheck "shellcheck (changed scripts)" step shellcheck_files "${words[@]}"
			else
				pc_add static - "shellcheck" note "not installed (CI's scripts-and-workflows job runs it)"
			fi
			;;
		esac
	done <"$plan"
	pc_add static spdx "check-spdx" step check_spdx
	if [ "$mode" = scoped ]; then
		# A Go-only change can link a new third-party package (or a sub-licence of a linked module): no go.mod edit.
		pc_add static licenses "check-licenses" step check_licenses
		pc_add static skiplists "check-skiplists" step check_skiplists
		pc_add static exits "check-exits" step check_exits
		pc_add static fd "check-fd (ADR 0023 descriptor ownership)" step check_fd
	fi
	pc_add static rulecheck "rulecheck" step rulecheck
	[ "$mode" != scoped ] || pc_add static isocheck "isocheck (harnesses keep out of ~/.tego)" step isocheck
	while read -r kind tags rest; do
		run=()
		read -ra words <<<"$rest"
		if [ "$kind" = run ]; then
			run=(-run "${words[0]}")
			words=("${words[@]:1}")
		elif [ "$kind" != test ]; then
			continue
		fi
		label="${#words[@]} pkgs"
		[ "${#run[@]}" -eq 0 ] || label="$label, -run"
		case "$tags" in
		-) pc_add tests unit "unit tests ($label)" step gated_unit "${run[@]}" "${words[@]}" ;;
		tegotesthooks) pc_add tests unit "tegotesthooks tests ($label)" step hooks_test "${run[@]}" "${words[@]}" ;;
		integration) pc_add integration integration "integration tests ($label)" step gated_integration "${run[@]}" "${words[@]}" ;;
		esac
	done <"$plan"
}

mode=full
if [ -n "${TEGO_PRECOMMIT_SINCE:-}" ]; then
	# No plan (a base git does not know, a tools/affected that does not build) is never fewer checks: the full gate.
	if ! "$GO" run ./tools/affected -base "$TEGO_PRECOMMIT_SINCE" -plan >"$tmp/plan"; then
		echo "precommit: tools/affected found no plan for the change since $TEGO_PRECOMMIT_SINCE (above): running the full gate"
		echo "mode full" >"$tmp/plan"
	fi
	mode="$(sed -n 's/^mode //p' "$tmp/plan")"
	case "$mode" in
	full) echo "precommit: a global input changed, or there is no plan (above): running the full gate" ;;
	docs | scoped)
		echo "precommit: $mode mode since $TEGO_PRECOMMIT_SINCE: an in-between check, never a merge's gate"
		# shellcheck disable=SC2034 # read by the sourced runner
		PC_VERDICT="precommit: every selected step passed ($mode mode since $TEGO_PRECOMMIT_SINCE; not a merge gate)"
		;;
	*)
		echo "precommit: tools/affected printed no mode: running the full gate"
		mode=full
		;;
	esac
fi
echo "precommit: $PC_JOBS job(s) at once (TEGO_PRECOMMIT_JOBS)"
if [ "$mode" = full ]; then add_full; else add_scoped "$tmp/plan"; fi
pc_run static
pc_run tests
pc_run integration
pc_finish
