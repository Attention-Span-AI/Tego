#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# coverage.sh — statement coverage of the whole module, merged across the suites that exercise it:
#
#   unit         go test ./...
#   integration  go test -tags integration ./... (the unprivileged half: root tests skip here)
#   vm           with --vm, the privileged suites of test/vm/root-suites.sh, each run as root in its own
#                KVM guest by test/vm/kvm-run.sh, as `make vm-root-test` runs them
#   kill tests   with --kill-tests ROW, the tego that one kernel-matrix row's kill tests run, as the user
#                and as root, in that row's guests: test/vm/matrix.sh ROW with VM_COVER=1
#
# Why it exists: the code with the least coverage is the root-only code whose real tests run only as root
# (launch, internal/bpf, platform/sys, doctor), and without the guests' share nobody can tell which of its
# fail-closed branches the privileged suites exercise at all. Every suite writes binary coverage data
# (GOCOVERDIR, Go 1.20+) for every package of the module (-coverpkg), in atomic mode so the sets merge;
# `go tool covdata` merges them. The guests have no shared filesystem with the host, so each guest prints
# its data files on its console, one "TEGO-COVFILE <name> <base64>" line each, and this script decodes
# them from the console log. A guest that returns none (it timed out, panicked, or never booted, so there is
# no console at all) is reported and left out, and the collection goes on to the next.
#
# A test binary built with -cover that re-executes itself (launch's child stage, the ledger's crash helper,
# the supervisor's target) prints "warning: GOCOVERDIR not set" as that child exits unless GOCOVERDIR is in
# its environment, and a test that reads the child's stderr then fails. So every suite runs with GOCOVERDIR
# set as well as -test.gocoverdir, which is also how those children's own lines get counted, and the guests'
# data directory is writable by every uid, since a root run drops its agent to the invoking user. A test that
# still fails under instrumentation is reported and does not stop the collection: this measures coverage,
# and the suites' verdicts come from the jobs that run them uninstrumented.
#
# The kill tests (test/e2e, driven in a row's guests by test/vm/run-matrix-row.sh) are shell scripts that run
# the tego binary itself, so their share is that binary's, not a test binary's. VM_COVER=1 is the switch
# between the two scripts: matrix.sh then builds the tego it stages with `go build -cover -covermode=atomic
# -coverpkg=<module>/...` (and -tags tegobpf as it otherwise would), and run-matrix-row.sh sets GOCOVERDIR
# to a directory every uid can write, since a root run drops its agent to the user and the user half runs
# tego as the user, and prints each data file as a TEGO-COVFILE line after its results. Every boot's
# console lands in $VM_OUT/matrix/ROW/boot*.console, which this script reads. The launcher's child stage
# starts with an empty environment (internal/runtime/launch), so its own lines are not in the figure: it
# ends in the agent's execve, which writes no counters, and one that exits instead prints "warning:
# GOCOVERDIR not set", which a kill test reading that stderr exactly can fail on under this build. Like the
# suites, this run is report-only, and the kill tests' verdicts come from the uninstrumented matrix run.
#
# Output in DIR (default bin/coverage): percent.txt, one line per package with its coverage from the unit
# and integration suites and, with --vm or --kill-tests, with what the guests returned added (+vm);
# coverage.out, the merged profile in the text format `go tool cover -html` reads; and the raw data
# directories.
#
# DIR is emptied first, so it is named by a flag, never by position: a bare word is a package filter.
# Were the output positional, `../../scripts/coverage.sh --vm launch` run from internal/runtime would take
# "launch" for the output and remove that package's source. For the same reason an existing DIR is
# removed only when it holds the marker file this script writes into every DIR it makes; any other
# non-empty path is refused. Options are read wherever they stand among the filters, and a filter without
# --vm, where it would choose nothing, is a usage error: either way the output would otherwise go somewhere
# other than the caller asked (`coverage.sh /tmp/cov`, the positional form this replaced, or
# `coverage.sh --vm launch -o DIR`), and quietly.
#
# Usage: scripts/coverage.sh [--vm] [--kill-tests ROW] [-o DIR] [package-substring...]
#   --vm                 also run the privileged suites in KVM guests (see test/vm/README.md)
#   --kill-tests ROW     also run the kill tests of one kernel-matrix row with a -cover tego
#   -o DIR               where the output goes (default bin/coverage in the repository)
#   package-substring    with --vm only: the privileged packages whose path contains one of these
# Environment: GO (go); TEGO_VM_LOCK, a file every suite's guest boot takes `flock` on, for a machine where
# several jobs boot guests (matrix.sh takes its own, TEGO_VM_CACHE's guest.lock); VM_SUITE_TIMEOUT (seconds
# per guest, default 1500, above 300; the suite's own -test.timeout is that less 300); matrix.sh's VM_* and kvm-run.sh's TEGO_VM_*; TEGO_VM_HARNESS, a directory that
# stands in for test/vm (kvm-run.sh, matrix.sh, fetch-kernel.py, go-shim.sh), for scripts/coverage_test.sh.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
GO="${GO:-go}"
usage() {
	sed -n '/^# Usage:/,/^# Environment:/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//' >&2
	exit 2
}
vm=0
kill_row=""
out="$repo/bin/coverage"
filters=()
while [ $# -gt 0 ]; do
	case "$1" in
	--vm) vm=1; shift ;;
	--kill-tests) [ $# -ge 2 ] || usage; kill_row="$2"; shift 2 ;;
	--kill-tests=*) kill_row="${1#--kill-tests=}"; [ -n "$kill_row" ] || usage; shift ;;
	-o) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
	-o*) out="${1#-o}"; shift ;;
	-h | --help) usage ;;
	--) shift; filters+=("$@"); break ;;
	-*) echo "coverage: unknown option $1" >&2; usage ;;
	*) filters+=("$1"); shift ;;
	esac
done
[ -n "$out" ] || usage
if [ "${#filters[@]}" -gt 0 ] && [ "$vm" = 0 ]; then
	echo "coverage: ${filters[*]}: a package filter chooses among the privileged suites, which only --vm runs; the output directory is -o DIR" >&2
	usage
fi
# Each guest's bound; the suite's own -test.timeout ends 300s before it, as root-suites.sh's does, so a slow
# suite's panic names its running tests (it was a fixed 20m, which cut short a suite given a longer bound).
# Plain seconds only: root-suites.sh's "pkg=seconds" words would reach kvm-run.sh's --timeout unread.
suite_timeout="${VM_SUITE_TIMEOUT:-1500}"
if [ "$vm" = 1 ]; then
	case "$suite_timeout" in
	"" | *[!0-9]*) echo "coverage: VM_SUITE_TIMEOUT must be plain seconds, not \"$suite_timeout\"" >&2; exit 2 ;;
	esac
	[ "$suite_timeout" -gt 300 ] || { echo "coverage: VM_SUITE_TIMEOUT must be above 300 seconds, the suite's margin inside it" >&2; exit 2; }
fi
vmdir="${TEGO_VM_HARNESS:-$repo/test/vm}"
# The row names a directory matrix.sh empties, so it is checked against the list before anything runs, as
# matrix.sh itself checks it, rather than after the unit and integration suites have spent their minutes.
if [ -n "$kill_row" ]; then
	rows="$(python3 "$vmdir/fetch-kernel.py" --list | awk '{ printf " %s", $1 }') " ||
		{ echo "coverage: --kill-tests: fetch-kernel.py --list failed" >&2; exit 2; }
	case "$rows" in
	*" $kill_row "*) ;;
	*) echo "coverage: --kill-tests: \"$kill_row\" is not a kernel-matrix row (rows:$rows)" >&2; exit 2 ;;
	esac
fi
# The same packages, working directories, helpers and sudo identity as test/vm/root-suites.sh, whose
# comments say why each is what it is; only the -cover build and the data coming back are added. They are
# chosen before anything runs, so a filter that matches nothing stops the script before the unit and
# integration suites spend their minutes.
# shellcheck source=test/vm/suites.sh
. "$repo/test/vm/suites.sh"
pkgs=("${PKGS[@]}")
if [ "${#filters[@]}" -gt 0 ]; then
	selected=()
	for p in "${pkgs[@]}"; do
		for f in "${filters[@]}"; do
			case "$p" in *"$f"*) selected+=("$p"); break ;; esac
		done
	done
	pkgs=("${selected[@]+"${selected[@]}"}")
	[ "${#pkgs[@]}" -gt 0 ] || { echo "coverage: no privileged package matches ${filters[*]}" >&2; exit 2; }
fi
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac
cd "$repo"
module="$("$GO" list -m)"

marker=.tego-coverage
if [ -e "$out" ] && [ ! -f "$out/$marker" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
	echo "coverage: $out exists and was not made by coverage.sh (no $marker in it); not emptying it. Name another directory with -o." >&2
	exit 2
fi
rm -rf "$out"
mkdir -p "$out/unit" "$out/integration"
echo "made by scripts/coverage.sh, which empties this directory on its next run" >"$out/$marker"

# Every package of the module is instrumented in every suite, so a line one package's tests reach in
# another package counts, as it does for the privileged suites, whose tests drive launch, the supervisor
# and the BPF loader through each other.
cover=(-cover -covermode=atomic "-coverpkg=$module/...")

failed=0
echo "== unit"
GOCOVERDIR="$out/unit" "$GO" test -p 4 "${cover[@]}" ./... -args -test.gocoverdir="$out/unit" ||
	{ echo "coverage: a unit test failed under instrumentation (above); collection goes on" >&2; failed=1; }
echo "== integration (unprivileged)"
GOCOVERDIR="$out/integration" "$GO" test -p 4 -tags integration "${cover[@]}" ./... -args -test.gocoverdir="$out/integration" ||
	{ echo "coverage: an integration test failed under instrumentation (above); collection goes on" >&2; failed=1; }

# harvest DIR CONSOLE...: decodes every "TEGO-COVFILE <name> <base64>" line of the consoles into DIR and
# prints how many files DIR then holds. A console that does not exist, or holds no such line, adds nothing:
# that is a guest that returned no data, which the caller reports and goes on from, so nothing here may
# fail under errexit and pipefail, where a grep matching nothing, or a console never written, once ended the
# whole collection with no percent.txt. A line cut short by a guest stopped mid-print does not decode and is
# dropped; a name with a slash would write outside DIR and is not a name the guest's own loop prints.
harvest() {
	local dir="$1" console name data
	shift
	mkdir -p "$dir"
	for console in "$@"; do
		[ -f "$console" ] || continue
		while read -r _ name data; do
			case "$name" in "" | */* | . | ..) continue ;; esac
			printf '%s' "$data" | base64 -d >"$dir/$name" 2>/dev/null || rm -f "$dir/$name"
		done < <(tr -d '\r' <"$console" | grep -a '^TEGO-COVFILE ' || true)
	done
	find "$dir" -type f | wc -l
}

# add_input NAME DIR COUNT: DIR joins the merge when it holds data that reads; otherwise NAME is reported.
add_input() {
	if [ "$3" -eq 0 ]; then
		echo "coverage: no coverage data came back from $1" >&2
		failed=1
		return
	fi
	if ! "$GO" tool covdata percent -i="$2" >/dev/null 2>&1; then
		echo "coverage: the coverage data from $1 does not read (a console cut short?); left out" >&2
		failed=1
		return
	fi
	inputs="$inputs,$2"
}

inputs="$out/unit,$out/integration"
if [ "$vm" = 1 ]; then
	vmout="$out/vm"
	mkdir -p "$vmout/bin" "$vmout/prebuilt" "$vmout/logs" "$vmout/src"
	"$here/tree-files.sh" | tar --null -T - -cf - | tar -xf - -C "$vmout/src"
	for h in "${HELPERS[@]}"; do
		CGO_ENABLED=0 "$GO" build -o "$vmout/prebuilt/${h##*/}" "./$h"
		CGO_ENABLED=0 "$GO" build -tags tegobpf -o "$vmout/prebuilt/${h##*/}.tegobpf" "./$h"
		CGO_ENABLED=0 "$GO" build -tags tegotesthooks -o "$vmout/prebuilt/${h##*/}.testhooks" "./$h"
		CGO_ENABLED=0 "$GO" build -tags tegobpf,tegotesthooks -o "$vmout/prebuilt/${h##*/}.tegobpf.testhooks" "./$h"
	done
	lock=()
	[ -z "${TEGO_VM_LOCK:-}" ] || lock=(flock "$TEGO_VM_LOCK")
	for p in "${pkgs[@]}"; do
		suite="${p//\//_}"
		bin="$vmout/bin/$suite.test"
		# A suite whose tests load the BPF objects runs with them embedded, as root-suites.sh's tagged
		# variant does (the objects are committed), so the tier-2 paths it drives count; the helpers it
		# builds at run time are then the tagged ones too (go-shim.sh reads GOFLAGS).
		tags=integration
		# The guest is a throwaway machine: tests that change host-wide state run there (root-suites.sh).
		env_args=(--env "TEGO_DISPOSABLE_HOST=kvm")
		# Read the complete dependency list: grep -q can stop go list with
		# SIGPIPE, which pipefail mistakes for an absent BPF dependency.
		if "$GO" list -tags integration -test -deps "./$p" 2>/dev/null | grep -x "$module/internal/bpf" >/dev/null; then
			tags=integration,tegobpf
			env_args+=(--env "GOFLAGS=-tags=$tags")
		fi
		echo "== $p, -tags $tags (as root in a KVM guest)"
		CGO_ENABLED=0 "$GO" test -c -tags "$tags" "${cover[@]}" -o "$bin" "./$p"
		# The data goes to the console as one "TEGO-COVFILE <name> <base64>" line per file, after the
		# suite, whatever its result: a failing suite's coverage is still what it exercised.
		# shellcheck disable=SC2016 # the script is the guest's, and the guest's sh expands it
		"${lock[@]}" "$vmdir/kvm-run.sh" --sudo --timeout "$suite_timeout" \
			--log "$vmout/logs/$suite.console" --status "$vmout/logs/$suite.status" \
			--file "$bin:/vm/$suite.test" --file "$vmout/src:/src" --file "$vmout/prebuilt:/vm/prebuilt" \
			--file "$vmdir/go-shim.sh:/usr/local/bin/go" --cwd "/src/$p" "${env_args[@]+"${env_args[@]}"}" \
			-- /bin/sh -c '
				mkdir -p /tmp/covdata && chmod 1777 /tmp/covdata
				GOCOVERDIR=/tmp/covdata "$0" "-test.timeout=$1" -test.gocoverdir=/tmp/covdata >/tmp/suite.out 2>&1; rc=$?
				cat /tmp/suite.out
				for f in /tmp/covdata/*; do
					[ -f "$f" ] && echo "TEGO-COVFILE ${f##*/} $(base64 -w0 "$f")"
				done
				exit "$rc"' "/vm/$suite.test" "$((suite_timeout - 300))s" || { echo "coverage: $p failed in the guest (status: $(cat "$vmout/logs/$suite.status" 2>/dev/null || echo none))" >&2; failed=1; }
		n=$(harvest "$vmout/data/$suite" "$vmout/logs/$suite.console")
		echo "   $n coverage data file(s) back from the guest"
		add_input "$p's guest" "$vmout/data/$suite" "$n"
	done
fi
if [ -n "$kill_row" ]; then
	# matrix.sh reports its rows' verdicts itself and exits 1 when a check failed: under the -cover build
	# that is a finding about this run, and what the kill tests reached still counts.
	ktout="$out/killtests"
	mkdir -p "$ktout"
	echo "== kill tests of the $kill_row row, with a -cover tego (as the user and as root in KVM guests)"
	VM_OUT="$ktout/vm" VM_COVER=1 "$vmdir/matrix.sh" "$kill_row" ||
		{ echo "coverage: a kill test failed under instrumentation, or $kill_row did not boot (above); collection goes on" >&2; failed=1; }
	n=$(harvest "$ktout/data" "$ktout/vm/matrix/$kill_row"/boot*.console)
	echo "   $n coverage data file(s) back from $kill_row's guests"
	add_input "the kill tests on $kill_row" "$ktout/data" "$n"
fi
guests=0
[ "$vm" = 0 ] && [ -z "$kill_row" ] || guests=1

# percent_of DIRS: "package percent" per line, from `go tool covdata percent`. The package is the word
# before "coverage:", not the line's first: covdata prints "\t<package>\t\t" for every package and then the
# figure with its newline only for one that has statements, so a package with none (bpf, a generated
# bindings-only package) is left at the start of the next package's line. Reading $1 dropped
# internal/bpf, whose 69.7% sat behind such a name, from percent.txt.
percent_of() {
	"$GO" tool covdata percent -i="$1" |
		awk '{ for (i = 2; i < NF; i++) if ($i == "coverage:") { p = $(i + 1); sub(/%$/, "", p); print $(i - 1), p } }' | sort
}
mkdir -p "$out/merged"
"$GO" tool covdata merge -i="$inputs" -o="$out/merged"
"$GO" tool covdata textfmt -i="$out/merged" -o="$out/coverage.out"
percent_of "$out/unit,$out/integration" >"$out/without-vm.txt"
if [ "$guests" = 1 ]; then
	percent_of "$out/merged" >"$out/with-vm.txt"
	{
		printf '%-60s %10s %10s\n' package unit+int +vm
		join "$out/without-vm.txt" "$out/with-vm.txt" | awk '{ printf "%-60s %9s%% %9s%%\n", $1, $2, $3 }'
	} >"$out/percent.txt"
else
	{
		printf '%-60s %10s\n' package unit+int
		awk '{ printf "%-60s %9s%%\n", $1, $2 }' "$out/without-vm.txt"
	} >"$out/percent.txt"
fi
echo "== coverage by package ($out/percent.txt)"
cat "$out/percent.txt"
if [ "$failed" = 1 ]; then
	echo "coverage: some tests failed under instrumentation or in a guest; the figures above omit what they did not reach" >&2
fi
