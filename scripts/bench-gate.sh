#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# bench-gate.sh — the hot paths' benchmarks of this checkout against a base commit's, decided by benchstat
# (ADR 0028 S1: "CI runs benchstat against the parent commit with a threshold wider than measured noise").
#
# Why it exists: the decision paths the kernel waits on (fanotify's decideOpen, the supervisor's notified
# syscall, the pipeline's queue) have a budget per event (P0-DESIGN §9), and several allocate nothing today.
# A benchmark only reports; nothing failed when a change slowed one down or made it allocate. The five that
# must stay at zero are pinned by AllocsPerRun unit tests as well; this gate covers every benchmark listed
# below, against the base, on the same machine and in the same job.
#
# Method: both trees' test binaries are built first (CGO_ENABLED=0, as the product), then run in ROUNDS rounds,
# each package's base binary and head binary back to back, with the side that goes first alternating from
# round to round so a drift in the machine's load over the job lands on both sides alike. Each binary runs
# from its own tree's package directory (tests read testdata), -test.benchtime BENCHTIME -test.count 1
# -test.benchmem. benchstat then compares the ROUNDS samples of each side, and its CSV form is what the
# decision reads: the table form is printed for the reader only.
#
# What fails the gate, per benchmark:
#   allocs/op   the base's median is 0 and the head's is not: a zero-allocation path now allocates
#   B/op        more than +10%, where benchstat finds the change significant (p < 0.05, its default); a B/op
#               of 0 that becomes non-zero, likewise significant, counts as over it
#   sec/op      more than +25% at p < 0.01
# A benchmark named in noisy below is compared and printed and never fails the gate: its spread on a shared
# runner is wider than these thresholds. A package or benchmark the base does not have is reported, not
# compared; a benchmark, or a whole package's results, the base has and the head does not fails the gate (a rename or a regex that no longer
# matches would otherwise drop it from the gate unseen), unless it is one of the noisy ones. A head binary that does not build, or whose run fails, fails the gate: the benchmark itself is
# broken. A base that does not build or run is reported, and what it did produce is still compared.
#
# Usage: scripts/bench-gate.sh [-n ROUNDS] [-t BENCHTIME] [-o DIR] [--head DIR] BASE_DIR
#        scripts/bench-gate.sh compare BASE_RESULTS HEAD_RESULTS
#   BASE_DIR     a checkout of the base commit (CI: a git worktree of it)
#   --head DIR   the checkout under test (default: the one holding this script)
#   -n ROUNDS    rounds per side (default 10)
#   -t BENCHTIME -test.benchtime of every run (default 100ms)
#   -o DIR       where binaries and results go (default: a new temporary directory, kept and named); an
#                existing DIR must be empty or one this script made
#   compare      the decision alone, over two directories of <package>.txt results as the gate writes them
# Environment: GO (default go), BENCHSTAT (default benchstat); BENCH_GATE_PACKAGES replaces the package list
# (the self-test's fake packages).
# Exit: 0 no gated regression; 1 a gated regression, or head's benchmarks failed to build or run; 2 usage.
set -euo pipefail

# The benchmarks the gate runs, one package per line: its directory, the -test.bench regex, and the build
# tags its test binary needs. Adding a benchmark is adding its name to a regex, or a line here. The regexes
# keep each round short (about 8 s a side on an i7-10870H); a whole package's benchmarks would add the slow
# ones (BenchmarkSweepNRuns/100 takes 6 ms an op, BenchmarkCompile several) to every round.
default_packages='
internal/policy/decide               ^BenchmarkIndexedEvaluator$
internal/runtime/enforce/cgroup      ^Benchmark(PolicyDecide|DecideOpenByEntryCount|DecideEventOffTheRun|ListenerHandle|SlotAcquireRelease|BuildRuleMaps)
internal/runtime/supervisor          ^Benchmark(NotificationRoundTrip|ParseSockaddr|NearestFS|SendMMsgTail|SeccompNotifyRoundTrip)$  integration
internal/runtime                     ^Benchmark(PipelineEvent|QueueEmit|SweepLiveNRuns)$
internal/runtime/derive              ^BenchmarkSteps
internal/runtime/capture/httpstream  ^Benchmark(Feed|FeedExchange|Chunked|Feed1ByteChunks)$
internal/runtime/capture/forwarder   ^BenchmarkForward$
internal/runtime/capture/uprobe      ^BenchmarkHandle$
internal/runtime/derive/anthropic    ^BenchmarkParse$
internal/ledger                      ^Benchmark(Append|AppendRefused|RefusalFlood|RefusalHostileTarget|IterFullRun|Blob|RedactStage|SplitBlobsStage)$
pkg/spec/record                      ^Benchmark(MarshalLine|Decode|VerifyLine)$
internal/bpf                         ^Benchmark
internal/runtime/observe             ^Benchmark(DecodeInto|Drain)$
internal/runtime/limits              ^Benchmark(Observe|Tick)$
internal/platform/sys                ^Benchmark(Borrow|Hold|OwnedOpenClose)$
'

# Report-only benchmarks, by top-level name: compared and printed, never failed. Feed and FeedExchange
# (httpstream's reassembly, whose buffers put the collector's timing into every op), BuildRuleMaps (per run,
# not per event, and allocation-heavy), SendMMsgTail (a thousand decisions an op, GC-bound), IterFullRun (one
# op is a whole 100,000-line ledger), SeccompNotifyRoundTrip (a real kernel round trip: two context switches an
# op on a shared runner), SlotAcquireRelease (a file and its lock per op), Blob and SplitBlobsStage (a blob file
# created and renamed per op), OwnedOpenClose (an open and a close of /dev/null per op; ADR 0023's P9 records it
# beside its raw twin, while Borrow and Hold, the lease itself, are gated).
noisy='Feed FeedExchange BuildRuleMaps SendMMsgTail IterFullRun SeccompNotifyRoundTrip SlotAcquireRelease Blob SplitBlobsStage OwnedOpenClose'

GO=${GO:-go}
BENCHSTAT=${BENCHSTAT:-benchstat}

usage() {
	sed -n 's/^# \{0,1\}//; /^Usage:/,/^Exit:/p' "$0" >&2
	exit 2
}

# key names a package's files: its directory with the slashes made underscores.
key() { printf '%s' "$1" | tr / _; }

# ADR 0028 S1 has an absolute query budget, including when the base lacks this
# new benchmark. Every measured sample must be below 1us with no allocation.
absolute_queries() { # absolute_queries FILE
	awk '
	function finite(s) {
		return s ~ /^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][+-]?[0-9]+)?$/ &&
			tolower(sprintf("%.17g", s + 0)) !~ /inf|nan/
	}
	/^BenchmarkIndexedEvaluator\// {
		name = $1; tier = name; sub(/^BenchmarkIndexedEvaluator\//, "", tier); sub(/-[0-9]+$/, "", tier)
		seen[tier] = 1; ns = bytes = allocs = -1
		for (i = 3; i < NF; i += 2) {
			if (($(i+1) == "ns/op" || $(i+1) == "B/op" || $(i+1) == "allocs/op") && !finite($i)) {
				printf "FAIL indexed-query %s: invalid %s value %s\n", name, $(i+1), $i
				continue
			}
			if ($(i+1) == "ns/op") ns = $i + 0
			if ($(i+1) == "B/op") bytes = $i + 0
			if ($(i+1) == "allocs/op") allocs = $i + 0
		}
		if (ns < 0 || ns >= 1000 || bytes != 0 || allocs != 0)
			printf "FAIL indexed-query %s: %g ns/op, %g B/op, %g allocs/op; requires <1000 ns/op and zero allocations\n", name, ns, bytes, allocs
	}
	END {
		n = split("landlock cgroup bpflsm", tiers, " ")
		for (i = 1; i <= n; i++) if (!(tiers[i] in seen))
			printf "FAIL indexed-query: missing %s benchmark samples\n", tiers[i]
	}' "$1"
}

# decide reads benchstat's CSV for one package on stdin and prints one line per finding:
# "FAIL <why>", "note <why>" (report-only or not compared).
decide() { # decide PACKAGE
	awk -F, -v pkg="$1" -v noisy="$noisy" '
	BEGIN { n = split(noisy, l, " "); for (i = 1; i <= n; i++) quiet[l[i]] = 1 }
	function finite(s) {
		return s ~ /^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][+-]?[0-9]+)?$/ &&
			tolower(sprintf("%.17g", s + 0)) !~ /inf|nan/
	}
	# The two header lines of each unit table: the side labels, then the unit in the second column.
	/^,/ { if ($3 == "CI") unit = $2; next }
	NF == 0 || $1 == "geomean" { next }
	unit == "" { next } # the configuration lines above the first table
	{
		name = $1
		if (NF < 7) {
			value = ($2 == "" ? $4 : $2)
			if (!finite(value) || value + 0 < 0) {
				printf "FAIL %s %s: invalid %s value %s\n", pkg, name, unit, value
				next
			}
			# One side only: a benchmark the base does not have (or no longer runs). Said once, under the first unit.
			if (!(name in once)) {
				once[name] = 1
				side = ($2 == "" ? "head" : "base")
				top = name; sub(/\/.*/, "", top); sub(/-[0-9]+$/, "", top)
				# One the head lost is what a rename or a -test.bench regex that no longer matches looks like,
				# and the gate would lose what it guards; only a report-only benchmark may go missing quietly.
				if (side == "base" && !(top in quiet))
					printf "FAIL %s %s: the base has it and the head does not: renamed, or no longer matched by the package'"'"'s regex\n", pkg, name
				else
					printf "note %s %s: only the %s has it; not compared\n", pkg, name, side
			}
			next
		}
		for (i = 2; i <= NF - 6; i++) name = name "," $i
		gsub(/^"|"$/, "", name)
		top = name; sub(/\/.*/, "", top); sub(/-[0-9]+$/, "", top)
		base = $(NF - 5); head = $(NF - 3); delta = $(NF - 1)
		pct = delta; sub(/%$/, "", pct)
		if (!finite(base) || !finite(head) || base + 0 < 0 || head + 0 < 0 ||
			(delta != "~" && delta != "?" && (delta !~ /%$/ || !finite(pct)))) {
			printf "FAIL %s %s: invalid %s comparison values %s -> %s (%s)\n", pkg, name, unit, base, head, delta
			next
		}
		# Pinned benchstat omits p= when its exact p-value is zero (Comparison.String).
		p = 0
		if ($NF ~ /^p=/) {
			p = $NF; sub(/^p=/, "", p); sub(/ .*/, "", p)
			if (!finite(p) || p + 0 < 0 || p + 0 > 1 || $NF !~ /^p=[^ ]+ n=[1-9][0-9]*(\+[1-9][0-9]*)?$/) {
				printf "FAIL %s %s: invalid comparison p-value %s\n", pkg, name, $NF
				next
			}
		} else if ($NF !~ /^n=[1-9][0-9]*(\+[1-9][0-9]*)?$/) {
			printf "FAIL %s %s: invalid comparison p-value %s\n", pkg, name, $NF
			next
		}
		base += 0; head += 0; pct += 0; p += 0
		why = ""
		if (unit == "allocs/op" && base == 0 && head > 0)
			why = sprintf("allocs/op %g -> %g: a zero-allocation benchmark now allocates", base, head)
		else if (unit == "B/op" && delta ~ /^\+/ && pct > 10)
			why = sprintf("B/op %s (%s): over +10%%", delta, $NF)
		else if (unit == "B/op" && delta == "?" && base == 0 && head > 0 && p < 0.05)
			why = sprintf("B/op %g -> %g (%s): over +10%%", base, head, $NF)
		else if (unit == "sec/op" && delta ~ /^\+/ && pct > 25 && p < 0.01)
			why = sprintf("sec/op %s (%s): over +25%% at p<0.01", delta, $NF)
		if (why == "") next
		if (top in quiet) printf "note %s %s: %s (report-only)\n", pkg, name, why
		else printf "FAIL %s %s: %s\n", pkg, name, why
	}'
}

# compare runs benchstat over every package the head has results for and prints the tables and the findings;
# it returns 1 when anything fails the gate.
compare() { # compare BASE_RESULTS HEAD_RESULTS
	local based=$1 headd=$2 status=0 f k pkg csv
	command -v "$BENCHSTAT" >/dev/null || { echo "bench-gate: no benchstat ($BENCHSTAT)" >&2; return 1; }
	local findings
	findings=$(mktemp "${TMPDIR:-/tmp}/bench-gate.XXXXXX")
	if [ -e "$headd/internal_policy_decide.txt" ]; then
		absolute_queries "$headd/internal_policy_decide.txt" >>"$findings"
	fi
	for f in "$headd"/*.txt; do
		[ -e "$f" ] || continue
		k=$(basename "$f" .txt)
		pkg=$(awk '/^pkg: / { print $2; exit }' "$f")
		pkg=${pkg:-$k}
		if [ ! -s "$based/$k.txt" ] || ! grep -q '^Benchmark' "$based/$k.txt"; then
			echo "note $pkg: the base has no results for it; not compared" >>"$findings"
			continue
		fi
		echo "== $pkg"
		# -ignore pkg: each file holds one package, and its pkg: line names the module path, which a base from before
		# ADR 0060 spells otherwise; grouping by it would leave every base benchmark unpaired.
		"$BENCHSTAT" -ignore pkg "base=$based/$k.txt" "head=$f" 2>/dev/null || true
		echo
		if ! csv=$("$BENCHSTAT" -format csv -ignore pkg "base=$based/$k.txt" "head=$f" 2>/dev/null); then
			echo "FAIL $pkg: benchstat could not read the results" >>"$findings"
			continue
		fi
		printf '%s\n' "$csv" | decide "$pkg" >>"$findings"
	done
	# A package the base has results for and the head has none: deleted, moved, or its regex matches nothing.
	# Only a package whose every base benchmark is report-only may go missing quietly.
	for f in "$based"/*.txt; do
		[ -e "$f" ] || continue
		k=$(basename "$f" .txt)
		grep -q '^Benchmark' "$f" || continue
		if [ -s "$headd/$k.txt" ] && grep -q '^Benchmark' "$headd/$k.txt"; then continue; fi
		pkg=$(awk '/^pkg: / { print $2; exit }' "$f")
		pkg=${pkg:-$k}
		if awk -v noisy="$noisy" 'BEGIN { n = split(noisy, l, " "); for (i = 1; i <= n; i++) quiet[l[i]] = 1 }
			/^Benchmark/ { top = $1; sub(/^Benchmark/, "", top); sub(/\/.*/, "", top); sub(/-[0-9]+$/, "", top)
				if (!(top in quiet)) gated = 1 }
			END { exit gated ? 0 : 1 }' "$f"; then
			echo "FAIL $pkg: the base has benchmarks here and the head has none: package removed, renamed, or no longer matched by its regex" >>"$findings"
		else
			echo "note $pkg: only the base has results (report-only benchmarks); not compared" >>"$findings"
		fi
	done
	echo "== findings"
	if [ -s "$findings" ]; then cat "$findings"; else echo "none"; fi
	grep -q '^FAIL' "$findings" && status=1
	rm -f "$findings"
	return $status
}

# build makes one side's test binaries; a package the side does not have is skipped, and a build failure is
# returned for the caller to weigh (fatal for the head, reported for the base).
build() { # build SIDE SRC OUT
	local side=$1 src=$2 out=$3 status=0 pkg regex tags
	mkdir -p "$out/$side/bin"
	while read -r pkg regex tags; do
		[ -n "$pkg" ] || continue
		if [ ! -d "$src/$pkg" ]; then
			echo "note $pkg: the $side has no such package; not compared" | tee -a "$out/notes"
			continue
		fi
		if ! (cd "$src" && CGO_ENABLED=0 "$GO" test -c ${tags:+-tags "$tags"} -o "$out/$side/bin/$(key "$pkg").test" "./$pkg"); then
			echo "note $pkg: the $side's test binary did not build" | tee -a "$out/notes"
			status=1
		fi
	done <<<"$packages"
	return $status
}

# run is one side's run of one package, appended to its results; stderr is kept beside them.
run() { # run SIDE SRC OUT PKG REGEX
	local side=$1 src=$2 out=$3 pkg=$4 regex=$5 k
	k=$(key "$pkg")
	[ -x "$out/$side/bin/$k.test" ] || return 0
	(cd "$src/$pkg" && "$out/$side/bin/$k.test" -test.run '^$' -test.bench "$regex" -test.benchtime "$benchtime" \
		-test.count 1 -test.benchmem -test.timeout 10m) >>"$out/$side/$k.txt" 2>>"$out/$side/$k.err"
}

if [ "${1:-}" = compare ]; then
	[ $# -eq 3 ] || usage
	compare "$2" "$3"
	exit $?
fi

rounds=10 benchtime=100ms out="" head=""
while [ $# -gt 0 ]; do
	case "$1" in
	-n) rounds=${2:?}; shift 2 ;;
	-t) benchtime=${2:?}; shift 2 ;;
	-o) out=${2:?}; shift 2 ;;
	--head) head=${2:?}; shift 2 ;;
	-h | --help) usage ;;
	-*) usage ;;
	*) break ;;
	esac
done
[ $# -eq 1 ] || usage
case "$rounds" in '' | *[!0-9]* | 0) usage ;; esac
base=$(CDPATH='' cd -- "$1" && pwd)
head=${head:-$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)}
head=$(CDPATH='' cd -- "$head" && pwd)
packages=${BENCH_GATE_PACKAGES:-$default_packages}
out=${out:-$(mktemp -d "${TMPDIR:-/tmp}/bench-gate.XXXXXX")}
# DIR's base/ and head/ are emptied before a run, so a DIR that holds anything else is one this script did not
# make, and is refused rather than emptied: -o names it, and a slip there must not remove someone's base/.
if [ -e "$out" ] && [ ! -e "$out/.bench-gate" ] && [ -n "$(ls -A "$out")" ]; then
	echo "bench-gate: $out is not empty and is not a directory bench-gate.sh made; not using it" >&2
	exit 2
fi
mkdir -p "$out"
: >"$out/.bench-gate"
rm -rf "${out:?}/base" "${out:?}/head" "$out/notes"
echo "bench-gate: base $base, head $head, $rounds rounds at $benchtime, results in $out"

broken=0
build head "$head" "$out" || broken=1
build base "$base" "$out" || true
start=$(date +%s)
for r in $(seq 1 "$rounds"); do
	order="base head"
	[ $((r % 2)) -eq 1 ] || order="head base"
	while read -r pkg regex _; do
		[ -n "$pkg" ] || continue
		for side in $order; do
			src=$base
			[ "$side" = head ] && src=$head
			if ! run "$side" "$src" "$out" "$pkg" "$regex"; then
				echo "note $pkg: the $side's run failed in round $r ($out/$side/$(key "$pkg").err)" | tee -a "$out/notes"
				[ "$side" = head ] && broken=1
			fi
		done
	done <<<"$packages"
done
echo "bench-gate: $rounds rounds in $(($(date +%s) - start)) s"
status=0
compare "$out/base" "$out/head" || status=1
if [ -s "$out/notes" ]; then
	echo "== notes"
	cat "$out/notes"
fi
if [ "$broken" -ne 0 ]; then
	echo "FAIL the head's benchmarks did not all build and run; see the notes above"
	for f in "$out"/head/*.err; do
		[ -s "$f" ] || continue
		echo "-- $f"
		tail -n 20 "$f"
	done
	status=1
fi
exit $status
