#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests bench-gate.sh's decision and its runs, with a stand-in for go whose test binaries print canned
# benchmark output, so nothing is compiled or measured. Two fake trees stand in for the base and the head
# checkouts; a package's bench.out is what its binary prints each round.
#
# What it holds bench-gate.sh to: each of the three rules fails the gate on its own benchmark (allocs/op from
# zero, B/op over +10%, sec/op over +25% at p<0.01), a sub-benchmark included, and nothing else does — a
# smaller B/op or sec/op growth, a faster benchmark, allocations added to a benchmark that already allocated,
# a report-only benchmark however much it grew, a +40% change whose p is 0.029, a benchmark or package only
# one side has; the sides alternate which runs first from round to round, each binary runs from its own tree's
# package directory, and a package's build tags reach go test -c; a head that does not build or whose run
# fails fails the gate, while a base that does not is reported and the gate goes on; and an output directory the
# gate did not make is refused, not emptied. An accepted step turns a B/op or sec/op failure into a note only
# against its own base commit (a base checkout's HEAD, or BENCH_GATE_BASE_COMMIT in compare mode), only at or below
# its ceiling, and only for the package, name and unit it names; an entry that does not apply or matched nothing is
# named; a malformed one stops the gate before anything is built. The list's own v0.1.3 entries are held to the
# figures the hosted runner measured for them.
#
# benchstat is the pinned one when BENCHSTAT names it (CI's bench job does); otherwise a stand-in replays the
# CSV the pinned version, golang.org/x/perf v0.0.0-20260908200009-22c9c6c9d4da, printed for these inputs, so
# the decision is tested everywhere and its reading of benchstat's format wherever benchstat is installed.
set -eu
# A git hook's repository is not the fake base's (the precommit hook runs this test).
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
# The cases below name their accepted steps and base commits; none comes from the caller.
unset BENCH_GATE_ACCEPTED BENCH_GATE_BASE_COMMIT

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
gate="${here}/bench-gate.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-bench-gate-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

fail=0
check() { # check NAME WANT_EXIT GOT_EXIT
	if [ "$2" = "$3" ]; then
		echo "ok   $1"
	else
		echo "FAIL $1: exit $3, want $2" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}
expect() { # expect NAME PATTERN FILE
	if ! grep -q -- "$2" "$3"; then
		echo "FAIL $1: $3 lacks '$2'" >&2
		sed 's/^/     /' "$3" >&2
		fail=1
	fi
}
refuse() { # refuse NAME PATTERN FILE
	if grep -q -- "$2" "$3"; then
		echo "FAIL $1: $3 has '$2'" >&2
		sed 's/^/     /' "$3" >&2
		fail=1
	fi
}

# The stand-in go: `go test -c [-tags T] -o OUT ./PKG` writes OUT as a script that logs its side, package,
# working directory and arguments, fails when its working directory holds a file named fail, and otherwise
# prints bench.out from there; a package directory holding nobuild does not build.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/go" <<'EOF'
#!/bin/sh
[ "$1 $2" = "test -c" ] || { echo "stand-in go: refusing $*" >&2; exit 42; }
shift 2
tags="" out="" pkg=""
while [ $# -gt 0 ]; do
	case "$1" in
	-tags) tags=$2; shift 2 ;;
	-o) out=$2; shift 2 ;;
	*) pkg=${1#./}; shift ;;
	esac
done
[ ! -e "$pkg/nobuild" ] || { echo "stand-in go: $pkg does not build" >&2; exit 1; }
case "$out" in
*/base/*) side=base ;;
*/head/*) side=head ;;
*) echo "stand-in go: -o $out names no side" >&2; exit 42 ;;
esac
echo "build $side $pkg tags=$tags cgo=$CGO_ENABLED" >>"$BG_LOG"
cat >"$out" <<BIN
#!/bin/sh
echo "run $side $pkg \$PWD \$*" >>"\$BG_LOG"
[ ! -e fail ] || { echo "boom" >&2; exit 1; }
cat bench.out
BIN
chmod +x "$out"
EOF
chmod +x "$tmp/bin/go"

# The stand-in benchstat: the table form says which fixture it is, the CSV form replays the pinned version's.
mkdir -p "$tmp/csv"
cat >"$tmp/benchstat" <<'EOF'
#!/bin/sh
csv=0 head=""
for a in "$@"; do
	case "$a" in
	-format) ;;
	csv) csv=1 ;;
	head=*) head=${a#head=} ;;
	esac
done
fixture=$(sed -n 's/^fixture: //p' "$head" | head -n 1)
[ -n "$fixture" ] || exit 0
if [ "$csv" = 1 ]; then cat "$BG_CSV/$fixture.csv"; else echo "(benchstat table of $fixture)"; fi
EOF
chmod +x "$tmp/benchstat"

# What the pinned benchstat printed for each fixture's results (-format csv, base=... head=...).
cat >"$tmp/csv/regress.csv" <<'EOF'
goos: linux
goarch: amd64
pkg: example.com/fake/a
cpu: fake
fixture: regress
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
ZeroGrew-4,1.0000000000000001e-07,0%,1.0000000000000001e-07,0%,~,p=1.000 n=10
BytesGrew-4,1.0000000000000001e-07,0%,1.0000000000000001e-07,0%,~,p=1.000 n=10
BytesWithin-4,1.0000000000000001e-07,0%,1.0000000000000001e-07,0%,~,p=1.000 n=10
Slower-4,1.0000000000000001e-07,0%,1.4e-07,0%,+40.00%,p=0.000 n=10
SlowerSlightly-4,1.0000000000000001e-07,0%,1.1e-07,0%,+10.00%,p=0.000 n=10
Faster-4,1.0000000000000001e-07,0%,6.000000000000001e-08,0%,-40.00%,p=0.000 n=10
Feed-4,1.0000000000000001e-07,0%,2.0000000000000002e-07,0%,+100.00%,p=0.000 n=10
EntryCount/refused/20-4,3.0000000000000004e-07,0%,3.0000000000000004e-07,0%,~,p=1.000 n=10
Many-4,1.0000000000000001e-07,0%,1.0000000000000001e-07,0%,~,p=1.000 n=10
OnlyBase-4,1.0000000000000001e-07,0%
OnlyHead-4,,,1.0000000000000001e-07,0%
geomean,1.116123174033901e-07,,1.1868130747559408e-07,,+7.06%,

,base,,head,,,
,B/op,CI,B/op,CI,vs base,P
ZeroGrew-4,0,0%,8,0%,?,p=0.000 n=10
BytesGrew-4,100,0%,120,0%,+20.00%,p=0.000 n=10
BytesWithin-4,100,0%,105,0%,+5.00%,p=0.000 n=10
Slower-4,100,0%,100,0%,~,p=1.000 n=10
SlowerSlightly-4,100,0%,100,0%,~,p=1.000 n=10
Faster-4,100,0%,100,0%,~,p=1.000 n=10
Feed-4,0,0%,8,0%,?,p=0.000 n=10
EntryCount/refused/20-4,0,0%,8,0%,?,p=0.000 n=10
Many-4,100,0%,100,0%,~,p=1.000 n=10
OnlyBase-4,0,0%
OnlyHead-4,,,0,0%
geomean,,,,,?,

,base,,head,,,
,allocs/op,CI,allocs/op,CI,vs base,P
ZeroGrew-4,0,0%,1,0%,?,p=0.000 n=10
BytesGrew-4,2,0%,2,0%,~,p=1.000 n=10
BytesWithin-4,2,0%,2,0%,~,p=1.000 n=10
Slower-4,2,0%,2,0%,~,p=1.000 n=10
SlowerSlightly-4,2,0%,2,0%,~,p=1.000 n=10
Faster-4,2,0%,2,0%,~,p=1.000 n=10
Feed-4,0,0%,1,0%,?,p=0.000 n=10
EntryCount/refused/20-4,0,0%,1,0%,?,p=0.000 n=10
Many-4,5,0%,6,0%,+20.00%,p=0.000 n=10
OnlyBase-4,0,0%
OnlyHead-4,,,0,0%
geomean,,,,,?,
EOF
cat >"$tmp/csv/same.csv" <<'EOF'
goos: linux
goarch: amd64
pkg: example.com/fake/a
cpu: fake
fixture: same
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
ZeroGrew-4,1.0000000000000001e-07,0%,1.0000000000000001e-07,0%,~,p=1.000 n=10
EntryCount/refused/20-4,3.0000000000000004e-07,0%,3.0000000000000004e-07,0%,~,p=1.000 n=10
geomean,1.7320508075688772e-07,,1.7320508075688772e-07,,+0.00%,

,base,,head,,,
,B/op,CI,B/op,CI,vs base,P
ZeroGrew-4,0,0%,0,0%,~,p=1.000 n=10
EntryCount/refused/20-4,0,0%,0,0%,~,p=1.000 n=10
geomean,,,,,+0.00%,

,base,,head,,,
,allocs/op,CI,allocs/op,CI,vs base,P
ZeroGrew-4,0,0%,0,0%,~,p=1.000 n=10
EntryCount/refused/20-4,0,0%,0,0%,~,p=1.000 n=10
geomean,,,,,+0.00%,
EOF
cat >"$tmp/csv/few.csv" <<'EOF'
goos: linux
goarch: amd64
pkg: example.com/fake/a
cpu: fake
fixture: few
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
Slower-4,1.0000000000000001e-07,∞,1.4e-07,∞,+40.00%,p=0.029 n=4
geomean,9.999999999999994e-08,,1.4000000000000004e-07,,+40.00%,

,base,,head,,,
,B/op,CI,B/op,CI,vs base,P
Slower-4,0,∞,0,∞,~,p=1.000 n=4
geomean,,,,,+0.00%,

,base,,head,,,
,allocs/op,CI,allocs/op,CI,vs base,P
Slower-4,0,∞,0,∞,~,p=1.000 n=4
geomean,,,,,+0.00%,
EOF

# bench writes one round of a fake binary's output: hdr FIXTURE, then one line per "NAME NS BYTES ALLOCS".
bench() { # bench FILE FIXTURE [NAME NS BYTES ALLOCS]...
	f=$1 fixture=$2
	shift 2
	printf 'goos: linux\ngoarch: amd64\npkg: example.com/fake/a\ncpu: fake\nfixture: %s\n' "$fixture" >"$f"
	while [ $# -ge 4 ]; do
		printf 'Benchmark%s-4 \t    1000\t %s ns/op\t %s B/op\t %s allocs/op\n' "$1" "$2" "$3" "$4" >>"$f"
		shift 4
	done
	echo PASS >>"$f"
}

# trees makes a base and a head tree for one fixture: fake/a in both, fake/b in the head only.
trees() { # trees FIXTURE
	rm -rf "$tmp/base" "$tmp/head" "$tmp/res" "$tmp/log"
	mkdir -p "$tmp/base/fake/a" "$tmp/head/fake/a" "$tmp/head/fake/b"
	: >"$tmp/log"
	case "$1" in
	regress)
		bench "$tmp/base/fake/a/bench.out" regress ZeroGrew 100 0 0 BytesGrew 100 100 2 BytesWithin 100 100 2 \
			Slower 100 100 2 SlowerSlightly 100 100 2 Faster 100 100 2 Feed 100 0 0 EntryCount/refused/20 300 0 0 \
			Many 100 100 5 OnlyBase 100 0 0
		bench "$tmp/head/fake/a/bench.out" regress ZeroGrew 100 8 1 BytesGrew 100 120 2 BytesWithin 100 105 2 \
			Slower 140 100 2 SlowerSlightly 110 100 2 Faster 60 100 2 Feed 200 8 1 EntryCount/refused/20 300 8 1 \
			Many 100 100 6 OnlyHead 100 0 0
		;;
	same)
		bench "$tmp/base/fake/a/bench.out" same ZeroGrew 100 0 0 EntryCount/refused/20 300 0 0
		cp "$tmp/base/fake/a/bench.out" "$tmp/head/fake/a/bench.out"
		;;
	esac
	# fake/b's results carry no fixture line: the stand-in benchstat is never asked about it, the base having none.
	bench "$tmp/head/fake/b/bench.out" ""
}

BENCHSTAT=${BENCHSTAT:-$tmp/benchstat}
BG_LOG="$tmp/log" BG_CSV="$tmp/csv" BENCH_GATE_PACKAGES='
fake/a  ^Benchmark  integration
fake/b  ^Benchmark
'
PATH="$tmp/bin:$PATH"
# The self-test owns its compiler stand-in, even when make inherited an absolute GO.
GO="$tmp/bin/go"
export BENCHSTAT BG_LOG BG_CSV BENCH_GATE_PACKAGES PATH GO
echo "bench-gate_test: benchstat is $BENCHSTAT"

# Every rule fails the gate on its own benchmark, and nothing else does.
trees regress
rc=0
"$gate" -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "the three rules fail the gate" 1 "$rc"
grep '^FAIL' "$tmp/out" | sed 's/:.*//' | sort >"$tmp/fails"
sort >"$tmp/want" <<'EOF'
FAIL example.com/fake/a EntryCount/refused/20-4
FAIL example.com/fake/a EntryCount/refused/20-4
FAIL example.com/fake/a OnlyBase-4
FAIL example.com/fake/a BytesGrew-4
FAIL example.com/fake/a Slower-4
FAIL example.com/fake/a ZeroGrew-4
FAIL example.com/fake/a ZeroGrew-4
EOF
if ! cmp -s "$tmp/fails" "$tmp/want"; then
	echo "FAIL the failing benchmarks: got" >&2
	sed 's/^/     /' "$tmp/fails" >&2
	sed 's/^/     /' "$tmp/out" >&2
	fail=1
fi
expect "allocs/op from zero" 'FAIL example.com/fake/a ZeroGrew-4: allocs/op 0 -> 1' "$tmp/out"
expect "B/op from zero" 'FAIL example.com/fake/a ZeroGrew-4: B/op 0 -> 8' "$tmp/out"
expect "B/op over +10%" 'FAIL example.com/fake/a BytesGrew-4: B/op +20.00%' "$tmp/out"
expect "sec/op over +25% at p<0.01" 'FAIL example.com/fake/a Slower-4: sec/op +40.00%' "$tmp/out"
expect "a sub-benchmark's allocations" 'FAIL example.com/fake/a EntryCount/refused/20-4: allocs/op 0 -> 1' "$tmp/out"
expect "a report-only benchmark is reported" 'note example.com/fake/a Feed-4: sec/op +100.00%.*(report-only)' "$tmp/out"
refuse "a report-only benchmark never fails" '^FAIL example.com/fake/a Feed' "$tmp/out"
expect "a benchmark the base lacks" 'note example.com/fake/a OnlyHead-4: only the head has it' "$tmp/out"
expect "a benchmark the head lacks fails the gate" 'FAIL example.com/fake/a OnlyBase-4: the base has it and the head does not' "$tmp/out"
expect "a package the base lacks" 'note fake/b: the base has no such package; not compared' "$tmp/out"
expect "the table is printed" '(benchstat table of regress)\|│' "$tmp/out"
# Ten rounds, each package's two sides back to back, base first in odd rounds and head first in even ones.
grep '^run [a-z]* fake/a ' "$tmp/log" | awk '{ print $2 }' | tr '\n' ' ' >"$tmp/order"
want="base head head base base head head base base head head base base head head base base head head base "
if [ "$(cat "$tmp/order")" != "$want" ]; then
	echo "FAIL the sides alternate: got '$(cat "$tmp/order")'" >&2
	fail=1
fi
expect "the base runs in the base's package directory" "^run base fake/a $tmp/base/fake/a -test.run" "$tmp/log"
expect "the head runs in the head's package directory" "^run head fake/a $tmp/head/fake/a -test.run" "$tmp/log"
expect "each run is one sample at the benchtime" '-test.bench ^Benchmark -test.benchtime 100ms -test.count 1 -test.benchmem' "$tmp/log"
expect "a package's tags reach go test -c" '^build head fake/a tags=integration cgo=0' "$tmp/log"
expect "no tags where the list names none" '^build head fake/b tags= cgo=0' "$tmp/log"

# The same results on both sides pass.
trees same
rc=0
"$gate" -n 10 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "unchanged benchmarks pass" 0 "$rc"
refuse "unchanged benchmarks fail nothing" '^FAIL' "$tmp/out"

# +40% at p=0.029, all four samples a side can give, is not p<0.01.
mkdir -p "$tmp/few/base" "$tmp/few/head"
bench "$tmp/few/b1" few Slower 100 0 0
bench "$tmp/few/h1" few Slower 140 0 0
for _ in 1 2 3 4; do cat "$tmp/few/b1" >>"$tmp/few/base/fake_a.txt"; cat "$tmp/few/h1" >>"$tmp/few/head/fake_a.txt"; done
rc=0
"$gate" compare "$tmp/few/base" "$tmp/few/head" >"$tmp/out" 2>&1 || rc=$?
check "a slowdown benchstat cannot tell at p<0.01 passes" 0 "$rc"

# A head whose benchmarks fail to run fails the gate; a base whose do is reported.
trees same
: >"$tmp/head/fake/a/fail"
rc=0
"$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "a head run that fails fails the gate" 1 "$rc"
expect "the failed head run is named" "note fake/a: the head's run failed in round 1" "$tmp/out"
expect "its stderr is shown" 'boom' "$tmp/out"
trees same
: >"$tmp/base/fake/a/fail"
rc=0
"$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "a base run that fails is reported" 0 "$rc"
expect "the failed base run is named" "note fake/a: the base's run failed in round 1" "$tmp/out"
expect "the base's missing results are named" 'note example.com/fake/a: the base has no results for it' "$tmp/out"

# A head that does not build fails the gate; a base that does not is reported.
trees same
: >"$tmp/head/fake/a/nobuild"
rc=0
"$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "a head that does not build fails the gate" 1 "$rc"
expect "the unbuilt head package is named" "note fake/a: the head's test binary did not build" "$tmp/out"
trees same
: >"$tmp/base/fake/a/nobuild"
rc=0
"$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "a base that does not build is reported" 0 "$rc"
expect "the unbuilt base package is named" "note fake/a: the base's test binary did not build" "$tmp/out"

# A package the head lost (deleted or moved) while the base has its benchmarks fails the gate.
trees same
rm -rf "$tmp/head/fake/a"
rc=0
"$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "a package the head lost fails the gate" 1 "$rc"
expect "the lost package is named" 'FAIL example.com/fake/a: the base has benchmarks here and the head has none' "$tmp/out"
# ... unless every benchmark it had is report-only.
trees same
bench "$tmp/base/fake/a/bench.out" same Feed 100 0 0
rm -rf "$tmp/head/fake/a"
rc=0
"$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "a lost package of report-only benchmarks passes" 0 "$rc"
expect "it is reported" 'note example.com/fake/a: only the base has results' "$tmp/out"

# An output directory the gate did not make is refused, and left as it was.
mkdir -p "$tmp/mine/base"
: >"$tmp/mine/base/keep"
rc=0
"$gate" -n 2 -o "$tmp/mine" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "an output directory the gate did not make is refused" 2 "$rc"
[ -e "$tmp/mine/base/keep" ] || { echo "FAIL the refused directory was emptied" >&2; fail=1; }

# Usage errors.
for args in "" "-n 0 $tmp/base" "-n x $tmp/base" "compare $tmp/base" "-q $tmp/base" "$tmp/base $tmp/head"; do
	rc=0
	# shellcheck disable=SC2086 # the cases are word lists
	"$gate" $args >"$tmp/out" 2>&1 || rc=$?
	check "usage: '$args'" 2 "$rc"
done

# The indexed query's absolute budget also applies to a head-only benchmark.
mkdir -p "$tmp/absolute-base" "$tmp/absolute-head"
for scenario in fast slow allocates missing bad-ns bad-bytes bad-allocs nan infinity overflow; do
	{
		printf 'pkg: github.com/attention-span-ai/tego/internal/policy/decide\n'
		for tier in landlock cgroup bpflsm; do
			[ "$scenario:$tier" != missing:bpflsm ] || continue
			ns=999 bytes=0 allocs=0
			[ "$scenario" != slow ] || ns=1000
			[ "$scenario" != allocates ] || allocs=1
			[ "$scenario" != bad-ns ] || ns=garbage
			[ "$scenario" != bad-bytes ] || bytes=garbage
			[ "$scenario" != bad-allocs ] || allocs=garbage
			[ "$scenario" != nan ] || ns=NaN
			[ "$scenario" != infinity ] || ns=+Inf
			[ "$scenario" != overflow ] || ns=1e999
			printf 'BenchmarkIndexedEvaluator/%s-2 10000 %s ns/op %s B/op %s allocs/op\n' "$tier" "$ns" "$bytes" "$allocs"
		done
	} >"$tmp/absolute-head/internal_policy_decide.txt"
	rc=0
	"$gate" compare "$tmp/absolute-base" "$tmp/absolute-head" >"$tmp/out" 2>&1 || rc=$?
	want=1
	[ "$scenario" != fast ] || want=0
	check "absolute indexed-query budget: $scenario" "$want" "$rc"
done

# Exercise the actual CSV decision with the owned stand-in, including benchstat's
# valid exact-zero p-value form and unequal sample-count form. Confidence ranges
# may be infinite for a small sample; measured centers and p-values may not.
mkdir -p "$tmp/numeric-base" "$tmp/numeric-head"
bench "$tmp/numeric-base/fake_a.txt" numeric Check 100 0 0
bench "$tmp/numeric-head/fake_a.txt" numeric Check 100 0 0
for scenario in valid exponent zero-p negative-delta bad-base bad-head negative-base negative-head nan infinity overflow bad-delta infinite-delta bad-p nan-p infinite-p overflow-p negative-p high-p missing-p; do
	base=1e-7 head=1e-7 delta='~' p='p=1.000 n=10' want=1
	case "$scenario" in
	valid) want=0 ;;
	exponent) base=+1.0e-7 head=.0000001 want=0 ;;
	zero-p) delta=0.00% p='n=10+8' want=0 ;;
	negative-delta) head=9e-8 delta=-10.00% p='p=0.001 n=10' want=0 ;;
	bad-base) base=garbage ;;
	bad-head) head=garbage ;;
	negative-base) base=-1 ;;
	negative-head) head=-1 ;;
	nan) head=NaN ;;
	infinity) head=+Inf ;;
	overflow) head=1e999 ;;
	bad-delta) delta=garbage% ;;
	infinite-delta) delta=+Inf% ;;
	bad-p) p='p=garbage n=10' ;;
	nan-p) p='p=NaN n=10' ;;
	infinite-p) p='p=+Inf n=10' ;;
	overflow-p) p='p=1e999 n=10' ;;
	negative-p) p='p=-.1 n=10' ;;
	high-p) p='p=1.1 n=10' ;;
	missing-p) p='' ;;
	esac
	printf ',base,,head,,,\n,sec/op,CI,sec/op,CI,vs base,P\nCheck-4,%s,∞,%s,∞,%s,%s\n' "$base" "$head" "$delta" "$p" >"$tmp/csv/numeric.csv"
	rc=0
	BENCHSTAT="$tmp/benchstat" "$gate" compare "$tmp/numeric-base" "$tmp/numeric-head" >"$tmp/out" 2>&1 || rc=$?
	check "CSV numeric validation: $scenario" "$want" "$rc"
done

# Accepted steps. exec stands for C8's exec cases as CI's hosted runner measured them for v0.1.3 against public main
# f8efe5ca2ab8 (n=10): B/op +10.53%, +16.16% and +17.42%, sec/op +3.70%, ~ and +11.18%, allocs/op 59 -> 66,
# 58 -> 67 and 239 -> 257 (script, 16 and 128 arguments), the unguarded exec and the floor's refusal unchanged (their
# values here are stand-ins). Ten equal rounds a side, which the pinned benchstat reads to those same figures.
cat >"$tmp/csv/exec.csv" <<'EOF'
goos: linux
goarch: amd64
cpu: fake
fixture: exec
,base,,head,,,
,sec/op,CI,sec/op,CI,vs base,P
ExecCommandCost/unguarded-4,1.5e-05,0%,1.5e-05,0%,~,p=1.000 n=10
ExecCommandCost/script-4,1e-05,0%,1.037e-05,0%,+3.70%,p=0.000 n=10
ExecCommandCost/args16-4,1.2e-05,0%,1.2e-05,0%,~,p=1.000 n=10
ExecCommandCost/args128-4,4e-05,0%,4.4472000000000004e-05,0%,+11.18%,p=0.000 n=10
ExecCommandCost/floor_refused8-4,9e-06,0%,9e-06,0%,~,p=1.000 n=10
geomean,1.4531652409004686e-05,,1.4951201217773073e-05,,+2.89%,

,base,,head,,,
,B/op,CI,B/op,CI,vs base,P
ExecCommandCost/unguarded-4,2048,0%,2048,0%,~,p=1.000 n=10
ExecCommandCost/script-4,4104,0%,4536,0%,+10.53%,p=0.000 n=10
ExecCommandCost/args16-4,3961,0%,4601,0%,+16.16%,p=0.000 n=10
ExecCommandCost/args128-4,33065,0%,38825,0%,+17.42%,p=0.000 n=10
ExecCommandCost/floor_refused8-4,1024,0%,1024,0%,~,p=1.000 n=10
geomean,4077.5765793204373,,4426.427246717607,,+8.56%,

,base,,head,,,
,allocs/op,CI,allocs/op,CI,vs base,P
ExecCommandCost/unguarded-4,30,0%,30,0%,~,p=1.000 n=10
ExecCommandCost/script-4,59,0%,66,0%,+11.86%,p=0.000 n=10
ExecCommandCost/args16-4,58,0%,67,0%,+15.52%,p=0.000 n=10
ExecCommandCost/args128-4,239,0%,257,0%,+7.53%,p=0.000 n=10
ExecCommandCost/floor_refused8-4,12,0%,12,0%,~,p=1.000 n=10
geomean,49.40786428453554,,52.768028978893646,,+6.80%,
EOF
exec_results() { # exec_results MODULE: $tmp/exec/{base,head}, the supervisor's results under that module path
	rm -rf "$tmp/exec"
	mkdir -p "$tmp/exec/base" "$tmp/exec/head"
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		bench "$tmp/round" exec ExecCommandCost/unguarded 15000 2048 30 ExecCommandCost/script 10000 4104 59 \
			ExecCommandCost/args16 12000 3961 58 ExecCommandCost/args128 40000 33065 239 ExecCommandCost/floor_refused8 9000 1024 12
		sed "s|^pkg: .*|pkg: $1/internal/runtime/supervisor|" "$tmp/round" >>"$tmp/exec/base/internal_runtime_supervisor.txt"
		bench "$tmp/round" exec ExecCommandCost/unguarded 15000 2048 30 ExecCommandCost/script 10370 4536 66 \
			ExecCommandCost/args16 12000 4601 67 ExecCommandCost/args128 44472 38825 257 ExecCommandCost/floor_refused8 9000 1024 12
		sed "s|^pkg: .*|pkg: $1/internal/runtime/supervisor|" "$tmp/round" >>"$tmp/exec/head/internal_runtime_supervisor.txt"
	done
}
v013=f8efe5ca2ab899598df2173c05119686b4c2cd57
other=0123456789abcdef0123456789abcdef01234567
why='v0.1.3 decides a guarded exec with two readers of the command rules (ADR 0048)'

# The list's own entries accept the measured step against their base, the name's -4 stripped, under any module path
# that ends in the package's directory: this tree's (the cases below keep its results) and another.
for module in example.com/fork/tego github.com/attention-span-ai/tego; do
	exec_results "$module"
	rc=0
	BENCH_GATE_BASE_COMMIT=$v013 "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
	check "accepted steps: v0.1.3's measured step passes against its base ($module)" 0 "$rc"
	refuse "accepted steps: nothing fails ($module)" '^FAIL' "$tmp/out"
	for c in 'script-4: B/op +10.53%' 'args16-4: B/op +16.16%' 'args128-4: B/op +17.42%'; do
		expect "accepted steps: $c is a note ($module)" "^note $module/internal/runtime/supervisor ExecCommandCost/$c (p=0.000 n=10): over +10% (accepted step against f8efe5ca2ab8, ceiling +25%: $why)\$" "$tmp/out"
	done
	refuse "accepted steps: every entry applied ($module)" 'does not apply\|did not occur' "$tmp/out"
done

# Above its ceiling a step still fails, the ceiling named; at it, it is accepted.
rc=0
BENCH_GATE_BASE_COMMIT=$other BENCH_GATE_ACCEPTED="
$other  internal/runtime/supervisor  ExecCommandCost/script   B/op  10.53  at the ceiling
$other  internal/runtime/supervisor  ExecCommandCost/args16   B/op  12     under the step
$other  internal/runtime/supervisor  ExecCommandCost/args128  B/op  12     under the step
" "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: a step over its ceiling fails" 1 "$rc"
expect "accepted steps: at the ceiling is accepted" '^note github.com/attention-span-ai/tego/internal/runtime/supervisor ExecCommandCost/script-4: B/op +10.53% .*(accepted step against 0123456789ab, ceiling +10.53%: at the ceiling)$' "$tmp/out"
expect "accepted steps: over the ceiling names it" '^FAIL github.com/attention-span-ai/tego/internal/runtime/supervisor ExecCommandCost/args16-4: B/op +16.16% (p=0.000 n=10): over +10%; over the accepted ceiling +12%$' "$tmp/out"
expect "accepted steps: over the ceiling names it (128)" '^FAIL github.com/attention-span-ai/tego/internal/runtime/supervisor ExecCommandCost/args128-4: B/op +17.42% (p=0.000 n=10): over +10%; over the accepted ceiling +12%$' "$tmp/out"
refuse "accepted steps: a step that failed was matched" 'did not occur' "$tmp/out"

# Against another base the list's entries do not apply: the ordinary failures, and a note for each entry.
rc=0
BENCH_GATE_BASE_COMMIT=$other "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: another base fails as before" 1 "$rc"
for b in script-4 args16-4 args128-4; do
	expect "accepted steps: another base, $b fails" "^FAIL github.com/attention-span-ai/tego/internal/runtime/supervisor ExecCommandCost/$b: B/op +[0-9.]*% (p=0.000 n=10): over +10%\$" "$tmp/out"
	expect "accepted steps: another base, $b's entry is named" "^note accepted step internal/runtime/supervisor ExecCommandCost/${b%-4} B/op (against f8efe5ca2ab8): does not apply to this base (0123456789ab)" "$tmp/out"
done
refuse "accepted steps: another base accepts nothing" 'accepted step against\|accepted ceiling' "$tmp/out"

# compare mode without BENCH_GATE_BASE_COMMIT, unset or empty: no entry applies.
for set in unset empty; do
	rc=0
	if [ "$set" = unset ]; then
		"$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
	else
		BENCH_GATE_BASE_COMMIT='' "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
	fi
	check "accepted steps: compare with BENCH_GATE_BASE_COMMIT $set fails as before" 1 "$rc"
	expect "accepted steps: compare, base $set, is said" '^note accepted steps: BENCH_GATE_BASE_COMMIT is not set; none applies$' "$tmp/out"
	expect "accepted steps: compare, base $set, entries named" 'ExecCommandCost/args16 B/op (against f8efe5ca2ab8): does not apply to this base (unknown)' "$tmp/out"
	refuse "accepted steps: compare, base $set, accepts nothing" 'accepted step against' "$tmp/out"
done

# An applicable entry that matched no failure is named; so is one whose package, name or unit is not the finding's
# (a directory matches whole path elements only, and the name is without Benchmark and -<GOMAXPROCS>).
rc=0
BENCH_GATE_BASE_COMMIT=$other BENCH_GATE_ACCEPTED="
$other  internal/runtime/supervisor  ExecCommandCost/script     B/op    25  r
$other  internal/runtime/supervisor  ExecCommandCost/args16     B/op    25  r
$other  internal/runtime/supervisor  ExecCommandCost/args128    B/op    25  r
$other  internal/runtime/supervisor  ExecCommandCost/unguarded  B/op    25  nothing grew
$other  internal/runtime/supervisor  ExecCommandCost/args128    sec/op  25  under the threshold
" "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: an entry that matched nothing passes" 0 "$rc"
expect "accepted steps: an unmatched entry is named" '^note accepted step internal/runtime/supervisor ExecCommandCost/unguarded B/op (against 0123456789ab, ceiling +25%): applies to this base and matched no failure' "$tmp/out"
expect "accepted steps: an entry under the threshold is named" '^note accepted step internal/runtime/supervisor ExecCommandCost/args128 sec/op (against 0123456789ab, ceiling +25%): applies to this base and matched no failure' "$tmp/out"
rc=0
BENCH_GATE_BASE_COMMIT=$other BENCH_GATE_ACCEPTED="
$other  untime/supervisor            ExecCommandCost/script            B/op    25  r
$other  internal/runtime             ExecCommandCost/script            B/op    25  r
$other  internal/runtime/supervisor  ExecCommandCost/args16-4          B/op    25  r
$other  internal/runtime/supervisor  BenchmarkExecCommandCost/args128  B/op    25  r
$other  internal/runtime/supervisor  ExecCommandCost/args128           sec/op  25  r
" "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: another package, name or unit accepts nothing" 1 "$rc"
grep -c '^FAIL' "$tmp/out" >"$tmp/count" || true
[ "$(cat "$tmp/count")" = 3 ] || { echo "FAIL accepted steps: want 3 FAIL lines, got $(cat "$tmp/count")" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; }
[ "$(grep -c 'matched no failure' "$tmp/out")" = 5 ] || { echo "FAIL accepted steps: want 5 unmatched entries named" >&2; sed 's/^/     /' "$tmp/out" >&2; fail=1; }
refuse "accepted steps: no near match is accepted" 'accepted step against\|accepted ceiling' "$tmp/out"

# A base checkout's HEAD is the base commit: the steps it names become notes, B/op from zero and allocs/op from
# zero still fail, and the rest of the gate is as before.
trees regress
(
	export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
	cd "$tmp/base"
	git init -q .
	git add -A
	git -c user.name=bench-gate-test -c user.email=bench-gate-test@example.invalid -c commit.gpgsign=false \
		commit -q --no-verify -m base
)
head_commit=$(git -C "$tmp/base" rev-parse HEAD)
short=$(printf '%.12s' "$head_commit")
rc=0
BENCH_GATE_ACCEPTED="
$head_commit  fake/a  BytesGrew  B/op    25    more bytes on purpose
$head_commit  fake/a  Slower     sec/op  50    slower on purpose
$head_commit  fake/a  ZeroGrew   B/op    1000  never accepted from zero
" "$gate" -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: a base checkout's HEAD selects its entries" 1 "$rc"
grep '^FAIL' "$tmp/out" | sed 's/:.*//' | sort >"$tmp/fails"
sort >"$tmp/want" <<'EOF'
FAIL example.com/fake/a EntryCount/refused/20-4
FAIL example.com/fake/a EntryCount/refused/20-4
FAIL example.com/fake/a OnlyBase-4
FAIL example.com/fake/a ZeroGrew-4
FAIL example.com/fake/a ZeroGrew-4
EOF
if ! cmp -s "$tmp/fails" "$tmp/want"; then
	echo "FAIL accepted steps: the failing benchmarks: got" >&2
	sed 's/^/     /' "$tmp/fails" >&2
	sed 's/^/     /' "$tmp/out" >&2
	fail=1
fi
expect "accepted steps: B/op accepted in a run" "^note example.com/fake/a BytesGrew-4: B/op +20.00% (p=0.000 n=10): over +10% (accepted step against $short, ceiling +25%: more bytes on purpose)\$" "$tmp/out"
expect "accepted steps: sec/op accepted in a run" "^note example.com/fake/a Slower-4: sec/op +40.00% (p=0.000 n=10): over +25% at p<0.01 (accepted step against $short, ceiling +50%: slower on purpose)\$" "$tmp/out"
expect "accepted steps: B/op from zero is never accepted" '^FAIL example.com/fake/a ZeroGrew-4: B/op 0 -> 8 (p=0.000 n=10): over +10%$' "$tmp/out"
expect "accepted steps: B/op from zero leaves its entry unmatched" "^note accepted step fake/a ZeroGrew B/op (against $short, ceiling +1000%): applies to this base and matched no failure" "$tmp/out"

# A base that is no git checkout has no commit: no entry applies, and the gate says why.
trees same
rc=0
GIT_CEILING_DIRECTORIES=$tmp "$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: a base with no commit passes as before" 0 "$rc"
expect "accepted steps: a base with no commit is said" "^note accepted steps: git rev-parse HEAD failed in $tmp/base; none applies\$" "$tmp/out"
expect "accepted steps: the list's entries are named" 'ExecCommandCost/script B/op (against f8efe5ca2ab8): does not apply to this base (unknown)' "$tmp/out"

# A malformed entry stops the gate, naming its line, before anything is built; allocs/op is never a unit here, even
# for an allocs/op-from-zero finding the entry names.
trees regress
for entry in \
	"$v013 internal/runtime/supervisor ExecCommandCost/script|wrong field count" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script B/op 25|no reason" \
	"f8efe5ca2ab8 internal/runtime/supervisor ExecCommandCost/script B/op 25 r|base commit f8efe5ca2ab8 is not a full commit id" \
	"F8EFE5CA2AB899598DF2173C05119686B4C2CD57 internal/runtime/supervisor ExecCommandCost/script B/op 25 r|base commit F8EFE5CA2AB899598DF2173C05119686B4C2CD57 is not a full commit id" \
	"$v013 fake/a ZeroGrew allocs/op 25 r|unit allocs/op is not B/op or sec/op" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script ns/op 25 r|unit ns/op is not" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script B/op x r|ceiling x is not a positive number" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script B/op 25% r|ceiling 25% is not" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script B/op 0 r|ceiling 0 is not" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script B/op 0.0 r|ceiling 0.0 is not" \
	"$v013 internal/runtime/supervisor ExecCommandCost/script B/op -5 r|ceiling -5 is not"; do
	want=${entry#*|}
	entry=${entry%%|*}
	: >"$tmp/log"
	rc=0
	BENCH_GATE_ACCEPTED="
$entry
" "$gate" -n 2 -o "$tmp/res" --head "$tmp/head" "$tmp/base" >"$tmp/out" 2>&1 || rc=$?
	check "accepted steps: malformed, $want" 2 "$rc"
	expect "accepted steps: malformed, $want, line named" "malformed accepted step, line 2 of the list: $want" "$tmp/out"
	[ ! -s "$tmp/log" ] || { echo "FAIL accepted steps: malformed, $want: something was built or run" >&2; fail=1; }
done
rc=0
BENCH_GATE_BASE_COMMIT=$v013 BENCH_GATE_ACCEPTED="
$v013 internal/runtime/supervisor ExecCommandCost/script allocs/op 25 r
" "$gate" compare "$tmp/exec/base" "$tmp/exec/head" >"$tmp/out" 2>&1 || rc=$?
check "accepted steps: malformed in compare mode" 2 "$rc"
refuse "accepted steps: malformed in compare mode compares nothing" '^== findings' "$tmp/out"

exit $fail
