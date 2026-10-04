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
# gate did not make is refused, not emptied.
#
# benchstat is the pinned one when BENCHSTAT names it (CI's bench job does); otherwise a stand-in replays the
# CSV the pinned version, golang.org/x/perf v0.0.0-20260908200009-22c9c6c9d4da, printed for these inputs, so
# the decision is tested everywhere and its reading of benchstat's format wherever benchstat is installed.
set -eu

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

exit $fail
