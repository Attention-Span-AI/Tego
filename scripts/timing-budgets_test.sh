#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests timing-budgets.sh's runs and its decision, with a stand-in for go whose test binaries print canned -test.v
# output, so nothing is compiled or measured. A fake tree's package directory holds out.txt, what its binary prints,
# and optionally rc, the status it exits with.
#
# What it holds timing-budgets.sh to: every budget test passing in budget mode passes the script, a TARGET-MISS among
# them included (and listed); a test that fails, is skipped, prints no PASS line, or passes without one line of
# budget mode fails it, as does a binary that exits non-zero with every line passing and a package that does not
# build; each binary runs from its own package directory with TEGO_TIMING_BUDGETS=1, -test.run naming exactly its
# tests, -test.v and -test.count 1, built cgo-free with its package's tags; and an output directory the script did
# not make is refused, not emptied.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-timing-budgets-test.XXXXXX")
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

# The stand-in go: `go test -c [-tags T] -o OUT ./PKG` writes OUT as a script that logs its working directory, its
# TEGO_TIMING_BUDGETS and its arguments, prints out.txt from there and exits with rc's status when rc is there; a
# package directory holding nobuild does not build.
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
echo "build $pkg tags=$tags cgo=$CGO_ENABLED" >>"$TB_LOG"
cat >"$out" <<BIN
#!/bin/sh
echo "run $pkg \$PWD budgets=\$TEGO_TIMING_BUDGETS \$*" >>"\$TB_LOG"
cat out.txt
[ ! -e rc ] || exit "\$(cat rc)"
exit 0
BIN
chmod +x "$out"
EOF
chmod +x "$tmp/bin/go"

# tree NAME: a fresh fake tree holding the script, with packages a (tags x) and b (no tags), each passing its tests
# in budget mode.
tree() {
	t="$tmp/$1"
	mkdir -p "$t/scripts" "$t/pkg/a" "$t/pkg/b"
	cp "$here/timing-budgets.sh" "$t/scripts/"
	cat >"$t/pkg/a/out.txt" <<'EOF'
=== RUN   TestA1
    a_test.go:10: case one: +5µs (target +6µs, limit +12µs; ADR 0048 C8, budget mode)
--- PASS: TestA1 (0.10s)
=== RUN   TestA2
    a_test.go:20: case two: 400ns (target 500ns, limit 1µs; ADR 0048 C8, budget mode)
--- PASS: TestA2 (0.20s)
PASS
EOF
	cat >"$t/pkg/b/out.txt" <<'EOF'
=== RUN   TestB
    b_test.go:5: plan: 30ms (no target, limit 200ms; enforce-plane §10, budget mode)
--- PASS: TestB (0.30s)
PASS
EOF
	echo "$t"
}
tests='
pkg/a  x  TestA1 TestA2
pkg/b  -  TestB
'
run() { # run TREE [ARGS...]: the script in TREE, its output in $tmp/out, its exit status in $rc
	t=$1
	shift
	: >"$tmp/log"
	rc=0
	PATH="$tmp/bin:$PATH" TB_LOG="$tmp/log" TIMING_BUDGETS_TESTS=$tests TMPDIR="$tmp" "$t/scripts/timing-budgets.sh" "$@" \
		>"$tmp/out" 2>&1 || rc=$?
}

t=$(tree pass)
run "$t" -o "$tmp/o-pass"
check "every budget met" 0 "$rc"
expect "every budget met: TestA1 ok" "^ok   TestA1" "$tmp/out"
expect "every budget met: TestB ok" "^ok   TestB" "$tmp/out"
expect "a's binary runs from pkg/a in budget mode with its tests" "^run pkg/a $t/pkg/a budgets=1 -test.run ^(TestA1|TestA2)\$ -test.v -test.count 1" "$tmp/log"
expect "b's binary runs from pkg/b in budget mode with its test" "^run pkg/b $t/pkg/b budgets=1 -test.run ^(TestB)\$ -test.v -test.count 1" "$tmp/log"
expect "a builds cgo-free with its tags" "^build pkg/a tags=x cgo=0" "$tmp/log"
expect "b builds cgo-free with none" "^build pkg/b tags= cgo=0" "$tmp/log"

t=$(tree miss)
sed -i 's|^--- PASS: TestA2|    a_test.go:21: TARGET-MISS: case two 600ns > 500ns (ADR 0048 C8)\n--- PASS: TestA2|' "$t/pkg/a/out.txt"
run "$t"
check "a target missed, the limit met" 0 "$rc"
expect "a target missed: listed" "^TARGET-MISS TestA2:" "$tmp/out"
expect "a target missed: its line" "TARGET-MISS: case two 600ns > 500ns" "$tmp/out"

t=$(tree failed)
sed -i 's|^--- PASS: TestA1|    a_test.go:11: case one: +13µs over the +12µs limit (ADR 0048 C8)\n--- FAIL: TestA1|' "$t/pkg/a/out.txt"
echo 1 >"$t/pkg/a/rc"
run "$t"
check "a limit missed" 1 "$rc"
expect "a limit missed: named" "^FAIL TestA1: failed" "$tmp/out"

t=$(tree skipped)
sed -i 's|^--- PASS: TestB|--- SKIP: TestB|' "$t/pkg/b/out.txt"
run "$t"
check "a budget test skipped" 1 "$rc"
expect "a budget test skipped: named" "^FAIL TestB: skipped" "$tmp/out"

t=$(tree absent)
sed -i '/TestA2/d' "$t/pkg/a/out.txt"
run "$t"
check "a budget test that did not run" 1 "$rc"
expect "a budget test that did not run: named" "^FAIL TestA2: did not run" "$tmp/out"

t=$(tree unasserted)
sed -i 's|, budget mode)$|, unit gate)|' "$t/pkg/b/out.txt"
run "$t"
check "a pass without budget mode" 1 "$rc"
expect "a pass without budget mode: named" "^FAIL TestB: passed without asserting a budget in budget mode" "$tmp/out"

t=$(tree exited)
echo 3 >"$t/pkg/b/rc"
run "$t"
check "a binary that exits non-zero" 1 "$rc"
expect "a binary that exits non-zero: named" "^FAIL pkg/b: the test binary exited 3" "$tmp/out"

t=$(tree nobuild)
: >"$t/pkg/a/nobuild"
run "$t"
check "a package that does not build" 1 "$rc"
expect "a package that does not build: named" "^FAIL pkg/a (tags x): the test binary did not build" "$tmp/out"
expect "a package that does not build: the next still runs" "^ok   TestB" "$tmp/out"

t=$(tree foreign)
mkdir -p "$tmp/foreign"
: >"$tmp/foreign/keep"
run "$t" -o "$tmp/foreign"
check "an output directory the script did not make" 2 "$rc"
[ -e "$tmp/foreign/keep" ] || { echo "FAIL an output directory the script did not make: emptied" >&2; fail=1; }

exit "$fail"
