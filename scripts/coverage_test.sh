#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Tests coverage.sh's reading of its arguments, the part that decides which directory it empties and
# fills, with a stand-in for go so nothing is compiled and no guest boots: the stand-in answers `go list -m`,
# lets every test and covdata step succeed without output, and fails `go build`, which a --vm run reaches
# only after its output directory is made and its packages are chosen, and before its first guest.
#
# What it holds coverage.sh to: the output goes where -o names wherever -o stands among the filters; a bare
# word without --vm is refused before anything is made (it was once ignored, and the output went to
# bin/coverage); a filter that matches no privileged package is refused before the suites run; an existing
# directory coverage.sh did not make is never emptied, and one it made is emptied before it is reused.
#
# The guest half runs against a second stand-in, a directory standing in for test/vm (TEGO_VM_HARNESS) whose
# kvm-run.sh and matrix.sh boot nothing and write the consoles a guest would: a guest that returns no coverage
# data, whether it timed out with a console or never booted and wrote none, is reported and the collection
# goes on to the next suite and to percent.txt (under pipefail its empty harvest once ended the whole run);
# VM_SUITE_TIMEOUT is the guest's bound and the suite's own -test.timeout is 300s inside it (once a fixed 20m);
# --kill-tests ROW runs matrix.sh for ROW with VM_COVER=1 and merges the data its boot consoles carry, and an
# unknown row is refused before anything is made.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="${here}/coverage.sh"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tego-coverage-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT INT TERM

# `tool covdata percent` answers as the real one does when a package with no statements comes first: covdata
# prints "\t<package>\t\t" for every package and the figure with its newline only for one that has
# statements, so internal/bpf's figure lands on the bpf package's line.
cat >"$tmp/go" <<'EOF'
#!/bin/sh
case "$1" in
	list) [ "${2:-}" = -m ] && echo github.com/attention-span-ai/tego ;;
	test) ;;
	tool)
		[ "$2 $3" = "covdata percent" ] || exit 0
		printf '\tgithub.com/attention-span-ai/tego/bpf\t\t\tgithub.com/attention-span-ai/tego/internal/bpf\t\tcoverage: 69.7%% of statements\n'
		printf '\tgithub.com/attention-span-ai/tego/pkg/spec/record\t\tcoverage: 94.3%% of statements\n'
		;;
	*) echo "stand-in go: refusing $*" >&2; exit 42 ;;
esac
EOF
chmod +x "$tmp/go"

# go-all builds too: `test -c` and `build` make an empty file at -o, and `tool covdata merge` records its
# inputs in $COVTEST_MERGED, so a case can tell which guests' data went into the figure.
cat >"$tmp/go-all" <<'EOF'
#!/bin/sh
case "$1" in
	list)
		if [ "${2:-}" = -m ]; then
			echo github.com/attention-span-ai/tego
		elif [ "${COVTEST_BPF_DEPS:-}" = 1 ]; then
			# More than a pipe buffer after the match: an early-exiting grep
			# makes the producer fail with SIGPIPE under coverage.sh's pipefail.
			awk 'BEGIN { print "github.com/attention-span-ai/tego/internal/bpf"; for (i = 0; i < 10000; i++) print "example.com/dependency/package" i }'
		fi
		;;
	test | build)
		prev=""
		for a in "$@"; do
			[ "$prev" = -o ] && : >"$a"
			prev=$a
		done
		;;
	tool) [ "$2 $3" != "covdata merge" ] || echo "$4" >>"$COVTEST_MERGED" ;;
	*) echo "stand-in go: refusing $*" >&2; exit 42 ;;
esac
EOF
chmod +x "$tmp/go-all"

# The harness: kvm-run.sh answers per suite, from the working directory it is given. observe's guest timed out
# after its console began and printed no data; launch's never booted and left no console; every other suite
# returns one data file. matrix.sh writes two boot consoles for its row, each with one data file, and fails
# as a row with a failing check does.
mkdir -p "$tmp/harness"
cat >"$tmp/harness/kvm-run.sh" <<'EOF'
#!/bin/sh
log="" status="" cwd="" timeout=""
while [ $# -gt 0 ]; do
	case "$1" in
	--log) log=$2; shift 2 ;;
	--status) status=$2; shift 2 ;;
	--cwd) cwd=$2; shift 2 ;;
	--timeout) timeout=$2; shift 2 ;;
	--) shift; break ;;
	*) shift ;;
	esac
done
# With COVTEST_GUEST set (a directory), the guest's own /bin/sh -c script runs here, its /tmp moved under that
# directory and its test binary a stand-in that records its arguments, so a case can read the -test.timeout the
# suite would get against the guest's --timeout.
if [ -n "${COVTEST_GUEST:-}" ]; then
	echo "kvm-run.sh --timeout $timeout" >"$COVTEST_GUEST/args"
	[ "$1 $2" = "/bin/sh -c" ] || { echo "stand-in kvm-run.sh: not a /bin/sh -c guest command: $*" >&2; exit 3; }
	script=$(printf '%s' "$3" | sed "s#/tmp/#$COVTEST_GUEST/tmp/#g")
	shift 4
	/bin/sh -c "$script" "$COVTEST_GUEST/suite.test" "$@" >"$log" 2>&1
	echo "guest $?" >"$status"
	exit 0
fi
case "$cwd" in
*/observe)
	printf 'booting\r\n=== RUN   TestSomething\r\n' >"$log"
	echo timeout >"$status"
	exit 124
	;;
*/launch)
	echo "kvm-run: /dev/kvm is not usable" >&2
	exit 97
	;;
esac
printf 'PASS\r\nTEGO-COVFILE covmeta.%s %s\r\n' "${cwd##*/}" "$(printf 'data of %s' "${cwd##*/}" | base64 -w0)" >"$log"
echo "guest 0" >"$status"
EOF
cat >"$tmp/harness/matrix.sh" <<'EOF'
#!/bin/sh
[ "${VM_COVER:-}" = 1 ] || { echo "stand-in matrix.sh: VM_COVER is not 1" >&2; exit 3; }
dir="$VM_OUT/matrix/$1"
mkdir -p "$dir"
printf 'MATRIX-RESULT kt1 root FAIL 1 x\r\nTEGO-COVFILE covcounters.boot1 %s\r\n' "$(printf 'boot1 data' | base64 -w0)" >"$dir/boot1.console"
printf 'TEGO-COVFILE covcounters.boot2 %s\r\n' "$(printf 'boot2 data' | base64 -w0)" >"$dir/boot2.console"
exit 1
EOF
cat >"$tmp/harness/fetch-kernel.py" <<'EOF'
import sys
if sys.argv[1:] == ["--list"]:
    print("debian-13  6.12")
    print("rhel-9  5.14")
EOF
: >"$tmp/harness/go-shim.sh"
chmod +x "$tmp/harness/kvm-run.sh" "$tmp/harness/matrix.sh"

fail=0
# run WANT_EXIT NAME ARGS...: coverage.sh with the stand-in go; its output is in $tmp/out.
run() {
	want=$1
	name=$2
	shift 2
	set +e
	GO="${GO_STANDIN:-$tmp/go}" TEGO_VM_HARNESS="$tmp/harness" COVTEST_MERGED="$tmp/merged" bash "$script" "$@" >"$tmp/out" 2>&1
	got=$?
	set -e
	if [ "$got" = "$want" ]; then
		echo "ok   $name"
	else
		echo "FAIL $name: exit $got, want $want" >&2
		sed 's/^/     /' "$tmp/out" >&2
		fail=1
	fi
}
made() { # made NAME DIR: DIR is one coverage.sh made
	if [ ! -f "$2/.tego-coverage" ]; then
		echo "FAIL $1: $2 was not made" >&2
		fail=1
	fi
}
absent() { # absent NAME DIR
	if [ -e "$2" ]; then
		echo "FAIL $1: $2 exists" >&2
		fail=1
	fi
}

run 0 "-o DIR alone collects into DIR" -o "$tmp/plain"
made "-o DIR alone" "$tmp/plain"
[ -f "$tmp/plain/percent.txt" ] || { echo "FAIL -o DIR alone: no percent.txt" >&2; fail=1; }
# percent.txt names the package before each "coverage:", so the one behind a package with no statements is
# kept, and the statement-less package itself is not listed (internal/bpf was once dropped this way).
if ! grep -Eq '^github\.com/attention-span-ai/tego/internal/bpf +69\.7%$' "$tmp/plain/percent.txt" ||
	! grep -Eq '^github\.com/attention-span-ai/tego/pkg/spec/record +94\.3%$' "$tmp/plain/percent.txt" ||
	grep -Eq '^github\.com/attention-span-ai/tego/bpf ' "$tmp/plain/percent.txt"; then
	echo "FAIL percent.txt: a package behind one with no statements is dropped or misnamed:" >&2
	sed 's/^/     /' "$tmp/plain/percent.txt" >&2
	fail=1
else
	echo "ok   percent.txt keeps the package behind one with no statements"
fi

run 2 "a bare word without --vm is refused, not taken for the output or ignored" "$tmp/positional"
absent "a bare word without --vm" "$tmp/positional"
grep -q 'only --vm runs' "$tmp/out" || { echo "FAIL a bare word without --vm: the refusal does not say why" >&2; fail=1; }

run 2 "a filter after -- without --vm is refused" -o "$tmp/dashdash" -- launch
absent "a filter after -- without --vm" "$tmp/dashdash"

# 42 is the stand-in's `go build`: the run got past choosing its output and its packages.
run 42 "-o after a filter is still the output" --vm launch -o "$tmp/after"
made "-o after a filter" "$tmp/after"
[ -d "$tmp/after/vm" ] || { echo "FAIL -o after a filter: the --vm half did not start" >&2; fail=1; }

run 42 "--vm after a filter still runs the privileged half" launch --vm -o"$tmp/late"
made "--vm after a filter" "$tmp/late"
[ -d "$tmp/late/vm" ] || { echo "FAIL --vm after a filter: the --vm half did not start" >&2; fail=1; }

run 2 "a filter that matches no privileged package is refused before anything runs" --vm -o "$tmp/nomatch" no-such-package
absent "a filter that matches nothing" "$tmp/nomatch"
if grep -q '^== unit' "$tmp/out"; then
	echo "FAIL a filter that matches nothing: the suites ran before it was refused" >&2
	fail=1
fi

mkdir -p "$tmp/theirs"
echo keep >"$tmp/theirs/file"
run 2 "a non-empty directory coverage.sh did not make is not emptied" -o "$tmp/theirs"
[ -f "$tmp/theirs/file" ] || { echo "FAIL a directory coverage.sh did not make was emptied" >&2; fail=1; }

echo stale >"$tmp/plain/stale"
run 0 "a directory coverage.sh made is emptied and reused" -o "$tmp/plain"
made "a reused directory" "$tmp/plain"
absent "a reused directory" "$tmp/plain/stale"

run 2 "an unknown option is a usage error" --bogus -o "$tmp/bogus"
absent "an unknown option" "$tmp/bogus"

has() { # has NAME PATTERN FILE: FILE holds a line matching PATTERN
	if ! grep -q -- "$2" "$3" 2>/dev/null; then
		echo "FAIL $1: no line matching \"$2\" in $3" >&2
		fail=1
	fi
}
lacks() { # lacks NAME PATTERN FILE: FILE holds no line matching PATTERN
	if grep -q -- "$2" "$3" 2>/dev/null; then
		echo "FAIL $1: a line matching \"$2\" in $3" >&2
		fail=1
	fi
}

GO_STANDIN="$tmp/go-all"
COVTEST_BPF_DEPS=1
export COVTEST_BPF_DEPS
run 0 "a long dependency list retains the BPF suite" --vm -o "$tmp/bpf-deps" doctor
has "a long dependency list" "^== internal/doctor, -tags integration,tegobpf " "$tmp/out"
unset COVTEST_BPF_DEPS
: >"$tmp/merged"
run 0 "a guest that returns no data does not stop the collection" --vm -o "$tmp/nodata" observe launch doctor
name="a guest that returns no data"
has "$name" "no coverage data came back from internal/runtime/observe's guest" "$tmp/out"
has "$name" "no coverage data came back from internal/runtime/launch's guest" "$tmp/out"
has "$name" "== internal/doctor," "$tmp/out"
[ "$(cat "$tmp/nodata/vm/data/internal_doctor/covmeta.doctor" 2>/dev/null)" = "data of doctor" ] ||
	{ echo "FAIL $name: doctor's data file was not decoded after the empty guests" >&2; fail=1; }
[ -f "$tmp/nodata/percent.txt" ] || { echo "FAIL $name: no percent.txt" >&2; fail=1; }
has "$name" "+vm" "$tmp/nodata/percent.txt"
has "$name" "/vm/data/internal_doctor" "$tmp/merged"
lacks "$name" "internal_runtime_observe" "$tmp/merged"
lacks "$name" "internal_runtime_launch" "$tmp/merged"

# VM_SUITE_TIMEOUT bounds the guest, and the suite's own -test.timeout ends 300s before it, as root-suites.sh's
# does, so a slow suite's panic names its running tests (it was once a fixed 20m whatever the guest's bound).
mkdir -p "$tmp/guest"
cat >"$tmp/guest/suite.test" <<'EOF'
#!/bin/sh
echo "suite.test $*" >>"$COVTEST_GUEST/args"
EOF
chmod +x "$tmp/guest/suite.test"
COVTEST_GUEST="$tmp/guest" VM_SUITE_TIMEOUT=3000
export COVTEST_GUEST VM_SUITE_TIMEOUT
run 0 "VM_SUITE_TIMEOUT sets the guest's bound and the suite's own timeout 300s inside it" --vm -o "$tmp/timeout" doctor
name="VM_SUITE_TIMEOUT"
has "$name" "^kvm-run.sh --timeout 3000$" "$tmp/guest/args"
has "$name" "^suite.test -test.timeout=2700s -test.gocoverdir=" "$tmp/guest/args"
VM_SUITE_TIMEOUT=300
run 2 "a VM_SUITE_TIMEOUT that leaves the suite no time is refused before anything is made" --vm -o "$tmp/short" doctor
absent "a VM_SUITE_TIMEOUT of 300" "$tmp/short"
VM_SUITE_TIMEOUT="1500 internal/doctor=3000"
run 2 "a VM_SUITE_TIMEOUT that is not plain seconds is refused before anything is made" --vm -o "$tmp/spec" doctor
absent "a VM_SUITE_TIMEOUT that is not plain seconds" "$tmp/spec"
unset COVTEST_GUEST VM_SUITE_TIMEOUT

# The suites and helpers are root-suites.sh's own: a run over every package boots one guest for each package
# root-suites.sh runs and builds each helper the guests' tests `go build` at run time (a missing one dies in
# go-shim.sh with "no prebuilt binary" and fails the tests that need it).
run 0 "--vm runs every package and builds every helper root-suites.sh does" --vm -o "$tmp/all"
name="--vm's suites and helpers"
for p in $(bash -c '. "$1"; printf "%s\n" "${PKGS[@]}"' _ "$here/../test/vm/suites.sh"); do
	has "$name" "^== $p, " "$tmp/out"
done
for h in $(bash -c '. "$1"; printf "%s\n" "${HELPERS[@]}"' _ "$here/../test/vm/suites.sh"); do
	[ -f "$tmp/all/vm/prebuilt/${h##*/}" ] || { echo "FAIL $name: helper $h was not built" >&2; fail=1; }
done

: >"$tmp/merged"
run 0 "--kill-tests merges the data every boot of the row printed" --kill-tests debian-13 -o "$tmp/kt"
name="--kill-tests"
has "$name" "a kill test failed under instrumentation" "$tmp/out"
if [ "$(cat "$tmp/kt/killtests/data/covcounters.boot1" 2>/dev/null)" != "boot1 data" ] ||
	[ "$(cat "$tmp/kt/killtests/data/covcounters.boot2" 2>/dev/null)" != "boot2 data" ]; then
	echo "FAIL $name: the two boots' data files were not both decoded" >&2
	fail=1
fi
has "$name" "/killtests/data" "$tmp/merged"
has "$name" "+vm" "$tmp/kt/percent.txt"

run 2 "--kill-tests with a row the matrix does not have is refused before anything is made" --kill-tests no-such-row -o "$tmp/ktbad"
absent "--kill-tests with an unknown row" "$tmp/ktbad"
has "--kill-tests with an unknown row" "is not a kernel-matrix row" "$tmp/out"

exit "$fail"
