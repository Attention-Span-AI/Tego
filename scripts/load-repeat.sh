#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# load-repeat.sh WORK TESTBIN TEST BURNERS COUNT LABEL
#
# Run one test of a compiled integration test binary COUNT times, under BURNERS busy loops (0: a quiet host), in the
# empty-home isolated view: HOME, TMPDIR and the Go caches' own folders are under WORK, so no tego state of the person
# running it is read or written (the test binary starts the real tego and tego-control it builds from the tree, with
# TEGO_TEST_* pointed into its own temporary folder by internal/testutil.TegoEnv).
#
# It never starts a busy-loop measurement while tego-gate.service is active, and stops (the burners and the test, each
# by its exact pid) when the gate starts during the run. Each run's whole output is kept in WORK/runs/LABEL/runN.out;
# WORK/runs/LABEL/results.tsv has one line per run: number, result, seconds, load average at its start.
set -u
if [ "$#" -ne 6 ]; then
	echo "usage: load-repeat.sh WORK TESTBIN TEST BURNERS COUNT LABEL" >&2
	exit 2
fi
work=$1 testbin=$2 test=$3 burners=$4 count=$5 label=$6
real_home=$HOME
dir=$work/runs/$label
mkdir -p "$dir" "$work/home" "$work/tmp"
gate() { [ "$(systemctl --user is-active tego-gate.service)" = active ]; }
if gate; then
	echo "tego-gate.service is active: not starting"
	exit 3
fi
export HOME=$work/home TMPDIR=$work/tmp GOTMPDIR=$work/tmp GOMAXPROCS=4 GOFLAGS=-p=2 CGO_ENABLED=0
export GOCACHE=$real_home/.cache/go-build GOMODCACHE=$real_home/go/pkg/mod GOPATH=$real_home/go
export PATH=/usr/bin:$real_home/.local/go/bin:$real_home/go/bin:$PATH
pids=()
for _ in $(seq 1 "$burners"); do
	timeout 3000 sh -c 'while :; do :; done' >/dev/null 2>&1 &
	pids+=($!)
done
testpid=$work/testpid-$label
: >"$testpid"
stopall() {
	[ "${#pids[@]}" -gt 0 ] && kill "${pids[@]}" 2>/dev/null
	[ -s "$testpid" ] && kill "$(cat "$testpid")" 2>/dev/null
	return 0
}
trap stopall EXIT
(while sleep 2; do
	if gate; then
		echo "GATE STARTED $(date +%T): stopping" >>"$dir/GATE"
		stopall
		exit
	fi
done) &
watcher=$!
sleep 5
uptime
: >"$dir/results.tsv"
pass=0 fail=0
# The test runs from its package's folder in the tree (it finds the module from there): LOAD_REPEAT_PKGDIR.
cd "${LOAD_REPEAT_PKGDIR:?set LOAD_REPEAT_PKGDIR to the test package folder}" || exit 1
for i in $(seq 1 "$count"); do
	if gate; then
		echo "gate active: stopping before run $i"
		break
	fi
	load=$(cut -d' ' -f1 /proc/loadavg)
	start=$(date +%s.%N)
	timeout 600 "$testbin" -test.count=1 -test.run "^${test}\$" -test.v >"$dir/run$i.out" 2>&1 &
	echo $! >"$testpid"
	wait $!
	rc=$?
	: >"$testpid"
	secs=$(echo "$(date +%s.%N) - $start" | bc)
	if [ $rc -eq 0 ] && grep -q -- "^--- PASS: $test " "$dir/run$i.out"; then
		pass=$((pass + 1))
		printf '%s\tPASS\t%s\t%s\n' "$i" "$secs" "$load" >>"$dir/results.tsv"
	else
		fail=$((fail + 1))
		printf '%s\tFAIL rc=%s\t%s\t%s\n' "$i" "$rc" "$secs" "$load" >>"$dir/results.tsv"
	fi
done
kill "$watcher" 2>/dev/null
echo "$test ($burners busy loops, $label): pass=$pass fail=$fail"
echo finished
