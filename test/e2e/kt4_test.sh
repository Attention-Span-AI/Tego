#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests how kill test 4 (test/e2e/kt4-ordinary.sh) times a run under tego, against the harness defect the
# re-acceptance run found: kill test 4 took a run's wall time around
# kt_run, whose bound is timeout(1), and uutils' timeout notices its command's exit only on a 100 ms poll. Where
# the host's timeout is uutils' (Ubuntu 25.10's), and so in that host's kernel-matrix guests, whose userland is
# the host's, every run under tego was timed up to 100 ms longer than it was, and the five baseline runs,
# which kt_run does not bound, were not: R18's 2x bound was judged against runs the harness itself had
# lengthened, on rows whose margin was tens of milliseconds.
#
# Kill test 4 runs as written, from a copy of test/e2e, with its go kind and three stand-ins first on PATH: a
# go whose build takes 200 ms; a tego that answers doctor and compile and runs the command it is given; and a
# timeout that returns 400 ms after its command exits, a late notice larger than the real one so the verdict
# cannot fall inside the timing's own noise. The baseline is then about 200 ms, R18's budget about 400 ms, and
# a run under the stand-in tego about 200 ms of its own. Timed around the bound, each run is about 600 ms and
# broken; timed around the command inside it, each is about 200 ms. No go, tego, root or network is needed.
#
# Run it as a user, or as root under sudo, where kill test 4 runs its baseline as the sudo user through setpriv
# as it does in the kernel-matrix guest; as root with no sudo user kill test 4 is a named skip, so it refuses.
#
# Usage: test/e2e/kt4_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-kt4-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail "jq is not on PATH; kill test 4 reads tego compile's output with it"
if [ "$(id -u)" = 0 ] && { [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" = 0 ]; }; then
	fail "run as a user, or as root under sudo from a user: as root with no sudo user kill test 4 skips"
fi

# kt_repo_root is two directories above lib.sh, so the copy's repository root is $tmp, where the go kind
# copies the cpu workload's main.go from.
mkdir -p "$tmp/test/e2e" "$tmp/test/workloads/build/cpu" "$tmp/bin" "$tmp/goroot"
# Under sudo the baseline runs the go stand-in as the sudo user, who has to reach it through $tmp.
chmod 755 "$tmp" "$tmp/bin"
cp "$here/kt4-ordinary.sh" "$here/lib.sh" "$here/kt-exit.sh" "$tmp/test/e2e/"
printf 'package main\n\nfunc main() {}\n' >"$tmp/test/workloads/build/cpu/main.go"

cat >"$tmp/bin/timeout" <<'EOF'
#!/usr/bin/env bash
# timeout [-k N] BOUND COMMAND...: runs COMMAND and returns its status 400 ms after it exits.
while [ $# -gt 0 ]; do
	case "$1" in
	-k) shift 2 ;;
	-*) shift ;;
	*) break ;;
	esac
done
shift
"$@"
rc=$?
sleep 0.4
exit "$rc"
EOF
cat >"$tmp/bin/go" <<'EOF'
#!/usr/bin/env bash
case "$1" in
env) echo "$STUB_GOROOT" ;;
build) sleep 0.2 ;;
*) echo "go stand-in: unexpected $*" >&2; exit 2 ;;
esac
EOF
cat >"$tmp/bin/tego" <<'EOF'
#!/usr/bin/env bash
# A stand-in for a tegotesthooks build: the name TEGO_TEST_CHAIN_ANCHOR is what kt_require_testhooks looks for.
# doctor: every tier is available. compile: one declared write entry, which no run refuses. run: a ledger with
# its first line under the machine config's ledger_root, then the command after --, as tego runs it.
case "$1" in
doctor) exit 0 ;;
compile) echo '{"fs":[{"kind":"write","path":"/kt4-test-declared"}],"exec":[],"net":[]}' ;;
run)
	root="$(sed -n 's/^ledger_root: //p' "$TEGO_CONFIG")"
	mkdir -p "$root/r-kt4-test"
	echo '{"kind":"run_start"}' >"$root/r-kt4-test/events.jsonl"
	while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done
	shift
	"$@"
	;;
*) echo "tego stand-in: unexpected $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$tmp/bin/timeout" "$tmp/bin/go" "$tmp/bin/tego"

env PATH="$tmp/bin:$PATH" TMPDIR="$tmp" HOME="$tmp" STUB_GOROOT="$tmp/goroot" \
	TEGO_BIN="$tmp/bin/tego" KT4_KINDS=go KT4_TIERS=landlock KT4_RUNS=3 \
	bash "$tmp/test/e2e/kt4-ordinary.sh" >"$tmp/out" 2>&1
rc=$?
line="$(grep '^KT-HALF kt4 go-landlock ' "$tmp/out")"

# 1. The verdict: every run unbroken, since tego's stand-in adds nothing to the work it runs.
[ "$rc" = 0 ] || fail "kill test 4 exited $rc, want 0: ${line:-$(tail -3 "$tmp/out")}"
case "$line" in
*" PASS 3 of 3 runs unbroken "*) ;;
*) fail "want \"PASS 3 of 3 runs unbroken\": ${line:-no KT-HALF line}" ;;
esac

# 2. The median it reports is the run's own, not the run plus the bound's late notice.
median="$(sed -n 's/.*under tego median \([0-9]*\)ms.*/\1/p' <<<"$line")"
[ -n "$median" ] || fail "no median under tego in: $line"
[ "$median" -lt 400 ] || fail "the median under tego is ${median}ms, which holds the stand-in timeout's 400 ms: $line"

echo "PASS kill test 4 times each run inside kt_run's bound (median ${median}ms under the stand-in tego)"
