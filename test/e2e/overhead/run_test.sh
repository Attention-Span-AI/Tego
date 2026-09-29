#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests what run.sh decides and leaves behind, with a stand-in for tego, so it needs no root, network, go,
# npm or BPF:
#
#   - the ledgers of the runs it times. Every timed run writes one; kept, at the default counts, they came to
#     about 550 MB in the kernel-matrix guest's RAM-backed /tmp, where a timed npm run exited 137 (SIGKILL) part
#     way through kill test 3, twice (2026-09-23), and ran to the end once they were removed; what killed it was
#     not isolated. Before each run the ledger root must hold none of the earlier runs' ledgers, unless --keep
#     asked for them.
#   - the paths it writes into the shell commands of each cell, a --work with a space in it included: split at
#     the space, the removal of those ledgers removed the directory the path's first word names.
#   - the rows of tier cgroup, which the 2026-09-23 acceptance run found missing: cells in every record mode
#     when doctor offers the tier, and one row per workload naming doctor's reason when it does not; and a
#     tier-bpflsm row for every workload either way, so no tier vanishes from the table.
#
# The stand-in answers `doctor --json` with tier cgroup offered or not (STUB_CGROUP), accepts every `compile`,
# and for every `run` records how many run directories the ledger root already holds, then writes one of its
# own. The noop and cpu workloads are scripts that exit 0 (--workload-bin). PATH holds only the tools run.sh
# needs, without curl, npm or go, so the python and npm workloads are named skips and nothing is fetched.
#
# Usage: test/e2e/overhead/run_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-run-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

mkdir -p "$tmp/path" "$tmp/wb" "$tmp/cache" "$tmp/home"
for t in bash python3 env mkdir mktemp chmod cat date uname grep cut sed cp rm wc tee id dirname basename ls head \
	tail sort readlink sleep true false awk tr sha256sum mv; do
	p="$(command -v "$t")" || fail "$t is not on PATH"
	ln -s "$p" "$tmp/path/$t"
done
for w in noop cpu; do
	printf '#!/bin/sh\nexit 0\n' >"$tmp/wb/$w"
	chmod +x "$tmp/wb/$w"
done
cat >"$tmp/tego" <<'EOF'
#!/usr/bin/env bash
# A stand-in for a tegotesthooks build: the name TEGO_TEST_CHAIN_ANCHOR is what run.sh looks for.
case "$1" in
doctor)
	printf '{"tiers":{"landlock":true,"cgroup":%s,"bpflsm":false},"missing":{"cgroup":["stand-in: no root"],"bpflsm":["stand-in: not built"]}}\n' "$STUB_CGROUP"
	;;
compile) echo "compile $2" >>"$STUB_LOG" ;;
run)
	root="$(sed -n 's/^ledger_root: //p' "$TEGO_CONFIG")"
	n="$(ls -d "$root"/r-* 2>/dev/null | wc -l)"
	echo "run-saw $n" >>"$STUB_LOG"
	echo "anchor ${TEGO_TEST_CHAIN_ANCHOR:-none} ownlog ${TEGO_TEST_OWN_LOG_HOME:-none}" >>"$STUB_LOG"
	echo "runtime ${XDG_RUNTIME_DIR:-none} $(ls -ld "${XDG_RUNTIME_DIR:-/nonexistent}" 2>/dev/null | cut -c1-10)" >>"$STUB_LOG"
	run="$root/r-$$-$RANDOM"
	mkdir -p "$run" && : >"$run/events.jsonl"
	;;
esac
exit 0
EOF
chmod +x "$tmp/tego"

# harness runs run.sh with the stand-ins, a clean environment plus the given variables (VAR=value ...) and, after
# a --, the given arguments, and returns its exit code; run_harness also fails the test unless it exits 0 and
# writes its table to $tmp/out.md.
harness() {
	local vars=() args=()
	while [ $# -gt 0 ] && [ "$1" != -- ]; do vars+=("$1"); shift; done
	[ "${1:-}" != -- ] || { shift; args=("$@"); }
	rm -f "$tmp/stub.log" "$tmp/out.md"
	env -i PATH="$tmp/path" HOME="$tmp/home" TMPDIR="$tmp" STUB_LOG="$tmp/stub.log" "${vars[@]}" \
		bash "$here/run.sh" --tego "$tmp/tego" --workload-bin "$tmp/wb" --cache "$tmp/cache" --warmup 1 --runs 2 \
		--passes 1 --seed 1 --out "$tmp/out.md" "${args[@]}" >"$tmp/run.log" 2>&1
}
run_harness() {
	harness "$@" || fail "run.sh $* exited $?: $(tail -3 "$tmp/run.log")"
	[ -s "$tmp/out.md" ] || fail "run.sh wrote no table"
}
max_seen() { sed -n 's/^run-saw //p' "$tmp/stub.log" | sort -n | tail -1; }
row() { grep -E "^\| $1 \| $2 \|" "$tmp/out.md"; }

# 1. Tier cgroup offered: cells in every record mode for every workload that ran, a bpflsm row naming doctor's
# reason, and no earlier ledger in the ledger root when any run starts.
run_harness STUB_CGROUP=true
[ "$(max_seen)" = 0 ] || fail "a run started with $(max_seen) earlier ledgers in the ledger root; each run's must go before the next"
for w in noop cpu; do
	for r in full summary off; do
		row "$w" cgroup | grep -q "| $r |" || fail "no $w/cgroup/$r row although doctor offers tier cgroup"
	done
	row "$w" bpflsm | grep -q 'skipped: stand-in: not built' || fail "no $w/bpflsm row with doctor's reason"
done
grep -q 'compile agent.cgroup.yaml' "$tmp/stub.log" || fail "the tier-cgroup copy of the contract was never compiled"
for w in python npm; do
	row "$w" '\*' | grep -q skipped || fail "the $w workload, which cannot run here, has no skip row"
done

# 2. Tier cgroup not offered: one row per workload that names doctor's reason, and no cgroup cell.
run_harness STUB_CGROUP=false
for w in noop cpu; do
	if ! { [ "$(row "$w" cgroup | wc -l)" = 1 ] && row "$w" cgroup | grep -q 'skipped: stand-in: no root'; }; then
		fail "tier cgroup unavailable, but $w's cgroup rows are: $(row "$w" cgroup)"
	fi
done

# 3. --keep keeps every run's ledger, as it says.
run_harness STUB_CGROUP=false -- --keep --work "$tmp/kept"
[ "$(max_seen)" -gt 0 ] || fail "--keep, yet the ledgers of earlier runs were removed"

# 4. A --work with a space in its path: the directory its first word names, a sibling of the work directory, is
# left alone, and the harness runs there as anywhere else, removing each run's ledger before the next. The python
# and npm workloads run here too, so their own prepares, which remove and recreate directories under --work, are
# exercised: a primed cache of their own (a pip module that writes an empty pytest into --target, and a non-empty
# npm cache) and an npm that exits 0. Nothing may be written into that sibling either: a --target split at the
# space put pytest/ there with keep.txt still in place. And tego itself lives under the spaced path, as run.sh's
# own default ($work/tego) puts it, so every cell's command runs it through the quoted path; split, it named the
# sibling directory.
mkdir -p "$tmp/victim" "$tmp/victim space" "$tmp/cache4/python/wheelhouse" "$tmp/cache4/python/pip-bootstrap/pip" \
	"$tmp/cache4/npm/cache" "$tmp/npmbin"
: >"$tmp/victim/keep.txt"
cp "$tmp/tego" "$tmp/victim space/tego"
: >"$tmp/cache4/npm/cache/primed"
sha256sum "$here/../../workloads/build/python/requirements.txt" | cut -c1-16 >"$tmp/cache4/python/.stamp"
: >"$tmp/cache4/python/pip-bootstrap/pip/__init__.py"
cat >"$tmp/cache4/python/pip-bootstrap/pip/__main__.py" <<'PY'
import os, sys
pkg = os.path.join(sys.argv[sys.argv.index("--target") + 1], "pytest")
os.makedirs(pkg, exist_ok=True)
for f in ("__init__.py", "__main__.py"):
    open(os.path.join(pkg, f), "w").close()
PY
printf '#!/bin/sh\nexit 0\n' >"$tmp/npmbin/npm"
chmod +x "$tmp/npmbin/npm"
harness STUB_CGROUP=true PATH="$tmp/path:$tmp/npmbin" -- --work "$tmp/victim space/w" --cache "$tmp/cache4" \
	--tego "$tmp/victim space/tego"
code=$?
[ -f "$tmp/victim/keep.txt" ] || fail "--work '$tmp/victim space/w' removed $tmp/victim, a directory outside it"
# shellcheck disable=SC2012 # the one name this test itself wrote, compared whole
[ "$(ls -A "$tmp/victim")" = keep.txt ] ||
	fail "--work '$tmp/victim space/w' wrote into $tmp/victim, a directory outside it: $(ls -A "$tmp/victim" | tr '\n' ' ')"
[ "$code" = 0 ] && [ -s "$tmp/out.md" ] ||
	fail "run.sh --work '$tmp/victim space/w' exited $code or wrote no table: $(tail -3 "$tmp/run.log")"
[ "$(max_seen)" = 0 ] || fail "--work with a space: a run started with $(max_seen) earlier ledgers in the ledger root"
for w in noop cpu python npm; do
	row "$w" cgroup | grep -q '| full |' || fail "--work with a space: no $w/cgroup/full row"
	! row "$w" cgroup | grep -q 'no bare row' || fail "--work with a space: $w's bare baseline did not run"
done

# A python cache whose pip-bootstrap is there but whose priming never finished (no stamp: the run was killed
# before the wheelhouse was complete) is not primed. It was taken for primed on the bootstrap directory alone.
mkdir -p "$tmp/cache5/python/pip-bootstrap/pip" "$tmp/cache5/python/wheelhouse"
harness STUB_CGROUP=true -- --work "$tmp/w5" --cache "$tmp/cache5" || true
! grep -q 'python cache already primed' "$tmp/run.log" ||
	fail "a python cache with a bootstrap directory and no stamp was taken for primed"

# 6. Every timed run is anchored in the work directory, never the invoking user's own ~/.tego (identity-config.md
# R27): the stand-in sees the isolation variables run.sh exports, and a binary handed in with --tego that is not a
# test build is refused (exit 2) unless this is a disposable machine.
run_harness STUB_CGROUP=false XDG_RUNTIME_DIR=/run/user/12345 -- --work "$tmp/w6"
grep -q "^anchor $tmp/w6/tego-own/chain.log ownlog $tmp/w6/tego-own/home" "$tmp/stub.log" ||
	fail "a timed run did not see the work directory's anchor and own-log home: $(grep '^anchor' "$tmp/stub.log" | sort -u | head -2)"
# ... and its runtime directory is the work directory's, 0700, not the inherited one: a launch makes
# <XDG_RUNTIME_DIR>/tego and sweeps the invoking user's crashed runs' directories there (R27 clause b4).
[ "$(sed -n 's/^runtime //p' "$tmp/stub.log" | sort -u)" = "$tmp/w6/tego-own/run drwx------" ] ||
	fail "a timed run did not see the work directory's own XDG_RUNTIME_DIR, 0700: $(grep '^runtime' "$tmp/stub.log" | sort -u | head -2)"
printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/product-tego"
chmod +x "$tmp/product-tego"
harness STUB_CGROUP=false -- --work "$tmp/w7" --tego "$tmp/product-tego"
code=$?
[ "$code" = 2 ] || fail "a product build handed to run.sh exited $code, want 2: $(tail -2 "$tmp/run.log")"
grep -q 'not built with -tags tegotesthooks' "$tmp/run.log" || fail "the refusal does not say why: $(tail -2 "$tmp/run.log")"
harness STUB_CGROUP=false TEGO_DISPOSABLE_HOST=kvm -- --work "$tmp/w8" --tego "$tmp/product-tego"
code=$?
! grep -q 'not built with -tags tegotesthooks' "$tmp/run.log" || fail "a disposable machine was refused a product build ($code)"

echo "ok run_test.sh"
