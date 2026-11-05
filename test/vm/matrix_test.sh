#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests three things matrix.sh decides before any guest boots, against the leftovers the final review of the
# 2026-09-23 acceptance run found, and what the 2026-10-05 rows added:
#
#   - the bound on one boot. Kill test 3, which VM_KT3=1 adds to a row, may take its whole VM_TEST_TIMEOUT,
#     and the row's own bound (VM_ROW_TIMEOUT, 3600 s) left it no room: raising VM_TEST_TIMEOUT for a slow
#     row, as the README advised, still let kvm-run.sh kill the guest at 3600 s with kill test 3 unfinished.
#   - what VM_KT4_TOOLS=1 carries, so kill test 4's npm and go kinds run as root in the guest instead of
#     being named skips on every row: node, the directory npm's package lives in with its links followed,
#     and a GOROOT trimmed of what a build of another module never reads, each reachable from /usr/local/bin;
#   - what a doctor-only row is (fetch-kernel.py's DOCTOR_ONLY: Ubuntu 22.04's 5.15, where no tier is offered): one
#     boot that runs run-matrix-row.sh --only doctor-refusal, never the kill tests, never a second boot owed to kill
#     test 6 (c), whatever VM_ONLY says, and a failed refusal fails the row.
#
# matrix.sh runs as written, from a copy of test/vm in a tree of stand-ins: a fetch-kernel.py that names one
# row, a kvm-run.sh that records its arguments and reports a guest that ran, a go that "builds" by writing a
# script and names a GOROOT made here, a pydeps.sh with no cache, and a node and npm laid out as a Debian
# host lays them out. Nothing boots and no network is used; jq and python3 must be on PATH, as for the real
# script.
#
# Usage: test/vm/matrix_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/tego-matrix-test.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL $*" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || fail "jq is not on PATH; matrix.sh itself refuses to run without it"

repo="$tmp/repo"
mkdir -p "$repo/test/vm" "$repo/test/e2e" "$repo/test/workloads/build/noop" "$repo/test/workloads/build/cpu" \
	"$repo/examples" "$repo/internal/runtime/limits/testdata" "$tmp/bin" "$tmp/cache"
: >"$repo/internal/runtime/limits/testdata/prices.yaml"
cp "$here/matrix.sh" "$here/fwd-run.sh" "$repo/test/vm/"
# The fetch-kernel.py stand-in: STUB_ROWS is "name:body ..." (default row-a:full), printed as the real --list prints
# its rows (name, series, kind, body, label) and --body answers; STUB_FETCH_FAIL names a row whose fetch fails.
cat >"$repo/test/vm/fetch-kernel.py" <<'EOF'
import os, sys
rows = [r.split(":") for r in os.environ.get("STUB_ROWS", "row-a:full").split()]
a = sys.argv[1:]
if a == ["--list"]:
    for name, body in rows:
        print(f"{name:<14} 6.1    deb   {body:<11} stand-in")
elif a[:1] == ["--name"]:
    print("matrix-" + a[1])
elif a[:1] == ["--body"]:
    if a[1] not in dict(rows):
        sys.exit(2)
    print(dict(rows)[a[1]])
elif a and a[0] == os.environ.get("STUB_FETCH_FAIL"):
    sys.exit(1)
EOF
# The kvm-run.sh stand-in refuses a --file whose source does not exist, as the real one does before it boots,
# and only then writes the console and the status that tell matrix.sh a guest ran.
cat >"$repo/test/vm/kvm-run.sh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$STUB_ARGS"
[ -z "${STUB_BOOTS:-}" ] || echo "$*" >>"$STUB_BOOTS"
log="" status=""
while [ $# -gt 0 ]; do
	case "$1" in
	--log) log="$2"; shift 2 ;;
	--status) status="$2"; shift 2 ;;
	--file)
		[ -e "${2%%:*}" ] || { echo "kvm-run: --file ${2%%:*} does not exist" >&2; exit 2; }
		shift 2
		;;
	--) break ;;
	*) shift ;;
	esac
done
echo "MATRIX-KERNEL stand-in lsm=${STUB_LSM-lockdown,yama,bpf}" >"$log"
[ -z "${STUB_FIX:-}" ] || echo "KT6-LSM-FIX $STUB_FIX" >>"$log"
# The facts run-matrix-row.sh prints from doctor's text: STUB_FACTS on a row's first boot, STUB_FACTS2 on the second.
case " $* " in *" kt6c "*) facts="${STUB_FACTS2:-}" ;; *) facts="${STUB_FACTS:-}" ;; esac
[ -z "$facts" ] || echo "MATRIX-FACTS $facts" >>"$log"
case "${STUB_GUEST:-ok}" in
ok) echo "MATRIX-RESULT c root PASS 0 fine" >>"$log"; echo "guest 0" >"$status"; exit 0 ;;
skipkt) printf 'MATRIX-RESULT kt1-identity[KT_TIER=cgroup] root SKIP 77 jq is not usable\n' >>"$log"; echo "guest 0" >"$status"; exit 0 ;;
skipok) printf 'MATRIX-RESULT kt3-overhead root SKIP - not run\nKT-HALF kt2-capture uprobe SKIP no root\n' >>"$log"; echo "guest 0" >"$status"; exit 0 ;;
timeout) echo timeout >"$status"; exit 124 ;;
noreport) echo no-report >"$status"; exit 125 ;;
usage) echo usage >"$status"; exit 2 ;;
nostatus) exit 2 ;;
env) echo env >"$status"; exit 97 ;;
empty) echo "guest 1" >"$status"; exit 1 ;;
killed) echo "MATRIX-RESULT c root PASS 0 fine" >>"$log"; echo "guest 137" >"$status"; exit 137 ;;
refusalfails) echo "MATRIX-RESULT doctor-refusal user FAIL 1 this machine offers a tier" >>"$log"; echo "guest 1" >"$status"; exit 1 ;;
esac
EOF
printf '#!/bin/sh\nexit 1\n' >"$repo/test/e2e/pydeps.sh"
chmod +x "$repo/test/vm/kvm-run.sh" "$repo/test/e2e/pydeps.sh"

# The go stand-in and the GOROOT it names: a build is a script at -o, and the GOROOT has one file in each part
# the stage keeps and in each it leaves out.
goroot="$tmp/goroot"
mkdir -p "$goroot/bin" "$goroot/pkg/tool/linux_amd64" "$goroot/src/fmt" "$goroot/src/cmd/go" "$goroot/test" \
	"$goroot/api" "$goroot/doc" "$goroot/misc"
printf '#!/bin/sh\n' >"$goroot/bin/go"
chmod +x "$goroot/bin/go"
for f in pkg/tool/linux_amd64/compile src/fmt/print.go src/cmd/go/main.go test/t.go api/go1.txt doc/d.html misc/m; do
	: >"$goroot/$f"
done
cat >"$tmp/bin/go" <<EOF
#!/usr/bin/env bash
case "\$1" in
env) [ "\${2:-}" = GOROOT ] && echo "$goroot" ;;
list) echo example.com/stand-in ;;
build)
	echo "\$*" >>"$tmp/go.args"
	out=""
	while [ \$# -gt 0 ]; do [ "\$1" != -o ] || out="\$2"; shift; done
	printf '#!/bin/sh\nexit 0\n' >"\$out" && chmod +x "\$out"
	;;
*) exit 1 ;;
esac
EOF
chmod +x "$tmp/bin/go"

# node and npm as Debian lays them out: npm's package among its dependencies in one directory, a dependency
# linking a file outside it, and npm's man pages linking the host's man tree.
pfx="$tmp/node"
mkdir -p "$pfx/bin" "$pfx/share/nodejs/npm/bin" "$pfx/share/nodejs/dep" "$tmp/javascript" "$tmp/man/man1"
printf '#!/bin/sh\n' >"$pfx/bin/node"
printf 'require("../lib/cli.js")\n' >"$pfx/share/nodejs/npm/bin/npm-cli.js"
chmod +x "$pfx/bin/node" "$pfx/share/nodejs/npm/bin/npm-cli.js"
ln -s ../share/nodejs/npm/bin/npm-cli.js "$pfx/bin/npm"
printf 'module.exports = 1\n' >"$tmp/javascript/ext.js"
ln -s "$tmp/javascript/ext.js" "$pfx/share/nodejs/dep/ext.js"
: >"$tmp/man/man1/npm.1"
ln -s "$tmp/man" "$pfx/share/nodejs/npm/man"

# run_matrix runs the copy of matrix.sh with the given variables and the rows of MROWS (row-a alone by default); it
# fails the test when matrix.sh does not exit 0, and leaves the stand-in kvm-run.sh's last arguments in $tmp/args,
# one per line, and one line per boot in $tmp/boots.
MROWS=(row-a)
run_matrix() {
	rm -f "$tmp/args" "$tmp/boots"
	env -i PATH="$pfx/bin:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/bin/go" VM_OUT="$tmp/out" \
		TEGO_VM_CACHE="$tmp/cache" STUB_ARGS="$tmp/args" STUB_BOOTS="$tmp/boots" "$@" \
		bash "$repo/test/vm/matrix.sh" "${MROWS[@]+"${MROWS[@]}"}" >"$tmp/out.log" 2>&1 ||
		fail "matrix.sh $* exited $?: $(tail -3 "$tmp/out.log")"
	[ -s "$tmp/args" ] || fail "matrix.sh $* booted nothing: $(tail -3 "$tmp/out.log")"
}
# arg_after prints the argument that follows the first one equal to $1.
arg_after() { awk -v k="$1" 'found { print; exit } $0 == k { found = 1 }' "$tmp/args"; }
has_arg() { grep -qxF -- "$1" "$tmp/args"; }

# 1. The boot's bound: 3600 s alone, 3600 s plus kill test 3's own bound with VM_KT3=1, and a VM_ROW_TIMEOUT given
# by hand as given. The guest is told the per-test bound it is to apply.
run_matrix
has_arg --delegate-user || fail "the matrix guest inherits user delegation from the host instead of providing its fixture"
[ "$(arg_after --timeout)" = 3600 ] || fail "row bound without VM_KT3 is $(arg_after --timeout), want 3600"
has_arg VM_TEST_TIMEOUT=1500 || fail "the guest was not given VM_TEST_TIMEOUT=1500"
run_matrix VM_KT3=1
[ "$(arg_after --timeout)" = 5100 ] ||
	fail "row bound with VM_KT3=1 is $(arg_after --timeout), want 5100: kill test 3's 1500 s on top of the row's 3600 s"
run_matrix VM_KT3=1 VM_TEST_TIMEOUT=3000
[ "$(arg_after --timeout)" = 6600 ] || fail "row bound with VM_KT3=1 VM_TEST_TIMEOUT=3000 is $(arg_after --timeout), want 6600"
has_arg VM_TEST_TIMEOUT=3000 || fail "the guest was not given VM_TEST_TIMEOUT=3000"
run_matrix VM_KT3=1 VM_ROW_TIMEOUT=4000
[ "$(arg_after --timeout)" = 4000 ] || fail "a VM_ROW_TIMEOUT given by hand became $(arg_after --timeout), want 4000"

# 2. Nothing of kill test 4's tools goes in without VM_KT4_TOOLS=1.
grep -q -e ':/usr/local/go$' -e ':/usr/local/bin/node$' -e ':/usr/local/bin/npm$' "$tmp/args" &&
	fail "kill test 4's tools were carried without VM_KT4_TOOLS=1"

# 3. With it: node where it is, npm's directory where it is, both and go on PATH through /usr/local/bin, and
# what each staged copy holds.
run_matrix VM_KT4_TOOLS=1
stage="$tmp/out/matrix/stage/kt4"
has_arg "$pfx/bin/node:$pfx/bin/node" || fail "node was not carried at its own path"
has_arg "$stage/npm-root:$pfx/share/nodejs" || fail "npm's directory was not carried at its own path"
for t in node npm go; do
	has_arg "$stage/bin/$t:/usr/local/bin/$t" || fail "$t is not on the guest's PATH through /usr/local/bin"
done
has_arg "$stage/go:/usr/local/go" || fail "GOROOT was not carried to /usr/local/go"
[ "$(readlink "$stage/bin/go")" = ../go/bin/go ] && [ -x "$stage/bin/go" ] ||
	fail "/usr/local/bin/go leads to $(readlink "$stage/bin/go"), want ../go/bin/go, which resolves in the stage as in the guest"
[ "$(readlink "$stage/bin/npm")" = "$pfx/share/nodejs/npm/bin/npm-cli.js" ] ||
	fail "/usr/local/bin/npm leads to $(readlink "$stage/bin/npm"), want npm-cli.js's real path"
[ -f "$stage/npm-root/dep/ext.js" ] && [ ! -L "$stage/npm-root/dep/ext.js" ] ||
	fail "a link out of npm's directory was carried as a link, which would dangle in the guest"
[ ! -e "$stage/npm-root/npm/man" ] || fail "npm's man pages, a link to the host's man tree, were carried"
for f in bin/go pkg/tool/linux_amd64/compile src/fmt/print.go; do
	[ -e "$stage/go/$f" ] || fail "the staged GOROOT lacks $f, which a build reads"
done
for d in src/cmd test api doc misc; do
	[ ! -e "$stage/go/$d" ] || fail "the staged GOROOT carries $d, which a build of another module never reads"
done

# 4. Kill test 3's harness keeps a primed npm cache on this host, and with VM_KT3=1 as well it goes where kill test
# 3 points the harness as root in the guest; without VM_KT3=1 it stays out.
bench="$tmp/.cache/tego-overhead-bench/npm"
mkdir -p "$bench/cache" && : >"$bench/cache/index"
run_matrix VM_KT4_TOOLS=1
has_arg "$bench:/root/.cache/tego-overhead-bench/npm" && fail "the npm bench cache went in without VM_KT3=1"
run_matrix VM_KT4_TOOLS=1 VM_KT3=1
has_arg "$bench:/root/.cache/tego-overhead-bench/npm" ||
	fail "with VM_KT3=1 and VM_KT4_TOOLS=1 the primed npm bench cache was not carried to root's default cache"

# 5. A row that did not complete is a failure: a guest that reported no check, one that died after passing
# checks without a failing one, and a kernel that could not be fetched.
not_green() {
	env -i PATH="$pfx/bin:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/bin/go" VM_OUT="$tmp/out" \
		TEGO_VM_CACHE="$tmp/cache" STUB_ARGS="$tmp/args" "$@" \
		bash "$repo/test/vm/matrix.sh" "${MROWS[@]+"${MROWS[@]}"}" >"$tmp/out.log" 2>&1 && fail "matrix.sh $* exited 0 for a row that did not complete"
	return 0
}
not_green STUB_GUEST=empty
not_green STUB_GUEST=killed
# A guest that booted but timed out, ended without a report or hit a usage error is a failed row (exit 1), never 97, which is "this
# box cannot boot a guest"; only the env status keeps 97.
for g in timeout noreport usage nostatus env; do
	env -i PATH="$pfx/bin:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/bin/go" VM_OUT="$tmp/out" \
		TEGO_VM_CACHE="$tmp/cache" STUB_ARGS="$tmp/args" STUB_GUEST=$g \
		bash "$repo/test/vm/matrix.sh" row-a >"$tmp/out.log" 2>&1
	rc=$?
	want=1
	[ "$g" != env ] || want=97
	[ "$rc" = "$want" ] || fail "STUB_GUEST=$g: matrix.sh exited $rc, want $want"
done
# A kill test that skipped is a failed row; kill test 3's named skip and a half's skip are not.
not_green STUB_GUEST=skipkt
run_matrix STUB_GUEST=skipok
# A kernel without bpf in its LSM list whose kill test 6 printed no fix line never ran half (c): a failed row. With
# the line it boots twice and passes; with bpf already active there is no reboot to owe.
not_green STUB_LSM=lockdown,yama
not_green STUB_LSM=
run_matrix STUB_LSM=lockdown,yama STUB_FIX=lockdown,yama,bpf
grep -q '^KT6_LSM_FIX=lockdown,yama,bpf$' "$tmp/args" || fail "boot2 was not handed the fix line"
run_matrix STUB_LSM=lockdown,bpf,yama
# One of two rows failing to fetch, the other running fine.
MROWS=(row-a row-b)
not_green STUB_ROWS="row-a:full row-b:full" STUB_FETCH_FAIL=row-b
MROWS=(row-a)

# 7. The boot lock's directory need not exist yet: a machine that never fetched a kernel (the host row) boots.
rm -rf "$tmp/cache"
run_matrix
[ -d "$tmp/cache" ] || fail "matrix.sh left no cache directory for its lock"

# 8. VM_ONLY names the one kill test a boot runs alone, kill test 4 or 5, as the guest's --only (kill test 5's cost of
# an untouched ask entry, measured on a row's one boot with VM_ONLY_LSM naming its lsm= line); VM_KT5_TIERS and
# VM_KT5_RUNS reach the guest as its own environment, and a name that is neither kill test is a usage error (2) before
# any guest boots, as an unknown row is.
run_matrix VM_ONLY=kt5 VM_KT5_TIERS=bpflsm VM_KT5_RUNS=3
[ "$(arg_after --only)" = kt5 ] || fail "VM_ONLY=kt5 booted with --only \"$(arg_after --only)\""
has_arg VM_KT5_TIERS=bpflsm || fail "the guest was not given VM_KT5_TIERS=bpflsm"
has_arg VM_KT5_RUNS=3 || fail "the guest was not given VM_KT5_RUNS=3"
run_matrix VM_ONLY=kt4
[ "$(arg_after --only)" = kt4 ] || fail "VM_ONLY=kt4 booted with --only \"$(arg_after --only)\""
run_matrix
has_arg --only && fail "a boot with no VM_ONLY was told to run one kill test alone"
has_arg VM_KT5_TIERS= || fail "the guest was not given an empty VM_KT5_TIERS, so its default tiers apply"
rm -f "$tmp/args"
env -i PATH="$pfx/bin:$PATH" HOME="$tmp" TMPDIR="$tmp" GO="$tmp/bin/go" VM_OUT="$tmp/out" TEGO_VM_CACHE="$tmp/cache" \
	STUB_ARGS="$tmp/args" VM_ONLY=kt6c bash "$repo/test/vm/matrix.sh" row-a >"$tmp/out.log" 2>&1
rc=$?
[ "$rc" = 2 ] || fail "VM_ONLY=kt6c exited $rc, want the usage error 2"
[ ! -s "$tmp/args" ] || fail "VM_ONLY=kt6c booted a guest"

# 9. VM_TESTHOOKS=1 stages a tego built with the test hooks as well as the BPF objects, which kill test 5's plane
# pins need (TEGO_TEST_PLANE), says so, and hands the guest VM_KT5_PLANES; without it the build is the objects' alone,
# the binary a release ships. The stand-in objects make the tagged build the one tried.
mkdir -p "$repo/internal/bpf"
: >"$repo/internal/bpf/stub_bpfel.o"
rm -f "$tmp/go.args"
run_matrix
grep -q -- 'build -tags tegobpf -o ' "$tmp/go.args" || fail "the staged tego was not built with -tags tegobpf alone: $(cat "$tmp/go.args")"
grep -q tegotesthooks "$tmp/go.args" && fail "a build without VM_TESTHOOKS=1 carried the test hooks: $(cat "$tmp/go.args")"
rm -f "$tmp/go.args"
run_matrix VM_TESTHOOKS=1 VM_KT5_PLANES="lsm fmod_ret"
grep -q -- 'build -tags tegobpf,tegotesthooks -o ' "$tmp/go.args" || fail "VM_TESTHOOKS=1 did not build with the test hooks: $(cat "$tmp/go.args")"
grep -q 'with the test hooks (VM_TESTHOOKS=1)' "$tmp/out.log" || fail "the build's note does not say it carries the test hooks: $(grep 'tego built' "$tmp/out.log")"
has_arg "VM_KT5_PLANES=lsm fmod_ret" || fail "the guest was not given VM_KT5_PLANES=\"lsm fmod_ret\""
rm -rf "${repo:?}/internal/bpf"

# 10. A doctor-only row (the fourth column of fetch-kernel.py --list) boots once and runs the refusal check and nothing
# else. Its kernel lists no bpf and no kill test 6 prints a fix line, which fails a full row (kt6/c-fix-missing above);
# here no second boot is owed, because no kill test runs. VM_ONLY=kt4 would run kill test 4 as root on a full row, and
# a doctor-only row has no tier to run it at, so it still runs the refusal. The row `host` is named only, so
# fetch-kernel.py is not asked its body, and it is a full row.
rows2="row-a:full row-d:doctor-only"
MROWS=(row-d)
run_matrix STUB_ROWS="$rows2" STUB_LSM=lockdown,yama
[ "$(wc -l <"$tmp/boots")" -eq 1 ] || fail "a doctor-only row booted $(wc -l <"$tmp/boots") times, want 1"
[ "$(arg_after --only)" = doctor-refusal ] || fail "a doctor-only row ran with --only \"$(arg_after --only)\", want doctor-refusal"
run_matrix STUB_ROWS="$rows2" VM_ONLY=kt4
[ "$(arg_after --only)" = doctor-refusal ] || fail "VM_ONLY=kt4 ran a doctor-only row with --only \"$(arg_after --only)\", want doctor-refusal"
MROWS=(row-a)
run_matrix STUB_ROWS="$rows2"
if grep -qe '--only' "$tmp/args"; then fail "a full row was run with --only \"$(arg_after --only)\""; fi
MROWS=(host)
run_matrix STUB_ROWS="$rows2"
if grep -qe '--only' "$tmp/args"; then fail "the host row was run with --only \"$(arg_after --only)\""; fi
# With no row named, every row runs: the full one as always and the doctor-only one for its refusal.
MROWS=()
run_matrix STUB_ROWS="$rows2"
[ "$(wc -l <"$tmp/boots")" -eq 2 ] || fail "two default rows booted $(wc -l <"$tmp/boots") times, want 2"
[ "$(grep -c -e '--only doctor-refusal' "$tmp/boots")" -eq 1 ] || fail "exactly one of the two boots should run --only doctor-refusal: $(cat "$tmp/boots")"
# A refusal that failed fails the row, and the report names the check.
MROWS=(row-d)
not_green STUB_ROWS="$rows2" STUB_GUEST=refusalfails
grep -q 'doctor-refusal' "$tmp/out/matrix/summary.json" || fail "summary.json does not hold the failed doctor-refusal check"
MROWS=(row-a)

# 9. The facts a boot prints (run-matrix-row.sh's MATRIX-FACTS line, from doctor-facts.sh) are kept per row and per
# boot in summary.json, and printed under the row's heading: cgroup_mode is ADR 0021 (7)'s column, "every matrix row
# selects a plane mode", which a reader can only judge if each boot's mode is in the report. The row's kernel has no
# bpf in its own list, so it boots twice, and the two boots differ.
sj="$tmp/out/matrix/summary.json"
run_matrix STUB_LSM=lockdown,yama STUB_FIX=lockdown,yama,bpf STUB_FACTS="landlock_abi=7 cgroup_mode=fmod_ret" STUB_FACTS2="landlock_abi=7 cgroup_mode=lsm"
[ "$(jq -c '."row-a".cgroup_mode' "$sj")" = '{"boot1":"fmod_ret","boot2":"lsm"}' ] ||
	fail "summary.json's cgroup_mode is $(jq -c '."row-a".cgroup_mode' "$sj"), want the mode of each boot"
[ "$(jq -c '."row-a".landlock_abi' "$sj")" = 7 ] || fail "summary.json's landlock_abi is $(jq -c '."row-a".landlock_abi' "$sj"), want 7"
grep -q 'cgroup_mode: boot1=fmod_ret boot2=lsm' "$tmp/out.log" || fail "the report does not print the row's cgroup_mode: $(tail -8 "$tmp/out.log")"
# A boot that printed no facts leaves its slot out, and a row none of whose boots did has an empty column and no ABI:
# the keys are always there, so a reader tells "not measured" from a row the report lost.
run_matrix STUB_LSM=lockdown,yama STUB_FIX=lockdown,yama,bpf STUB_FACTS="landlock_abi=7 cgroup_mode=fanotify"
[ "$(jq -c '."row-a".cgroup_mode' "$sj")" = '{"boot1":"fanotify"}' ] || fail "a boot with no facts left $(jq -c '."row-a".cgroup_mode' "$sj"), want only boot1's"
run_matrix
[ "$(jq -c '."row-a".cgroup_mode' "$sj")" = '{}' ] && [ "$(jq -c '."row-a".landlock_abi' "$sj")" = null ] ||
	fail "a row with no facts has cgroup_mode $(jq -c '."row-a".cgroup_mode' "$sj") and landlock_abi $(jq -c '."row-a".landlock_abi' "$sj"), want {} and null"
# A doctor-only row prints the facts of its refusal: ABI 1 and no plane.
MROWS=(row-d)
run_matrix STUB_ROWS="$rows2" STUB_FACTS="landlock_abi=1 cgroup_mode=none"
[ "$(jq -c '."row-d".cgroup_mode' "$sj")" = '{"boot1":"none"}' ] && [ "$(jq -c '."row-d".landlock_abi' "$sj")" = 1 ] ||
	fail "a doctor-only row's facts are $(jq -c '."row-d" | [.landlock_abi, .cgroup_mode]' "$sj")"
MROWS=(row-a)

# 11. Every repository file the kill tests read through kt_repo_root (test/e2e/*.sh, as they are in this checkout) is
# in the guest's /src: the guest has no checkout, and a file left out is a kill test that meets a machine it was not
# written for. kt_config's price table is the case that failed (2026-10-24): it lies outside the
# directories the stage copies whole, so every kill test's config named none, and kill test 7 (b)'s contract, which
# declares cost_usd, was refused [budget-unmetered] on every row.
mapfile -t ktfiles < <(grep -o -h 'kt_repo_root)/[A-Za-z0-9_./-]*' "$here/../e2e/"*.sh | sed 's|^kt_repo_root)/||' | sort -u)
[ "${#ktfiles[@]}" -gt 0 ] || fail "found no kt_repo_root path in test/e2e/*.sh: this case reads them from there"
for f in "${ktfiles[@]}"; do
	[ -e "$repo/$f" ] || { mkdir -p "$repo/$(dirname "$f")" && : >"$repo/$f"; }
done
run_matrix
for f in "${ktfiles[@]}"; do
	[ -e "$tmp/out/matrix/stage/src/$f" ] || fail "the guest's /src lacks $f, which test/e2e reads through kt_repo_root"
done

echo "ok matrix_test.sh"
