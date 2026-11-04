#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# root-suites.sh — `make vm-root-test`: build the privileged packages' integration test binaries
# (static, `go test -c -tags integration[,tegobpf]`) and run each one as root, with -test.v, in its
# own KVM guest booted by test/vm/kvm-run.sh; then `tego doctor` from a binary with the objects
# embedded. It exists because those suites are the ones this repo's own `make integration` can only
# skip on a box without root: every requireRoot/Geteuid gate in them passes in the guest, and the
# guest boots with `bpf` in lsm=, so tier 3's probes see a BPF LSM kernel as well.
#
# A skip is not a pass. The report counts, per suite, the top-level tests that ran (passed or failed)
# against the ones that skipped, with each skip's own reason, and the script fails when any suite
# failed, did not build, or ran nothing at all; when a test skipped that test/vm/root-skips.txt does not
# allow; and, on a run of every package with no VM_RUN, when a test test/vm/root-must-pass.txt names did
# not pass. Each suite's go test -json stream is kept beside its console log (VM_OUT/logs/<suite>.json).
#
# Usage: test/vm/root-suites.sh [package-substring...]   (default: every package below)
#        test/vm/root-suites.sh --gather DIR              (after the VM_SHARD runs: below)
# Environment: GO (go), VM_OUT (bin/vm: binaries, logs, summary.json), VM_BPF (auto|yes|no: whether
#   to build the tegobpf variants; auto builds them when internal/bpf compiles with the tag, i.e.
#   after `make gen`), VM_RUN (a -test.run pattern for every suite), VM_SUITE_TIMEOUT (seconds per
#   guest; a "pkg=seconds" word sets one package's; default "1500 internal/runtime/enforce/cgroup=6000": that
#   package's tegobpf suite took 2517-3765 s of a guest on a loaded host on 2026-10-17, far past 1500's own 1200 s;
#   the suite's own go test -timeout is that less 300), VM_HOST (kvm, the default, or sudo: see below), VM_BOOTS (empty, or both: every
#   suite on the lsm=...,bpf boot and again on the host's list without bpf, below; lsm-bpf or default-lsm: that boot alone), VM_CGROUP (empty, or
#   service: see below), VM_MODULES (kernel modules each guest loads before its suite, space-separated,
#   passed to kvm-run.sh --module; default test/vm/suites.sh's GUEST_MODULES, "overlay btrfs unix_diag tcp_diag",
#   which scripts/coverage.sh --vm's guests load too and which says what needs each; VM_MODULES="" loads none),
#   VM_SUITE_MEM (per-package guest memory, "pkg=size ...", over
#   TEGO_VM_MEM; e.g. "internal/runtime/enforce/cgroup=2560M" for its 32 concurrent runs), plus kvm-run.sh's
#   TEGO_VM_* knobs.
#   VM_FIXTURE_ROOT optionally stages a directory's contents at the guest root,
#   for extra tools and their libraries a manual run wants in the guest.
#   TEGO_VM_ROW=<row> boots a kernel-matrix row (fetch-kernel.py --list; `host` is this box's own kernel) instead of the
#   host's kernel, sets TEGO_VM_KERNEL to it, and tells each suite's guest the row by name: test/conformance's baseline
#   reads it as `where.row`, and enforce/landlock's integration tests hold fedora-7.2 to Landlock ABI 10 with it.
#
# VM_HOST=sudo runs every suite, and `tego doctor`, on this host instead: as root through sudo (or
# directly when this shell is root already), from the package's own directory in this checkout, with
# go-shim.sh first on PATH as `go` and sudo's secure_path after it. Its doctor is the product build only
# where TEGO_DISPOSABLE_HOST is set (below); elsewhere the tegotesthooks build with an isolation of the
# run's own (identity-config.md R27). It is CI's root-suites job
# (.github/workflows/ci.yml): a hosted runner has passwordless sudo and no /dev/kvm to rely on, and
# without it the privileged suites would run per push nowhere. Each suite's -test.v output is
# printed as it runs and kept in VM_OUT/logs. A test that changes host-wide state it cannot isolate
# (TestRootLauncherRefusesGroupHostState: /run/tego and /etc/group) runs only where TEGO_DISPOSABLE_HOST
# is set: every KVM guest, and under VM_HOST=sudo a GitHub Actions runner or a caller that sets it
# itself for a throwaway machine. On a developer's own machine it skips, and the skip gate below fails the
# run for it, so a sudo run there is not mistaken for a full one.
#
# VM_SHARD=<name> runs one shard of test/vm/suites.sh's ROOT_SHARDS, as CI's root-suites-shard matrix does: its
# packages, and with a part "j/n" only part j of each of their suites' top-level tests (below), the must-pass gate
# left to `test/vm/root-suites.sh --gather DIR`, which holds every shard's VM_OUT under DIR to have finished and
# passed and runs that gate over all their logs (CI's root-suites job; test/vm/README.md "CI's shards").
#
# VM_CGROUP=service starts each guest's suite from /system.slice/tego-ci.service with another process
# beside it, where a CI runner's `sudo` from a job step starts it, instead of from a copy of this shell's
# cgroup chain. With TEGO_VM_LSM=kernel and TEGO_VM_LOCKDOWN=none it is the nearest this harness comes to
# the root-suites job on a hosted runner, which is how the job's must-pass list was checked before it ran
# there (test/vm/README.md).
#
# In the guest, each suite runs the way bpf/README.md and the tests' own comments say to run them,
# `sudo go test ...` from this shell: kvm-run.sh --sudo sets SUDO_UID/SUDO_GID/SUDO_USER to the
# invoking user (a root `tego run` drops the agent to that uid, and refuses without it) and places the
# test in a copy of this shell's cgroup chain. Its working directory is its own package directory in a
# copy of this tree's files (/src/<package>), as `go test` would give it, and /usr/local/bin/go is
# test/vm/go-shim.sh serving the helpers some tests `go build` at run time from /vm/prebuilt. A tagged
# suite runs with GOFLAGS=-tags=integration,tegobpf so those helpers are the tagged ones too.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/vm/fwd-run.sh
. "$here/fwd-run.sh"
# shellcheck source=test/vm/conformance-require.sh
. "$here/conformance-require.sh"
repo="$(cd "$here/../.." && pwd)"

# ---- the shards (VM_SHARD, --gather) -------------------------------------------------------------
# shard_plan checks test/vm/suites.sh's ROOT_SHARDS (sourced by the caller) against PKGS: every name once, every
# package named a package of PKGS, no package in two shards unless they are its parts, every part 1..n of a split
# set of packages present once, at most one "*" shard, and every package of PKGS in some shard. It prints each
# problem and returns 1 when there is one.
shard_plan() {
	local bad=0 e name pkgs part p q j n stars=0
	declare -A seen_name=() owner=() parts=() nparts=()
	for e in "${ROOT_SHARDS[@]}"; do
		IFS='|' read -r name pkgs part <<<"$e"
		case "$name" in "" | *[!a-z0-9-]*) echo "root-suites: ROOT_SHARDS entry '$e': a name is lower-case letters, digits and -" >&2; bad=1; continue ;; esac
		[ -z "${seen_name[$name]:-}" ] || { echo "root-suites: ROOT_SHARDS names shard $name twice" >&2; bad=1; }
		seen_name[$name]=1
		if [ "$pkgs" = "*" ]; then
			stars=$((stars + 1))
			[ -z "$part" ] || { echo "root-suites: ROOT_SHARDS shard $name: the \"*\" shard runs whole suites, not a part" >&2; bad=1; }
			continue
		fi
		[ -n "$pkgs" ] || { echo "root-suites: ROOT_SHARDS shard $name names no package" >&2; bad=1; continue; }
		if [ -n "$part" ]; then
			j="${part%%/*}" n="${part#*/}"
			case "$j/$n" in [1-9]/[1-9] | [1-9]/[1-9][0-9] | [1-9][0-9]/[1-9][0-9]) ;; *) echo "root-suites: ROOT_SHARDS shard $name: part '$part' is not j/n" >&2; bad=1; continue ;; esac
			[ "$j" -le "$n" ] && [ "$n" -ge 2 ] || { echo "root-suites: ROOT_SHARDS shard $name: part $part is not one of 2 or more" >&2; bad=1; continue; }
			[ -z "${parts[$pkgs/$j]:-}" ] || { echo "root-suites: ROOT_SHARDS has part $j of '$pkgs' twice" >&2; bad=1; }
			parts[$pkgs/$j]=$n
			if [ -z "${nparts[$pkgs]:-}" ]; then nparts[$pkgs]=$n; elif [ "${nparts[$pkgs]}" != "$n" ]; then
				echo "root-suites: ROOT_SHARDS splits '$pkgs' into ${nparts[$pkgs]} parts and into $n" >&2
				bad=1
			fi
		fi
		for p in $pkgs; do
			q=""
			for q in "${PKGS[@]}"; do [ "$q" != "$p" ] || break; done
			[ "$q" = "$p" ] || { echo "root-suites: ROOT_SHARDS shard $name names $p, which is not in PKGS" >&2; bad=1; continue; }
			if [ -n "${owner[$p]:-}" ] && { [ -z "$part" ] || [ "${owner[$p]}" != "parts of $pkgs" ]; }; then
				echo "root-suites: ROOT_SHARDS runs $p in shard $name and in ${owner[$p]}" >&2
				bad=1
			fi
			if [ -n "$part" ]; then owner[$p]="parts of $pkgs"; else owner[$p]="shard $name"; fi
		done
	done
	for e in "${!nparts[@]}"; do
		for ((j = 1; j <= ${nparts[$e]}; j++)); do
			[ -n "${parts[$e/$j]:-}" ] || { echo "root-suites: ROOT_SHARDS splits '$e' into ${nparts[$e]} parts and has no part $j" >&2; bad=1; }
		done
	done
	[ "$stars" -le 1 ] || { echo "root-suites: ROOT_SHARDS has $stars \"*\" shards" >&2; bad=1; }
	if [ "$stars" = 0 ]; then
		for p in "${PKGS[@]}"; do
			[ -n "${owner[$p]:-}" ] || { echo "root-suites: no shard of ROOT_SHARDS runs $p" >&2; bad=1; }
		done
	fi
	return "$bad"
}

# --gather DIR: the last step of CI's root-suites job, after its shards. DIR holds each shard's VM_OUT (its logs/,
# summary.json and shard.done), one directory each, in any layout. Every shard of ROOT_SHARDS must have finished and
# passed, none twice and no other, and then root-must-pass.txt is checked over the go test -json logs of all of them
# together: a root-only test must have passed in some shard's build and failed in none, as one whole run checks it.
if [ "${1:-}" = --gather ]; then
	[ $# = 2 ] && [ -d "$2" ] || { echo "usage: test/vm/root-suites.sh --gather DIR (the shards' VM_OUT directories)" >&2; exit 2; }
	gdir="$(cd "$2" && pwd)"
	# shellcheck source=test/vm/suites.sh
	. "$here/suites.sh"
	shard_plan || exit 2
	status=0
	declare -A done_by=()
	while IFS= read -r -d '' f; do
		read -r gname gstatus <"$f" || true
		[ -z "${done_by[$gname]:-}" ] || { echo "root-suites: shard $gname finished twice: ${done_by[$gname]} and $f" >&2; status=1; }
		done_by[$gname]="$f"
		known=0
		for e in "${ROOT_SHARDS[@]}"; do [ "${e%%|*}" != "$gname" ] || known=1; done
		[ "$known" = 1 ] || { echo "root-suites: $f names shard '$gname', which ROOT_SHARDS does not" >&2; status=1; }
	done < <(find "$gdir" -name shard.done -type f -print0)
	echo "== shards (test/vm/suites.sh ROOT_SHARDS)"
	for e in "${ROOT_SHARDS[@]}"; do
		gname="${e%%|*}"
		if [ -z "${done_by[$gname]:-}" ]; then
			echo "FAIL $gname: no shard.done (the shard did not run, did not finish or uploaded no logs)"
			status=1
			continue
		fi
		read -r _ gstatus <"${done_by[$gname]}" || true
		if [ "$gstatus" = 0 ]; then echo "ok   $gname"; else echo "FAIL $gname: exit ${gstatus:-none}"; status=1; fi
	done
	jsons=()
	for f in "${done_by[@]}"; do
		for j in "$(dirname "$f")"/logs/*.json; do [ ! -s "$j" ] || jsons+=("$j"); done
	done
	echo
	if [ "${#jsons[@]}" = 0 ]; then
		echo "root-suites: the shards left no go test -json log" >&2
		exit 1
	fi
	"$repo/scripts/skipgate.sh" --must-pass "$here/root-must-pass.txt" "${jsons[@]}" >"$gdir/skipgate-must-pass.log" 2>&1 || status=1
	if grep -q '^== must pass' "$gdir/skipgate-must-pass.log"; then sed -n '/^== must pass/,$p' "$gdir/skipgate-must-pass.log"; else cat "$gdir/skipgate-must-pass.log"; fi
	echo
	echo "== root-suites: ${#ROOT_SHARDS[@]} shards, ${#jsons[@]} suites' logs: $([ "$status" = 0 ] && echo pass || echo FAIL)"
	exit "$status"
fi
GO="${GO:-go}"
OUT="${VM_OUT:-$repo/bin/vm}"
case "$OUT" in /*) ;; *) OUT="$repo/$OUT" ;; esac
BPF="${VM_BPF:-auto}"
SUITE_TIMEOUT_SPEC="${VM_SUITE_TIMEOUT:-1500 internal/runtime/enforce/cgroup=6000}"
HOSTMODE="${VM_HOST:-kvm}"
# DISPOSABLE is the TEGO_DISPOSABLE_HOST a VM_HOST=sudo suite gets (a guest always gets "kvm"): the caller's own, or
# github-actions on a GitHub Actions runner, whose sudo drops GITHUB_ACTIONS from the tests' environment.
DISPOSABLE="${TEGO_DISPOSABLE_HOST:-}"
[ -n "$DISPOSABLE" ] || [ "${GITHUB_ACTIONS:-}" != true ] || DISPOSABLE=github-actions
CGROUP="${VM_CGROUP:-}"
case "$HOSTMODE" in kvm | sudo) ;; *) echo "root-suites: VM_HOST must be kvm or sudo, not $HOSTMODE" >&2; exit 2 ;; esac
case "$CGROUP" in "" | service) ;; *) echo "root-suites: VM_CGROUP must be empty or service, not $CGROUP" >&2; exit 2 ;; esac

# TEGO_VM_ROW names the kernel-matrix row (test/vm/fetch-kernel.py --list, or host) every guest boots. Its kernel is
# fetched, unless TEGO_VM_KERNEL already names it (the nightly fetches its own), and TEGO_VM_KERNEL is set to it. The row's
# name reaches each suite's guest as TEGO_VM_ROW, which test/conformance reads as a baseline entry's `where.row` and
# enforce/landlock's integration tests read to hold the row to its Landlock ABI (fedora-7.2: 10). A name that is not a
# row, a doctor-only row (no tier is offered there, so no suite has anything to run: matrix.sh runs its refusal check), a run on
# this host instead of a guest, and a kernel set by hand for another row are usage errors before anything is built:
# suites that ran on one kernel under another's name would be judged by the wrong row's expectations.
ROW="${TEGO_VM_ROW:-}"
if [ -n "$ROW" ]; then
	[ "$HOSTMODE" = kvm ] || { echo "root-suites: TEGO_VM_ROW=$ROW needs VM_HOST=kvm: a row is a guest's kernel" >&2; exit 2; }
	if [ "$ROW" = host ]; then
		row_kernel="$(uname -r)"
	else
		row_kernel="$(python3 "$here/fetch-kernel.py" --name "$ROW" 2>/dev/null)" ||
			{ echo "root-suites: TEGO_VM_ROW=$ROW is not a kernel-matrix row (python3 $here/fetch-kernel.py --list)" >&2; exit 2; }
		if [ "$(python3 "$here/fetch-kernel.py" --body "$ROW")" = doctor-only ]; then
			echo "root-suites: TEGO_VM_ROW=$ROW is a doctor-only row: no tier is offered there, so no suite has anything to run (test/vm/matrix.sh runs its refusal check)" >&2
			exit 2
		fi
	fi
	if [ -n "${TEGO_VM_KERNEL:-}" ] && [ "$TEGO_VM_KERNEL" != "$row_kernel" ]; then
		echo "root-suites: TEGO_VM_ROW=$ROW boots $row_kernel, but TEGO_VM_KERNEL=$TEGO_VM_KERNEL says another kernel" >&2
		exit 2
	fi
	if [ "$ROW" != host ] && [ -z "${TEGO_VM_KERNEL:-}" ]; then
		python3 "$here/fetch-kernel.py" "$ROW" >/dev/null || exit $?
	fi
	export TEGO_VM_KERNEL="$row_kernel"
	# kvm-run.sh fetches a module package with apt, and only for the kernel this host runs (linux-modules-<version>): a
	# row's distro kernel has none to fetch, and the default modules (overlay, btrfs) would end every guest with exit 97
	# before its suite ran. A row's guests load none unless VM_MODULES names some; the tests that want overlayfs or btrfs
	# then meet the row kernel's own, and test/vm/root-skips.txt says which of them may skip there.
	if [ "$ROW" != host ] && [ -z "${VM_MODULES+x}" ]; then
		export VM_MODULES=""
	fi
fi

# VM_BOOTS=both runs the whole invocation twice, once per boot tier 3 needs (TIER3-PLAN §9, T11): "lsm-bpf", the
# default boot (the host's lsm= list plus bpf: the decision plane's LSM mode, tier bpflsm), and "default-lsm", the
# host's own list without bpf (the plane's fmod_ret mode; tier bpflsm refused with the GRUB line). Each boot's
# results go under VM_OUT/<boot>, and the run fails when either boot does. VM_BOOTS=lsm-bpf or default-lsm runs that
# boot alone, the same way: a CI job whose bound holds one boot's suites runs each boot in a job of its own
# (vm-matrix's tier-3 parts). Guests only: VM_HOST=sudo cannot reboot.
case "${VM_BOOTS:-}" in
"") ;;
both | lsm-bpf | default-lsm)
	[ "$HOSTMODE" = kvm ] || { echo "root-suites: VM_BOOTS=$VM_BOOTS needs VM_HOST=kvm" >&2; exit 2; }
	host_lsm="$(cat /sys/kernel/security/lsm 2>/dev/null)"
	[ -n "$host_lsm" ] || { echo "root-suites: VM_BOOTS=$VM_BOOTS reads the host's lsm list, and /sys/kernel/security/lsm is empty" >&2; exit 2; }
	no_bpf="$(tr ',' '\n' <<<"$host_lsm" | grep -vx bpf | paste -sd, -)"
	boots="lsm-bpf default-lsm"
	[ "$VM_BOOTS" = both ] || boots="$VM_BOOTS"
	overall=0
	for boot in $boots; do
		lsm="$no_bpf,bpf"
		[ "$boot" = lsm-bpf ] || lsm="$no_bpf"
		echo "== root-suites: boot $boot (lsm=$lsm)"
		VM_BOOTS="" VM_OUT="$OUT/$boot" TEGO_VM_LSM="$lsm" "$here/root-suites.sh" "$@" || overall=1
	done
	echo "== root-suites: ${boots// / and }: $([ "$overall" = 0 ] && echo pass || echo FAIL) (per boot under $OUT/<boot>)"
	exit "$overall"
	;;
*) echo "root-suites: VM_BOOTS must be empty, both, lsm-bpf or default-lsm, not $VM_BOOTS" >&2; exit 2 ;;
esac
module="$(cd "$repo" && "$GO" list -m)"

# PKGS, HELPERS and GUEST_MODULES: shared with scripts/coverage.sh --vm.
# shellcheck source=test/vm/suites.sh
. "$here/suites.sh"

if [ $# -gt 0 ]; then
	selected=()
	for p in "${PKGS[@]}"; do
		for f in "$@"; do
			case "$p" in *"$f"*) selected+=("$p"); break ;; esac
		done
	done
	PKGS=("${selected[@]+"${selected[@]}"}")
	[ "${#PKGS[@]}" -gt 0 ] || { echo "root-suites: no package matches $*" >&2; exit 2; }
fi

# VM_SHARD=<name>: one shard of ROOT_SHARDS (test/vm/suites.sh), CI's root-suites-shard matrix: that shard's packages,
# and of each of their suites the part it names (PART, "j/n", below). The must-pass gate is --gather's, over every
# shard; this run writes VM_OUT/shard.done ("<name> <status>") at its end for it.
SHARD="${VM_SHARD:-}"
PART=""
if [ -n "$SHARD" ]; then
	[ $# -eq 0 ] || { echo "root-suites: VM_SHARD=$SHARD selects its own packages; name none" >&2; exit 2; }
	[ -z "${VM_RUN:-}" ] || { echo "root-suites: VM_SHARD=$SHARD runs its own part of each suite; VM_RUN would narrow it again" >&2; exit 2; }
	shard_plan || exit 2
	entry=""
	for e in "${ROOT_SHARDS[@]}"; do [ "${e%%|*}" != "$SHARD" ] || entry="$e"; done
	[ -n "$entry" ] || { echo "root-suites: VM_SHARD=$SHARD is not a shard of test/vm/suites.sh's ROOT_SHARDS" >&2; exit 2; }
	IFS='|' read -r _ shard_pkgs PART <<<"$entry"
	if [ "$shard_pkgs" = "*" ]; then
		declare -A named=()
		for e in "${ROOT_SHARDS[@]}"; do
			IFS='|' read -r _ q _ <<<"$e"
			[ "$q" = "*" ] || for p in $q; do named[$p]=1; done
		done
		selected=()
		for p in "${PKGS[@]}"; do [ -n "${named[$p]:-}" ] || selected+=("$p"); done
	else
		read -r -a selected <<<"$shard_pkgs"
	fi
	PKGS=("${selected[@]+"${selected[@]}"}")
	[ "${#PKGS[@]}" -gt 0 ] || { echo "root-suites: VM_SHARD=$SHARD has no package to run" >&2; exit 2; }
	echo "root-suites: shard $SHARD: ${PKGS[*]}${PART:+, part $PART of each suite}"
fi

mkdir -p "$OUT/bin" "$OUT/prebuilt" "$OUT/logs"
rm -f "$OUT/shard.done"
results="$OUT/results.tsv"
: >"$results"
cd "$repo" || exit 1
export CGO_ENABLED=0

# ---- the tegobpf variants ---------------------------------------------------------------------

bpf_state="off"
bpf_note=""
if [ "$BPF" != no ]; then
	if ! ls internal/bpf/*_bpfel.o >/dev/null 2>&1; then
		bpf_note="no generated BPF objects in internal/bpf (run: make gen)"
	elif ! "$GO" build -tags tegobpf ./internal/bpf/ >"$OUT/logs/build-internal_bpf-tegobpf.log" 2>&1; then
		bpf_note="internal/bpf does not build with -tags tegobpf (see $OUT/logs/build-internal_bpf-tegobpf.log)"
	else
		bpf_state="on"
	fi
	if [ "$bpf_state" = off ]; then
		echo "root-suites: tegobpf suites not built: $bpf_note" >&2
		[ "$BPF" != yes ] || { echo "root-suites: VM_BPF=yes but the tagged build is impossible" >&2; exit 1; }
	fi
fi
# The conformance axes this boot must run (TEGO_CONFORMANCE_REQUIRE): cgroup and fmod_ret on every boot, lsm and
# bpflsm too on a boot with bpf among its LSMs (conformance-require.sh). Amended 2026-10-05: a fixed cgroup,fmod_ret
# let the lsm and bpflsm axes drop on the lsm-bpf boot with nothing failing.
conformance_required="$(conformance_require "$HOSTMODE" "$bpf_state" "${TEGO_VM_LSM:-}" "$(cat /sys/kernel/security/lsm 2>/dev/null)")"
echo "root-suites: TEGO_CONFORMANCE_REQUIRE=$conformance_required"
# The conformance runner's budget, report and spaces (test/conformance/report.go, gen.go) and the matrix row a baseline entry and a
# report row name, passed through when set: sudo's environment and a guest's start empty. A guest's console is the
# only way out of it, so a guest run reports with TEGO_CONFORMANCE_REPORT=-, each row a CONFORMANCE-ROW line.
conformance_env=() conformance_env_args=()
for v in TEGO_CONFORMANCE_BUDGET TEGO_CONFORMANCE_REPORT TEGO_CONFORMANCE_SPACES TEGO_VM_ROW; do
	[ -z "${!v:-}" ] || { conformance_env+=("$v=${!v}"); conformance_env_args+=(--env "$v=${!v}"); }
done
# The filesystems the conformance runner's mount fixtures must mount (ADR 0017 space 5, TEGO_CONFORMANCE_FS_REQUIRE):
# those of overlay and btrfs this run loads (VM_MODULES, below), so a guest that loads them fails a fixture whose mount
# fails, and a row whose guests load none runs the fixtures its kernel has built in and logs the others MOUNTS-ABSENT.
fs_required=""
for m in ${VM_MODULES-${GUEST_MODULES[*]}}; do
	case "$m" in overlay | btrfs) fs_required="${fs_required:+$fs_required }$m" ;; esac
done
if [ -n "$fs_required" ]; then
	conformance_env+=("TEGO_CONFORMANCE_FS_REQUIRE=$fs_required")
	conformance_env_args+=(--env "TEGO_CONFORMANCE_FS_REQUIRE=$fs_required")
fi
echo "root-suites: TEGO_CONFORMANCE_FS_REQUIRE=$fs_required"

# ---- build --------------------------------------------------------------------------------------

echo "== building into $OUT"
rm -rf "$OUT/src" "$OUT/shim"
if [ "$HOSTMODE" = kvm ]; then
	mkdir -p "$OUT/src"
	# The tree's own files (tracked plus untracked-not-ignored) as the suites' working directories.
	# A copy that failed part way would run the suites against a tree missing files, so any stage failing
	# (pipefail) ends the run here.
	"$repo/scripts/tree-files.sh" | tar --null -T - -cf - | tar -xf - -C "$OUT/src" ||
		{ echo "root-suites: copying the tree into $OUT/src failed" >&2; exit 1; }
else
	# On this host the suites run in the checkout itself; the shim is the guest's /usr/local/bin/go.
	mkdir -p "$OUT/shim"
	cp "$here/go-shim.sh" "$OUT/shim/go"
	chmod 0755 "$OUT/shim/go"
fi

# Each helper in every variant go-shim.sh serves: plain, .testhooks, and with the objects .tegobpf and
# .tegobpf.testhooks.
for h in "${HELPERS[@]}"; do
	name="${h##*/}"
	variants=("|" "tegotesthooks|.testhooks")
	[ "$bpf_state" != on ] || variants+=("tegobpf|.tegobpf" "tegobpf,tegotesthooks|.tegobpf.testhooks")
	for v in "${variants[@]}"; do
		tags="${v%%|*}"
		"$GO" build -tags "$tags" -o "$OUT/prebuilt/$name${v#*|}" "./$h" ||
			{ echo "root-suites: building helper $h -tags '$tags' failed" >&2; exit 1; }
	done
done

suites=() # suite|pkg|tags|binary
declare -A bpfpkg=() # the packages whose tests load the objects, so whose plain build skips those tests
for p in "${PKGS[@]}"; do
	base="${p//\//_}"
	variants=("integration")
	# grep reads the whole list (no -q): quitting at the first match can end go list with SIGPIPE, which
	# pipefail turns into "no match", and the package's tegobpf suite is then silently not built.
	if "$GO" list -tags integration -test -deps "./$p" 2>/dev/null | grep -x "$module/internal/bpf" >/dev/null; then
		bpfpkg["$p"]=1
		if [ "$bpf_state" = on ]; then
			variants+=("integration,tegobpf")
		elif [ "$BPF" != no ]; then
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$base.tegobpf" "$p" "integration,tegobpf" "not-run" "-" "$bpf_note" >>"$results"
		fi
	fi
	for tags in "${variants[@]}"; do
		suite="$base"
		[ "$tags" = integration ] || suite="$base.tegobpf"
		bin="$OUT/bin/$suite.test"
		echo "   go test -c -tags $tags ./$p"
		if "$GO" test -c -tags "$tags" -o "$bin" "./$p" >"$OUT/logs/build-$suite.log" 2>&1; then
			suites+=("$suite|$p|$tags|$bin")
			# Every top-level test this build holds, read from its sources (nothing is run), so the
			# report can name the tests a crash or a timeout never let run.
			(cd "$p" && "$GO" list -tags "$tags" -f '{{range .TestGoFiles}}{{.}} {{end}}{{range .XTestGoFiles}}{{.}} {{end}}' . |
				xargs sed -n 's/^func \(Test[A-Z0-9_][A-Za-z0-9_]*\)(\([a-z]*\) \*testing\.T) {$/\1/p') \
				>"$OUT/logs/$suite.list" 2>/dev/null
		else
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$suite" "$p" "$tags" "build-failed" "-" "$OUT/logs/build-$suite.log" >>"$results"
			cat "$OUT/logs/build-$suite.log" >&2
		fi
	done
done

# ---- run ----------------------------------------------------------------------------------------

run_args=()
[ -z "${VM_RUN:-}" ] || run_args+=("-test.run=$VM_RUN")
module_args=()
# test/vm/suites.sh's GUEST_MODULES by default, which says what needs each (overlay; btrfs, amended 2026-10-05;
# unix_diag, 2026-10-16; tcp_diag, 2026-10-27); scripts/coverage.sh --vm's guests load the same. VM_MODULES="" loads
# nothing.
for m in ${VM_MODULES-${GUEST_MODULES[*]}}; do module_args+=(--module "$m"); done
fixture_args=()
if [ -n "${VM_FIXTURE_ROOT:-}" ]; then
	[ -d "$VM_FIXTURE_ROOT" ] || { echo "root-suites.sh: VM_FIXTURE_ROOT is not a directory: $VM_FIXTURE_ROOT" >&2; exit 2; }
	fixture_args=(--file "$VM_FIXTURE_ROOT/.:/")
fi

# vm_code turns kvm-run.sh's exit code into the status column: the command's own code when the guest
# ran it, else vm-<reason> (timeout, no-report, env, usage), because 2, 124 and 125 are codes both
# kvm-run.sh and the programs under test use.
vm_code() {
	local st
	st="$(cat "$2" 2>/dev/null)"
	case "$st" in
	"guest $1") echo "$1" ;;
	"") echo "vm-no-status" ;;
	*) echo "vm-${st%% *}" ;;
	esac
}

# as_root is how VM_HOST=sudo runs a command as root: through sudo, whose secure_path and reset
# environment it then gets, or as it is when this shell is root. SUDO_UID and the rest are sudo's own.
as_root=()
[ "$HOSTMODE" = kvm ] || [ "$(id -u)" = 0 ] || as_root=(sudo)
host_path="$OUT/shim:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# service_cgroup is the VM_CGROUP=service wrapper: the guest's command moves itself into a service's cgroup
# and leaves a second process there, as a runner's job step shares its service with the runner, and then
# execs the suite. The second process is started from a subshell that ends at once, so init adopts it: it
# stays in the cgroup beside the suite and is no child of it, which a plain `sleep &` before the exec would
# have made it (the shell becomes the suite). A runner's suite has no such child, and tests that count their
# own children (internal/runtime's TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck and
# TestIntegrationFailedArmFailsTheRunBeforeTheAgent, ADR 0021 (2)) failed on it.
service_cgroup=()
# shellcheck disable=SC2016 # the script is the guest's, and the guest's sh expands it
[ "$CGROUP" != service ] || service_cgroup=(/bin/sh -c '
	umask 022
	d=/sys/fs/cgroup/system.slice/tego-ci.service
	mkdir -p "$d" && echo $$ >"$d/cgroup.procs" || exit 125
	(sleep 2147483647 &)
	exec "$@"' root-suites-service)

for s in "${suites[@]+"${suites[@]}"}"; do
	IFS='|' read -r suite pkg tags bin <<<"$s"
	# The default is the bare number; a "pkg=seconds" word overrides it for that package. The suite's own
	# -test.timeout ends it 300s before the guest's (or timeout's) bound does, so its panic names the running tests.
	SUITE_TIMEOUT=1500
	for w in $SUITE_TIMEOUT_SPEC; do
		case "$w" in *=*) [ "${w%%=*}" != "$pkg" ] || SUITE_TIMEOUT="${w#*=}" ;; *) SUITE_TIMEOUT="$w" ;; esac
	done
	go_timeout="$((SUITE_TIMEOUT - 300))s"
	# A part j/n of the suite: the top-level tests at positions j, j+n, j+2n... of its .list (read from its sources),
	# by -test.run; part n skips every other part's tests instead (-test.skip), so it also runs whatever the list does
	# not hold (fuzz targets, examples, a test the list's sed missed), and the n parts together run every test once.
	# The .list is then this part's tests, for summarize.py's "never started".
	part_args=()
	if [ -n "$PART" ]; then
		pj="${PART%%/*}" pn="${PART#*/}" mine=() others=() i=0
		while IFS= read -r t; do
			[ -n "$t" ] || continue
			if [ $((i % pn + 1)) = "$pj" ]; then mine+=("$t"); else others+=("$t"); fi
			i=$((i + 1))
		done <"$OUT/logs/$suite.list"
		if [ "$pj" != "$pn" ]; then
			part_args=("-test.run=^($(IFS='|'; echo "${mine[*]}"))\$")
		elif [ "${#others[@]}" -gt 0 ]; then
			part_args=("-test.skip=^($(IFS='|'; echo "${others[*]}"))\$")
		fi
		printf '%s\n' "${mine[@]+"${mine[@]}"}" >"$OUT/logs/$suite.list"
		echo "   part $PART of $suite: ${#mine[@]} of the $i tests its sources list$([ "$pj" != "$pn" ] || echo ', and any they do not')"
	fi
	echo
	if [ "$HOSTMODE" = sudo ]; then
		echo "== $suite (go test -tags $tags ./$pkg, as root on this host)"
		env_args=("PATH=$host_path" "TEGO_VM_PREBUILT=$OUT/prebuilt" "TEGO_CONFORMANCE_REQUIRE=$conformance_required" "${conformance_env[@]+"${conformance_env[@]}"}")
		[ -z "$DISPOSABLE" ] || env_args+=("TEGO_DISPOSABLE_HOST=$DISPOSABLE")
		[ "$tags" = integration ] || env_args+=("GOFLAGS=-tags=$tags")
		(cd "$repo/$pkg" && "${as_root[@]+"${as_root[@]}"}" env "${env_args[@]}" \
			"$here/bounded-run.sh" "$SUITE_TIMEOUT" "$bin" -test.v -test.timeout=$go_timeout "${run_args[@]+"${run_args[@]}"}" "${part_args[@]+"${part_args[@]}"}") 2>&1 |
			tee "$OUT/logs/$suite.console"
		code="${PIPESTATUS[0]}"
	else
		echo "== $suite (go test -tags $tags ./$pkg, as root in a KVM guest)"
		env_args=(--env "TEGO_CONFORMANCE_REQUIRE=$conformance_required" "${conformance_env_args[@]+"${conformance_env_args[@]}"}" --env "TEGO_DISPOSABLE_HOST=kvm")
		[ "$tags" = integration ] || env_args+=(--env "GOFLAGS=-tags=$tags")
		# VM_SUITE_MEM gives one package's guests their own TEGO_VM_MEM ("pkg=size ..."), where the rest share a
		# smaller one: enforce/cgroup's 32 concurrent runs of TestTier2ConcurrentRunsOfOneBuild need about 2.5G, and in
		# a 1536M guest the OOM killer ends some of them (TIER3-PLAN T11).
		suite_mem="${TEGO_VM_MEM:-}"
		for m in ${VM_SUITE_MEM:-}; do [ "${m%%=*}" != "$pkg" ] || suite_mem="${m#*=}"; done
		TEGO_VM_MEM="$suite_mem" fwd_run "$here/kvm-run.sh" --sudo --timeout "$SUITE_TIMEOUT" --log "$OUT/logs/$suite.console" --status "$OUT/logs/$suite.status" \
			"${module_args[@]+"${module_args[@]}"}" --file "$bin:/vm/$(basename "$bin")" --file "$OUT/src:/src" --file "$OUT/prebuilt:/vm/prebuilt" \
			--file "$here/go-shim.sh:/usr/local/bin/go" --cwd "/src/$pkg" "${env_args[@]+"${env_args[@]}"}" \
			"${fixture_args[@]+"${fixture_args[@]}"}" \
			-- "${service_cgroup[@]+"${service_cgroup[@]}"}" "/vm/$(basename "$bin")" -test.v -test.timeout=$go_timeout "${run_args[@]+"${run_args[@]}"}" "${part_args[@]+"${part_args[@]}"}"
		code="$(vm_code $? "$OUT/logs/$suite.status")"
	fi
	tr -d '\r' <"$OUT/logs/$suite.console" | "$GO" tool test2json -p "$module/$pkg" >"$OUT/logs/$suite.json" 2>/dev/null
	printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$suite" "$pkg" "$tags" "$code" "$OUT/logs/$suite.json" "$OUT/logs/$suite.console" >>"$results"
done

# `sudo tego doctor` itself, from the binary a root user would install: objects embedded when they
# exist. Its verdict is `--require cgroup`: as root on a kernel with the tier-2 hooks, doctor must reach
# at least tier cgroup, the same bar internal/doctor's TestIntegrationAsRoot sets; and, from the build with the
# objects where bpf is an active LSM (the lsm=...,bpf boot), tier bpflsm too (TIER3-PLAN T11, enforce-plane R28).
doctor_bin="$OUT/prebuilt/tego"
doctor_suite="tego-doctor"
if [ "$bpf_state" = on ]; then
	doctor_bin="$OUT/prebuilt/tego.tegobpf"
	doctor_suite="tego-doctor.tegobpf"
fi
# shellcheck disable=SC2016 # the sh that runs the script expands it, with the binary as $0
doctor_script='
	"$0" doctor; a=$?
	"$0" doctor --require cgroup >/dev/null 2>&1; b=$?
	"$0" doctor --require bpflsm >/dev/null 2>&1; c=$?
	echo "tego doctor: exit=$a, --require cgroup exit=$b, --require bpflsm exit=$c"
	[ "$a" -eq 0 ] || exit "$a"
	[ "$b" -eq 0 ] || exit "$b"
	case "$1:,$(cat /sys/kernel/security/lsm 2>/dev/null)," in
	on:*,bpf,*) exit "$c" ;;
	esac
	exit 0'
echo
if [ "$HOSTMODE" = sudo ]; then
	# On this host the doctor is not in a disposable guest (identity-config.md R27). Where TEGO_DISPOSABLE_HOST says the
	# machine is disposable (a CI runner) it is the product build, run as a root user would run it. Anywhere else it is
	# the tegotesthooks build of the same tags, given a machine config, chain anchor and own-log home of this run's own,
	# as test/vm/run-matrix-row.sh's with_iso gives a guest's: a product build ignores the two test variables, and under
	# sudo logs to SUDO_UID's own ~/.tego/tego.log. sudo resets the environment, so the variables go on its command line.
	doctor_env=()
	if [ -n "$DISPOSABLE" ]; then
		echo "== $doctor_suite (tego doctor as root on this host, the product build: TEGO_DISPOSABLE_HOST=$DISPOSABLE)"
	else
		doctor_bin="$doctor_bin.testhooks"
		iso="$OUT/doctor-iso"
		rm -rf "$iso"
		mkdir -p "$iso/log-home"
		chmod 755 "$iso"
		printf 'version: 0\nledger_root: %s/runs\n' "$iso" >"$iso/config.yaml"
		chmod 600 "$iso/config.yaml"
		doctor_env=(env "TEGO_CONFIG=$iso/config.yaml" "TEGO_TEST_CHAIN_ANCHOR=$iso/chain.log" "TEGO_TEST_OWN_LOG_HOME=$iso/log-home" HISTFILE=/dev/null)
		echo "== $doctor_suite (tego doctor as root on this host, the tegotesthooks build with a machine config, anchor and own log in $iso: TEGO_DISPOSABLE_HOST is not set, so the product build, which would log to your own ~/.tego, is not run here)"
	fi
	"${as_root[@]+"${as_root[@]}"}" "${doctor_env[@]+"${doctor_env[@]}"}" "$here/bounded-run.sh" 300 /bin/sh -c "$doctor_script" "$doctor_bin" "$bpf_state" 2>&1 | tee "$OUT/logs/$doctor_suite.console"
	code="${PIPESTATUS[0]}"
else
	echo "== $doctor_suite (tego doctor as root in a KVM guest)"
	fwd_run "$here/kvm-run.sh" --sudo --timeout 300 --log "$OUT/logs/$doctor_suite.console" --status "$OUT/logs/$doctor_suite.status" \
		--file "$doctor_bin:/vm/tego" -- "${service_cgroup[@]+"${service_cgroup[@]}"}" /bin/sh -c "$doctor_script" /vm/tego "$bpf_state"
	code="$(vm_code $? "$OUT/logs/$doctor_suite.status")"
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$doctor_suite" "cmd/tego" "$([ "$bpf_state" = on ] && echo tegobpf || echo -)" "$code" "-" "$OUT/logs/$doctor_suite.console" >>"$results"

echo
status=0
python3 "$here/summarize.py" "$results" "$OUT/summary.json" || status=1

# ---- the skip and must-pass gates ----------------------------------------------------------------
# A skip exits 0 like a pass, so the suites' JSON goes through scripts/skipgate.sh against
# test/vm/root-skips.txt, the skips a root run may take, each with its reason: a test
# that stopped running as root fails the run instead of passing with it. The entries whose reason starts
# "untagged:" are the tests only a build without the objects skips, so they are allowed in the plain build of
# a package whose tests load the objects and in no other. Then the root-only tests of test/vm/root-must-pass.txt
# must have passed in some build and failed in none, when every package ran and no VM_RUN narrowed them.
# gate_report HEADER LOG: the gate's verdict section (the package results and failures are summarize.py's), or
# the whole log when it has none (a usage error: a malformed list, a stream with no test).
gate_report() {
	if grep -q -- "$1" "$2"; then
		sed -n "/$1/,\$p" "$2"
	else
		cat "$2"
	fi
}
strict=() lenient=()
for s in "${suites[@]+"${suites[@]}"}"; do
	IFS='|' read -r suite pkg tags _ <<<"$s"
	json="$OUT/logs/$suite.json"
	[ -s "$json" ] || continue
	if [ "$tags" = integration ] && [ -n "${bpfpkg[$pkg]:-}" ]; then
		lenient+=("$json")
	else
		strict+=("$json")
	fi
done
grep -v '[[:space:]]#[[:space:]]*untagged:' "$here/root-skips.txt" >"$OUT/root-skips.tagged.txt"
if [ "${#strict[@]}" -gt 0 ]; then
	echo
	echo "== skips of the tagged builds and the packages without objects (test/vm/root-skips.txt, untagged: entries left out)"
	"$repo/scripts/skipgate.sh" "$OUT/root-skips.tagged.txt" "${strict[@]}" >"$OUT/logs/skipgate-strict.log" 2>&1 || status=1
	gate_report '^== skipped tests' "$OUT/logs/skipgate-strict.log"
fi
if [ "${#lenient[@]}" -gt 0 ]; then
	echo
	echo "== skips of the plain builds of the packages whose tests load the objects (test/vm/root-skips.txt)"
	"$repo/scripts/skipgate.sh" "$here/root-skips.txt" "${lenient[@]}" >"$OUT/logs/skipgate-plain.log" 2>&1 || status=1
	gate_report '^== skipped tests' "$OUT/logs/skipgate-plain.log"
fi
if [ $# -eq 0 ] && [ -z "${VM_RUN:-}" ] && [ -z "$SHARD" ] && [ "${#strict[@]}" -gt 0 ]; then
	echo
	"$repo/scripts/skipgate.sh" --must-pass "$here/root-must-pass.txt" "${strict[@]}" "${lenient[@]+"${lenient[@]}"}" \
		>"$OUT/logs/skipgate-must-pass.log" 2>&1 || status=1
	gate_report '^== must pass' "$OUT/logs/skipgate-must-pass.log"
fi
[ -z "$SHARD" ] || echo "$SHARD $status" >"$OUT/shard.done"
exit "$status"
