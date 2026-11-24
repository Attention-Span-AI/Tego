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
# not pass (on a run of named packages on a row, the entries scoped to that row for the packages it ran). Each suite's go test -json stream is kept beside its console log (VM_OUT/logs/<suite>.json).
# A guest that something outside this script ended (kvm-run.sh's exit 98, "lost signal <n>": the host's memory guard
# or OOM killer, a kill by hand) is no result for its suite: the suite's row says guest-lost, a GUEST-LOST line names
# it at the end, and the script exits 98 instead of 1, so a lost guest is never read as a failing test.
#
# Usage: test/vm/root-suites.sh [package-substring | =exact/package ...] (default: every package below)
#        test/vm/root-suites.sh --gather DIR              (after the VM_SHARD runs: below)
# Environment: GO (go), VM_OUT (bin/vm: binaries, logs, summary.json), VM_BPF (auto|yes|no: whether
#   to build the tegobpf variants; auto builds them when internal/bpf compiles with the tag, i.e.
#   after `make gen`), VM_RUN (a -test.run pattern for every suite, which runs a split package whole), VM_PART_RUN (an
#   extended regular expression, grep -E, of top-level test names: a split package keeps its parts, each running only
#   its own tests the expression matches, and a part that has none runs no guest; a package that is not split runs
#   them by -test.run; the must-pass gate holds nothing then, as with VM_RUN), VM_COUNT (a -test.count for every suite: one
#   guest loops a test, as a capture loss once needed tens of rounds of one test), VM_SUITE_TIMEOUT (seconds per
#   guest; "pkg=seconds" sets one package, "suite=seconds" one build (e.g. internal_runtime_enforce_cgroup.tegobpf); default "1500 internal/runtime/enforce/cgroup=3000": that
#   package runs as the parts of test/vm/suites.sh's ROOT_SPLITS (below), a guest each, and a part takes at most 1111 s (its whole
#   tegobpf suite took 5093 s on 2026-11-19, 2517-3765 s on a loaded host on 2026-10-17, past 1500's own 1200 s; a cap named for
#   a package or a build is each part's);
#   the suite's own go test -timeout is that less 300), VM_HOST (kvm, the default, or sudo: see below), VM_BOOTS (empty, or both: every
#   suite on the lsm=...,bpf boot and again on the host's list without bpf, below; lsm-bpf or default-lsm: that boot alone), VM_CGROUP (empty, or
#   service: see below), VM_MODULES (kernel modules each guest loads before its suite, space-separated,
#   passed to kvm-run.sh --module; default test/vm/suites.sh's GUEST_MODULES, "overlay btrfs unix_diag tcp_diag",
#   which scripts/coverage.sh --vm's guests load too and which says what needs each; VM_MODULES="" loads none),
#   VM_SUITE_MEM (per-package guest memory, "pkg=size ...", over
#   TEGO_VM_MEM; e.g. "internal/runtime/enforce/cgroup=2560M" for its 32 concurrent runs), plus kvm-run.sh's
#   TEGO_VM_* knobs.
#   TEGO_TEST_PLANE_PREEMPT=waive reaches every suite (PREEMPT_WAIVER below).
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
# A shard that exited 98 lost a guest: it is GUEST-LOST, not FAIL, and the gather exits 98 whatever else failed.
if [ "${1:-}" = --gather ]; then
	[ $# = 2 ] && [ -d "$2" ] || { echo "usage: test/vm/root-suites.sh --gather DIR (the shards' VM_OUT directories)" >&2; exit 2; }
	gdir="$(cd "$2" && pwd)"
	# shellcheck source=test/vm/suites.sh
	. "$here/suites.sh"
	shard_plan || exit 2
	status=0
	lost=0 # a shard that lost a guest (exit 98): the gather is then no verdict either, and exits 98 whatever else failed
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
		case "$gstatus" in
		0) echo "ok   $gname" ;;
		98) echo "GUEST-LOST $gname: a guest was lost (exit 98): its suites have no result"; lost=1 ;;
		*) echo "FAIL $gname: exit ${gstatus:-none}"; status=1 ;;
		esac
	done
	jsons=()
	for f in "${done_by[@]}"; do
		for j in "$(dirname "$f")"/logs/*.json; do [ ! -s "$j" ] || jsons+=("$j"); done
	done
	echo
	if [ "${#jsons[@]}" = 0 ]; then
		echo "root-suites: the shards left no go test -json log" >&2
		[ "$lost" = 0 ] || exit 98
		exit 1
	fi
	"$repo/scripts/skipgate.sh" --must-pass "$here/root-must-pass.txt" "${jsons[@]}" >"$gdir/skipgate-must-pass.log" 2>&1 || status=1
	if grep -q '^== must pass' "$gdir/skipgate-must-pass.log"; then sed -n '/^== must pass/,$p' "$gdir/skipgate-must-pass.log"; else cat "$gdir/skipgate-must-pass.log"; fi
	echo
	if [ "$lost" = 1 ]; then
		echo "== root-suites: ${#ROOT_SHARDS[@]} shards, ${#jsons[@]} suites' logs: GUEST-LOST (a shard lost a guest: no verdict for its suites, run it again)"
		exit 98
	fi
	echo "== root-suites: ${#ROOT_SHARDS[@]} shards, ${#jsons[@]} suites' logs: $([ "$status" = 0 ] && echo pass || echo FAIL)"
	exit "$status"
fi
GO="${GO:-go}"
OUT="${VM_OUT:-$repo/bin/vm}"
case "$OUT" in /*) ;; *) OUT="$repo/$OUT" ;; esac
BPF="${VM_BPF:-auto}"
SUITE_TIMEOUT_SPEC="${VM_SUITE_TIMEOUT:-1500 internal/runtime/enforce/cgroup=3000}"
HOSTMODE="${VM_HOST:-kvm}"
# DISPOSABLE is the TEGO_DISPOSABLE_HOST a VM_HOST=sudo suite gets (a guest always gets "kvm"): the caller's own, or
# github-actions on a GitHub Actions runner, whose sudo drops GITHUB_ACTIONS from the tests' environment.
DISPOSABLE="${TEGO_DISPOSABLE_HOST:-}"
[ -n "$DISPOSABLE" ] || [ "${GITHUB_ACTIONS:-}" != true ] || DISPOSABLE=github-actions
CGROUP="${VM_CGROUP:-}"
# PREEMPT_WAIVER is TEGO_TEST_PLANE_PREEMPT, which every suite gets when the caller sets it: "waive" lets a test
# build's doctor probe fmod_ret mode on a kernel that preempts kernel code (internal/doctor preempt_testhook.go, ADR
# 0024 (16)), which a product build rules out. CI's root-suites job sets it on GitHub's x86_64 runner, whose 7.0 kernel
# offers only full and lazy preemption and no bpf LSM, so that the plane suites keep testing fmod_ret mode's
# decisions there, and vm-matrix's tier-3 step for its fedora-7.0 and fedora-7.2 rows (lazy preemption). Without it
# such a kernel offers tier cgroup no plane mode unless bpf is an active LSM, so the plane suites skip and
# test/conformance's required fmod_ret axis (conformance-require.sh) fails. The arm64 job's first root step leaves it
# unset (its kernel preempts fully, and doctor's refusal is what that step checks); its next sets it for the stress cell.
PREEMPT_WAIVER="${TEGO_TEST_PLANE_PREEMPT:-}"
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
	# The fedora-7.0 and fedora-7.2 kernels preempt kernel code (lazy preemption), so a product doctor rules fmod_ret mode out
	# there and the fmod_ret subtests of the plane suites skip (unlisted, so the skip gate fails) and conformance's required
	# fmod_ret axis fails. vm-matrix sets the waiver for these rows; a caller that forgot it (q22, 2026-11-20) got that
	# failure, not a regression. The row therefore defaults to it; a value the caller set, even an empty "none", is kept.
	case "$ROW" in
	fedora-7.0 | fedora-7.2)
		if [ -z "${TEGO_TEST_PLANE_PREEMPT+x}" ]; then
			PREEMPT_WAIVER=waive
			echo "root-suites: TEGO_VM_ROW=$ROW preempts kernel code: TEGO_TEST_PLANE_PREEMPT=waive by default (set it to another value to override)" >&2
		fi
		;;
	esac
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
	# These rows have authenticated module packages. Without unix_diag the own-socket cells correctly refuse
	# unix-origin-unread; Fedora's built-in btrfs still needs its loadable loop driver for the fixture image.
	# Preserve an explicit VM_MODULES, including an empty one for missing-feature tests.
	if [ "$ROW" != host ] && [ -z "${VM_MODULES+x}" ]; then
		case "$ROW" in
		debian-13 | al2023 | al2023-6.12) export VM_MODULES="overlay crc32c_generic loop btrfs unix_diag tcp_diag" ;;
		fedora-7.0 | fedora-7.2) export VM_MODULES="loop" ;;
		ubuntu-24.04 | ubuntu-25.10) export VM_MODULES="overlay btrfs unix_diag inet_diag tcp_diag" ;;
		*) export VM_MODULES="" ;;
		esac
	fi
	if [ "$ROW" != host ] && [ -n "${VM_MODULES:-}" ]; then
		python3 "$here/fetch-kernel.py" --modules "$ROW" >/dev/null || exit $?
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
		VM_BOOTS="" VM_OUT="$OUT/$boot" TEGO_VM_LSM="$lsm" "$here/root-suites.sh" "$@"
		rc=$?
		# A lost guest (98) on either boot makes the whole run 98: it has no result for that boot's lost suites.
		if [ "$rc" = 98 ]; then overall=98; elif [ "$rc" != 0 ] && [ "$overall" = 0 ]; then overall=1; fi
	done
	case "$overall" in 0) verdict=pass ;; 98) verdict="GUEST-LOST (a guest was lost: no result for its suites)" ;; *) verdict=FAIL ;; esac
	echo "== root-suites: ${boots// / and }: $verdict (per boot under $OUT/<boot>)"
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
			case "$f" in
			=*) [ "$p" = "${f#=}" ] || continue ;;
			*) case "$p" in *"$f"*) ;; *) continue ;; esac ;;
			esac
			selected+=("$p")
			break
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
	[ -z "${VM_PART_RUN:-}" ] || { echo "root-suites: VM_SHARD=$SHARD runs its own part of each suite; VM_PART_RUN would narrow it again" >&2; exit 2; }
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
# The host packages the guest copies are the host's own and not pinned (kvm-run.sh HOST_PKGS): the run's environment
# facts name their versions, so two machines' runs can be compared.
"$here/host-facts.sh" python3 git nodejs >"$OUT/host-packages.txt"
echo "root-suites: host packages in the guest (the host's own, not pinned): $(tr '\n' ' ' <"$OUT/host-packages.txt")"
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
# those of overlay and btrfs this run loads (VM_MODULES, below). Every named full matrix row except RHEL 9 requires
# Btrfs too, including Fedora's built-in driver and explicit empty module lists: losing the driver must fail the
# fixture. RHEL 9 alone may report it absent; the skip registry restricts the plane fixture's allowance to that row.
fs_required=""
for m in ${VM_MODULES-${GUEST_MODULES[*]}}; do
	case "$m" in overlay | btrfs) fs_required="${fs_required:+$fs_required }$m" ;; esac
done
case "$ROW" in
"" | rhel-9) ;;
*) case " $fs_required " in *" btrfs "*) ;; *) fs_required="${fs_required:+$fs_required }btrfs" ;; esac ;;
esac
if [ -n "$fs_required" ]; then
	conformance_env+=("TEGO_CONFORMANCE_FS_REQUIRE=$fs_required")
	conformance_env_args+=(--env "TEGO_CONFORMANCE_FS_REQUIRE=$fs_required")
fi
echo "root-suites: TEGO_CONFORMANCE_FS_REQUIRE=$fs_required"

# suite_list DIR TAGS: every top-level test a package's test build holds, read from its sources (nothing is run), one
# name a line, in the order of the package's files.
suite_list() {
	(cd "$1" && "$GO" list -tags "$2" -f '{{range .TestGoFiles}}{{.}} {{end}}{{range .XTestGoFiles}}{{.}} {{end}}' . |
		xargs sed -n 's/^func \(Test[A-Z0-9_][A-Za-z0-9_]*\)(\([a-z]*\) \*testing\.T) {$/\1/p')
}

# split_count PKG: the number of parts test/vm/suites.sh's ROOT_SPLITS gives a package ("" when it is run whole).
split_count() {
	local e name pkg n
	for e in "${ROOT_SPLITS[@]}"; do
		IFS='|' read -r name pkg n <<<"$e"
		if [ "$pkg" = "$1" ]; then echo "$n"; return 0; fi
	done
	return 0
}

# split_part J N LISTFILE: part J of N of the tests LISTFILE names (one a line). A test is in the part its position in the
# list says: the J-th, J+N-th, J+2N-th ... of it, so each test is in exactly one part whatever the list holds, and a
# test added to the package is in one of them without anyone naming it. Sets PART_MINE (this part's tests), PART_TOTAL
# (the list's) and PART_ARGS: parts 1 to N-1 run theirs by -test.run; part N skips every other part's tests by -test.skip
# instead (-test.run when the list is one part's own), so it also runs whatever the list does not hold (fuzz targets,
# examples, a test the list's sed missed): together the N parts run every test of the binary once.
# With VM_PART_RUN each part keeps only its own tests the expression matches, and runs them by -test.run, part N too.
split_part() {
	local pj="$1" pn="$2" t i=0 others=() kept=()
	PART_MINE=() PART_ARGS=() PART_TOTAL=0
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		if [ $((i % pn + 1)) = "$pj" ]; then PART_MINE+=("$t"); else others+=("$t"); fi
		i=$((i + 1))
	done <"$3"
	PART_TOTAL=$i
	if [ -n "${VM_PART_RUN:-}" ]; then
		for t in "${PART_MINE[@]+"${PART_MINE[@]}"}"; do
			if printf '%s\n' "$t" | grep -Eq -- "$VM_PART_RUN"; then kept+=("$t"); fi
		done
		PART_MINE=("${kept[@]+"${kept[@]}"}")
		[ "${#PART_MINE[@]}" -eq 0 ] || PART_ARGS=("-test.run=^($(IFS='|'; echo "${PART_MINE[*]}"))\$")
		return 0
	fi
	if [ "$pj" != "$pn" ]; then
		PART_ARGS=("-test.run=^($(IFS='|'; echo "${PART_MINE[*]-}"))\$")
	elif [ "${#others[@]}" -gt 0 ]; then
		PART_ARGS=("-test.skip=^($(IFS='|'; echo "${others[*]}"))\$")
	fi
}

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

suites=() # suite|pkg|tags|binary|part (j/n or empty)|the build's own name, whose .list holds all its tests
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
			# Every top-level test this build holds, read from its sources (nothing is run), so the
			# report can name the tests a crash or a timeout never let run.
			suite_list "$p" "$tags" >"$OUT/logs/$suite.list" 2>/dev/null
			# A package ROOT_SPLITS splits runs as its parts, each its own guest and its own suite row of the same package,
			# unless this run is a shard (VM_SHARD names its parts itself) or runs a named test (VM_RUN).
			split_n=""
			{ [ -n "$SHARD" ] || [ -n "${VM_RUN:-}" ]; } || split_n="$(split_count "$p")"
			if [ -n "$split_n" ]; then
				for ((j = 1; j <= split_n; j++)); do
					if [ -n "${VM_PART_RUN:-}" ]; then
						split_part "$j" "$split_n" "$OUT/logs/$suite.list"
						[ "${#PART_MINE[@]}" -gt 0 ] || continue # no test of this part matches: no guest for it
					fi
					suites+=("$suite.p$j|$p|$tags|$bin|$j/$split_n|$suite")
				done
			elif [ -n "${VM_PART_RUN:-}" ]; then
				# Not split: the matching tests by name, as a part runs them.
				split_part 1 1 "$OUT/logs/$suite.list"
				if [ "${#PART_MINE[@]}" -gt 0 ]; then suites+=("$suite|$p|$tags|$bin|1/1|$suite"); fi
			else
				suites+=("$suite|$p|$tags|$bin|$PART|$suite")
			fi
		else
			printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$suite" "$p" "$tags" "build-failed" "-" "$OUT/logs/build-$suite.log" >>"$results"
			cat "$OUT/logs/build-$suite.log" >&2
		fi
	done
done

# ---- run ----------------------------------------------------------------------------------------

run_args=()
[ -z "${VM_RUN:-}" ] || [ -z "${VM_PART_RUN:-}" ] || { echo "root-suites: VM_RUN runs a package whole and VM_PART_RUN keeps its parts; set one" >&2; exit 2; }
[ -z "${VM_RUN:-}" ] || run_args+=("-test.run=$VM_RUN")
if [ -n "${VM_COUNT:-}" ]; then
	[[ "$VM_COUNT" =~ ^[1-9][0-9]{0,3}$ ]] || { echo "root-suites: VM_COUNT must be a count from 1 to 9999, got $VM_COUNT" >&2; exit 2; }
	run_args+=("-test.count=$VM_COUNT")
fi
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
# ran it, else vm-<reason> (lost, timeout, no-report, env, usage), because 2, 124 and 125 are codes both
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

lost=() # the suites whose guest kvm-run.sh reported lost (vm-lost), each with its status line
for s in "${suites[@]+"${suites[@]}"}"; do
	IFS='|' read -r suite pkg tags bin spart lname <<<"$s"
	# The default is the bare number; "pkg=seconds" or "suite=seconds" overrides that package/build. The suite's own
	# -test.timeout ends it 300s before the guest's (or timeout's) bound does, so its panic names the running tests.
	SUITE_TIMEOUT=1500
	for w in $SUITE_TIMEOUT_SPEC; do
		case "$w" in *=*) [ "${w%%=*}" != "$pkg" ] && [ "${w%%=*}" != "$lname" ] || SUITE_TIMEOUT="${w#*=}" ;; *) SUITE_TIMEOUT="$w" ;; esac
	done
	go_timeout="$((SUITE_TIMEOUT - 300))s"
	# A part j/n of the suite (split_part): its .list is then this part's tests, for summarize.py's "never started".
	part_args=()
	if [ -n "$spart" ]; then
		split_part "${spart%%/*}" "${spart#*/}" "$OUT/logs/$lname.list"
		part_args=("${PART_ARGS[@]+"${PART_ARGS[@]}"}")
		printf '%s\n' "${PART_MINE[@]+"${PART_MINE[@]}"}" >"$OUT/logs/$suite.list"
		echo "   part $spart of $lname: ${#PART_MINE[@]} of the $PART_TOTAL tests its sources list$([ "${spart%%/*}" != "${spart#*/}" ] || echo ', and any they do not')"
	fi
	echo
	if [ "$HOSTMODE" = sudo ]; then
		echo "== $suite (go test -tags $tags ./$pkg, as root on this host)"
		env_args=("PATH=$host_path" "TEGO_VM_PREBUILT=$OUT/prebuilt" "TEGO_CONFORMANCE_REQUIRE=$conformance_required" "${conformance_env[@]+"${conformance_env[@]}"}")
		[ -z "$DISPOSABLE" ] || env_args+=("TEGO_DISPOSABLE_HOST=$DISPOSABLE")
		[ -z "$PREEMPT_WAIVER" ] || env_args+=("TEGO_TEST_PLANE_PREEMPT=$PREEMPT_WAIVER")
		[ "$tags" = integration ] || env_args+=("GOFLAGS=-tags=$tags")
		(cd "$repo/$pkg" && "${as_root[@]+"${as_root[@]}"}" env "${env_args[@]}" \
			"$here/bounded-run.sh" "$SUITE_TIMEOUT" "$bin" -test.v -test.timeout=$go_timeout "${run_args[@]+"${run_args[@]}"}" "${part_args[@]+"${part_args[@]}"}") 2>&1 |
			tee "$OUT/logs/$suite.console"
		code="${PIPESTATUS[0]}"
	else
		echo "== $suite (go test -tags $tags ./$pkg, as root in a KVM guest)"
		env_args=(--env "TEGO_CONFORMANCE_REQUIRE=$conformance_required" "${conformance_env_args[@]+"${conformance_env_args[@]}"}" --env "TEGO_DISPOSABLE_HOST=kvm")
		[ -z "$PREEMPT_WAIVER" ] || env_args+=(--env "TEGO_TEST_PLANE_PREEMPT=$PREEMPT_WAIVER")
		[ "$tags" = integration ] || env_args+=(--env "GOFLAGS=-tags=$tags")
		# VM_SUITE_MEM gives one package's guests their own TEGO_VM_MEM ("pkg=size ..."), where the rest share a
		# smaller one: 2560M passed historically elsewhere; Debian and RHEL use a 3G pass point, not a measured
		# minimum. One OOM victim was about 72 MB, so 32 such runs fit 2560M only tightly (test/vm/README.md).
		suite_mem="${TEGO_VM_MEM:-}"
		for m in ${VM_SUITE_MEM:-}; do [ "${m%%=*}" != "$pkg" ] || suite_mem="${m#*=}"; done
		TEGO_VM_MEM="$suite_mem" fwd_run "$here/kvm-run.sh" --sudo --timeout "$SUITE_TIMEOUT" --log "$OUT/logs/$suite.console" --status "$OUT/logs/$suite.status" \
			"${module_args[@]+"${module_args[@]}"}" --file "$bin:/vm/$(basename "$bin")" --file "$OUT/src:/src" --file "$OUT/prebuilt:/vm/prebuilt" \
			--file "$here/go-shim.sh:/usr/local/bin/go" --cwd "/src/$pkg" "${env_args[@]+"${env_args[@]}"}" \
			"${fixture_args[@]+"${fixture_args[@]}"}" \
			-- "${service_cgroup[@]+"${service_cgroup[@]}"}" "/vm/$(basename "$bin")" -test.v -test.timeout=$go_timeout "${run_args[@]+"${run_args[@]}"}" "${part_args[@]+"${part_args[@]}"}"
		code="$(vm_code $? "$OUT/logs/$suite.status")"
		[ "$code" != vm-lost ] || lost+=("$suite ($(cat "$OUT/logs/$suite.status"))")
	fi
	tr -d '\r' <"$OUT/logs/$suite.console" | python3 "$here/consoleframe.py" | "$GO" tool test2json -p "$module/$pkg" >"$OUT/logs/$suite.json" 2>/dev/null
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
		"${module_args[@]+"${module_args[@]}"}" --file "$doctor_bin:/vm/tego" -- "${service_cgroup[@]+"${service_cgroup[@]}"}" /bin/sh -c "$doctor_script" /vm/tego "$bpf_state"
	code="$(vm_code $? "$OUT/logs/$doctor_suite.status")"
	[ "$code" != vm-lost ] || lost+=("$doctor_suite ($(cat "$OUT/logs/$doctor_suite.status"))")
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
	"$repo/scripts/skipgate.sh" --row "$ROW" "$OUT/root-skips.tagged.txt" "${strict[@]}" >"$OUT/logs/skipgate-strict.log" 2>&1 || status=1
	gate_report '^== skipped tests' "$OUT/logs/skipgate-strict.log"
fi
if [ "${#lenient[@]}" -gt 0 ]; then
	echo
	echo "== skips of the plain builds of the packages whose tests load the objects (test/vm/root-skips.txt)"
	"$repo/scripts/skipgate.sh" --row "$ROW" "$here/root-skips.txt" "${lenient[@]}" >"$OUT/logs/skipgate-plain.log" 2>&1 || status=1
	gate_report '^== skipped tests' "$OUT/logs/skipgate-plain.log"
fi
# A run of every package holds the whole list, its row's entries included. A run of named packages on a row holds only
# that row's own entries (row=ROW) for the packages it ran: a proof row's must-pass, such as vm-matrix's internal/cli run
# on fedora-7.0 for TestIntegrationAdoptSkipIsRecordedAtOnce. Unscoped entries, other rows' entries and entries of
# packages it did not run are left to the run that holds them; VM_RUN and a shard still hold none here.
mustlist=""
if [ -z "${VM_RUN:-}" ] && [ -z "${VM_PART_RUN:-}" ] && [ -z "$SHARD" ] && [ "${#strict[@]}" -gt 0 ]; then
	if [ $# -eq 0 ]; then
		mustlist="$here/root-must-pass.txt"
	elif [ -n "$ROW" ]; then
		ran=" "
		for s in "${suites[@]}"; do
			IFS='|' read -r _ pkg _ <<<"$s"
			ran+="$pkg "
		done
		while IFS= read -r line || [ -n "$line" ]; do
			case "$line" in "" | "#"*) continue ;; esac
			read -r pkg _ scope _ <<<"${line%%[[:space:]]#*}" || true
			[ "${scope:-}" = "row=$ROW" ] || continue
			case "$ran" in *" $pkg "*) printf '%s\n' "$line" ;; esac
		done <"$here/root-must-pass.txt" >"$OUT/root-must-pass.row.txt"
		[ ! -s "$OUT/root-must-pass.row.txt" ] || mustlist="$OUT/root-must-pass.row.txt"
	fi
fi
if [ -n "$mustlist" ]; then
	echo
	"$repo/scripts/skipgate.sh" --must-pass --row "$ROW" "$mustlist" "${strict[@]}" "${lenient[@]+"${lenient[@]}"}" \
		>"$OUT/logs/skipgate-must-pass.log" 2>&1 || status=1
	gate_report '^== must pass' "$OUT/logs/skipgate-must-pass.log"
fi
if [ "${#lost[@]}" -gt 0 ]; then
	echo
	for l in "${lost[@]}"; do
		echo "GUEST-LOST: $l: qemu was ended from outside before the suite finished; this is not a test result"
	done
	echo "root-suites: ${#lost[@]} guest(s) lost; exit 98, not a test verdict (run those suites again; on a shared host read its memory guard's log)"
	status=98
fi
[ -z "$SHARD" ] || echo "$SHARD $status" >"$OUT/shard.done"
exit "$status"
