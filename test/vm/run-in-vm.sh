#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# run-in-vm.sh — run one command as root in a KVM guest booted from one kernel-matrix row's own distro
# kernel (P0-DESIGN §10 "Kernel matrix (`test/vm`): Ubuntu 24.04 6.8, Debian 13 6.12, RHEL 9 5.14, AL2023 6.1 and
# 6.12, Fedora 7.0", and its 2026-10-05 amendment: Ubuntu 25.10 6.17 and Fedora 7.2), returning
# that command's own exit code.
#
# It is the matrix's boot step on its own, for looking at one kernel by hand: test/vm/fetch-kernel.py
# fetches the row's kernel from the distro's own mirror, and test/vm/kvm-run.sh boots it the way a fresh
# install boots it — the kernel's own lsm= list (TEGO_VM_LSM=kernel) and no lockdown — unless the
# environment says otherwise. `make vm-test` and `make vm-matrix` (test/vm/matrix.sh) are the kill tests
# on these kernels; this script runs whatever it is given.
#
# An earlier version booted the row under virtme-ng, which shares the host's root filesystem into the
# guest, and could fetch only Ubuntu's kernel; the other five rows stopped with exit 97. kvm-run.sh needs
# neither vng nor root, and fetch-kernel.py reaches every row.
#
# Usage: test/vm/run-in-vm.sh <row> [kvm-run.sh options] -- [sudo] <command> [args...]
#        test/vm/run-in-vm.sh --list
# Exit code: the command's own when the guest ran it; otherwise kvm-run.sh's (97 this box cannot boot a
# guest or fetch the kernel, with a message naming what is missing; 124 timeout; 125 no report); 2 on a
# usage error.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
	echo "usage: $(basename "$0") <row> [kvm-run.sh options] -- [sudo] <command> [args...]" >&2
	echo "       $(basename "$0") --list" >&2
	python3 "$here/fetch-kernel.py" --list | sed 's/^/  /' >&2
	exit 2
}

[ $# -ge 1 ] || usage
if [ "$1" = --list ]; then
	exec python3 "$here/fetch-kernel.py" --list
fi
row="$1"
shift
name="$(python3 "$here/fetch-kernel.py" --name "$row" 2>/dev/null)" || usage
case " $* " in *" -- "*) ;; *) usage ;; esac

# A command written for the virtme-ng harness says `sudo <program>`, since vng ran it as the calling user.
# The guest runs it as root already and has no sudo, so a leading sudo becomes kvm-run.sh --sudo, which is
# what sudo would have set up: SUDO_UID and friends, and the calling shell's cgroup chain. A host file named
# right after it is copied in as kvm-run.sh copies any command it is given (its own header says which).
args=()
while [ $# -gt 0 ] && [ "$1" != -- ]; do args+=("$1"); shift; done
shift
if [ "${1:-}" = sudo ]; then
	shift
	args+=(--sudo)
fi
[ $# -ge 1 ] || usage
# The scheduled workflow gave the virtme-ng harness the row's body directly, `run-matrix-row.sh <tego>`,
# which relied on vng sharing the host's files. The body now needs the tree, jq and the Python packages
# staged into the guest and a second boot for kill test 6 (c), which is matrix.sh's job, so that one command
# is handed to matrix.sh for the row, and matrix.sh builds the binary it stages.
case "$1" in
*run-matrix-row.sh)
	echo "run-in-vm: running the row's body through test/vm/matrix.sh $row (it builds and stages its own tego)" >&2
	exec "$here/matrix.sh" "$row"
	;;
esac

python3 "$here/fetch-kernel.py" "$row" >/dev/null || exit $?
export TEGO_VM_KERNEL="$name"
export TEGO_VM_LSM="${TEGO_VM_LSM:-kernel}"
export TEGO_VM_LOCKDOWN="${TEGO_VM_LOCKDOWN:-none}"
exec "$here/kvm-run.sh" "${args[@]+"${args[@]}"}" -- "$@"
