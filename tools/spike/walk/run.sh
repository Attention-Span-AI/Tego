#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — SPIKE (TIER3-PLAN T0): the guest side. build.sh's output directory, with this file copied into it, goes
# into a KVM guest as /vm/sw, e.g. (under the shared guest lock):
#   flock ~/.cache/tego-vm/guest.lock test/vm/run-in-vm.sh rhel-9 --file OUT:/vm/sw -- /bin/sh /vm/sw/run.sh
#   flock ~/.cache/tego-vm/guest.lock test/vm/kvm-run.sh --file OUT:/vm/sw -- /bin/sh /vm/sw/run.sh   # 6.17, lsm+bpf
# TEGO_VM_LOCKDOWN=confidentiality with SKIP_BENCH=1 SKIP_ROWMAP=1 gives the lockdown rows. results-2026-09-29.tsv
# is what it printed.
cd /vm/sw || exit 1
./spike env
./spike load -dir . -reps "${REPS:-5}"
[ "${SKIP_BENCH:-0}" = 1 ] || ./spike bench -dir . -n "${N:-100000}" -reps 3
[ "${SKIP_ROWMAP:-0}" = 1 ] || ./spike rowmap -dir . -reps 20 -rows 64
echo DONE
