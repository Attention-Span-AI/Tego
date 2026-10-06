# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
#
# Sourced by root-suites.sh: the axes test/conformance's TestConformanceKernel must run on one boot, the value of
# TEGO_CONFORMANCE_REQUIRE (ADR 0017; test/conformance/kernel_integration_test.go). An axis the list names and the
# machine does not offer fails the test, instead of leaving that column of the kernel conformance unchecked behind
# a green parent test.
#
#   conformance_require HOSTMODE BPF_STATE VM_LSM HOST_LSM
#
# HOSTMODE is root-suites.sh's VM_HOST (kvm or sudo), BPF_STATE whether the tegobpf variants were built (on or
# off), VM_LSM the guest's TEGO_VM_LSM as kvm-run.sh reads it ("" for the host's list plus bpf, "kernel" for the
# kernel's own default, else the full lsm= value), and HOST_LSM the list in this host's /sys/kernel/security/lsm,
# which is the boot a VM_HOST=sudo run is on. It prints the list.
#
# Every root boot requires tier cgroup and the fmod_ret plane mode. A boot with bpf among its LSMs requires the lsm
# plane mode and tier bpflsm as well, when the objects are built (TIER3-PLAN §9, T11): VM_BOOTS=both's lsm-bpf boot,
# a single guest boot (kvm-run.sh adds bpf to the host's list) and a sudo host whose own list has bpf. The
# default-lsm boot does not, and neither does a kernel booted with its own default list (TEGO_VM_LSM=kernel, the
# kernel matrix), whose LSMs this script cannot know; there the test itself fails when bpf turns out active and
# either axis is missing.
conformance_require() {
	local hostmode="$1" bpf_state="$2" vm_lsm="$3" host_lsm="$4" boot_lsm="" require="cgroup,fmod_ret"
	if [ "$hostmode" = sudo ]; then
		boot_lsm="$host_lsm"
	else
		case "$vm_lsm" in
		"") boot_lsm="bpf" ;;
		kernel) boot_lsm="" ;;
		*) boot_lsm="$vm_lsm" ;;
		esac
	fi
	if [ "$bpf_state" = on ]; then
		case ",$boot_lsm," in *,bpf,*) require="$require,lsm,bpflsm" ;; esac
	fi
	printf '%s\n' "$require"
}
