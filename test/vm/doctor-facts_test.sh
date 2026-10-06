#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Tests doctor-facts.sh, which reads the text of `tego doctor` and prints the two facts the kernel matrix keeps per
# row and boot (ADR 0021 (7)): the Landlock ABI, and the decision plane tier cgroup decides opens by (cgroup_mode).
# The inputs are lines `tego doctor` really printed as root in a KVM guest on 2026-10-05, on the rows they name
# (the programs line is cut after the plane clause, which is the part read), so a change to doctor's wording that
# the parser no longer reads fails here, not as an empty column in the nightly's report.
#
# Usage: test/vm/doctor-facts_test.sh. Exit 0 when every case passed, 1 on the first that did not.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "FAIL $*" >&2; exit 1; }

# facts NAME WANT TEXT: the script's output on TEXT is WANT.
facts() {
	local name="$1" want="$2" text="$3" got
	got="$("$here/doctor-facts.sh" <<<"$text" 2>&1)"
	[ "$got" = "$want" ] || fail "$name: got \"$got\", want \"$want\""
}

PROG='ok   programs: 25 of 25 hooks load and attach; trace_proc is its rdonly build (the kernel'"'"'s BTF has bpf_rdonly_cast and bpf_loop); capture (uprobe_ssl, no tier): 6 of 6 programs load and attach at /usr/lib/x86_64-linux-gnu/libssl.so.3; decision plane:'

# fedora-7.2: bpf is active, the plane runs in LSM mode, tier bpflsm.
facts "fedora-7.2 as root" "landlock_abi=10 cgroup_mode=lsm" "ok   kernel: 7.2.9-300.fc45.x86_64 (>= 5.14.0)
ok   landlock: ABI 10
ok   lsm: lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm via lsm_list_modules(2); bpf is active
$PROG lsm (tiers 2 and 3 decide opens in the kernel); build decide_rd, lsm mode ok, fmod_ret mode ok
tier: bpflsm"

# ubuntu-25.10: no bpf in the kernel's list, the plane in fmod_ret mode, tier cgroup.
facts "ubuntu-25.10 as root" "landlock_abi=7 cgroup_mode=fmod_ret" "ok   landlock: ABI 7
off  lsm: lockdown,capability,landlock,yama,apparmor,ima,evm via lsm_list_modules(2); bpf is not active: tier 3 (bpflsm) is unavailable
$PROG fmod_ret (tier 2 decides opens in the kernel; tier 3 needs bpf in lsm=); build decide_rd
tier: cgroup"

# ubuntu-22.04: ABI 1, and doctor's programs line still names a fanotify plane, but no tier cgroup is offered, so
# there is no tier-cgroup mode to report.
facts "ubuntu-22.04 as root" "landlock_abi=1 cgroup_mode=none" "FAIL landlock: ABI 1 is below the supported minimum 2 (rename and link confined to one directory); fix: boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)
$PROG fanotify (no plane mode passed the probe; tier 2 decides opens by fanotify); build none loads
tier: none (this machine can only record)
missing for landlock: landlock: ABI 1 is below the supported minimum 2 (rename and link confined to one directory)"

# A host that falls back to fanotify while it offers tier cgroup (AL2023 under lockdown=confidentiality, arm64 where the
# probe fails): the mode is the fallback's name, which is the column ADR 0021 (7) wants read.
facts "tier cgroup on the fanotify fallback" "landlock_abi=2 cgroup_mode=fanotify" "ok   landlock: ABI 2
$PROG fanotify (no plane mode passed the probe; tier 2 decides opens by fanotify)
tier: cgroup"

# As the user, doctor skips the programs: the plane says it needs root, and the tier is landlock.
facts "an unprivileged doctor" "landlock_abi=7 cgroup_mode=none" "ok   landlock: ABI 7
skip programs: requires root to test (bpf(BPF_PROG_LOAD) needs CAP_BPF; this kernel disables unprivileged BPF); decision plane: requires root to test; fix: re-run as root
tier: landlock"

# No Landlock at all reads as ABI 0.
facts "a kernel with no Landlock" "landlock_abi=0 cgroup_mode=none" "FAIL landlock: landlock_create_ruleset: function not implemented (tier landlock unavailable); fix: boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y
tier: none (this machine can only record)"

# A tier cgroup with a plane clause the parser does not know is "unknown", never "none": the column must not say a
# row has no plane when doctor's words changed.
facts "tier cgroup with no clause" "landlock_abi=7 cgroup_mode=unknown" "ok   landlock: ABI 7
ok   programs: 25 of 25 hooks load and attach
tier: cgroup"
facts "tier cgroup with another clause" "landlock_abi=7 cgroup_mode=unknown" "ok   landlock: ABI 7
ok   programs: 25 of 25 hooks load and attach; decision plane: bpf_lsm2 (tiers 2 and 3 decide opens in the kernel)
tier: cgroup"

# Without a tier line there is nothing to judge: no facts, and a status.
out="$("$here/doctor-facts.sh" <<<"" 2>/dev/null)"
rc=$?
[ "$rc" = 1 ] && [ -z "$out" ] || fail "empty input printed \"$out\" and exited $rc, want nothing and 1"

echo "ok doctor-facts_test.sh"
