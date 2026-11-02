# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2034 # The arrays are consumed by the scripts sourcing this file.
#
# The privileged suites, the helpers they need and the kernel modules their guests load, sourced by
# test/vm/root-suites.sh and scripts/coverage.sh --vm so the two cannot drift (coverage.sh once lacked three
# packages and three helpers, and the tests that `go build` the missing helpers failed in the guest; until
# 2026-11-02 it loaded no module, and the dashboard's suites failed closed in its guests). Bash arrays; nothing
# here runs.

# The last packages hold root-only tests too, which skip everywhere a run does not list them:
# the supervisor's unix relay to a target of another uid and in its own mount namespace,
# RunAs taking a task's credentials, tier 1 creating a missing write directory as the dropped uid, the ledger's
# hand-over to the invoking user, and the own log's chown.
PKGS=(
	internal/runtime/enforce/cgroup
	internal/bpf
	internal/runtime/observe
	internal/runtime/capture/uprobe
	internal/runtime/cgroup
	internal/runtime/launch
	internal/runtime/deputy # the open deputy started as root: its confinement without an inherited no_new_privs (ADR 0041 D2)
	internal/runtime
	internal/doctor
	internal/runtime/supervisor
	internal/platform/sys
	internal/runtime/enforce/landlock
	internal/platform/proc
	internal/ledger
	internal/cli
	internal/runtime/hoststate
	test/conformance
	internal/watch/watcher # the agent watcher: the proc connector needs CAP_NET_ADMIN
	internal/watch/adopt # adoption's held-file reads: files held from a chroot, a detached mount, btrfs (mount, chroot)
	test/vm/cmd/permlistener # the third-party fanotify listener; its tests mount a tmpfs and mark only that
	internal/handoff # the sealed handoff refusing a real euid 0 and a noexec mount, and vm.memfd_noexec set in a new pid namespace (ADR 0100 (1b))
	internal/control/cli # tego-control's guard refusing a real euid 0 in every command (ADR 0100 (1b))
	internal/control/web # the dashboard's peer check refusing a client of another real uid on the kernel's own tcp table (F21)
	internal/runscope # InRun as root, in the initial cgroup namespace and in a child's own (ADR 0100)
	internal/platform/peer # the peer check as root on the guest's kernel: below 6.5 (rhel-9, al2023) its pidfd_open fallback for real
)
# The kernel modules each guest loads before its suite (kvm-run.sh --module), unless VM_MODULES names others. A guest
# has no module tree of its own, so its kernel cannot load one on demand as a host's does; on a kernel-matrix row's
# kernel kvm-run.sh has none to fetch either, so a row's guests load none unless VM_MODULES names the row's own
# (test/vm/README.md).
#   overlay    the decision plane's overlayfs cell (internal/bpf TestPlaneStepAHooksDecide's overlay subtest) skips
#              without it, and root-skips.txt allows that only where the kernel has no overlayfs
#   btrfs      internal/runtime/enforce/cgroup's TestPlaneRunBtrfsSubvolumeInodeIdentity mounts a loop-file btrfs,
#              and root-skips.txt allows its skip in the plain build only (2026-10-05)
#   unix_diag  the supervisor asks sock_diag which file each unix socket the run bound is bound to (supervisor R11a),
#              and without it refuses every socket under a write entry unix-origin-unread (2026-10-16)
#   tcp_diag   with inet_diag under it: the dashboard asks sock_diag which cgroup each TCP client socket was made in
#              (internal/platform/peer TCPSocketCgroup, whose TestTCPSocketCgroupIsTheMakersCgroup skips without it)
#              and refuses every sign-in and POST it cannot answer, so internal/control/web's and
#              internal/control/cli's suites fail without it (2026-10-27)
GUEST_MODULES=(overlay btrfs unix_diag tcp_diag)
# Helpers the tests `go build` at run time; go-shim.sh serves them by last path element.
HELPERS=(cmd/tego test/conformance/cmd/actor internal/runtime/cgroup/testdata/memhog test/workloads/model-agent test/workloads/retriever-agent test/workloads/signaller test/workloads/sigio test/workloads/procscope test/workloads/uringsock test/workloads/uringbind test/workloads/execracer test/workloads/ifaces test/vm/cmd/permlistener)
