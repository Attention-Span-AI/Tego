# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash
# shellcheck disable=SC2034 # Both arrays are consumed by the scripts sourcing this file.
#
# The privileged suites and the helpers they need, sourced by test/vm/root-suites.sh and scripts/coverage.sh
# --vm so the two cannot drift (coverage.sh once lacked three packages and three helpers, and the tests that
# `go build` the missing helpers failed in the guest). Bash arrays; nothing here runs.

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
	internal/runscope # InRun as root, in the initial cgroup namespace and in a child's own (ADR 0100)
	internal/platform/peer # the peer check as root on the guest's kernel: below 6.5 (rhel-9, al2023) its pidfd_open fallback for real
)
# Helpers the tests `go build` at run time; go-shim.sh serves them by last path element.
HELPERS=(cmd/tego test/conformance/cmd/actor internal/runtime/cgroup/testdata/memhog test/workloads/model-agent test/workloads/retriever-agent test/workloads/signaller test/workloads/sigio test/workloads/procscope test/workloads/uringsock test/workloads/uringbind test/workloads/execracer test/vm/cmd/permlistener)
