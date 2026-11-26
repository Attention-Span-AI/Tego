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
	internal/platform/hostaddr # policy rules and the tables they lead to, added as root in a network namespace of the guest (GAPS C46, D30)
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
HELPERS=(cmd/tego test/conformance/cmd/actor internal/runtime/cgroup/testdata/memhog test/workloads/model-agent test/workloads/ledger-attacker test/workloads/retriever-agent test/workloads/signaller test/workloads/sigio test/workloads/procscope test/workloads/uringsock test/workloads/uringbind test/workloads/execracer test/workloads/ifaces test/workloads/strictimport test/vm/cmd/permlistener)
# The packages whose suites run as parts, "<name>|<package>|<n>": each of the package's two suites (plain and tegobpf) in
# n guests, part j of n running the tests at positions j, j+n, j+2n ... of the suite's list (read from its sources), and
# part n also every test the list does not hold (the fuzz targets, an example): root-suites.sh's split_part. Every test of
# the package is in exactly one part, and a test added to it needs no entry anywhere. A run of the package by
# test/vm/root-suites.sh (a developer's `make vm-root-test`, a maintainer's run, vm-matrix.yml's tier 3 steps) runs its parts
# one after another as suite rows of the same package (internal_runtime_enforce_cgroup.p1 ... .tegobpf.p6), so the skip
# gate and summary.json see one package, and a row of root-skips.txt matches whichever part ran the test. A run that names a
# test (VM_RUN) runs the package whole. CI's shards (ROOT_SHARDS below) are these parts, one runner each.
#
# Why 6 (2026-11-20, per-test times of the green KVM run of 2026-11-19, 4 vCPUs, the suite's tests run one at a time): the
# tegobpf suite took 5093 s whole, the cap of its 5700 s go timeout nearly reached by a host 20% slower (an earlier run of it
# ran out of it); its parts at n=4 take 1542 s at most, and at n=6 1110 s at most (the 3000 s guest cap's go timeout is 2700 s:
# 41% of it, 59% headroom; at 1.22x slower still 50%). The plain suite is 600 s whole, 218 s at most in a part. The length of the longest part is
# bounded by the longest tests (TestPlaneRunStallFollowsWhatTheSupervisorAnswers alone takes 209 s), so more parts would
# not shorten it much.
#
# Why internal/runtime is 3 (2026-11-24, a qualification run's two boots on 6.17, 4 vCPUs, tests one at a time):
# its tegobpf suite is 1006 s of tests whole (1012 s plain), against the 1200 s go timeout of the default 1500 s guest cap, 16%
# headroom. Boot 2, on a busier host, ran the same tests 2 to 3 times slower and the timeout ended it, a third of the tests
# unrun. At n=3 a part is 431 s at most (36% of the timeout) in the plain suite and 423 s in the tegobpf one, which a host
# 2.5 times slower still finishes.
ROOT_SPLITS=(
	"cgroup|internal/runtime/enforce/cgroup|6"
	"runtime|internal/runtime|3"
)
# The least guest memory a suite's guest may have, "<row>|<package>|<size>" (a row or a package of "*" matches all), a floor
# test/vm/root-suites.sh raises TEGO_VM_MEM and VM_SUITE_MEM to and says so: a caller's value cannot go under it.
#   *|*          every suite's guest unpacks the base userland (221 MB), the prebuilt helpers (427 MB with both tag sets and
#                the testhooks builds), the copied source (138 MB) and its test binary (19 to 71 MB) into the rootfs, a
#                tmpfs the kernel caps at half of RAM: 810 MB of conformance's tree needs 1.6 GB before one test runs.
#                At 1536M (vm-matrix.yml's global value until 2026-11-26) the unpack failed part way ("Initramfs unpacking
#                failed: write error") and test_conformance's binary, the last file, never arrived: exit 127 on 16 jobs
#                (public issue 91). 2560M leaves a gigabyte for the tests of the small suites.
#   cgroup, 4G   debian-13 and rhel-9: 32 concurrent root-tier runs (TestTier2ConcurrentRunsOfOneBuild/32) were
#                OOM-killed in a 3G guest on both boots; the other rows pass at 3G.
SUITE_MIN_MEM=(
	"*|*|2560M"
	"debian-13|internal/runtime/enforce/cgroup|4G"
	"rhel-9|internal/runtime/enforce/cgroup|4G"
)
# The shards of CI's root-suites job (.github/workflows/ci.yml's root-suites-shard matrix, one runner each), for
# VM_SHARD=<name> test/vm/root-suites.sh: "<name>|<packages>|<part>". <packages> is a space-separated list of exact
# package paths, or "*" for every package of PKGS no other shard names, so a package added to PKGS runs without a new
# shard. <part> is empty (the packages' whole suites) or "j/n": each of those packages' suites, plain and tegobpf, runs
# only part j of its top-level tests (ROOT_SPLITS above), and parts 1 to n of the same packages must all be shards
# here. `test/vm/root-suites.sh --gather DIR` then holds every shard named here to have run and passed, and runs the
# must-pass gate over all of them. On GitHub's runner (run 41706261848, 2026-11-03, one job) enforce/cgroup's tegobpf
# suite took 48 of the job's 91 minutes and its plain one 4, internal/runtime's two 15, test/conformance 10 (its
# TestConformanceKernel 8.7 alone) and the other 28 suites 11 together. The cgroup and runtime shards are ROOT_SPLITS'
# parts, made from it so the two cannot disagree.
ROOT_SHARDS=()
for _e in "${ROOT_SPLITS[@]}"; do
	IFS='|' read -r _name _pkg _n <<<"$_e"
	for ((_j = 1; _j <= _n; _j++)); do ROOT_SHARDS+=("$_name-$_j|$_pkg|$_j/$_n"); done
done
ROOT_SHARDS+=(
	"conformance|test/conformance|"
	"rest|*|"
)
unset _e _name _pkg _n _j
