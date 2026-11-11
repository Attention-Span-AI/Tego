# Tiers

Tego enforces a contract at one of three tiers. All three are in the release binary and in the one `make build` makes. `tego doctor` says which
one your machine gets, `tego run --tier <name>` pins one, and every run records the tier it had (`run_start.tier`).
The per-tier capability table is [spec/backend/CAPABILITIES.md](../spec/backend/CAPABILITIES.md).

| | Tier 1, `landlock` | Tier 2, `cgroup` | Tier 3, `bpflsm` |
|---|---|---|---|
| Mechanism | Landlock and a seccomp supervisor | BPF programs attached to the run's cgroup, and fanotify | The kernel decision plane in LSM mode, on top of tier 2 |
| Root | No | Yes: `sudo tego run`. The launcher is root for the whole run | Yes |
| Kernel | Landlock ABI 2 or newer (Linux 5.19 or later, or a backport such as RHEL 9's 5.14), with cgroup v2 and a subtree delegated to your user. The oldest kernels tested are 6.1 and RHEL 9's 5.14 | Landlock ABI 2 or newer, BPF, BTF and cgroup v2; no boot change | As tier 2, plus `bpf` in the boot LSM list |
| Works out of the box on | Any Linux 6.1 or later from a desktop login, Ubuntu 24.04 included, and RHEL 9 (CPU limits there need a one-time setup by an administrator, below). Not Ubuntu 22.04's stock 5.15, which has Landlock ABI 1. Over SSH, see [INSTALL.md](INSTALL.md#check-the-machine) | Any such host, with root | Debian 13, Fedora, RHEL 9 and 10, Amazon Linux 2023. Ubuntu after one boot line (below). Stock WSL2 from kernel 6.18.54.1 (WSL 3.0.3) |
| Held file reads (`fs.ask_read`) | Yes | Refused when the contract is compiled | Refused when the contract is compiled |
| Record of file reads | Not recorded under `record: summary`, the default: a read that `deny_read` refuses is still refused, and leaves no line. `record: full` records reads and slows every open | Recorded by eBPF; preemptible kernels can skip callbacks, with a shared-build gap (below) | As tier 2 |
| Live Adjustable mode | No | Yes | Yes |
| On a hosted CI runner | Yes: this is the CI mode | Yes, through `sudo`, on `ubuntu-24.04` | No: a hosted runner cannot change the kernel command line |

More rule kinds need a newer kernel at tier 1: TCP port rules need Landlock ABI 4 (Linux 6.7, or Red Hat's RHEL 9
backport), and further rules arrive at ABIs 6, 7, 9 and 10 ([GAPS.md](GAPS.md) B5). `tego doctor` prints your ABI.

RHEL 9 correction: v0.1.0 included the listener outcome hooks, but used the wrong BTF context for individual
syscall exits. On RHEL 9's 5.14, root-tier runs declaring `net.listen` failed before the agent started with
`attach tego_bind_result: cannot create bpf perf link: permission denied`. Ordinary outbound networking without
`net.listen` did not require that hook. The corrected build uses the individual syscall event's context for bind,
listen and exec outcomes; it keeps the required listener hooks and their coverage. The RHEL 9 support claim does
not establish that v0.1.0's listener controls worked. See [GAPS.md](GAPS.md) B5 for the measured boundary.
RHEL's proc-directory oracle test covers its private `fd` directory; the newer `fdinfo` directory permission
check is absent there, and the test reports that coverage distinction.

RHEL 9 CPU limits: on AlmaLinux 9.8 (kernel 5.14.0-687.61.1.el9_8, systemd 252), systemd turns on the memory
and pids controllers by default, but not cpu, for a user's login and for root. Tier 1 runs there, and
`tego doctor` says that cpu is not enabled. A run whose contract sets `limits.cpu` or `limits.cpu_weight` is
refused at start (exit 125), before the agent starts, and the message gives the fix. A `limits.cpu` ceiling in
`/etc/tego/config.yaml` gives every `tego run` a CPU limit, so with one they are all refused, although
`tego doctor` still reports tier landlock for a user. Memory and process limits apply as usual. To allow CPU
limits, an administrator runs this once, then reboots:

```sh
sudo mkdir -p /etc/systemd/system/user@.service.d /etc/systemd/user/app.slice.d /etc/systemd/system/system.slice.d
printf '[Service]\nDelegate=cpu memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/60-tego-cpu.conf
printf '[Slice]\nCPUWeight=100\n' | sudo tee /etc/systemd/user/app.slice.d/60-tego-cpu.conf
printf '[Slice]\nCPUWeight=100\n' | sudo tee /etc/systemd/system/system.slice.d/60-tego-cpu.conf
```

The first two files are for users. The first makes cpu available to each user's systemd, and the second makes it
turn cpu on, as Fedora's does by default. With the first alone, cpu stays off for users. The third is for root
runs: it keeps cpu on in the root cgroup. Writing `+cpu` there by hand does not last under systemd. See
[GAPS B15](GAPS.md).

For administrators: after the reboot, cpu is on in the root cgroup and in each user's systemd, as on a stock
Fedora 44 host. CPU time is then split by weight (100 each unless set) between system.slice and user.slice,
between users, and between the slices under each user's systemd, such as app.slice. The units inside one of those
slices are split this way only once one of them sets a CPU weight or `Delegate=yes` (`systemd.resource-control(5)`).

Syscall outcome hooks also require a readable tracefs event format whose `ret` field is eight bytes at
offset 16, matching the supported BPF syscall exit wrapper. Doctor and the loader reject divergent, missing
or unreadable layouts before loading or adopting the hooks, naming the reason. Doctor and run tier selection
withhold root tiers on any such layout refusal, including listener capability rows; present exec events do
not enter the optional attachment fallback for a layout failure.

The 6.1 plane uses probe reads and does not require `bpf_rdonly_cast`; its read-only build is selected only where
that kfunc exists. Under `lockdown=confidentiality`, 6.1 cannot load the probe reader. Both root tiers' tracing
callbacks can be skipped on a preemptible kernel. A `bpf-trampoline-miss/shared-build` record gap reports skipped
executions across that build during the run, including other runs and ungoverned tasks. It is not an exact count
of this run's lost records; one skipped callback can suppress multiple records. The recorder resolves and retains
program instances from their active links, rather than independent program pins. Missing, changed or unreadable
attachments/counters produce `bpf-trampoline-counter-unavailable`. Receipts and views keep coverage incomplete
and describe shared skipped executions, never “N events lost” or proof of loss in this run. Overlapping runs may
report the same skip. See [GAPS C53](GAPS.md).

## Platforms checked for v0.1.1

Measured on 2026-11-10 in local virtual machines. The user and root checks on RHEL 10 and arm64, and the first run
of the RHEL 9 root test suites, used a build from just before the overlayfs fix in the changelog's Security list.
That fix changes only the decision plane's programs. The overlayfs results and the second RHEL 9 run used the fixed
build, which is v0.1.1's code, and the Fedora 44 results used both builds.

### RHEL 10

On stock AlmaLinux 10.2 (kernel 6.12.0-211.74.1.el10_2, systemd 257, SELinux enforcing), no setup is needed: systemd
turns cpu on by default. A new user over SSH got tier landlock: `tego doctor --require landlock` and `tego test`
passed, a run refused a `deny_read` file and recorded it, `tego events <run> --verify` and `tego receipt <run> --verify`
passed, and CPU, memory and process limits applied. As root, `tego doctor` reports tier bpflsm with 27 of 27 hooks,
and runs at tiers cgroup and bpflsm refused a `deny_read` file, verified their records and applied CPU, memory and
process limits. With the fixed build, root runs at both tiers refused to make a file already on an overlay mount,
under a write entry, executable with `mprotect`; the build before the fix allowed it. The binaries were copied in,
not installed by the release installer, and the root test suites were not run there.

### arm64

In an emulated arm64 guest (QEMU without KVM, Ubuntu 24.04, kernel 6.8.0-147), a new user got tier landlock and
passed the same checks as on RHEL 10, limits aside; as root, `tego doctor` reports tier cgroup with 27 of 27 hooks
(Ubuntu's boot LSM list has no `bpf`). An emulated CPU is not arm64 hardware. On hardware, CI's `build-test-arm64`
job runs on GitHub's arm64 runner: it builds Tego, runs the unit tests, root `tego doctor` and selected root tests,
the plane's load test among them. It does not run the steps above as a user, and the full root test suites run on
amd64 only.

### Root test suites on RHEL 9

On stock AlmaLinux 9.8 (kernel 5.14.0-687.61.1.el9_8, SELinux enforcing, xfs), root `tego doctor` reports tier
bpflsm with 25 of 25 hooks, and root runs at tiers cgroup and bpflsm refused a `deny_read` file and verified their
records, with the fixed build too.

v0.1.1's root test suites (`test/vm/root-suites.sh`) do not all pass there. Every failure and both hangs below are
now explained. Apart from the overlayfs case, which v0.1.1 fixes, each is a bug in a test or a test that assumes a
host unlike RHEL 9; no product bug was found. Those tests are fixed for the next release: with the fixes, every
suite that failed or hung there runs to the end and its tests pass, with the skips named below. The suites ran as
root in local guests, one suite at a time, not in CI's shards. As of 2026-11-10:

- **Runs:** the first run reached 31 of 33 suites: 5817 top-level tests passed, 14 failed and 247 skipped. The
  second run added the two suites the first did not start: `test/conformance` (78 passed, 1 failed) and the four
  parts of the `tegobpf` build of `internal/runtime/enforce/cgroup` (565 passed, 1 failed). `internal/runtime`
  finished in neither run, because one of its tests hangs (below).
- **Fixed in v0.1.1:** the plane test's overlayfs case (the Security fix). With the fixed build that check passes on
  this kernel.
- **Two hangs, both in tests:** `TestHeldCloseEndsTheListenerBeforeTheDescriptorLimit` in
  `internal/runtime/enforce/cgroup` marks the mount of its temporary directory for fanotify permission events, and
  then starts a helper from its own test binary, which was on the same mount on this guest. Go starts the helper
  with vfork, so the helper's exec waits for the test's own fanotify group; if a garbage collection starts in that
  window, the whole test process stops, and Go's test timeout never fires. With `GOGC=1` it hung in 3 of 100 runs
  without the CPU setup above and in 1 of 100 with it, so the setup is not the cause. In `internal/runtime`,
  `TestIntegrationExecRuleNonRegularImage` runs its agent through `/bin/sh`, which is bash on RHEL: bash answers the
  refused exec of a FIFO by opening the FIFO to read it, and that open waits for a writer forever, with or without
  Tego.
- **SELinux execmod:** with SELinux enforcing, this host refuses to make a modified private file mapping executable,
  with or without Tego, so a contract cannot allow it here. SELinux decides before the plane's LSM hook runs, so in
  LSM mode the run's record has no line for that refusal; in fmod_ret mode the plane's own line is there
  ([GAPS.md](GAPS.md) B16). The plane's step C test, the conformance suite's execmod case and the plane's exec-map
  run test expect the mapping to be allowed, or decided by the plane, and fail. With SELinux permissive and the
  fixed build, the step C test passes. AlmaLinux 10.2 enforcing does not refuse it.
- **NSS:** `/etc/nsswitch.conf` has `passwd: sss files systemd`, so a program in a run that looks up a user or group
  connects to `/var/run/nscd/socket` and `/var/lib/sss/pipes/nss`. Under a contract whose `net:` section allowed one
  TCP address, the run refused and recorded those connects (tier landlock, launched as root). RHEL's bash also opens
  `/dev/tty` when it starts, which the run refused and recorded. Three tests do not expect these lines.
- **`RESOLVE_CACHED`:** on this kernel, `openat2` with `RESOLVE_CACHED` through a symlink failed with `EAGAIN` on
  xfs and on a tmpfs mounted `strictatime`, and succeeded on a `relatime` tmpfs once the link's access time was
  updated, so SELinux is not the reason. Tego's two-syscall fast path for an exec path through a symlink is not used
  there, and the full walk answers, which was right. One supervisor test expects the fast path. Which kernel
  function makes it fall back on xfs is not isolated.
- **Host's os-release:** a doctor golden test reads the host's `/etc/os-release`, so on any RHEL-family host it gets
  doctor's `grubby` fix line instead of the Debian `update-grub` line it expects. Doctor's line is right for the
  host; the test is wrong.
- **OOM timing:** a cgroup test gives the kernel 20 s to stop a child capped at 16 MiB with no swap. On the stock
  guest it was not stopped in time. Run from xfs, the child's own code was dropped from memory and read back again
  and again: in 25 s it hit its limit 666,918 times and was not killed, while its memory stayed within the cap. Run
  from tmpfs, it was killed in 0.03 s. After the CPU setup and a reboot the test passed once, in 16.81 s against the
  20 s bound; the setup is not shown to be the cause. Whether the kernel or xfs causes the thrash is not isolated. A
  program at a run's memory limit whose code is on xfs may thrash the same way; that was not measured with `tego run`.
- **No `WAIT_KILLABLE_RECV`:** this kernel refuses that seccomp listener flag, so a datagram or connect whose answer
  races a signal can be recorded twice. Under load, the UDP flood test once saw 4 more lines than datagrams in
  100,048 notifications; alone, it passed 6 of 6 runs.
- **Other host differences:** one cgroup test needs cpu on in the root cgroup and passes after the CPU setup above.
  xfs refused a 1024-byte symlink target, and two tests need one of about 2.5 KB. `nobody`'s home is `/`, so a root
  sweep of a run owned by `nobody` anchors it in `/.tego` at the file system root, which one test does not expect.
  Python 3.9 has no `os.unshare`, which one test calls. RHEL's bash (5.1.8) retries a refused create without
  `O_CREAT`, which gives one test a second line it does not expect. One conformance case expects RHEL 9's 5.14 to
  lack BPF perf links, which this 5.14 has.
- **Skips:** RHEL 9 refuses `io_uring_setup`, and those tests skip, as CI's skip list allows. CI's skip list does
  not name ten skips seen there, each with its own message: 6 btrfs tests (RHEL 9 ships no btrfs), one that needs
  busybox, one that skips while auditd runs, as it does on the stock image, and two `/proc/<pid>/fdinfo` cases,
  because the agent can list that directory there. Six more came from the test setup, not from RHEL: two plane
  compaction tests whose fixture only sets up ext4, f2fs or tmpfs, and four web tests that need node, which the
  guest did not have.

### Plane tests on Fedora 44

On Fedora 44 (kernel 6.19.10-300.fc44), v0.1.1's plane load test and its step A, B and C tests fail, with the build
before the overlayfs fix and the fixed build alike. Those tests hold the plane's programs to 20,000 verified
instructions (`socket_listen` to 64,000), and on this kernel the largest verifies in 63,939 (the kernel's own limit
is 1,000,000). Root `tego doctor` there loads the plane in LSM mode and reports tier bpflsm with 27 of 27 hooks.

The count comes from the kernel, not from the programs. The same bytes of the programs that call `bpf_loop` verify
in at most 14,562 instructions on mainline 6.19.3 and in up to 63,939 on mainline 6.19.4, 6.19.10 and 6.19.14; they
grew by up to 9.5 times, and the programs without `bpf_loop` did not change. Fedora 44's 6.19.10 counts exactly what
mainline 6.19.10 does, and on Fedora's 7.0.14 and 7.2.9 kernels the programs that call `bpf_loop` verify in at most
19,834. The likely cause is the stable backport, in 6.19.4, of upstream commit f597664454bd ("bpf: bpf_scc_visit
instance and backedges accumulation for bpf_loop()"). That is named from a bisection over releases, not isolated: no
kernel was built without it. The tests' budget is fixed for Linux 6.19.4 to 6.19.y for the next release.

## Choosing

- **No root, or you are not sure:** tier 1. It enforces files, programs and network rules, some of them in Tego's supervisor and
  not in the kernel ([spec/backend/CAPABILITIES.md](../spec/backend/CAPABILITIES.md) says which), and records exec, write and
  connect, not reads.
- **You can use `sudo` and want reads recorded:** tier 2.
- **You also want the decision plane to run as LSM hooks:** tier 3.

Granting `sudo` for `tego` is granting root. The root tiers are for machines whose `sudo` users are already their
administrators ([OPERATIONS.md](OPERATIONS.md), "Privileged path"). `tego-control`, which runs the dashboard, never runs as root.

## Tier 3 on Ubuntu

`bpf` is not in the boot LSM list on Ubuntu 24.04, 25.10 or 26.04, or on WSL2 kernels before 6.18.54.1. On Ubuntu this is one change
to the kernel command line:

1. Run `sudo "$(command -v tego)" doctor`. Its `lsm` line prints the line to use, built from the list your machine runs now,
   so no other security module is dropped.
2. Put that `lsm=...` into `GRUB_CMDLINE_LINUX_DEFAULT` in `/etc/default/grub`, run `sudo update-grub`, and reboot.
3. Check: `cat /sys/kernel/security/lsm` lists `bpf`, and `sudo "$(command -v tego)" doctor` ends its table with `tier: bpflsm`.

On an Ubuntu cloud image step 2 has no effect: `/etc/default/grub.d/50-cloudimg-settings.cfg` sets the same variable after
`/etc/default/grub` is read. Add a file that is read later instead, with the list `doctor` printed, then run `sudo update-grub`
and reboot:

```sh
echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=<the list doctor printed>"' | sudo tee /etc/default/grub.d/99-tego-lsm.cfg
```

Do not copy an `lsm=` line from somewhere else: it replaces the whole list. Without `bpf` in the list, `tego run --tier bpflsm`
is refused and never runs at another tier. On Fedora and the RHEL family, `grubby --update-kernel=ALL --args="lsm=..."` does
the same job.

At tier 2 without `bpf` in the list, the decision plane loads as `fmod_ret` hooks where the kernel allows it, and the kernel
decides opens, execs and file changes. `tego doctor` says which mode you are in. [OPERATIONS.md](OPERATIONS.md) ("Tier 3 and the
decision plane") describes the residual.

## Directory moves and protected names

At root tiers `cgroup` and `bpflsm`, a directory move that loses built-in `.env` name protection is refused,
even if both ends are writable and no secret exists there ([GAPS.md](GAPS.md) C55). An ordinary
`pip install --target ./target` staged in `./tmp` under a broad writable parent hits this limit: `target` is a
dependency boundary outside the parent's name coverage. Pip can copy instead and exit 0 with recorded refusals.
This occurred in v0.1.0 too. Tier `landlock` permits those pip moves.

Pre-create staging and target and explicitly declare both in `fs.write`. **Declarations alone do not extend
name coverage.** Keep the contract outside writable paths and launch from target: for a contract in the project
parent, use `fs.write: ["../tmp/", "./"]` and `(cd target && tego run ../agent.yaml ...)`. Use absolute entries
or rebase all relative entries for that cwd, set TMPDIR to the absolute staging path, and keep matching
`exec.allow` directory rights at both ends for native modules. The contract directory covers staging, and cwd
covers target. The refusal and `tego learn` explain this tested remedy without automatically allowing refusals.
Alternatively use a covered destination such as `site-packages`. A further dependency boundary and separate
denies/REFER still have their existing limits. See [OPERATIONS.md](OPERATIONS.md#directory-moves-and-protected-names-c55).

Landlock has no name-mutation floor: held reads retain launch-pinned objects, but future name-only matches
outside watched launch targets can be renamed, exchanged or hard-linked out of coverage before they are pinned
([GAPS.md](GAPS.md) A11). Keep secrets outside writable folders; changing tier does not erase other stated limits.

## What the tiers do not change

The tier does not change what Tego cannot do: an allowed destination is an open channel, an allowed interpreter can do
anything in its own memory, and the record is tamper-evident against an agent held by a contract, not against you, and not
against an agent in a record-only run. Those are in [GAPS.md](GAPS.md) (A1, A2, C9). Tier 3 decides only what happens inside a run's cgroup and only what the contract names.
