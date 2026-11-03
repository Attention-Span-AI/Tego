# test/vm — kernels and root, in a VM

Two harnesses live here. Both boot a KVM guest with `kvm-run.sh` and return the command's own exit code.

| Harness | What it is for | Needs on the host |
|---|---|---|
| `matrix.sh` + `run-matrix-row.sh` (`make vm-matrix`, `make vm-test`) | the kernel matrix (P0-DESIGN §10): `tego doctor` as the user and as root, and kill tests 1, 2, 4, 5, 6 and 7 with their root halves, on each row's own distro kernel | `/dev/kvm` read-write, network once per row to fetch its kernel, `jq`, `python3`, `xz`, `zstd` |
| `kvm-run.sh` + `root-suites.sh` (`make vm-root-test`) | the privileged Go suites, as root, on this box's own kernel with `bpf` in `lsm=` | `/dev/kvm` read-write, `apt-get download`, `dpkg-deb`, a static busybox. No root, no qemu, no clang |

`VM_MODULES` (space-separated) has each `root-suites.sh` guest load those kernel modules before its suite, through
`kvm-run.sh --module`: `VM_MODULES` defaults to `suites.sh`'s `GUEST_MODULES`, `overlay btrfs unix_diag tcp_diag`, which
says what needs each, and `scripts/coverage.sh --vm`'s guests load the same (*2026-11-02*: they loaded none, and
`internal/control/web`'s and `internal/control/cli`'s suites failed in them, since without `tcp_diag` the dashboard
refuses every sign-in). The decision plane's overlayfs cell (`internal/bpf`
`TestPlaneStepAHooksDecide`'s `overlay` subtest) needs overlay: without it the subtest skips, and `root-skips.txt` allows
that only on a kernel with no overlayfs. `internal/runtime/enforce/cgroup`'s `TestPlaneRunBtrfsSubvolumeInodeIdentity`
needs btrfs: it mounts a loop-file copy of an embedded empty btrfs (no btrfs-progs), and `root-skips.txt` allows its
skip only in the plain build, so the tegobpf build fails without the module (*added 2026-10-05*). `unix_diag` and
`tcp_diag` answer the supervisor's and the dashboard's sock_diag lookups, which refuse what they cannot look up. On a
hosted runner (`VM_HOST=sudo`) the kernel loads each on demand. `VM_MODULES=""` loads none.

`TEGO_VM_ROW=<row>` (*added 2026-10-05*) runs `root-suites.sh` on a kernel-matrix row's own kernel (below) instead of this
box's: the row is fetched (unless `TEGO_VM_KERNEL` already names it), every guest boots it, and each suite's guest gets the
row's name in its environment, where `test/conformance` reads it as a baseline entry's `where.row` and `enforce/landlock`'s
integration tests read it to hold `fedora-7.2` to Landlock ABI 10. `host` is this box's own kernel. A name that is not a row, a
doctor-only row (no tier is offered there, so no suite has anything to run), `VM_HOST=sudo` and a `TEGO_VM_KERNEL` that
names another row's kernel are usage errors (exit 2) before anything is built. `kvm-run.sh` fetches a module package with apt
for this box's own kernel only, so a row's guests load no module unless `VM_MODULES` names some (the default list ended every
guest at exit 97), and the tests that want overlayfs or btrfs meet the row kernel's own, where `root-skips.txt` says which of
them may skip. The modules `VM_MODULES` names on a row come from the row's own tree, which `fetch-kernel.py --modules <row>`
extracts (below; debian-13 has one). The nightly runs it as `TEGO_VM_ROW=$KERNEL test/vm/root-suites.sh ...`.

## The tier-3 perf suite: `make vm-perf`

`test/vm/perf.sh` boots one guest and runs `test/perf/cmd/perfsuite` as root: cold and warm start with per-phase timings,
Prepare's fill at 1, 1000 and cap-1 rows, a raw open loop per mode, and 2, 8 and 32 concurrent runs against a landlock control. It
fails over a limit in `test/perf/perf.go` and prints `TARGET-MISS` over a spec's target; `PERF_BOOT=default` boots with the kernel's own
`lsm=` (the plane in fmod_ret mode), `-budget name=value` moves a limit. `PERF_KERNEL=<row>` boots a kernel-matrix row's
kernel (below) instead of this box's, fetched as `matrix.sh` fetches it, with the console log in `perf-<row>-<boot>.console`; a
name that is not a row, a doctor-only row (no tier is offered there) and a kernel that cannot be fetched stop it before the
build (exit 2, 2 and 97). The budgets are the 6.17 guest's, so on another row an exit of 1 is a figure to record, not a gate.
`perf_test.sh` holds this to stand-ins. Results and open conditions: docs/p0/enforce-plane.md §10.1.

## ADR 0021's pairs runs: `make vm-pairs`

```sh
make vm-pairs                                                  # every variant, the bpf boot, this box's kernel
make vm-pairs VARIANTS="pie two-inodes" PAIRS_N=50             # a smoke: 50 pairs per phase
PAIRS_KERNEL=al2023-6.12 PAIRS_BOOT=both test/vm/pairs.sh      # a kernel-matrix row, both boots
```

`test/vm/pairs.sh` builds `tego` (static) and `tego-pie` (`-buildmode=pie`), both `-tags tegobpf,tegotesthooks` so the
plane can be pinned, plus `permlistener`, and refuses to boot anything unless `test/vm/cmd/elfinterp` finds a loader and
`ET_DYN` in the PIE and no loader in the static build. It then boots one guest per variant and boot (a freeze loses one variant,
not the rest) and runs `tier2-pairs.sh` once per phase:

| Variant | Phases (`PLANE:MODE:PAIRS`) | What else |
|---|---|---|
| `two-inodes` | `fanotify:plain:400 fanotify:timeout:300 fanotify:kill:300` | `COPY_B=1`: the pair's second launcher is a copy at another inode |
| `third-party` | the same | `permlistener` (allow-touch) marks `/` beside the runs |
| `guest-freeze` | `fanotify:plain:200 fanotify:timeout:300` | `AGENT_SLEEP=1`, uprobe capture: a whole-guest freeze once reported with two concurrent runs of one build |
| `pie` | `fanotify:plain:50 auto:plain:50` | the PIE against the static build, and `SELF_DENY`: a `deny_read` over the PIE's own file, by a hard link beside the secret (agent-contract R10 keeps a write entry off the file itself) |
| `plane-control` | `auto:plain:200` | `COPY_B=1` and `permlistener`: the harness with a plane mode (not an ADR 0021 condition) |

`tier2-pairs.sh` pins each phase's plane through `TEGO_TEST_PLANE` and judges each pair once, from all of its evidence,
before cleanup (`assert_pair`, `judge`; ADR 0021's 2026-10-19 note holds the table). The pair first settles: it waits up
to `SETTLE` seconds for every started run's `run_end`, which a killed launcher's reaper writes once the run's cgroup is
empty. Every started run then names that `decision_plane`, refuses a `deny_read` file on `/` (nested in a write entry, so
Landlock lets the read through to the plane or the listener) at most once and only by that plane's mechanism, holds no
other verdict on it and no exec line for the stage, and is one launcher's by `run_start`'s `launcher_pid` (under `timeout`,
the pid the launcher wrote before its exec). Each launcher gets one verdict from its exit status, whether a kill phase's
`SIGKILL` targeted it, its own run and its output (the agent says `PAIRS-READ opened` or `refused`, and the secret's
content is the read's effect), and nothing else passes: `complete` (exit 0, one refusal, `run_end` reason `exit`, the
agent's read refused), the target's `killed-early`, `killed-in-run` or `killed-read` (exit 137), or `failed`, which fails
the pair. `killed-read` is E15's stated window on the fallback (the killed launcher's agent runs undecided by fanotify until
the reaper kills it): it passes only in a run that never refused the file and that its reaper closed (`run_end` reason
`orphaned`), and is counted (`killed_reads`) and warned. A kill phase draws its kill point from the previous pair's length and fails when fewer
than half its pairs lost their targeted launcher (`KILL_MIN`; a phase under 20 pairs can miss it by chance). Each console is
read into `$VM_OUT/pairs/<row>/<boot>/<variant>/summary.json` (`pairs`, `ok`, `stall`, `plane`, `inodes`, `listener`
events/tego/late, `cleanup_retries`, `kills`, `kills_started` and `killed_reads`, the phases and the reasons for a failure); a variant passes
only with `PAIRS-DONE n/n` in every phase and no watchdog line, and the script exits 0 only when every variant passed. A listener event answered at its
deadline is a warning. A `PLANE=auto` phase that ran the fallback fails `plane-control` (it then controls nothing) and is a
warning for `pie` (a row with no plane mode). `PAIRS_N` replaces every phase's count, `PAIRS_BOOT=both` boots each variant on the host's `lsm=` plus
`bpf` and on the kernel's own, and `PAIRS_KERNEL=<row>` boots a kernel-matrix row (a doctor-only row is refused). `pairs_test.sh`
holds the driver and the console reader to stand-ins; `tier2-pairs_test.sh` holds the guest script's judgement (every
combination of one launcher's evidence against the table, and the loop over stand-in launchers) and setup.

## The kernel matrix: `make vm-matrix`

```sh
make vm-matrix                                   # every row
make vm-matrix VM_ROWS="debian-13 rhel-9"        # some rows
make vm-test VM_KERNEL=al2023-6.12               # one row (an unknown row is a usage error, exit 2)
test/vm/matrix.sh --save-fixtures ubuntu-24.04   # and copy that row's recorded ledgers into test/fixtures/ledger
test/vm/run-in-vm.sh fedora-7.0 -- /bin/sh -c 'uname -r; cat /sys/kernel/security/lsm'   # one command on one row
VM_ONLY=kt4 VM_KT4_TOOLS=1 VM_KT4_TIERS=bpflsm test/vm/matrix.sh debian-13   # kill test 4 alone, at tier 3 (KT4_TIERS)
```

| Row | Kernel | Source (`fetch-kernel.py`) |
|---|---|---|
| `ubuntu-24.04` | 6.8 GA | `linux-image-generic`'s image in noble-updates, archive.ubuntu.com |
| `debian-13` | 6.12 | `linux-image-amd64`'s image in trixie, deb.debian.org |
| `rhel-9` | 5.14 | AlmaLinux 9 BaseOS `kernel-core` (RHEL's own packages need a subscription; AlmaLinux rebuilds the same sources and configuration) |
| `al2023` | 6.1 | Amazon Linux 2023 core `kernel`, through the repository's mirror list |
| `al2023-6.12` | 6.12 | Amazon Linux 2023 core `kernel6.12` |
| `fedora-7.0` | 7.0 | the newest 7.0.x `kernel-core` on koji (Fedora's own repositories follow the newest series) |
| `ubuntu-25.10` | 6.17 | `linux-image-generic`'s image in questing-updates, archive.ubuntu.com (*added 2026-10-05*): the GA kernel of the series this project is developed on, Landlock ABI 7, `bpf` not in its own `lsm=` |
| `fedora-7.2` | 7.2 | the newest 7.2.x `kernel-core` on koji (*added 2026-10-05*): Landlock ABI 10, so the pathname unix socket rules of ABI 9 and the UDP port rules of ABI 10, which no other row's kernel has, run against a kernel that has them (`TestIntegrationUnixConnect` and `TestIntegrationUDPPorts` in `enforce/landlock`: with Landlock alone, no supervisor, an undeclared pathname socket and UDP port are refused by the kernel) |
| `ubuntu-22.04` | 5.15 GA | `linux-image-generic`'s image in jammy-updates, archive.ubuntu.com (*added 2026-10-05*): **doctor-only**, see below |

`ubuntu-22.04` is the one **doctor-only** row (`fetch-kernel.py --list`'s fourth column, or `--body <row>`; its
`DOCTOR_ONLY` set). Its GA kernel, 5.15, has Landlock ABI 1, and ABI 1 kernels (5.13 to 5.18) are unsupported
(ARCHITECTURE §14): doctor offers no tier there, tier 2 never runs, and no kill test has a tier to run at. `matrix.sh`
boots such a row once and runs `run-matrix-row.sh --only doctor-refusal`, which is `doctor-refusal.sh` as the user and
as root: `tego doctor` exits 1 and says `tier: none` and ends on `fix: boot a kernel >= 5.19 (Landlock ABI 2,
LANDLOCK_ACCESS_FS_REFER)`; `doctor --require landlock` exits 211; `doctor --json` holds no tier and an ABI below 2;
and `tego run` exits 125 `[tier-unavailable]` with that fix, with the tier auto-selected and with `--tier landlock`
pinned. A kernel with no Landlock at all (`boot a kernel >= 5.13 with CONFIG_SECURITY_LANDLOCK=y`, or `add landlock to
the kernel's lsm= line`) is the same refusal with another fix, and passes. The check fails when a part is wrong and
when the machine offers a tier at all, since a doctor-only row whose kernel gained one should run in full; it never
starts a run on a machine whose doctor offers one. `doctor-refusal_test.sh` holds each part to a stand-in that gets it
wrong. `VM_ONLY` does not apply to the row, and the nightly reads the body from `fetch-kernel.py --body`, so no row name
is written in `vm-matrix.yml`'s steps. Whether Ubuntu 22.04 GA is a promised platform is the maintainers' call;
the row asserts what holds either way, that Tego refuses the machine and says how to fix it. First run, 2026-10-05,
5.15.0-198-generic (5.15.0-198.208) in a 1536M guest: Landlock ABI 1, doctor's tier none, both identities pass.

`fetch-kernel.py` needs no root: a `.deb` is an ar archive around a tar and an `.rpm` is a lead and two
headers in front of a compressed cpio, so it streams the one file it needs, `vmlinuz`, into
`~/.cache/tego-vm/kernel/matrix-<row>/` with a `source.json` naming the package and version. It fetches
once; `--refresh` fetches the newest build again. No module is loaded: the guest's root is an initramfs of
this host's userland and the console is the 8250 UART every one of these kernels builds in.

`fetch-kernel.py --modules <row>` (*2026-11-02*) extracts the row's own module tree, for a guest that wants one:
`kvm-run.sh --module` reads `matrix-<row>/mods/lib/modules/matrix-<row>/` before it asks apt, and apt has no module
package for a row's kernel. The tree is the `lib/modules/<release>/` of the package the same call has just
authenticated, extracted once per package and stamped with its digest (`mods/.package-sha256`); a fetch that brings
another package removes it with the old image. Only Debian's image package carries its modules (debian-13). Ubuntu
ships them in a package of their own (`linux-modules-<release>`) and an RPM row's `kernel-core` carries only some, so
those rows are refused (exit 97), and `kvm-run.sh` refuses a `--module` on a row with no tree, naming this command.
`kvm-run.sh` loads a module after what modinfo's `depends:` names, not its `softdep:`s. On debian-13's 6.12 btrfs
needs `libcrc32c`, whose init needs a crc32c algorithm that Debian builds as a module, so a guest that loads btrfs
there names `crc32c_generic` before it. `TestPlaneRunBtrfsSubvolumeInodeIdentity` mounts its btrfs on a loop device,
and Debian builds `loop` as a module too (Ubuntu builds both in), so a guest that runs it there names `loop` as well.
The nightly's coverage step names both: its debian-13 guests load `overlay crc32c_generic loop btrfs unix_diag
tcp_diag`, root-suites.sh's list with the two Debian needs (*2026-11-02*: the tests those modules un-skip there, the
overlayfs cells, the btrfs test, the supervisor's unix_diag tests, the peer check's TCP lookup and the dashboard's
sign-ins, passed on that kernel as root).

Publisher authentication is mandatory. `gpg` and `gpgv` verify signatures against
[shipped keys pinned by full fingerprint](keys/README.md): Ubuntu/Debian
`InRelease` authenticates `Packages.xz`, which authenticates the DEB; AlmaLinux and
Amazon Linux `repomd.xml.asc` authenticates the primary index and RPM; Fedora uses
Koji's signed RPM variant and checks both its header signature and the compressed
payload SHA256 recorded in that signed header. Missing, invalid, expired/revoked,
unknown-key or weak-hash signatures refuse the row before extraction/boot (exit 97).

The cache retains the package and signing proof under `proof/`. Every cache reuse
reverifies that proof and re-extracts the kernel, then compares the authenticated
image bytes with `vmlinuz`; editing both the image and its `source.json` digest
cannot authorize a replacement. Legacy caches without proofs are fetched again.
`source.json` records the signing method, publisher fingerprints and proof digest,
and is included in the matrix summary. Cached proofs attest a historical package;
they do not promise the latest available security update. `--refresh` downloads
current metadata, checking `Valid-Until` where the publisher provides it.

Results of 2026-09-29 (`root-suites.sh` for `internal/runtime/observe`,
`enforce/cgroup`, `internal/bpf`, `internal/doctor`, `test/conformance`, then `matrix.sh` with `VM_TEST_TIMEOUT=900`, 1536M guests).
The suites were run before and after the test and Memlock fixes; the table is after (a suite is both builds, plain and `tegobpf`):

| Row | Suites | Kill tests 1, 2, 7 (b), doctor | Left failing |
|---|---|---|---|
| `rhel-9` 5.14 | all pass | all pass, doctor 26 of 26 hooks (`fexit/security_file_truncate`, `cgroup/connect_unix`, `cgroup/sendmsg_unix` absent by design), uprobes 6 of 6 | none |
| `al2023` 6.1 | enforce/cgroup, observe, bpf, doctor failed (tegobpf builds); fixed, see below | kt1 pass; kt2 uprobe half and kt7 (b) failed, pass since the fix below; doctor 26 of 26, uprobes 6 of 6 since then | none (fixed: `uprobe_ssl`'s `tego_ssl_write`, `tego_ssl_write_ex`, `tego_ssl_read_return` were refused by the 6.1 verifier ("R2 unbounded memory access" at `bpf_probe_read_user`, "invalid access to memory, mem_size=592 off=80 size=32768"), so capture was unavailable and a run with a tokens budget was refused (exit 125)) |
| `ubuntu-24.04` 6.8 | same set as `al2023`, the same cause, the same fix | kt1 pass; kt2 uprobe half and kt7 (b) failed, pass since the fix below; doctor 29 of 29, uprobes 6 of 6 since then | none (fixed: the same three `uprobe_ssl` programs) |
| `debian-13` 6.12 | all pass | all pass, doctor 29 of 29, uprobes 6 of 6 | none (kt4 pip missed R18's 19 of 20 on a loaded host: timing) |
| host 6.17 (control) | all pass | all pass, doctor 29 of 29 | none (kt4 pip at tier landlock missed R18 on a loaded host: timing) |

The uprobe rows were fixed and run again the same day (root-suites.sh per row with `TEGO_VM_KERNEL=matrix-<row>`,
then `matrix.sh al2023 ubuntu-24.04 host`): clang had dropped `tego_ssl_emit_class`'s clamp as dead and passed the read a
copy of the length from a stack slot the class branches had not tested, which 6.12+ verifiers follow and 6.1 and 6.8 do not;
the clamp now follows `barrier_var(n)` right at the call (internal/bpf `TestSSLUserReadSizeIsClampedAtTheCall` checks the
compiled objects). `TestObjectsLoadOnThisKernel/uprobe_ssl` (6 of 6 programs), the `capture/uprobe` suite,
observe's `TestIntegrationKernelRecordDrivesCapture` and doctor's `TestIntegrationAsRoot` pass in the tegobpf build on
rhel-9 5.14, al2023 6.1, ubuntu-24.04 6.8, debian-13 6.12 and 6.17, and on 6.17 under `lockdown=confidentiality`
(uprobe_ssl and `capture/uprobe`); kt2's uprobe half (20 of 20 pairs) and kt7 (b) (5 of 5 model requests) pass on al2023,
ubuntu-24.04 and 6.17. Kill test 4 missed R18 on al2023 in that run (12 and 9 of 20) with other guests running beside it: timing.
The pre-6.7 unix skips and the pre-6.2 `tego_file_truncate` skip are in `root-skips.txt`.

Found and fixed by this run: `bpf.Memlock` read 0 for a ring on 6.1 (fdinfo has no size for a ring buffer before 6.2), so
`bpf.ring_budget` could be passed without limit (now charged `ringFootprint`); the suites' `trace_proc` loaders
and doctor's BTF checks assumed `security_file_truncate` (6.2+; RHEL 9's 5.14 carries it in its BTF and doctor holds it back
by version, 6.1 has neither); `TestTier2ConcurrentRunsOfOneBuild` counted the exec of `true` from the kernel record, which
since ADR 0016 step 3 is the supervisor's line (failed on every kernel, 6.17 too).

The 2026-09-29 rows count the six required individual TLS programs. ADR 0026 (8)'s 2026-10-04 implementation adds
two optional multi dispatchers, which the kernel's measured multi-link capability selects; a kernel without it keeps
individual capture. No dated result of both delivery paths is recorded here yet.

Results of 2026-09-30, tier 3 (TIER3-PLAN T11; `matrix.sh` per row with `VM_KT4_TOOLS=1`, 1536M guests;
`VM_BOOTS=both root-suites.sh` on the 6.17 guest):

| Row | bpf LSM | doctor as root | kt1 bpflsm | kt4 pip / npm / go at bpflsm | kt6 (c) | kt7 (b): cgroup / bpflsm |
|---|---|---|---|---|---|---|
| `debian-13` 6.12 | kernel's list | bpflsm | PASS | 20/20 / 4/20 / 0/20 | PASS | PASS / PASS |
| `rhel-9` 5.14 | kernel's list | bpflsm | PASS | 20/20 / 20/20 / 0/20 | PASS | PASS / PASS |
| `al2023` 6.1 | kernel's list | bpflsm | PASS | 20/20 / 3/20 / 0/20 | PASS | PASS / PASS |
| 6.17 guest, both boots | lsm= | bpflsm / cgroup | – | – | – | – |

On `enforce/cgroup`, `internal/bpf`, `test/conformance`, `internal/doctor` and the
supervisor on both 6.17 boots, and `enforce/cgroup` and `test/conformance` on `rhel-9`: conformance (bpflsm axis and
parity included) and `TestPlaneSecondRunAdoptsThePlane` pass everywhere; `TestPlaneRunAdmitsIOUring`'s plane half
skips on `rhel-9`, where `kernel.io_uring_disabled` is set. Found there and fixed: `TestTier2UnixEndToEnd` wanted
an unlisted datagram name to pass below 6.7, which since T15 the plane refuses (EACCES) at a plane mode, and
`TestTier2ConcurrentRunsOfOneBuild/32` was OOM-killed in 1536M guests; `VM_SUITE_MEM=internal/runtime/enforce/cgroup=2560M`
gives that suite's guests the memory its 32 runs need, and both pass on `rhel-9`. Doctor's `TestIntegrationForRunAsRoot`
failed on both boots until a later fix.

The table is the rerun with the per-link exec rows in (`VM_KT4_TOOLS=1`), host load average
6 to 43 from other jobs on the host, so kill test 4's timings are those of a loaded host: every other check of the three
rows passed. The first run, before those rows, had kill tests 1 and 4 (pip) at `bpflsm` refused at Prepare: the guest's
userland is this host's (Ubuntu 25.10), whose uutils coreutils are one inode under every command's name. Kill test
4's misses are go at cgroup and bpflsm on every row (0/20) and npm at bpflsm on two; at tier landlock the same kinds
mostly pass, so the cost is the root tiers' own (enforce-plane §10.1).

Results of 2026-10-05 and 2026-10-06, the rows `fedora-7.2`, `ubuntu-25.10` and `ubuntu-22.04` (`matrix.sh fedora-7.2
ubuntu-25.10 ubuntu-22.04`, 1536M guests, the kernels fetched and signature-checked those days; the npm and go kinds of
kill test 4, kill test 7 (a) and kill test 3 are the named skips they are on every row). The last two columns are
`summary.json`'s:

| Row | Kernel | Landlock ABI | `cgroup_mode`, boot 1 / boot 2 | Checks |
|---|---|---|---|---|
| `fedora-7.2` | 7.2.9-300.fc45 | 10 | lsm | doctor: landlock as the user, bpflsm as root; kill tests 1 (all three tiers), 2 (both halves), 4 (pip at all three tiers, 20 of 20), 6 (a, b, c) and 7 (b at cgroup and bpflsm) pass |
| `ubuntu-25.10` | 6.17.0-41 | 7 | fmod_ret / lsm | doctor: landlock, cgroup as root, bpflsm after the lsm= line; kill tests 1, 2, 6 (a, b on the first boot, c on the second), 7 and 4 at cgroup and bpflsm pass; kill test 4 (pip) at tier landlock passed 20 of 20 in the first run (2281 ms against a 2026 ms baseline), missed R18 in the second (4255 ms against 1951 ms, 0 of 20) while two other guests ran on the same host, and passed 20 of 20 again run alone (`VM_ONLY=kt4`, 2506 ms against 2025 ms; cgroup 19 of 20): timing |
| `ubuntu-22.04` | 5.15.0-198 | 1 | none | `doctor-refusal` as the user and as root pass: tier none, the fix `boot a kernel >= 5.19 (Landlock ABI 2, LANDLOCK_ACCESS_FS_REFER)`, 211 for `--require landlock`, 125 `[tier-unavailable]` from `tego run` |

Also on `fedora-7.2` (`TEGO_VM_ROW=fedora-7.2 root-suites.sh`): `enforce/landlock` passes (158 tests ran, 2 skipped as
`root-skips.txt` allows, none failed), among them `TestIntegrationUnixConnect` and `TestIntegrationUDPPorts` with the kernel
refusing an undeclared pathname socket and UDP port with no supervisor in the path; `test/conformance` passes, its tier
landlock axis and the cgroup and bpflsm axes included, against the empty baseline, with `row "fedora-7.2"` in its machine
line (31 ran, 1 allowed skip); `TestLandlockAuditOptIn` and the audit state readers pass; `PERF_KERNEL=fedora-7.2
test/vm/perf.sh -checks start` reports warm starts of 17.0 ms (landlock), 40.6 (cgroup-lsm), 40.8 (cgroup-fmod_ret) and 42.1
ms (bpflsm), PERF-RESULT PASS. `fedora-7.0` reports Landlock ABI 8, so `fedora-7.2` is the one row with ABI 9 and 10.

The first run of the two new rows found kill test 6's halves (b) and (c) failing on both, with the same code on two kernels:
the probe read the breadcrumb through `bpf(2)` while it sat in the run's cgroup, where the decision plane's `bpf` hook
(enforce-plane §2.20) refuses every `bpf(2)` command of a governed task. The probe now reads it after moving back out
(`kt6-fresh-vm.sh`), and the halves pass on both rows; it failed the same way before on any kernel whose plane carries that hook.

Each row boots twice at most. The first boot is a fresh install's: no `lsm=` (`TEGO_VM_LSM=kernel`, so the
kernel's own `CONFIG_LSM` decides) and no lockdown. It runs `run-matrix-row.sh` as root under `--sudo`:
`tego doctor` as the user (§12.2 wants `landlock`) and as root (`cgroup`), then the kill tests, each as the
identity its halves need. When `bpf` is not in the row's active list (Ubuntu), kill test 6 prints the
`lsm=` line doctor printed, and the second boot uses exactly that line to run half (c), R16's "after adding
bpf to lsm= exactly as printed and one reboot", passing the line back as `KT6_LSM_FIX` so the half can report
that the kernel's command line carries it. Debian 13, RHEL 9, AL2023 and Fedora list `bpf` already; there
half (c) runs in the first boot and says bpf came from the kernel's own list, with no boot line.
A row without `bpf` whose first boot prints no `KT6-LSM-FIX` line fails as `kt6/c-fix-missing`: half (c) never ran.

Tier 3 (TIER3-PLAN T11): on the boot where `bpf` is an active LSM (the first on Debian 13, RHEL 9, AL2023 and
Fedora; the second, with doctor's `lsm=` line, on Ubuntu), the row also checks `doctor-bpflsm` (`tego doctor
--require bpflsm` as root must pass: enforce-plane R28's "bpflsm yes") and runs kill tests 1 and 7 (b) at tier
`bpflsm` (`KT_TIER=bpflsm`, `KT7_TIER=bpflsm`, half `b-bpflsm`); kill test 4 adds `bpflsm` to the tiers it runs
whenever doctor offers it, and on the second boot runs it there alone. On a boot without `bpf` one `tier3 - SKIP`
line says so and is not a failure.

Each boot also prints what doctor said as root, `MATRIX-FACTS landlock_abi=<n> cgroup_mode=<mode>` (`doctor-facts.sh`, which
`doctor-facts_test.sh` holds to lines doctor printed in guests), and `summary.json` keeps it per row: `landlock_abi`, and
`cgroup_mode` as `{"boot1": ..., "boot2": ...}`, which the report prints under the row's heading. `cgroup_mode` is the
decision plane tier cgroup decides opens by on that boot, from the `decision plane:` clause of doctor's D7 line: `lsm`,
`fmod_ret`, or `fanotify`, the fallback; `none` where doctor offers no tier cgroup (the doctor-only row, whose clause
names a plane no run can use); `unknown` where it offers the tier and the clause is not one of the three. It is ADR 0021
(7)'s condition, every row selecting a plane mode, as a column: a row that says `fanotify` on any boot is one that
keeps the listener's enforcement role alive. A boot that ran no doctor (`VM_ONLY=kt4`) leaves its slot out.

Into the guest go: the tego binary with the BPF objects (built with `-tags tegobpf` when it builds, else
without, and the root halves then skip by name); `test/e2e`, `test/workloads`, `examples` and `test/vm`;
`jq` and its libraries; the Python packages `test/e2e/pydeps.sh` caches (pip, the §9 build workload's
wheels, the Anthropic SDK), since the guest has no network; and glibc's `librt`, `libpthread` and `libdl`,
which the Anthropic SDK's compiled `pydantic_core` loads (kill test 7 (b)) and the base image lacks. npm, node
and go go in only with `VM_KT4_TOOLS=1`, which carries this host's node with the libraries it loads, the
directory npm's package lives in (on Debian and Ubuntu its dependencies are that directory's other packages,
some linking into `/usr/share/javascript`, so its links are followed; npm's man pages are left out) and the
GOROOT of `$GO` at `/usr/local/go`, without `src/cmd`, `test`, `api`, `doc` and `misc`, each on the guest's
`PATH` through `/usr/local/bin`: about 450 MB more of a guest whose root lives in its RAM. Without it, kill
test 4's npm and go kinds are named skips in the guest and run where a host has them. With it, on 2026-09-23,
both kinds ran as root on every row, at both tiers, from the tegobpf build in 1536M,
2 vCPU guests, and failed R18's 2× bound everywhere, 0 of 20 runs unbroken each. Baseline median / median
under tego / budget, in ms:

| Row | npm, landlock | go, landlock | npm, cgroup | go, cgroup |
|---|---|---|---|---|
| `rhel-9` | 418 / 3713 / 836 | 120 / 3414 / 240 | 429 / 5014 / 858 | 120 / 4564 / 240 |
| `ubuntu-24.04` | 428 / 3518 / 856 | 128 / 3211 / 256 | 433 / 5171 / 866 | 122 / 4719 / 244 |
| `debian-13` | 406 / 2912 / 812 | 121 / 2668 / 242 | 418 / 4570 / 836 | 117 / 3721 / 234 |
| `al2023` | 412 / 4117 / 824 | 122 / 3771 / 244 | 418 / 6329 / 836 | 123 / 5074 / 246 |
| `al2023-6.12` | 410 / 4568 / 820 | 118 / 4214 / 236 | 416 / 7631 / 832 | 123 / 5876 / 246 |
| `fedora-7.0` | 419 / 1260 / 838 | 121 / 1012 / 242 | 416 / 1859 / 832 | 123 / 1261 / 246 |

The excess per run is about what a root run of `true` cost on the same rows in
the 2026-09-23 acceptance run (the doctor probe every root run then paid, and at tier cgroup
the tier's own fixed cost), which a sub-second workload cannot absorb within 2×. Re-run on a build where a root
run at tier landlock no longer probes doctor's programs, with kill test 4's timing fixed, both kinds passed 20 of 20
at tier landlock on every row and still failed 0 of 20 at tier cgroup on every row (that record's re-acceptance
update).

Why tier cgroup still failed, measured on 2026-09-24 in the 6.17 guest (1536M, 2 vCPUs) with a root `tego run
--tier cgroup -- true` under kill test 4's kind of contract, and `strace -f -T`: 1.1 s a run, of which (a) about
0.6 s was the build itself, loaded, verified and attached by every run that was alone on the machine and detached
when it left (one fentry program's load waited 0.40 s for the previous run's pending detach); (b) about 0.1 s was the
fanotify listener's loop waiting out its 100 ms poll timeout after the run was cancelled, since nothing woke it; and
(c) about 0.5 s was the uprobe capture source removing its twenty libssl probes one after another (0.015 s and
0.055 s alternately; closed from goroutines at once they still serialise in the kernel, 0.37 s). Fixed: (b), the
loop is woken by its context's end (`TestACancelledLoopDoesNotWaitOutItsPoll`), and (a), a build lingers for
`bpf.linger` after its last run (ADR 0022, `TestALingeringBuildIsAdoptedAndSweptOnlyWhenIdle`). The same run then
takes 45–60 ms with `capture: off` (tier landlock: 12–18 ms) and 530–600 ms as the contract is, the rest being (c).
Kill test 4 as root, `VM_ONLY=kt4 VM_KT4_TOOLS=1 test/vm/matrix.sh host debian-13` on a loaded host (load average
15; its baselines are up to twice the ones above), runs unbroken of 20, baseline / under tego / budget in ms:

| Row | pip, cgroup | npm, cgroup | go, cgroup |
|---|---|---|---|
| host (6.17) | **PASS** 20/20 — 5173 / 3537 / 10346 | FAIL 0/20 — 508 / 1094 / 1016 | FAIL 0/20 — 149 / 786 / 298 |
| `debian-13` | **PASS** 19/20 — 2284 / 3504 / 4568 | FAIL 0/20 — 584 / 1431 / 1168 | FAIL 0/20 — 205 / 1026 / 410 |

(At tier landlock the host row's pip broke 7 runs on that load and passed npm and go; `debian-13` passed all three.)
(c) measured on its own, the same guest, 2026-09-24, with `capture: auto` against `capture: off` (the uprobe source not
running): `npm install` 1.02-1.07 s against 0.49-0.52 s (bare 0.41-0.43 s), `go build` 0.74-0.79 s against
0.20-0.24 s (bare 0.12 s); `strace` put 4-18 ms on placing the six probes and 0.40-0.55 s on removing them, each
perf link's close taking 14-57 ms. Fixed by ADR 0026 (7) as amended (capture-derive R8): the probes are the build's,
pinned per library and adopted by the next run, and the last run out hands them to `tego __uprobe-detach`, which
removes them 2 s later unless a run holds them again. A grace of 0 was tried first: the next run's placement then
waited for the old probes' detach (pre-attach 75-340 ms, `npm install` 0.87-0.96 s). With the grace, `capture: auto`
costs a run about 10-20 ms over `capture: off`. Kill test 4 as root after the change, `VM_ONLY=kt4 VM_KT4_TOOLS=1
test/vm/matrix.sh host debian-13`, runs unbroken of 20, baseline / under tego (medians) /
budget in ms:

| Row | pip, cgroup | npm, cgroup | go, cgroup |
|---|---|---|---|
| host (6.17) | **PASS** 20/20 — 2210 / 2606 / 4420 | **PASS** 20/20 — 424 / 543 / 848 | FAIL 3/20 — 129 / 257 / 258 |
| `debian-13` | **PASS** 20/20 — 1938 / 2308 / 3876 | **PASS** 20/20 — 428 / 569 / 856 | FAIL 0/20 — 117 / 256 / 234 |

(Tier landlock passed all three kinds 20/20 on both rows.) After per-run rings (ADR 0026 (1)-(6)),
the host row once: pip **PASS** 20/20 (1863 / 2259 / 3726), npm **PASS** 20/20 (432 / 570 / 864), go FAIL 0/20
(128 / 286 / 256); tier landlock 20/20 on all three. An earlier run on the host at the same code gave go 15/20
(124 / 235 / 248). The rings cost that: each insert into or delete from a ring outer waits for an RCU grace period,
11.5 ms and 7.6 ms median in the 6.17 guest, four per capturing run. With a slot's rings reused by its next run
(ADR 0026 (6) as amended), on 2026-09-25, before and after in one session, go at tier
cgroup, baseline / under tego (medians) in ms and runs unbroken of 20: host (6.17) 183 / 360, 6 (a loaded run)
against 129 / 256, 3; `debian-13` 122 / 350, 0 against 141 / 317, 0: about 50 ms less per run on both. After, pip
and npm at tier cgroup passed 20/20 on the host (1932 / 2311 / 3864, 439 / 558 / 878); on `debian-13` npm 19/20 and
pip 18/20 (one 5.5 s run, on a host whose baselines moved 2x between runs); tier landlock 20/20 for all three on both.
**Condition left for go at tier cgroup:** the tier's own cost, not capture's. An `open(2)` of a run's
process costs 21-25 µs at tier cgroup against 1.3 µs bare, 1.5 µs with `--observe` (the eBPF record alone) and 1.8 µs at
tier landlock, on 6.17 and 6.12 alike (a 20,000-open loop): the fanotify permission round trip every open on a marked
mount makes (ADR 0021 (1)). `go build`'s ~2,500 opens make that about 50 ms, and a run's fixed start and end
(`tego run -- go version`: 34-43 ms against 5 ms bare) most of the rest, against a margin of one baseline, 117-129 ms.
ADR 0024's decision plane, which answers opens in the kernel, is what removes the first.
Kill test 3 runs only with `VM_KT3=1`: a two-vCPU guest shared with other guests is not the quiet machine
§9's budgets are measured on. With it, `matrix.sh` builds the harness's noop and cpu workloads here and carries
them in (`TEGO_BENCH_BIN=/vm/bench`, `test/e2e/overhead/run.sh --workload-bin`), since the harness would
otherwise build them with the go the guest lacks; the kill test hands the harness the staged tego and the
Python cache. Its npm workload is a named skip, unless `VM_KT4_TOOLS=1` carries npm as well: then the npm
cache the harness keeps on this host (`npm/` under `$TEGO_BENCH_CACHE`, by default
`~/.cache/tego-overhead-bench`, primed by any run of `run.sh` with network) goes in at root's default cache,
where kill test 3 points the harness, since the guest has no network to prime one. At its default counts that
is 30 cells (40 with npm), each run 13 times in each of two passes, all but the bare ones root `tego run`s.
In a 1536M, 2 vCPU guest it took 15 minutes on Fedora 7.0 without npm, and 18 with it (2026-09-23: 40
cells, every npm row measured at tiers landlock, observe and cgroup). The harness removes
each timed run's ledger before the next. Kept, the ledgers of a run with npm come to about 550 MB at these
counts, in the guest's `/tmp`, a tmpfs in its RAM: twice, about 17 minutes in, while they filled it, a timed
npm run exited 137 (SIGKILL), and with the ledgers removed the same row ran to the end. What killed it was not
isolated: replays did not bring it back, and 137 is also what a run's memory and pids caps give, and a global OOM
kill. Fedora 7.0 is the row whose root run was the fastest in the 2026-09-23 acceptance run, so on a row whose
root run takes seconds longer it can run past the default `VM_TEST_TIMEOUT` of 1500 s: raise that for such a row. The whole
boot is bounded too, by `VM_ROW_TIMEOUT`, and kill test 3 comes on top of the row's other checks, so with
`VM_KT3=1` that bound defaults to 3600 s plus `VM_TEST_TIMEOUT`, and raising `VM_TEST_TIMEOUT` raises it with
it. A `VM_ROW_TIMEOUT` set by hand is used as given and has to leave room for kill test 3's own bound.
Kill test 7 (a) runs the Claude Agent SDK, whose wheel bundles Claude Code (about 270 MB installed), and it
goes into the guest only with `VM_KT7A=1`, together with what Claude Code needs that the base image lacks:
`git`, which both Claude Code examples name, and the libraries the bundled binary and the SDK's compiled
modules load. The guest's root lives in its RAM and the kill test copies the SDK
once more: half (a) alone peaked at about 670 MB used in a 1536M guest. Without `VM_KT7A=1`, half (a) is a
named skip in the guest; it runs unprivileged, at tier landlock, on any host with `test/e2e/pydeps.sh
--claude-sdk`'s cache.

The results are the console: every check prints `MATRIX-RESULT <check> <as> <verdict> <exit> <detail>`,
every half `KT-HALF <test> <half> <verdict> <reason>`, and the ledgers the kill tests saved come out
base64-encoded between `MATRIX-FIXTURES-BEGIN` and `-END`. `matrix.sh` turns them into
`bin/vm/matrix/<row>/results.tsv` and `fixtures/`, prints one table for all rows and writes
`bin/vm/matrix/summary.json`. It exits 1 when any check failed or a kill test skipped, a guest reported no check or died without one failing, or a kernel could not be fetched; 97 when no guest ran on any row (this box cannot boot one, or no kernel could be fetched), and 2 on a usage
error, which an unknown row is: every row is checked against `fetch-kernel.py --list` before anything is
created or removed. A skip is never a pass: each names what it needed, and a skipped kill test (exit 77; a bash or usage error's 2 is a failure) fails the row, kill test 3's named skip apart.

With `VM_COVER=1` a row is a coverage run for `scripts/coverage.sh --kill-tests ROW`, not a verdict: the
staged tego is built with `-cover -covermode=atomic -coverpkg=<module>/...`, every check runs with
`GOCOVERDIR=/tmp/tego-covdata` (mode 1777, since the user halves run tego as the user), and after the
fixtures each data file comes out as one `TEGO-COVFILE <name> <base64>` line, which coverage.sh decodes from
`boot*.console` and merges with the suites' coverage.

`kvm-step_test.sh` is not a guest harness: it runs vm-matrix.yml's "enable KVM for the runner user" step
against stand-ins for sudo and a udev that applies its rule a second late, and CI's build-test job runs it.
`matrix_test.sh` is not one either: it runs `matrix.sh` over stand-ins for `fetch-kernel.py`, `kvm-run.sh`,
go and a Debian node and npm, and checks what it decides before a guest boots: the boot's bound with and
without `VM_KT3=1`, what `VM_KT4_TOOLS=1` carries, the kill test `VM_ONLY` runs alone and what `VM_TESTHOOKS=1`
builds. It needs `jq` and `python3`, as `matrix.sh` does, and
nothing else. CI's build-test job and `make harness-test` run it; this validates the host-side harness,
not a kernel guest boot.

## Kill test 5: what an untouched ask entry costs

`test/e2e/kt5-ask.sh` is FEATURES' kill test 5 (docs/FEATURES.md, "Kill test 5"), and `matrix.sh` runs it on every row beside kill
test 4, as root, in every tier the boot allows: landlock, cgroup (a cell for the decision plane the boot selects, named in
it: `cgroup@lsm`, `cgroup@fmod_ret`) and bpflsm where `bpf` is an active LSM (on a row's second boot, with the `lsm=` line
doctor printed, it runs alone at bpflsm). For each of two workloads, kill test 2's 20-step agent through the forwarder
(`agent20`) and kill test 4's `pip install` + `pytest` (`pip`), a cell runs one contract with an `fs.ask` and a `net.ask`
entry the workload never touches and the same contract without them (the two are one text but for those two lines; both
declare a `net:` section), one run of each that is not counted, then ten pairs in alternating order, and passes when the
median wall time with the entries is over the median without them by less than 1% of it or 1 s, whichever is larger. A miss
is a FAIL printed as `TARGET-MISS` with the figure; the budget is not moved. Every cell also prints `run_end.supervisor`'s
`notifications` and `held_ms` for both contracts, which is the attribution: at tiers cgroup and bpflsm an `fs.ask` entry
keeps every fs notification the decision plane would otherwise answer in the kernel (enforce-plane R27), and the cell shows
how many that is and what holding them cost.

```sh
VM_ONLY=kt5 test/vm/matrix.sh host                  # kill test 5 alone, on one boot: the kernel's own lsm= list
VM_ONLY=kt5 VM_ONLY_LSM=lockdown,capability,landlock,yama,apparmor,ima,evm,bpf test/vm/matrix.sh host   # bpf added: LSM mode and bpflsm
VM_ONLY=kt5 VM_TESTHOOKS=1 VM_KT5_TIERS=cgroup VM_KT5_PLANES="lsm fmod_ret fanotify" VM_ONLY_LSM=... test/vm/matrix.sh host
VM_ONLY=kt5 VM_KT5_RUNS=3 test/vm/matrix.sh host    # a smoke run, not the acceptance (the line says how many runs)
```

`VM_KT5_TIERS` and `VM_KT5_RUNS` are the script's `KT5_TIERS` and `KT5_RUNS`. `VM_KT5_PLANES` is its `KT5_PLANES`, which pins
tier cgroup's plane through `TEGO_TEST_PLANE`, and only a binary built with `-tags tegotesthooks` honours that, so
`VM_TESTHOOKS=1` stages one (a test build, not the binary a release ships); a pin the run did not get, because the mode is not
available on the boot or the binary ignores it, is a named skip.

Results of 2026-10-06 (`VM_ONLY=kt5`, one boot a row, ten runs a cell, 1536M 2-vCPU guests on a host that other jobs' guests
shared, so a baseline moves by a few hundred ms between boots and a cell's figure is the difference inside its own boot).
The script is the committed one but for three things added while the runs went, none of which changes what is measured: the
raw per-run lists in the console and the refusal of an unknown `KT5_KINDS` (after the first host boot, debian-13 and rhel-9),
the share of the run and the allowance-half note in a cell's figure (so that only the last of the host boots below has
them), and the check of `run_start`'s `capabilities.ask` (after every figure below; two host boots of three runs a cell with
it passed at landlock, cgroup@fmod_ret, cgroup@lsm and bpflsm, the pip build +73 to +264 ms at the plane tiers). The whole
matrix flow on the host row, both boots, ran kill test 5 in its place beside the others and alone at bpflsm on the second boot
and passed it, with kill tests 1, 2, 4 and 7; kill test 6's halves (b) and (c) failed there with a Python traceback in the
probe that reads the pinned `tego_reason_map` (half (b) run alone, with no kill test before it, with `PermissionError:
[Errno 13]` in its `BPF_MAP_LOOKUP_ELEM`; half (c) ran first on the second boot), so not for kill test 5. Median wall time in ms,
base contract -> with the two ask entries (difference); notifications and `held_ms` are `run_end.supervisor`'s for the pip
build. **Every cell passed**, on an allowance of 1000 ms each (1% of a run of 1 to 3.6 s is 10 to 36 ms), and the 20-step agent
made 2 notifications with and without the entries in every tier.

| Row, boot | Tier | 20-step agent | pip build | pip notifications | pip `held_ms` |
|---|---|---|---|---|---|
| host 6.17.0-41, the kernel's `lsm=` (no bpf) | landlock | 901 -> 899 (-2) | 2218 -> 2205 (-13) | 2509 -> 2509 | 209 -> 196 |
| | cgroup@fmod_ret | 918 -> 921 (+3) | 2097 -> 2360 (+263) | 19 -> 2509 | 4 -> 225 |
| host 6.17.0-41, `bpf` added | landlock | 964 -> 962 (-2) | 3605 -> 3142 (-463) | 2509 -> 2509 | 322 -> 263 |
| | cgroup@lsm | 968 -> 964 (-4) | 2444 -> 2446 (+2) | 19 -> 2509 | 4 -> 236 |
| | bpflsm | 947 -> 941 (-6) | 2092 -> 2340 (+248) | 19 -> 2509 | 4 -> 228 |
| the same boot again | landlock | 921 -> 914 (-7) | 2889 -> 2997 (+108) | 2509 -> 2509 | 271 -> 266 |
| | cgroup@lsm | 953 -> 951 (-2) | 2525 -> 2726 (+201) | 19 -> 2509 | 5 -> 250 |
| | bpflsm | 938 -> 930 (-8) | 2214 -> 2492 (+278) | 19 -> 2509 | 4 -> 234 |
| the whole matrix flow, first boot (no bpf) | landlock | 898 -> 926 (+28) | 2357 -> 2711 (+354) | 2509 -> 2509 | 220 -> 296 |
| | cgroup@fmod_ret | 940 -> 945 (+5) | 2442 -> 2827 (+385) | 19 -> 2509 | 5 -> 268 |
| the whole matrix flow, second boot (`bpf` added) | bpflsm | 939 -> 935 (-4) | 1855 -> 2085 (+230) | 19 -> 2509 | 3 -> 194 |
| the same boot, a test build, each plane pinned | cgroup@lsm | 941 -> 935 (-6) | 2467 -> 2812 (+345) | 19 -> 2509 | 5 -> 291 |
| | cgroup@fmod_ret | 939 -> 943 (+4) | 2829 -> 3329 (+500) | 19 -> 2509 | 5 -> 284 |
| | cgroup@fanotify | 931 -> 935 (+4) | 3266 -> 3183 (-83) | 2509 -> 2509 | 230 -> 264 |
| `debian-13` 6.12.107 | landlock | 941 -> 953 (+12) | 2100 -> 2070 (-30) | 2509 -> 2509 | 180 -> 182 |
| | cgroup@lsm | 978 -> 973 (-5) | 2061 -> 2284 (+223) | 19 -> 2509 | 3 -> 220 |
| | bpflsm | 970 -> 976 (+6) | 2052 -> 2241 (+189) | 19 -> 2509 | 3 -> 204 |
| `rhel-9` 5.14.0-687 | landlock | 909 -> 902 (-7) | 2795 -> 3006 (+211) | 2509 -> 2509 | 133 -> 147 |
| | cgroup@lsm | 970 -> 969 (-1) | 2687 -> 2969 (+282) | 19 -> 2509 | 3 -> 213 |
| | bpflsm | 969 -> 970 (+1) | 1978 -> 2155 (+177) | 19 -> 2509 | 3 -> 106 |
| `ubuntu-24.04` 6.8.0-146 | landlock | 892 -> 893 (+1) | 2311 -> 2310 (-1) | 2509 -> 2509 | 279 -> 263 |
| | cgroup@fmod_ret | 923 -> 920 (-3) | 2175 -> 2705 (+530) | 19 -> 2509 | 4 -> 288 |
| `al2023` 6.1.188 | landlock | 1095 -> 1089 (-6) | 2677 -> 2328 (-349) | 2509 -> 2509 | 131 -> 119 |
| | cgroup@lsm | 1128 -> 1130 (+2) | 2468 -> 2680 (+212) | 19 -> 2509 | 3 -> 184 |
| | bpflsm | 1130 -> 1134 (+4) | 2566 -> 3010 (+444) | 19 -> 2509 | 4 -> 188 |
| `al2023-6.12` 6.12.110 | landlock | 1078 -> 1071 (-7) | 2446 -> 2202 (-244) | 2509 -> 2509 | 230 -> 215 |
| | cgroup@lsm | 1112 -> 1116 (+4) | 2636 -> 3328 (+692) | 19 -> 2509 | 4 -> 339 |
| | bpflsm | 1135 -> 1140 (+5) | 2060 -> 2220 (+160) | 19 -> 2509 | 4 -> 259 |
| `fedora-7.0` 7.0.14 | landlock | 890 -> 892 (+2) | 2275 -> 2218 (-57) | 2509 -> 2509 | 220 -> 222 |
| | cgroup@lsm | 923 -> 923 (0) | 1933 -> 2195 (+262) | 19 -> 2509 | 3 -> 266 |
| | bpflsm | 930 -> 923 (-7) | 2247 -> 2500 (+253) | 19 -> 2509 | 5 -> 281 |

What it shows. At tier landlock the filter notifies every write-open and fs mutation of the pip build (2,509 of them) with or
without an entry, so the entries add nothing there: the figures from -463 to +354 ms are the shared host's noise, which the
alternating order cancels in the median only so far. At
tiers cgroup and bpflsm the decision plane answers those in the kernel and the filter notifies 19, until an `fs.ask` entry
keeps them all (enforce-plane R27): 19 -> 2,509 notifications, `held_ms` up by 100 to 335, and the pip build slower by 160
to 692 ms in all but one cell (the exception, +2 ms, had a base median the host's load had inflated), 8 to 26% of the run,
which is 60 to 280 us of wall time for each of the 2,490 notifications kept, the larger figures on the busiest boots. That is
over 1% of wall time and under 1 s, so each of those cells passes by the second half of R7's allowance, and says so ("over 1%
of the run and inside the allowance by its 1 s"). The 20-step agent makes two notifications, so the entries cost it at most 12
ms. The fanotify listener (tier cgroup with no plane) notifies the same 2,509 with and without the entries, and its cell shows
nothing (-83 ms; the listener's own cost is enforce-plane §10.1's).

The margin is the condition. The allowance closes at about ten thousand kept notifications a run at 100 us each: ARCHITECTURE
§15 counts an `npm install` of about 350 packages at 8,000 write-opens and mkdirs, which is 0.5 to 2 s here, not the 0.15 to
0.25 s its 4 to 8 us a notification gave. That figure was the design baseline's estimate of 2026-09-22, made before any
supervisor code existed and citing no benchmark, not an end-to-end measurement; the cells above measure a notification's cost
to a run end to end, in these 2-vCPU guests on a shared host. The follow-up if a workload of that size matters is the
narrower gate of enforce-plane §10.1: an ask-only filter arm that keeps only the write-opens whose path can match an ask scope.
It is not built, since the budget holds for the workloads R7 names.

## Privileged suites without root: `make vm-root-test`

```sh
make vm-root-test                               # every privileged package, as root in a KVM guest
test/vm/root-suites.sh uprobe doctor            # only the packages whose path contains these words
VM_RUN=TestIntegrationAsRoot test/vm/root-suites.sh doctor
```

For each package `PKGS` in `test/vm/suites.sh` lists (the privileged suites, most with a note of what they run as
root), it builds a static test binary with `go test -c -tags integration`. When the package's
tests import `internal/bpf` and the BPF objects are generated, it builds a second binary with
`-tags integration,tegobpf`. Each binary runs with `-test.v` in its own guest. A final guest runs
`sudo tego doctor` from a binary built with the objects when they exist. That run's verdict is
`--require cgroup`.

The last output is a table of the top-level tests that ran and the ones that skipped in each suite, with
each skip's reason and each failure's key lines. It is also written to `bin/vm/summary.json`. A suite
whose tests all skipped counts as not run, not as passed. The target fails when any suite fails, does
not build, or runs nothing. Logs are in `bin/vm/logs/<suite>.console`, and `<suite>.json` holds the
`go tool test2json` stream.

What the guest reproduces is `sudo go test ...` typed in the shell you ran it from. That is how
`bpf/README.md` and the tests' own comments say to run them:

- `SUDO_UID`, `SUDO_GID`, `SUDO_USER` and `SUDO_COMMAND` name you, and you get a passwd entry and a home
  directory. A root `tego run` drops the agent to that uid and refuses to start without it.
- The test runs in a copy of your shell's cgroup chain. Every level keeps its path, its
  `subtree_control` and its delegated owner.
- The working directory is the package's own directory in a copy of the tree (`/src/<package>`), as
  `go test` would set it.
- `/usr/local/bin/go` is `go-shim.sh`. It serves the three helpers that tests build at run time with
  `go build` (`cmd/tego`, `memhog`, `model-agent`). They are prebuilt on the host from the same tree,
  and a helper is the tegobpf build when `GOFLAGS` or the build's own `-tags` names that tag, and the
  tegotesthooks build when the build names that one (internal/runtime's CLI tests do, to keep tego's
  chain anchor and own log in their own directories).

### Both boots tier 3 needs: `VM_BOOTS=both`

```sh
VM_BOOTS=both make vm-root-test                  # every suite on the lsm=...,bpf boot, then without bpf
```

The default guest boots with the host's `lsm=` list plus `bpf`: the decision plane's LSM mode and tier `bpflsm`.
`VM_BOOTS=both` runs the whole invocation twice (TIER3-PLAN §9, T11): `lsm-bpf`, that boot, and `default-lsm`, the
host's list without `bpf`, where the plane runs in `fmod_ret` mode and `--tier bpflsm` is refused with the GRUB
line. Each boot's logs and summary go under `VM_OUT/<boot>`, and the run fails when either boot does.
`VM_BOOTS=lsm-bpf` or `VM_BOOTS=default-lsm` runs that boot alone, the same way: the nightly matrix gives each tier-3
boot a job of its own, since both boots' suite bounds together exceed a hosted job's 360 minutes. With the
objects built, the doctor check then also requires `--require bpflsm` wherever `bpf` is active. The conformance
suite runs tier cgroup once per plane mode and, on the `lsm-bpf` boot, tier `bpflsm` with its parity cells
(`compile --test`'s `bpflsm` column against the kernel, runner `parity` in `test/conformance/testdata/baseline.json`).
root-suites.sh sets `TEGO_CONFORMANCE_REQUIRE` per boot (`conformance-require.sh`): `cgroup,fmod_ret` on every boot,
plus `lsm,bpflsm` on a boot with `bpf` among its LSMs when the objects are built, so neither axis can drop on the
`lsm-bpf` boot behind a green test; under `TEGO_VM_LSM=kernel` the test's own check (bpf active, axis missing) fails.
It passes `TEGO_CONFORMANCE_BUDGET` (`strict` fails an axis over ADR 0017's budget), `TEGO_CONFORMANCE_REPORT` (`-`
prints a `CONFORMANCE-ROW` JSON line per cell and axis to the console) and `TEGO_VM_ROW` through when they are set.
vm-matrix.yml runs `enforce/cgroup`, `internal/bpf` and `test/conformance` this way on every row's kernel, and, in
each row's own job, `internal/platform/peer` and `internal/runscope`: the peer check's `pidfd_open` fallback runs on
rhel-9's 5.14 and al2023's 6.1, which have no `SO_PEERPIDFD`, and its tests fail either row whose kernel answers it.

### The same suites through sudo, and a runner's placement

`VM_HOST=sudo test/vm/root-suites.sh` runs every suite and the doctor check on this host rather than in
guests: as root through `sudo`, or directly from a root shell, in the package's own directory of this
checkout, with `go-shim.sh` first on `PATH`. It is CI's `root-suites` job (.github/workflows/ci.yml); a
GitHub-hosted runner has passwordless sudo. The doctor check there is the product build, run as a root user would
run it, only where `TEGO_DISPOSABLE_HOST` says the machine is disposable (a GitHub Actions runner sets it by itself);
anywhere else it is the `tegotesthooks` build of the same tags with a machine config, chain anchor and own-log home
of the run's own in `VM_OUT/doctor-iso`, since the product build under sudo logs to your own `~/.tego/tego.log`
(identity-config.md R27). There, each suite starts in the runner's service cgroup rather
than in a user's delegated subtree, and the kernel's lsm= list has no `bpf`. The suites also share one host, where
each guest's suite has a kernel of its own: a tier-2 run leaves its build pinned under `/sys/fs/bpf/tego` for
`bpf.linger` (five minutes) after it ends (ADR 0022), so a suite can start with an earlier suite's build still
pinned, and a run in it adopts that build and its plane answer. A test must not take a fresh bpffs for granted:
doctor's `TestIntegrationForRunAsRoot` wanted a probed plane answer and failed every root-suites job of
2026-11-02 on the build internal/runtime's tegobpf suite had left; it now reads the build's pin directory for
which answer to want. `VM_CGROUP=service` makes a
guest start its suite the same way, from `/system.slice/tego-ci.service` with another process beside it (an
orphan init has adopted, not a child of the suite: a runner's suite has none, and the arming tests of ADR 0021 (2)
count their own children), and with `TEGO_VM_LSM=kernel TEGO_VM_LOCKDOWN=none` the guest's LSMs and lockdown are
a stock kernel's.
That combination is how the job's must-pass list (`test/vm/root-must-pass.txt`) was checked before the
job first ran:

```sh
VM_BPF=yes VM_CGROUP=service TEGO_VM_LSM=kernel TEGO_VM_LOCKDOWN=none test/vm/root-suites.sh
```

Under that placement the launch suite's three tests that need a delegated `user@0.service` skip, and the
cgroup suite's two tests of the delegated subtree skip, as they will on a runner.

One difference no guest has: through sudo every suite runs on one host after the suites before it, and finds
what they left there, where each guest boots without it. The host state directory is one such thing. The cgroup
suite, which runs first, makes `/run/tego` as a root launcher does (its `pinState`), and agent-contract R6a
denies reading it in every table compiled while it exists. A test that counted every deny_read entry of a
compiled table therefore counted one more on the runner than in a guest: enforce/landlock's
`TestCompileCrossCheckNested` did, in every root-suites run of 2026-11-02. To see a later suite as the runner
does, make the directory, root 0700, in the guest before the test binary starts, with
`/bin/sh -c 'mkdir -m 0700 /run/tego && exec "$@"' sh` ahead of the binary in `kvm-run.sh`'s command.

A test that changes host-wide state it cannot isolate (`TestRootLauncherRefusesGroupHostState`:
`/run/tego` and `/etc/group`) runs only where `TEGO_DISPOSABLE_HOST` is set: every guest gets it, and
through sudo a GitHub Actions runner or a caller who sets it for a throwaway machine. On a developer's own
machine it skips, and the skip gate fails that run, so the host is never changed and the run is not
mistaken for a full one (ADR 0042, 2026-10-06 note). The conformance suite's bpf control, which lowers
`kernel.unprivileged_bpf_disabled` from 2 for a bpf(2) cell's fixture, does the same: elsewhere that
fixture fails, naming the variable (ADR 0017).

Every run, in a guest or through sudo, ends with two gates over the suites' `go test -json` logs
(`VM_OUT/logs/<suite>.json`), through `scripts/skipgate.sh`: each skip must be one `test/vm/root-skips.txt`
allows, with its reason (an entry whose reason starts `untagged:` only in the plain build of a package whose
tests load the objects), and, on a run of every package with no `VM_RUN`, each test `root-must-pass.txt`
names must have passed in some build and failed in none. `scripts/check-skiplists.sh` checks that both lists
name tests that exist.

### Getting the BPF objects without clang: `make gen`, `make vm-clang`

```sh
make gen                                        # the pinned toolchain (bpf/README.md), fetched without root
make gen CLANG=$(test/vm/fetch-clang.sh)        # clang/LLVM 20 from the distro's .debs, for trying a change
```

`fetch-clang.sh` downloads `clang-N`, `llvm-N` and their libraries into `~/.cache/tego-vm/clang`. It
prints the path of a `clang` wrapper that has an `llvm-strip` beside it. `CLANG=` puts that directory
first on `PATH`, because `internal/bpf/gen.go` calls plain `clang` and bpf2go derives `llvm-strip` from
that name. `root-suites.sh` builds the tegobpf suites only when `go build -tags tegobpf ./internal/bpf`
succeeds. Otherwise it reports those suites as not run and gives the reason.

## A third-party permission listener: `permlistener`

`test/vm/cmd/permlistener` is somebody else's fanotify permission listener, for the runs that have to show Tego's own
group (tier cgroup's fallback marks the mount of `/`, enforce-cgroup-observe §6 E34) works beside one. It is a test tool:
one static Go binary that no engine package imports, with two modes.

| Mode | What it does | For |
|---|---|---|
| `-mode allow-touch` (the default) | Marks the mount of each `-mark` (default `/`) for `FAN_OPEN_PERM` and `FAN_OPEN_EXEC_PERM`. Every open or exec by another process goes to one of `-workers` goroutines (default 4), which waits `-decide-delay` (2 ms), opens and reads each `-touch` file (default `/etc/os-release`), stats each `-stat` path (default `/usr/bin`) and answers `FAN_ALLOW`. | ADR 0021's pairs runs: "a third-party permission listener whose decisions open files on `/`", the cycle that ADR closes by ordering |
| `-mode deny -path P` | Marks the mount of `P`'s directory (or each `-mark`) for `FAN_OPEN_PERM`. An open of `P`, by name or by inode (a hard link counts), is answered `FAN_DENY`, so the opener gets EPERM, and every other open `FAN_ALLOW`, at once. It opens nothing. | ADR 0017 space 6, the third-party refusal cell |

`tier2-pairs.sh` starts it with `LISTENER=/vm/permlistener` (allow-touch, `-deadline` three times the watchdog's
stall); the conformance suite has no cell that does yet.

```sh
CGO_ENABLED=0 go build -o bin/vm/permlistener ./test/vm/cmd/permlistener                       # static: a guest carries no libc for it
CGO_ENABLED=0 GOARCH=arm64 go build -o bin/vm/permlistener.arm64 ./test/vm/cmd/permlistener    # it cross-builds for arm64
test/vm/kvm-run.sh --sudo --file bin/vm/permlistener:/vm/permlistener -- /bin/sh -c \
    'echo x >/tmp/secret; /vm/permlistener -mode deny -path /tmp/secret & p=$!; sleep 1; cat /tmp/secret; kill -TERM $p; wait $p'
```

It needs `CAP_SYS_ADMIN`. It checks that every `-mark`, `-touch` and `-stat` exists before it creates the group, then prints
`PERMLISTENER-READY` once its marks are placed. On `SIGTERM` or `SIGINT` the marks come down first (one `FAN_MARK_FLUSH`, which
names no path and so waits on no filesystem), what the group still holds is answered, the group closes, and the last line is
printed:

```
PERMLISTENER-STATS events=N tego=N self=N late=N denied=N exec=N failed=N malformed=N mode=M
```

`events` is every permission event the group delivered; `self` those from its own opens; `tego` those whose opener's `comm` begins
with `tego` (a launcher or a stage, a copy such as `tego-b` included, which proves the group saw their opens); `late` those answered at the deadline instead of by a
decision; `denied` those answered `FAN_DENY`; `exec` those that were an execve's; `failed` responses it could not write and
decisions that could not open what they were to; `malformed` reads it could not parse. In allow-touch mode, when nothing was late,
failed or still being decided at the stop, `self` is `events - self` times the number of `-touch` files: each decision opened each
file once. Diagnostics go to stderr, prefixed `permlistener:`. Exit status: 0 for a clean stop, 1 for a failed start or a group
that stopped working, 2 for a usage error.

Three properties keep it from being the stall it exists to provoke in somebody else. Its workers' opens are events of its own
group, so one reader goroutine answers an event from its own process `FAN_ALLOW` at once, never waits for a worker (the work queue
is unbounded) and opens nothing on a marked mount: no worker can wait on a reader that is waiting for it. An event no worker has
answered in `-deadline` (default 10 s) is answered `FAN_ALLOW` and counted `late`; a run whose watchdog should see a freeze before
this listener lets the opener through passes a `-deadline` longer than the watchdog's stall. And each event is answered once and
its descriptor closed once, whether its worker or the deadline comes first, because a second response would name a descriptor
number the kernel may already have given to another event. `SIGKILL` leaves the kernel to release the group (E15).

`go test ./test/vm/cmd/permlistener` needs no privilege: a socketpair stands in for the group (the decision table, the metadata
parse over byte fixtures and a fuzz target, the flags, the deadline's race with the workers, the stop). Four root tests,
`TestIntegration*`, run the binary against the kernel on a tmpfs they mount and mark themselves, so only their own opens are ever
behind the listener: `test/vm/root-suites.sh permlistener` runs them in a guest, CI's root-suites job runs them on the runner, and
`root-must-pass.txt` holds them.

## One command as root: `kvm-run.sh`

```sh
test/vm/kvm-run.sh -- /bin/sh -c 'cat /sys/kernel/security/lsm'
test/vm/kvm-run.sh ./x.test -test.v -test.run TestFoo     # a relative host path is copied in and run
test/vm/kvm-run.sh --sudo --file bin/tego:/usr/local/bin/tego -- tego doctor
test/vm/kvm-run.sh --module veth --dmesg -- ip link add veth0 type veth peer name veth1
test/vm/kvm-run.sh --prepare                              # fetch and build the cache, boot nothing
```

On first use it builds the following under `~/.cache/tego-vm` (`TEGO_VM_CACHE`). Everything is reused
after that:

1. **qemu.** It downloads `qemu-system-x86`, `-common`, `-data` and `seabios` with `apt-get download`
   and unpacks them with `dpkg-deb -x` into `root/`. It then runs `ldd` on `qemu-system-x86_64`. Each
   round, it fetches the packages' direct `Depends` that this host has not installed, until nothing is
   missing. On Ubuntu 25.10 that meant two rounds: `libaio1t64`, `libfdt1`, `libpmem1`, `librdmacm1t64`,
   `libslirp0` and their neighbours, then `libndctl6` and `libdaxctl1`. qemu runs with `LD_LIBRARY_PATH`
   set to that tree and `-L` set to its SeaBIOS and qemu firmware directories.
2. **The kernel.** It uses `linux-image-unsigned-$(uname -r)`, or `linux-image-$(uname -r)` when that is
   not available, so a result describes the kernel this box really runs. Override it with
   `TEGO_VM_KERNEL`. `linux-modules-$(uname -r)` is fetched only for `--module`: the root is an
   initramfs, and the console is the built-in 8250 UART.
3. **The base initramfs**, a gzip'd newc archive:
   - a static busybox, which `guest-init.sh` runs as `/init`;
   - these host packages, copied whole except `/usr/share`: dash, bash, coreutils (uutils and GNU),
     findutils, grep, sed, mawk, util-linux, mount, procps, iproute2, libc-bin (so `ldconfig -p`
     works), kmod, python3 (the host's own version, from python-pkgs.sh), bubblewrap, openssl, libssl3t64 (a real OpenSSL for the uprobe tests),
     bpftool and strace;
   - every shared library those binaries load, with symlinks and hard links kept as they are on the
     host, so `/bin/sleep` is the same uutils link it is here.

   The archive is about 30 MB compressed and 80 MB unpacked. It is rebuilt when `dpkg`'s status file,
   `guest-init.sh` or `BASE_VERSION` in `kvm-run.sh` changes.
   Directories keep the host's modes (`/` and `/usr/bin` are 0755, `/root` is 0700), whatever the
   calling shell's umask is.
4. **The boot:** `qemu-system-x86_64 -enable-kvm -cpu host -m 4G -smp 4 -nographic -no-reboot` with
   `console=ttyS0 panic=-1 quiet lsm=<the host's /sys/kernel/security/lsm>,bpf lockdown=<the host's
   mode>`. A Secure Boot Ubuntu host runs in `integrity` lockdown, and so does the guest. `TEGO_VM_MEM`,
   `TEGO_VM_SMP`, `TEGO_VM_LSM`, `TEGO_VM_LOCKDOWN` (`none`, `integrity`, `confidentiality`) and
   `TEGO_VM_APPEND` override these.

`/init` mounts what this host's systemd mounts, with the same options: proc, sysfs, devtmpfs, devpts,
cgroup2 (`nsdelegate,memory_recursiveprot`) with the host's root controllers enabled, bpffs, securityfs,
tracefs, debugfs, and tmpfs on `/tmp`, `/run` and `/dev/shm`. It writes back the host's hardening sysctls,
which systemd-sysctl applies on the host and a bare kernel does not: `fs.protected_*` (the host's
`protected_regular=2` changes what root may open with `O_CREAT` in `/tmp`), `kptr_restrict`,
`dmesg_restrict`, `yama.ptrace_scope`, `unprivileged_bpf_disabled`, `perf_event_paranoid`,
`suid_dumpable` (`TEGO_VM_HOST_SYSCTL=0` skips this). AppArmor's userns restrictions stay at the kernel
default, because the guest loads no AppArmor policy and without the host's profiles the restriction would
refuse more than the host does. It brings up `lo`, runs the command as root and prints
`TEGO-VM-EXIT:<nonce>:<code>`. Then it powers off. A boot takes about a second.

The command runs from the host's own `/bin/sh` (dash) with sudo's `secure_path`
(`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`). busybox serves `/init` only and is not
on that `PATH`, so a test that runs a host tool the guest does not carry gets "not found", as it would on
a host without that tool, and never a busybox applet in its place. Its stdout and stderr are a pipe, as `go test`
and CI's sudo suites give a test binary, not the console's terminal: `/init` copies the pipe to the console and stops
at an end line it writes once the command has exited, so a process the command left behind holding the pipe never
keeps the guest waiting (`console_pipe`). When a mount the tests depend on (proc,
sysfs, cgroup2, bpffs, securityfs, the tmpfs mounts) fails, or the command cannot be moved into its cgroup,
`/init` prints `tego-vm: FATAL: ...` and powers off without the sentinel.

Exit codes:

| Code | Meaning |
|---|---|
| the command's own | the guest ran the command |
| 97 | this box cannot boot a guest; the message names what is missing |
| 124 | the guest ran past `--timeout` |
| 125 | the guest ended without reporting a code (panic, init died, or `tego-vm: FATAL`) |
| 2 | usage error |

tego itself exits 2, 124 and 125 as well (`pkg/spec/identity/exit.go`). When the difference matters, pass
`--status FILE`: kvm-run.sh writes `guest <code>` there when the guest ran the command, and `timeout`,
`no-report`, `env` or `usage` otherwise. `root-suites.sh` uses it, and reports a suite whose guest failed as
`vm-error`, never as a test result.

## Trusted kernel digests

The default fetcher authenticates every row with publisher signatures. An optional
`TEGO_VM_KERNEL_MANIFEST=/path/to/trusted-kernels.json` adds independent digest
constraints for reproducible runs. It never disables signature verification.
A configured manifest must contain a pin for every selected row; malformed,
missing and mismatching pins fail closed. For example:

```json
{
  "version": 1,
  "rows": {
    "rhel-9": {
      "package_sha256": "<64 hex digits for the authenticated package>",
      "image_sha256": "<64 hex digits for the authenticated extracted image>",
      "provenance": "Publisher signature and pinned key fingerprint, or a reviewed artifact reference"
    }
  }
}
```

At least one digest and nonempty provenance are required. Establish those digests
through a trusted signing key or another independently authenticated source.
Package pins are checked before extraction; image pins are checked against the
extracted bytes and the actual cached image. Package-only pins also reverify the
retained package and re-extract it on every invocation, so the cache never relies
on a package hash copied into `source.json`. The checked manifest digest and
provenance are recorded separately under `trusted_manifest`, alongside the
publisher-signature evidence under `verification`.

Run `test/vm/fetch-kernel_test.sh` for cache/concurrency tests and real cryptographic
tests using disposable signing keys. Those tests cover wrong keys, modified
metadata/index/package/payload/image bytes, missing signatures, weak signature
hashes, and a substituted cache with a self-consistent `source.json`.
