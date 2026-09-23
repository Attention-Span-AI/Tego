# bpf/ — the kernel-side programs (C, CO-RE)

One file per concern, shared headers in `include/`. A file may be built more than once: `trace_proc` and the
decision plane's two files once per reader of kernel memory, and the plane's hooks in two modes from one body
(`internal/bpf/gen.go`). `bpf/tests` `TestReadmeTableNamesEverySource` holds this table to the tree.

| File | Attach point | Purpose |
|---|---|---|
| `decide.bpf.c` | `lsm/` and `fmod_ret/security_` (one mode loaded, never both): the filesystem and exec hooks in this file and `decide_stepb.h`, `mmap_file`/`file_mprotect` in `decide_stepc.h`, ptrace/BPF/key hooks in `decide_control.h`, and `socket_bind`/`socket_listen` in `decide_socket.h`/`decide_listen.h`; ADR 0043's name entries (the prefilter, the global name check and climb, D5) in `decide_names.h` | tier 3's decision plane: a governed run's resolved objects, process authority and requested listeners, 0 or `-EACCES` (ADRs 0024, 0025, 0043; built as `planerd` and `planepr`; `internal/bpf/plane.go` lists all 28 hooks) |
| `decide_fill.bpf.c` | `iter/task_file`, `syscall` | the plane's fill of its inode-keyed rows from the launcher's held descriptors, and the clear of a slot's stale rows (ADR 0025; built as `planefillrd` and `planefillpr`) |
| `cgroup_net.bpf.c` | `cgroup/connect4,6`, `sendmsg4,6`, `bind4,6`, `post_bind4,6`, `connect_unix`, `sendmsg_unix` (the two unix ones 6.7+), `cgroup/sock_create`, `cgroup/setsockopt`; `cgroup_skb/ingress,egress` from `net_packet.h`, `sockops` and `cgroup/sock_release` from `net_budget.h` | scoped destination and listener admission, ingress/reply state, network budgets and one-shot connect approvals; requested controls determine required attachments (`internal/runtime/enforce/cgroup/network_control.go`, `docs/p0/network-controls.md`), no BPF LSM needed for these cgroup hooks. `cgroup/sock_create` refuses an inet socket outside ADR 0018's allowlist (`include/socket_allow.h`, the plane's `socket_create` shares it) on any path to `inet_create`, and records its own refusal on the run's ring (`TEGO_EV_SOCK_CREATE`); `cgroup/setsockopt` refuses `SOL_TCP`'s `TCP_ULP`, whatever the name, on any path to the protocol's setsockopt (io_uring's `SOCKET_URING_OP_SETSOCKOPT` included) and records its own refusal (`TEGO_EV_SOCKOPT`; ADR 0018 (7)); both loaded with the object and attached and pinned with the run's links wherever they attach (`enforce/cgroup` `attachSocketPrograms`, ADR 0018 PR 2) |
| `cgroup_track.bpf.c` | `tp_btf/cgroup_mkdir`, `tp_btf/cgroup_rmdir` | materializes descendant cgroups into the run set |
| `trace_proc.bpf.c` | `tp_btf/sched_process_exec`, `tp_btf/sched_process_exit`; fexit on `security_file_open`, `security_path_unlink/rename/mkdir/mknod/rmdir/link/symlink/truncate` and `security_file_truncate` (6.2+), fentry on `security_socket_connect`; syscall-exit tracepoints for `execve`, `execveat`, `bind` and `listen`; fexit on `io_bind` and `io_listen` (6.11+) | the record, with the LSM chain's return (ADR 0016), plus actual exec and listener terminal outcomes, io_uring's bind and listen included; requested listener handoff requires bind/listen result attachment even with recording off |
| `uprobe_ssl.bpf.c` | individual uprobes/uretprobes on `SSL_*_ex`, `SSL_write`, `SSL_read`, and `SSL_free`'s entry, or an optional shared `uprobe.multi`/`uretprobe.multi` pair | plaintext capture keyed by SSL pointer, filtered by run and its capture ring; measured multi-link support and compatible pins select the pair, otherwise individual links remain the fallback (`internal/runtime/capture/uprobe/multi.go`) |
| `testonly/plane_fill.bpf.c` | `iter/task_file` | test-only fill of the plane's rows for the plane's root tests; its binding builds with `-tags integration,tegobpf` only and no tego binary embeds it |
| `testonly/exec_pin_facts.bpf.c` | `tp_btf/sched_process_exec`, `lsm/bprm_check_security`, `fmod_ret/security_bprm_check`, `syscall` | ADR 0048 P2's K0 probe: the kernel facts exec pins rest on (the pin MAC over the new image's argument area, `bpf_send_signal(SIGKILL)` before the first instruction, each binfmt stage at bprm_check, `bpf_get_ns_current_pid_tgid`, `current->ptrace`), measured per matrix row; built per reader with `-tags integration,tegobpf` only, and no tego binary embeds it |
| `spike/walk.bpf.c` | none in tego | TIER3-PLAN T0's walk spike, built only by `tools/spike/walk/build.sh`; not built into tego |

Rules:
- Every `.bpf.c` starts with `// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)` and defines `char _license[] SEC("license") = "Dual BSD/GPL";`. Without it the kernel refuses every LSM program and every `bpf_probe_read_*`/kfunc call.
- Declare the 6.1 prototype for every hook and read nothing past it; return 0 or -errno only; probe every hook in BTF at load (ARCHITECTURE §11). An fexit program declares every argument of its function, then `int ret`: the return is read from the slot after the last argument (`internal/bpf` `TestAttachTargetsResolve`). The exception is a hook newer than 6.1, whose program loads only where the hook exists: `connect_unix` and `sendmsg_unix` read `bpf_sock_addr_kern.uaddrlen` (6.7) and the backend leaves both out below 6.7.
- A tracing or uprobe program looks the current task's cgroup id up in `tego_run_set` first, and does nothing when
  it is not there. A network program never asks who the caller is: it reads the run from `tego_net_owners`, the
  cgroup storage of the cgroup it was attached to, because the caller of a relayed connect is the seccomp
  supervisor, not the run (docs/p0/enforce-cgroup-observe.md §5 R1). The one exception is
  `connect_unix`'s recognition of the supervisor's relay name, `/proc/self/fd/<n>`, which it admits only from the
  launcher's cgroup that `Attach` wrote into the owner; it selects no run and no row (§5 R7).
- No map may share its name with a struct: bpf2go's `-type` lookup sees both and stops (`bpf/tests`).
- A program that reads registers (`PT_REGS_*`, `BPF_UPROBE`, `BPF_KPROBE`) is compiled per architecture, never for
  `bpfel`/`bpfeb` (`internal/bpf/gen.go`, `TestUprobeObjectsNameAnArchitecture`).
- Read a `CGROUP_SOCK_ADDR` context member by value (`ctx->user_ip6[i]`), never through a pointer into the
  context: the verifier refuses a load through a moved context pointer.
- `include/events.h` is the single source of truth for event structs shared with Go (bpf2go copies them).
- `include/vmlinux.h` is generated once per supported kernel with `bpftool btf dump file /sys/kernel/btf/vmlinux format c`.
- Every program has a userspace test of its map logic under `tests/` before it is ever loaded.
- A record goes only to its run's own ring: after the run-set hit, `tego_ring_of` looks the ring up in its outer
  (`tego_events`, `tego_capture_events`) by the run's `run_idx`, and a slot with no ring gets nothing. Never reserve
  on a map by name, and count a loss at the run's slot (`tego_lost_inc(..., run->run_idx)`; ADR 0026,
  `TestRecordsGoToTheRunsOwnRing`).

## Build toolchain

The objects are compiled at development time only; a released binary embeds them and needs neither clang nor
headers. `internal/bpf/gen.go` drives `bpf2go`, and `make gen` runs it.

| Input | Version used to produce the committed state | Where it lives |
|---|---|---|
| clang / LLVM | **20.1.8** (`LLVM-20.1.8-Linux-X64.tar.xz`, sha256 `1ead36b3dfcb774b57be530df42bec70ab2d239fbce9889447c7a29a4ddc1ae6`), run on the C library below | fetched by `scripts/bpf-toolchain.sh` into `~/.cache/tego/bpf-toolchain`, which `make gen` runs |
| the C library clang runs on | Ubuntu 24.04's `libc6` **2.39-0ubuntu8.9** (sha256 `ff5557d99b51f761c4b7c92368b9cc45565eda17df9bf9eb4b134d09825008be`) and `zlib1g` 1:1.3.dfsg-3.1ubuntu2.2 (sha256 `84b9cf5752b29c9f92c27cd4c4ba9bbcc70b5ccf9b1b515421a28ae23212e273`); the release clang is linked against the host's glibc and its output depends on it, so the wrapper runs it through these, never the host's | the same script, from the Ubuntu archive's pool, or Launchpad's permanent package URLs when the pool fails; each download retried, and checked by its sha256 |
| libbpf headers | **v1.7.0** — `bpf_helpers.h`, `bpf_helper_defs.h`, `bpf_core_read.h`, `bpf_tracing.h`, `bpf_endian.h` from `github.com/libbpf/libbpf` `src/` | vendored verbatim, with their upstream `(LGPL-2.1 OR BSD-2-Clause)` SPDX lines, in `include/libbpf/` |
| `vmlinux.h` | generated from **Linux 6.17.0-41-generic** (Ubuntu) with `bpftool` **v7.7.0 / libbpf v1.7** | `include/vmlinux.h`, committed; exempt from the SPDX check (`scripts/check-spdx.sh`) |
| `cilium/ebpf` | v0.22.0 (`go.mod`) | the loader and `bpf2go` |
| `bpftool` (CI's second loader) | **v7.7.0 / libbpf v1.7**, libbpf/bpftool's static release (`bpftool-v7.7.0-amd64.tar.gz`, sha256 `09150596f09356b0ff632dd7f9856e0ea86bf96b269e9bc94278d9a9432a268c`) | fetched by `ci.yml` job `bpf-load`; the runner's kernel package (`linux-tools` of linux-azure-6.17 on Ubuntu 24.04) ships no bpftool (amended 2026-09-24) |

Sources include `"libbpf/bpf_helpers.h"` through `include/common.h`, never `<bpf/...>`: the vendored copies are
the build's only header input, so a machine with a different system libbpf produces the same object.

Regenerate `vmlinux.h` for another kernel with:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/include/vmlinux.h
```

It is a 6.17 dump, and CO-RE is what makes that safe on 6.1: every field access goes through `BPF_CORE_READ`
and every program reads only fields its hook's 6.1 prototype exposes. Two fields this matters for are named in
the sources: `kernfs_node`'s parent pointer (renamed `parent` → `__parent` in 6.14, so `cgroup_track` reaches a
parent through `cgrp->self.parent->cgroup` instead) and `sched_process_exit`'s second argument (added after
6.1, so it is not declared and not read).

## Regenerating and building with the objects

The bpf2go output (`internal/bpf/*_bpfe[lb].{go,o}`) **is committed**, as bpf2go projects do, so any
`go build -tags tegobpf` works without clang. The tier-2 objects (`cgroupnet`, `cgrouptrack`, `trace`, `tracerd`)
and the plane's (`planerd`, `planepr`, `planefillrd`, `planefillpr`) are compiled per byte order;
`uprobessl` is compiled for `amd64` and `arm64` only (`uprobessl_x86_bpfel.*`, `uprobessl_arm64_bpfel.*`), because
its register reads need an architecture, and `internal/bpf/objects_ssl_*.go` register it only there.

```sh
make gen                                     # regenerate with the pinned toolchain after editing bpf/; commit the result
go build ./...                               # no objects: everything else compiles and tests; bpf.Load reports ErrNotGenerated
go build -tags tegobpf ./...                # with the objects embedded
go test  -tags tegobpf ./internal/bpf/...   # layout parity, object shape, and every CO-RE relocation
                                             # resolved against this kernel's BTF — no privilege needed
```

**Why the C library is pinned.** The release clang is a dynamically linked binary, and the bytes it writes depend on
the glibc it runs on. On 2026-09-24, the same clang on the same input made `trace_bpfel.o` and `trace_bpfeb.o` with a
different `.BTF` section, the same length with its types in another order, on Ubuntu 24.04's glibc 2.39 than on
Ubuntu 25.10's 2.42; the program instructions were identical. Objects made on 25.10 therefore failed `bpf-gen` on
GitHub's 24.04 runner. `scripts/bpf-toolchain.sh` runs clang and llvm-strip through the loader and libraries of the
pinned packages, with none of the host's and without the environment variables that change how that glibc allocates
(`GLIBC_TUNABLES`, `MALLOC_*`) or what it loads (`LD_PRELOAD`), which change the output as well, so `make gen` writes
the same bytes on every x86_64 Linux machine whose `/etc/ld.so.preload` is empty.
`make gen CLANG=/path/to/clang` still compiles with another clang (`test/vm/fetch-clang.sh` fetches Ubuntu's
`clang-20` without root) for trying a change; its objects are not the ones to commit.

Warm pinned-object adoption uses `bpf.LoadAdoption`. `make gen` also runs
`tools/adoptiongen` over the completed ELF files and writes
`internal/bpf/adoption_specs_gen.go`: map definitions and program names/types,
keyed by each ELF's complete SHA-256. The original embedded objects and `bpf.Hash`
are unchanged by this projection. Missing, stale, unsupported, or unreadable
metadata takes the original full ELF loader. The generated-file check and parity
tests cover both byte orders, reader builds, and SSL architectures.

The API's `compact` result is an adoption-only contract. Its specification has no
instructions, BTF, or global data contents and must never reach `NewCollection`
or `NewMap`. A failed adoption reloads the full ELF before creating objects. An
adopted decision plane also reloads the full spec if a previously unused slot
needs inner maps, retaining their original BTF and initialization metadata.
Existing map compatibility, program/map ownership, and pinned-link checks still
run on each adoption. The generator refuses to project initialized maps other
than recognized unpinned global sections, or maps with extra definition bytes.

`scripts/check-bpf-objects.sh` checks the committed output from a clean tree: it extracts `git archive HEAD` into a temporary
directory, runs `make gen` there and compares every generated file byte for byte (`--worktree` takes the working tree
instead; `make precommit` runs it when bpf/ or internal/bpf/ differs from origin/main, `TEGO_PRECOMMIT_BPF=1` forces it).
clang's BTF output depends on the directory it runs in, so the script uses one fixed path (`/tmp/tego-bpf-check/tree`) and `scripts/check-bpf-objects.sh --fix` writes internal/bpf from it: commit objects that way, not from a plain `make gen` in a checkout (a checkout in another directory embeds other bytes).

CI (`.github/workflows/ci.yml`) keeps the committed output honest: job `bpf-gen` runs that script, i.e. `make gen` with the pinned
toolchain (cached between runs, fetched and sha256-checked by the script otherwise) and fails when `internal/bpf`
differs in any byte; job `bpf-load` loads every
program as root on the runner's kernel, through cilium/ebpf one program at a time and through `bpftool` (the pinned
static release in the table above), and runs the tier-2 backend's root tests.

`go test ./bpf/...` needs none of that: the static invariant checks read the C directly.

`make build` and the goreleaser build both pass `-tags tegobpf`, so their binaries embed the committed objects
and carry tier 2. A plain `go build ./cmd/tego` passes no tag and is tier 1 only: it reports tier 2 as
unavailable with the fix in the message.

## Running the root-only tests by hand

Nothing under `bpf/` or `internal/runtime/enforce/cgroup` can load a program or open a fanotify group without
privilege, so those tests skip with a reason instead of failing. They decide that from the effective capability
set, never from a load's error: the verifier refuses a program with `EACCES`, "permission denied", which a skip
keyed on the error text used to turn into a skip. On a box without root, `test/vm/kvm-run.sh` runs them as root in
a KVM guest (`make vm-root-test`, `test/vm/README.md`); with root:

```sh
# 1. verifier + attach-target resolution for every program, each loaded on its own, on this kernel
sudo go test -tags 'integration tegobpf' -run TestObjectsLoadOnThisKernel -v ./internal/bpf/

# 2. the same objects through bpftool, independently of cilium/ebpf. loadall, not load: each object holds
#    several programs. No pinmaps: every map is LIBBPF_PIN_BY_NAME, so libbpf pins each one itself under
#    /sys/fs/bpf/<name> and refuses a second pin path; those pins are removed after each object, by a root
#    shell, because /sys/fs/bpf is mode 700 and your own shell would hand rm the glob unexpanded. On a kernel
#    below 6.7 cgroupnet fails here on connect_unix, which the backend leaves out there (§5 R7).
#    Every committed bpfel object except uprobessl_arm64 (another architecture) and planetestfill (test-only),
#    as CI does.
for obj in internal/bpf/*_bpfel.o; do
  case $obj in *uprobessl_arm64_bpfel.o|*planetestfill_bpfel.o) continue ;; esac
  sudo mkdir -p /sys/fs/bpf/tego-probe
  sudo bpftool prog loadall "$obj" /sys/fs/bpf/tego-probe
  sudo ls /sys/fs/bpf/tego-probe
  sudo sh -c 'rm -rf /sys/fs/bpf/tego-probe /sys/fs/bpf/tego_*'
done

# 3. the tier-2 backend: pins, links, map population, whole-Prepare, and real connects decided in the kernel
sudo go test -tags 'integration tegobpf' -run 'TestPrepareOnRealKernel|TestNet.*OnRealKernel' -v \
    ./internal/runtime/enforce/cgroup/

# 4. the fanotify listener: group, marks, a refused read, the kernel's fail-open on listener death, and the
#    round trip an open pays on a marked mount
sudo go test -tags integration -run TestFanotify -bench BenchmarkFanotifyRoundTrip -v ./internal/runtime/enforce/cgroup/
```

Step 3 needs `cap_bpf,cap_perfmon,cap_net_admin` (or `cap_sys_admin`), cgroup v2, and `/sys/fs/bpf` mounted
(`mount -t bpf bpf /sys/fs/bpf` when it is not). Step 4 needs `cap_sys_admin` for `fanotify_init` with
`FAN_CLASS_CONTENT`. None of it changes the boot configuration. A kernel other than the host's can be booted in the
guest by placing its `vmlinuz` under `~/.cache/tego-vm/kernel/<version>/` and setting `TEGO_VM_KERNEL=<version>`;
that is how the 6.1 floor was run (Debian 12's `6.1.0-50-amd64`). `test/vm/fetch-kernel.py` caches each kernel-matrix
row's distro kernel as `matrix-<row>`, and on 2026-09-22 steps 1 and 3 and the `TestFanotify*` tests of step 4
passed as root, loaded from the committed objects, on ubuntu-24.04 (6.8.0-142), debian-13 (6.12.107), al2023
(6.1.186, `connect_unix` skipped), al2023-6.12 (6.12.103) and fedora-7.0 (7.0.14), as well as on Debian 12's
6.1.0-50 and the test machine's 6.17.0-41. RHEL 9's 5.14 is below the 6.1 floor and is not a target.
`.github/workflows/vm-matrix.yml` runs steps 1 and 3 on each of those rows.

What each of those tests asserts, so a manual run can be judged without reading them:

| Test | Asserts |
|---|---|
| `TestCORERelocationsResolve` (unprivileged, `-tags tegobpf`) | every CO-RE relocation in all four objects resolves against `/sys/kernel/btf/vmlinux` with none poisoned, which is §6 E31 checked before load rather than after |
| `TestObjectsLoadOnThisKernel` | every program of every object passes the verifier loaded on its own, then each object whole, and every `tp_btf`/`fentry` attach target resolves in this kernel's BTF; `connect_unix` is skipped below 6.7, where the backend leaves it out |
| `TestRingsOfAnySizeGoInTheOuter` | the record's ring outer takes a run's own ring of 64 KiB, 1 MiB and 8 MiB at once, each read back at its slot at its own size, which is what `Prepare` does with `record.ringbuf` (ADR 0026 (1)) |
| `TestPrepareOnRealKernel` | the whole of `Prepare`: pins created under `/sys/fs/bpf/tego/<hash>/`, the shared tracing links attached once, the run's cgroup inserted, `Attach` linking the cgroup programs and configuring `tego_net_owners`, and `Detach`/`Close` leaving nothing |
| `TestNetVerdictOnRealKernel` | real connects from a run's cgroup: allowed and refused TCP over IPv4 and IPv6 and unconnected UDP, a connect relayed from outside the run on a `pidfd_getfd` duplicate of the run's socket (what the supervisor does) refused in the kernel, a resolver query relayed the same way on a UDP socket admitted under `net.resolver` while port 53 on a non-resolver address is refused, a descendant cgroup decided without a run-set row, and the breadcrumb under the run's cgroup id agreeing with each syscall's result |
| `TestNetUnrestrictedOnRealKernel` | a contract with no `net:` section: a relayed connect, the run's own connect and an unconnected datagram all go through, and no breadcrumb is written, because no network program is attached (§5 R1) |
| `TestNetRefreshOnRealKernel` | a host entry whose address rotated is refused until `RefreshNet` moves the run's rows, then allowed at the new address and refused at the old one (§6 E7) |
| `TestFanotifyGroupOpens`, `TestFanotifyMarkAndUnmark` | the group this backend asks for is one the kernel grants, and a mount can be marked once and removed cleanly |
| `TestFanotifyRefusesDeniedRead` | a process in the run's cgroup opening a `deny_read` path is refused in the kernel with `EPERM` (the bare `FAN_DENY`; no kernel lets this group send `EACCES`, §6 E2), the refusal event names the rule and the file, and an unruled file opens normally |
| `TestFanotifyAllowedOpensKeepTheListener` | 60,000 allowed opens from the test's own goroutine with GOMAXPROCS 2, as fast as the listener answers, leave the listener running and the `deny_read` file refused: at the closer's cap the loop waits for a closer that had no processor instead of taking it for a held close (docs/p0/enforce-cgroup-observe.md §6 E35) |
| `TestFanotifyListenerDeathFailsOpen` | closing the group releases openers rather than blocking them — the documented default that makes a dead listener fatal to the run |
| `BenchmarkFanotifyRoundTrip` | one open on the marked mount against the same open unmarked, allowed on the path and refused after the membership read; P0-DESIGN §9 budgets the round trip at under 30 µs, and the first measurement, in the 2-vCPU KVM guest, was ~44 µs over an unmarked open (docs/p0/enforce-cgroup-observe.md §9) |

Everything else in those two packages runs unprivileged and is covered by `go test ./...`.

## What the root runs found

Loading every program on its own as root, first on a 6.17 kernel in the KVM guest and then on Debian 12's
6.1, is what settled these; each has a test that fails without its fix.

- **`make gen` could not run at all.** `uprobe_ssl.bpf.c` reads registers with `PT_REGS_*`, which libbpf refuses
  for `-target bpfel,bpfeb`; with an architecture target, bpf2go then stopped on a map and a struct both called
  `tego_ssl_scratch`. The map is now `tego_ssl_reads`, and `uprobessl` is built for `amd64,arm64` (arm64 needs
  `struct user_pt_regs`, which the x86 `vmlinux.h` lacks, so `common.h` declares its uapi layout).
- **`connect6` and `sendmsg6` did not pass the verifier.** Copying `ctx->user_ip6` through a pointer into the
  context is "dereference of modified ctx ptr"; the four words are now read by value.
- **No relayed connect was decided in the kernel.** The network programs keyed the run on the caller's cgroup,
  which for every connect the seccomp supervisor relays is the supervisor's. They now read the run from the
  attachment's cgroup storage (`tego_net_owners`).
- **Below 6.7 the whole of `cgroup_net` failed to load**, because the kernel checks `connect_unix`'s attach type
  at load, not at attach. The backend now leaves that one program out there.
- **Once relayed connects were decided, the kernel refused what the supervisor admits on its own authority**: a
  query to the machine's resolver on port 53 (supervisor R14), every connect under a contract with no `net:`
  section (SEMANTICS §1), and a host's address after a TTL refresh (supervisor R8). The rows now carry the run's
  resolvers as `net.resolver`, a run with no `net:` section gets no network program, and `RefreshNet` moves a
  host's rows. The runtime passes its resolver list to enforcement in `internal/runtime/run_setup.go` and to
  the supervisor in `internal/runtime/run_workers.go`. That worker refreshes the DNS set and calls the
  handle's `RefreshNet` when its resolved rows or expiry change; `internal/runtime/enforce/cgroup/attach.go`
  validates the table shape and replaces the scoped rows. Resolver admission and hostname refresh therefore
  share the runtime's address-refusal checks and compiled expiry policy
  (docs/p0/enforce-cgroup-observe.md §5 R5, §6 E7; docs/p0/network-controls.md §5 R5).

## What this kernel's BTF settled

Two questions `docs/p0/enforce-cgroup-observe.md` §11 left open were answered by reading the running kernel's
BTF while implementing, and the code follows the answers:

- **`connect_unix` decides by name (corrected 2026-09-23).** This bullet used to say it could not: `struct
  bpf_sock_addr` has no `sun_path` member, and the only unix address kfunc in the kernel's BTF is the write-side
  `bpf_sock_addr_set_sun_path`, so the program attached as a placeholder that always allowed. The uapi struct is
  not the whole context, though: `bpf_cast_to_kern_ctx` (6.2) gives the kernel's `struct bpf_sock_addr_kern`,
  whose `uaddr` is the kernel's copy of the caller's `sockaddr_un`, read through `bpf_rdonly_cast`, as the
  upstream selftest `connect_unix_prog.c` does. `connect_unix` and the new `sendmsg_unix` now decide a unix
  destination by that name on 6.7+ (docs/p0/enforce-cgroup-observe.md §5 R7), narrowing what the inherited tier-1
  Landlock ruleset and seccomp supervisor decide, which stay the only decision below 6.7. What the name cannot
  say, the socket it resolves to, stays the supervisor's for a connect. For a datagram, which the agent sends
  itself under the inherited Landlock domain, it is checked by that domain's `RESOLVE_UNIX` backstop at Landlock
  ABI 9 (Linux 7.1) and above (docs/p0/enforce-landlock.md R21), and by nothing below ABI 9.
- **The five fentry attach points exist with the prototypes the spec assumes** (argument counts from
  `/sys/kernel/btf/vmlinux`): `security_file_open(file)`, `security_path_unlink(dir, dentry)`,
  `security_path_mkdir(dir, dentry, mode)`, `security_path_rename(old_dir, old_dentry, new_dir, new_dentry,
  flags)`, `security_socket_connect(sock, address, addrlen)`. The programs declare exactly these and read no
  further argument, per R10's "no kernel-version split".
