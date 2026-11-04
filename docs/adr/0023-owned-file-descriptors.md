# ADR 0023: descriptors are owned values: one close-once type, and no raw close, dup-over or wrap outside it

Status: accepted 2026-10-05, as amended by the 2026-10-05 note below (A1–A11 and the lease budget P1–P9); partly built 2026-10-05: C1, the owner type, C2, its helpers and owner forms, and C4, the churn harness, and 2026-10-17: C3, the lint and the per-package ratchet, and 2026-10-19: C12, hoststate, C13, runtime/cgroup, C17, cli, C10, ledger, C6, launch (but for the ruleset handoff, which waits for C5's owner), C7, the runtime's notify-fd handoff, with the listener part of C8 that it needs, and C9, the runtime rest (implementation notes below); not built: the other package migrations, C5, C8 (but for its listener), C11, C14–C16, C18 and C19. Proposed 2026-09-23. Builds on two fixed descriptor bugs (the Why below). Amends only its own proposed text and supersedes nothing. ADRs 0020 (2), 0024, 0025 (2) and 0034 (2) already describe sys.FD as built; each carries a dated note from C0 saying it is not yet true and naming the commit that makes it true.

Decision: internal/platform/sys gets one owned-descriptor type, sys.FD. It closes once (an atomic swap to -1) and has no finalizer. Borrow() lends the number for a syscall made while the owner lives; Dup() duplicates it into a new sys.FD; Release() hands ownership to an *os.File, to ExtraFiles or to another process and leaves the FD empty. Outside internal/platform/sys, lint forbids: unix.Close, syscall.Close, os.NewFile with any argument, unix.Dup2, unix.Dup3, syscall.Dup2, syscall.Dup3, unix.CloseRange, and unix.Syscall, RawSyscall or Syscall6 with SYS_CLOSE, SYS_CLOSE_RANGE, SYS_DUP, SYS_DUP2 or SYS_DUP3. The statx owns check stays as a fail-closed runtime assertion wherever a Landlock rule is added from a held number. The raw close and wrap sites in non-test code migrate in order of blast radius: enforce/landlock; supervisor (notify fd, pidfd_getfd duplicates); launch (control pipe, pidfds); ledger; enforce/cgroup (fanotify group and event fds, cgroup directory fds); doctor; runtime/cgroup. The lint rule lands first with an exclusion list naming the unmigrated packages; each migration PR deletes its package from the list, and the list is empty when the ADR is done.

Why: [documented] Two bugs traced a finalizer of an *os.File that wrapped a number someone else owned. The reuse variant put a sibling's Landlock rule on another inode (EINVAL); a luckier reuse would have put it on the wrong inode without an error.
[measured] 91 unix.Close/syscall.Close and 15 os.NewFile calls in non-test code (supervisor 20, ledger 16, doctor 12, landlock 11 of the closes).
[documented] Dup2/Dup3 onto an occupied number, close_range and a raw SYS_CLOSE close a number as surely as Close, and a regex on os.NewFile(uintptr(x.Fd())) cannot follow a variable, so three lint patterns left the class open.
[inference] The statx check detects a reused number after the fact and cannot see a number reopened on the same inode; only ownership in the type system prevents the class.

Security argument: A misdirected landlock_add_rule grants a rule's rights on the wrong inode; a double close can take the ledger's descriptor or the seccomp notify fd. With every closing or aliasing primitive behind one type, a stray close is a lint error instead of a load-dependent heisenbug in the TCB. The statx assertion stays as the backstop where a wrong inode would change a grant, and ADR 0025's in-kernel fill reads only numbers a sys.FD owns and verifies them again.

Options considered: Rejected:
- Keep auditing by hand: the class recurred twice.
- The statx check alone: detects, does not prevent, cannot see a same-inode reopen.
- Wrapping every descriptor in *os.File: finalizers are the cause.
- Three lint patterns alone: they miss os.NewFile over a variable, Dup2/Dup3, close_range and raw syscalls.

Consequence: Every package that touches raw descriptors changes. Kernel interfaces that pass numbers (pidfd_getfd, SCM_RIGHTS, the seccomp notify fd, ExtraFiles, the reaper's inherited descriptors in ADR 0020) go through Release and Borrow explicitly.

Implementation plan:

1. internal/platform/sys/fd.go: sys.FD (atomic int32; Close, Borrow, Dup, Release, Valid). Tests under -race: 64 goroutines closing one FD close the number once (a sentinel dup3'd onto the freed number stays open); Borrow after Close fails; Release leaves the FD empty and the File owns the number; no finalizer (drop an FD, runtime.GC() twice, the number is still open).
2. .golangci.yml forbidigo rules listed above, plus tools/fdcheck (a small go/analysis pass, since forbidigo matches text) for unix.Syscall/RawSyscall/Syscall6 with the closing SYS_ constants; both exclude internal/platform/sys and _test.go, with the exclusion list of unmigrated packages.
3. One PR per package in the order above; each removes its entry from the list. Each PR runs that package's unwind and integration tests with -race -count=500 under load (go test -p 6 with a TMPDIR churn script alongside); the first PR also runs heldfd_test.go and heldfd_integration_test.go; the enforce/cgroup, runtime/cgroup, launch and supervisor PRs also run their root integration suites in GUEST.
Docs: ADR 0023; runtime-launch §5 (the ownership rule); CONTRIBUTING's lint section.

*Amended 2026-10-05 (refining the ADR plan):* The decision above stands, refined as follows.

### What this note supersedes in the text above

The text above stays verbatim. Where it and this note differ, the note governs:

| The text above says | Read instead |
|---|---|
| "closes once (an atomic swap to -1)"; "atomic int32" | one atomic state word with owns, strict, closing, kept, claimed and done bits and a lease count (A1). The number never changes after birth. |
| "Borrow() lends the number for a syscall made while the owner lives" | `Borrow(fn)` is a scoped, counted lease. A Close that meets a lease is deferred, or refused for a strict FD (A1). |
| "Release() … leaves the FD empty" | Release refuses while a lease is out (`ErrLeased`) and marks the FD kept (A1). |
| "tools/fdcheck (a small go/analysis pass, since forbidigo matches text)" | forbidigo resolves types. fdcheck is a standard-library AST tool with no x/tools (A3, A10). |
| the forbidden list (Close, NewFile, Dup2, Dup3, CloseRange, the closing SYS_ numbers) | that list, plus Dup, F_DUPFD, fcntl dup commands, ParseUnixRights, `(*os.File).Fd`, cilium `FD()` and `*FromFD` (A4, F5) |
| "the order: landlock; supervisor; launch; ledger; enforce/cgroup; doctor; runtime/cgroup" | 18 packages, ordered by the edge rule (A6) |
| "the exclusion list of unmigrated packages", one list | a per-package ratchet of counted raw sites (A9) |
| runtime-launch §9: "closed exactly once, on exactly one code path" | closed exactly once, by whichever holder closes first. Close-once makes every later Close a no-op (A1, R25). |

### Context

**What existed then.**
- There is no owner type and no lint rule. `.golangci.yml`'s forbidigo block holds only ADR 0021's four
  process-start rules.
- That block's one exclusion turns off *every* forbidigo rule in internal/platform/proc. It is
  `path: (_test\.go$|internal/platform/proc/|…)` with no `text:`.
- No fdcheck tool exists, and `golang.org/x/tools` is not in go.mod.
- The runtime backstops are the Landlock set's statx check (`fdSet.owns`, enforce-landlock I12) and the plane fill's
  identity check (enforce-plane R16).
- Neither forbidigo nor depguard keeps internal/testutil, tools/ or test/ out of the product binary. Nothing pulls
  them in today: `go list -deps ./cmd/tego` under the tag sets plain, tegobpf, tegotesthooks and both together
  names none of them.

**Census.** The counts cover non-test files outside internal/platform/sys, tools/, test/ and internal/testutil/,
with comment lines excluded:
- 184 `unix`/`syscall.Close`;
- 28 `os.NewFile`;
- 14 dup or `F_DUPFD`, one of them the tegotesthooks `Dup3` in plane_testhook.go;
- 1 `CloseRange`;
- 58 `(*os.File).Fd`;
- 4 cilium `Program/Map.FD()` borrows;
- 2 `ParseUnixRights`;
- 1 `link.NewFromFD`.

That is 292 sites, in 18 packages:
- The plan's 17: ledger, doctor, supervisor, internal/runtime, enforce/landlock, cli, enforce/cgroup, launch,
  hoststate, pkg/spec/agent, ask, dnsbroker, runtime/cgroup, capture/uprobe, pkg/spec/config, observe,
  capture/forwarder;
- internal/bpf, for its cilium borrow.

A further 109 calls produce raw numbers through `unix`/`syscall` producers such as Open, Openat, Openat2, Socket,
PidfdOpen and OpenByHandleAt. The proposed text counted 91 closes and 15 os.NewFile, in seven packages.

Inside internal/platform/sys, three int-returning producers also need owner forms:
- `SeccompSetFilterNewListener` (used at launch/child.go:278 and doctor/seccomp.go:182);
- The pidfd helpers;
- landlock's raw `SYS_LANDLOCK_CREATE_RULESET` (landlock/syscalls.go:55, outside sys).

**Accepted ADRs and specs already describe this ADR as built.**
- ADR 0020 (2): the reaper's descriptors are "each a sys.FD released into ExtraFiles".
- ADR 0024: "Prerequisites on master: … 0023". Tier 3 was built on R16's check alone.
- ADR 0025 (2), and enforce-plane.md near lines 1011 and 1182: the fill reads descriptors "owned by a sys.FD".
- ADR 0034 (2): `hoststate.Open()` returns "a verified sys.FD".

None of these is true today. C0 adds a dated note to each.

ADR 0031 (a) says enforce/api "any time after ADR 0023". The TCB API work (ADR 0031 (a)) is scheduled before
FD-MID. This note settles that conflict in A6.

### Decision

**A1. The owner and its lease.** The owner is `sys.FD`. Borrowing it is a counted lease, and a close that meets a
lease is deferred, or refused for a strict FD.

*State.* sys.FD keeps its number, which never changes after birth, and one atomic state word:

| Bit or field | Meaning |
|---|---|
| owns | set by a constructor. The zero FD has it clear, so the zero FD and an owner of number 0 can be told apart. |
| strict | set at birth (`sys.Strict`, below). It never changes. |
| closing | a Close, Release or Abandon was accepted. No new lease is granted. |
| kept | Release or Abandon: close(2) is never called on this number by this FD. |
| claimed | exactly one goroutine has won the right to call close(2). |
| done | close(2) has returned for this number, or a kept FD has no leases left. |
| leases | the count of leases out. |

A slow-path mutex guards three things the fast path never touches: the close hook, close(2)'s error, and a
lazily made `done` channel. Borrow and Return are atomics only.

*Operations.* "No-op" means the call returns nil and changes nothing.

| Call | zero or nil `*FD` | open, no lease | open, leases out | closing, leases out | close(2) running elsewhere | done (closed) | kept (released or abandoned) |
|---|---|---|---|---|---|---|---|
| `Borrow(fn)`, `Hold()`, `Dup()` | `ErrClosed` | lease, or new owner | lease, or new owner | `ErrClosed` | `ErrClosed` | `ErrClosed` | `ErrClosed` |
| `Close()`, not strict | no-op | close(2) now; returns its error | marks closing; returns nil; the last Return calls close(2) | no-op | no-op | no-op | no-op |
| `Close()`, strict | no-op | as CloseNow | `ErrLeased`, nothing changes | (cannot arise) | as CloseNow | no-op | no-op |
| `CloseNow()` | nil (owns nothing) | close(2) now; returns its error | `ErrLeased`, nothing changes | `ErrLeased` | waits for done, then nil | nil | `ErrClosed` ("released" or "abandoned") |
| `Release()`, `ReleaseNumber()` | `ErrClosed` | marks kept; gives the number | `ErrLeased` | `ErrClosed` | `ErrClosed` | `ErrClosed` | `ErrClosed` |
| `Abandon()` | no-op | marks kept | marks kept; leases go on; the last Return closes nothing | marks kept; cancels the deferred close | no-op (too late) | no-op | no-op |
| `OnClosed(fn)` | `ErrClosed` | registers fn | registers fn | registers fn | registers fn | runs fn now | `ErrClosed` (fn never runs) |

- **CloseNow's contract.** `CloseNow` returns nil exactly when no number this FD owned is still open: close(2) has
  returned for it, on any path, or it never owned one. It never returns nil while a close is only pending.
  - With a lease out, it returns `ErrLeased` and changes nothing.
  - While another goroutine is inside close(2) for this number, it waits for that call. The wait is bounded by
    that one syscall, not by any lease.
- **The close hook.** `OnClosed(fn func(err error))` registers one function. It runs after close(2) has returned,
  on whichever path closed the number (Close, CloseNow, or the last Return), and receives close(2)'s error. A
  second registration fails.
  - The hook never runs for a released or abandoned FD, so a dependency tied to it stays unmet: fail closed.
  - It runs on the closing goroutine, so it must not block and must not call the same FD.
  - It is how an ordering that depends on the close is expressed (T2.2), and how a deferred close's error is still
    reported.
- **Borrow.** `Borrow(fn func(n int) error) error` runs fn under a lease. It returns the lease with `defer`, so a
  panic in fn returns it too: the supervisor recovers per-notification panics and keeps running.
  - On a concrete `*sys.FD` it allocates nothing when fn does not escape.
  - Through an interface value whose dynamic type the compiler cannot see, a closure that captures locals escapes:
    2 allocations and 24 B per call, measured. Hot paths therefore call it on the concrete type (A11).
- **Hold.** `Hold() (*Lease, error)` is the lease for a loop's lifetime.
  - `Lease.Num()` gives the number. After Return it gives -1, and under `tegotesthooks` it panics.
  - `Lease.Return()` is idempotent, so a second Return never ends another holder's lease.
  - Under tegotesthooks a Lease records its holder's PC, so `ErrLeased` names who holds the FD.
  - There is no public unpaired `Borrow()`/`Return()`.
- **Close.** Close is close-once and idempotent. close(2) is never retried, EINTR included.
  - A deferred close's error goes to the hook if one is registered, and is otherwise dropped.
  - Under tegotesthooks every deferred close records the closer's and the holders' PCs. The KVM suites' teardown
    report lists them.
- **Strict at birth.** `sys.Strict(fd *FD, err error) (*FD, error)` takes a constructor's results directly, for
  example `sys.Strict(sys.Own(unix.Open(…)))`. fdcheck requires its argument to be a constructor call. A strict FD
  never defers a close: `Close` on it acts as `CloseNow`. Four kinds are strict:
  - descriptors that hold a flock. `(*FD).Flock` refuses a non-strict FD, so this one is enforced at run time;
  - pipe write ends, whose EOF a peer waits for. `sys.Pipe2` makes the write end strict;
  - The seccomp listener. `supervisor.New` refuses a listener that is not strict;
  - durability files whose close must report its error (ledger).

  The fanotify group is deliberately not strict: its ordering goes through the hook (T2.2).
- **Sharing.** Pointers to one FD may be shared. A transfer between components is a pointer move: the
  `r.notifyFD = -1` convention is no longer load-bearing.
  - Any holder that is the last owner on some path may Close. Close-once makes a second Close a no-op.
  - A holder that needs an independent lifetime takes `Dup()`.
- **Errors.** `ErrClosed` matches `unix.EBADF` and `ErrLeased` matches `unix.EBUSY` under `errors.Is`. The existing
  errno classifiers then keep their classes and their pinned texts when a Borrow fails. These are
  landlock paths.go:196 and ruleset.go:76-78 (§7 "Held descriptor lost"), launcher.go:488, supervisor
  `receive()`, execimage.go:87 and :173, and net.go:788.
- **Fail closed.** Neither error is ever skipped silently. Each is a failure on the path that met it:
  - a decision path refuses, where its mechanism can refuse. The exception is the fanotify tier: a response that
    cannot be written is GapFanotifyResponse, and the kernel answers ALLOW when the group is released (§6 E15,
    E34). That is a stated, recorded fail-open, and is unchanged;
  - a setup path fails Prepare or Start, exit 125, with a pinned text;
  - a teardown step reports, and keeps its fail-closed state (T2.2).
- **The stdio guard.** `Own`, `OwnSyscall`, `Adopt` and the sys helpers refuse numbers 0–2 at run time, one
  comparison, without closing them. The Go runtime reopens a closed 0–2 on /dev/null at start (runtime
  `checkfds`), so a real fresh descriptor is never 0–2. A 0 therefore means the call's result was not a
  descriptor. The one way to own stdio is `sys.Stdio(n)`, which appears only at the sites in stdio.txt (F4).

**A2. Where the type lives.** The type lives in internal/platform/sys, as the text above and ADRs 0020, 0025 and
0034 already say. There is no leaf package, no alias and no forwarders.
- pkg/spec stays free of internal/ (REPO-LAYOUT: "pkg/spec never imports internal"), and `spec-is-pure` is
  unchanged.
- Its one descriptor user after the spec split, pkg/spec/config/load/trust.go (config/trust.go today), switches to
  standard-library calls that are not forbidden:
  - the /proc link is read inside `f.SyscallConn().Control`;
  - `checkContains` becomes `Fstatat(dirfd, base, &st, AT_SYMLINK_NOFOLLOW)` inside `d.SyscallConn().Control`,
    instead of openat, fstat and close. A symlink or a different inode in the name's place still fails the
    (dev, ino) comparison and reports `reasonReplaced`, and ENOENT still maps to `reasonReplaced`. Being a stat, it
    cannot hang on a FIFO. Its error text keeps the prefix "config: reopen %s in its directory".
- ledger, check and serve today import no platform package. After C10, internal/ledger imports
  internal/platform/sys, which brings in only `golang.org/x/sys/unix` and `golang.org/x/net/bpf` (`go list -deps`).
  REPO-LAYOUT's diagram gains the ledger → platform/sys edge at C10.

**A3. Mechanism.** The mechanism is forbidigo plus a standard-library AST tool, `tools/fdcheck`. It uses no
go/analysis and no `golang.org/x/tools`. Three corrections of fact:
- **forbidigo with `analyze-types` matches more than text.** It resolves constants, function values, method values
  and qualified methods, cilium's included.
- **forbidigo misses methods promoted through embedding.** It does not report `w.Fd()` on a struct that embeds
  `*os.File`, nor `interface{ Fd() uintptr }`. fdcheck covers both (F5).
- **No lint run builds the `tegotesthooks` tag.** Six non-test files build only with that tag, and they compile
  into the binaries the KVM suites run. forbidigo has never seen them.
  - The tagged run's `build-tags` becomes `[integration, tegobpf, tegotesthooks]`. That run reported 0 issues on
    the tree, and no file is tagged `!tegotesthooks`.
  - scripts/lint-untagged.sh and ci.yml rewrite that exact line, so they change with it.
  - ADR 0021's rules gain the same coverage.

**A4. Forbidden primitives (forbidigo).** These rules apply outside the owner's files and the permanent exemptions
in A7. Every message contains "ADR 0023".

| Pattern | Package |
|---|---|
| `^(unix\|syscall)\.(Close\|Dup\|Dup2\|Dup3\|CloseRange)$` | |
| `^os\.NewFile$` | |
| `^os\.File\.Fd$` | `^os$` |
| `^(unix\|syscall)\.SYS_(CLOSE\|CLOSE_RANGE\|DUP\|DUP2\|DUP3\|IO_URING_SETUP\|IO_URING_ENTER\|IO_URING_REGISTER)$` | |
| `^(unix\|syscall)\.F_DUPFD(_CLOEXEC)?$` | |
| `^(unix\|syscall)\.ParseUnixRights$` | |
| `^(unix\|syscall)\.(ParseSocketControlMessage\|ParseOneSocketControlMessage\|SCM_RIGHTS)$` (added 2026-10-19) | |
| `^unix\.IoUringSetup$` | |
| `^link\.NewFromFD$` | `github.com/cilium/ebpf/link` |
| `^ebpf\.New(Map\|Program)FromFD$` | `github.com/cilium/ebpf` |
| `^ebpf\.(Program\|Map)\.FD$` | `github.com/cilium/ebpf` |

- **io_uring.** It is out of production. Its operations (IORING_OP_CLOSE, OPENAT, fixed files) close and install
  descriptors outside every rule here. Its only user is internal/testutil/uring, which is exempt. Bringing io_uring
  into the TCB needs its own ADR.
- **cilium borrows.** cilium v0.22.0's internal FD closes its number from a `runtime.AddCleanup`, so
  `prog.FD()` and `m.FD()` are the same borrow-without-lease as `(*os.File).Fd`.
  - The four sites go through internal/bpf/fdborrow.go: `ProgramFD(p, fn)` and `MapFD(m, fn)` run fn, then
    `runtime.KeepAlive` the object.
  - fn must cover every use of the number. doctor/programs.go:909 bakes a map's number into an instruction that the
    program load consumes, so that load runs inside `MapFD`'s fn.
- **Replacements for `(*os.File).Fd`:**
  - typed helpers over the stdlib's own lease: `sys.Flock(f, how)`, `sys.FstatFile(f)`, and `sys.FileDo(f, fn)`
    for the rare remaining cases;
  - owning a sys.FD where a loop needs the number on every iteration (P4).

**A5. Abandon.** `Abandon()` marks the FD closing and kept without calling close(2). Leases out at the time go on,
and the last Return closes nothing.
- It is the one way to forget a number of lost or unknown identity, as I12 requires.
- It appears only at the sites in tools/fdcheck/abandon.txt, which are enforce/landlock's `owns()` failure and its
  ruleset check.
- **Re-verify after Abandon.** A lease holder whose FD is abandoned mid-lease holds a number of unknown identity.
  Before any grant made through that number, it re-verifies identity. R16 does this in the fill. R25 states it as a
  rule, and T1.1 and T3.1 meet it.
- The statx check stays before every `landlock_add_rule` from a held number, and at cleanup. R16's identity check
  stays in the fill.

**A6. Scope and order.** The scope is the 18 packages above, or whatever the census finds on the tree FD-LINT
lands on. The order is a rule on edges, not on packages:
- **The edge rule.** Where package P hands a descriptor to package C, P's exported API changes to give an owner
  (`*sys.FD`) or lend one (`sys.Lender`) no later than the commit that migrates C.
- **It enforces itself.** The birth rule (A10) gives a migrated C no way to wrap an int that an unmigrated P still
  returns. F8 makes an int descriptor in a migrated package's exported API a lint error. (Amended 2026-10-19: those two stop C wrapping or exporting the int, not using it or passing it back to a P
  helper that closes it, so fdcheck also fails when a package baseline.txt does not list uses an API in the
  generated edge list.)
- **The edge list is generated.** C3 generates it mechanically (fdcheck `-edges`) and checks it in. The hand list
  then:

| Producer | Descriptor | Consumer |
|---|---|---|
| sys | pidfd helpers, `SeccompSetFilterNewListener` | everyone; launch, doctor |
| enforce/landlock | `enforce.Handle.LandlockRuleset` (implemented by landlock, cgroup and observe) | launch |
| enforce/landlock | `PlaneHeld`, `PlaneListenParent` | enforce/cgroup (fill) |
| launch | `Child.PidFD`, `WaitNotifyFD` | internal/runtime |
| internal/runtime | `supervisor.New` | supervisor |
| runtime/cgroup | the cgroup fd | `launch.Start` |
| hoststate | `Dir` | cgroup, runtime, uprobe |
| ledger | `Writer.OpenDirPath`, `ledger.OpenAt(dirfd int, …)` (writer.go:164) | the reaper, ledger users |
| ask | `RelayPool.Reserve(…, socketFD int)` (first_write.go:54) | supervisor |
| enforce/cgroup | `Handle.GrantConnect(fd int, …)` (network_approval.go:23) | supervisor |

- **The proposed order is replaced.** It put the supervisor before launch, so the supervisor would have wrapped a
  number launch still owned as an int.
- **ADR 0031 (a) comes first.** the TCB API work (ADR 0031 (a)) lands before FD-MID.
  - C5 then edits the `enforce/api.Handle` descriptor methods in place, and importers change no import line for
    this ADR.
  - ADR 0031's "any time after ADR 0023" is corrected by a dated note at C0. Moving an interface does not need its
    method types to be final first.
- **The stages.** FD-EARLY, FD-MID and FD-LATE, plus a small FD-GROUP stage, with two changes. The
  security-critical owners move forward:
  - **all of enforce/landlock (C5)** moves to FD-MID's first commit. That is the giving and lending API, the
    ruleset's birth and close, fdSet, and Abandon. The reuse bug's home is then closed earlier.
  - **the fanotify group (C11a)** moves to FD-GROUP, after the name backend's change to fanotify.go.

  The supervisor listener's lease is already in FD-MID (C7).
- **Owner style for new code.** Every change that lands between FD-LINT and the package's migration and touches an
  excluded package writes its new descriptor code in owner style. The ratchet forbids a rising count. 
**A7. Permanent exemptions, and keeping exempt code out of the binary.**
- **The owner's files.** These are named, not the whole tree: internal/platform/sys/{fd.go, fd_lease.go,
  fd_errors.go, fd_inherited.go, fd_testhooks.go (tegotesthooks), pidfd.go, cloexec.go, filedo.go, rights.go,
  pipe.go, dupover_testhook.go (tegotesthooks)}. The rest of sys (seccomp.go, landlock.go, prctl.go and the
  others) is under every rule. Its int-returning producers gain owner forms in C2.
- **Other exempt code.** `_test.go`, internal/testutil/, tools/, test/, and internal/bpf/fdborrow.go.
- **Test hooks are not exempt.** `*_testhook.go` files are linted (A3) and scanned (F6), because the KVM suites run
  them.
- **The plane reuse hook.** It moves to `sys.DupOverForTest(src *FD, dst int)`, which is tegotesthooks-only and
  lives in sys.
- **Exempt code never reaches the binary.**
  - A depguard rule, `testutil-never-in-binary`, with `files: ["$all", "!$test"]`, denies
    `github.com/attention-span-ai/tego/internal/testutil`, `…/tools` and `…/test` to every non-test file.
  - fdcheck (F11) also asserts that `go list -deps` of each product binary contains no exempt package. The
    binaries are ./cmd/tego, plus tegod when it exists, under the tag sets plain, tegobpf, tegotesthooks and
    tegobpf,tegotesthooks. Both checks passed. (Amended 2026-10-19: each tag set
    is listed for linux/amd64 and linux/arm64 with cgo off, as the release builds them, and for linux/amd64 with
    cgo, in the build's own environment, so the host's GOARCH, GOFLAGS and go.work change nothing,
    nor does the user's go env file, nor GOAMD64, GOARM64 or GOEXPERIMENT.)
- **Text-scoped exclusions.** The ADR 0021 exclusion gains `text: "ADR 0021"`, so internal/platform/proc is no
  longer exempt from ADR 0023's rules. The ADR 0023 exclusions carry `text: "ADR 0023"`.

**A8. No sys.FD finalizer, and what the garbage collector still closes.**
- **No sys.FD finalizer or cleanup in production.** Nothing closes a sys.FD's number because the garbage collector
  ran.
- **Other objects still close on collection.** An `*os.File` from `Release`, and cilium's Program, Map and Link
  objects, do close their numbers from runtime cleanups. That is safe only while they stay reachable.
  - Enforcement links stay attached because ADR 0020 (1) pins them.
  - Rule: an enforcement link or map that is not pinned stays reachable from the run's Handle for the whole run.
    C11b and C15 check every such object, and a `runtime.KeepAlive` in Detach makes it explicit.
- **Leak counter (tegotesthooks).** A `runtime.AddCleanup` over a separate tracking cell counts an FD that became
  unreachable while still owning an open number. It never closes the number. `sys.LeakedForTest()` exposes the
  count.
- **Run-teardown assertion (tegotesthooks).** A process-wide counter of outstanding leases is read at run start
  and at run end, and the run end fails its testhook check when the counter has grown. The KVM suites run runs
  serially, so this proves that every FD born for a run has zero leases at run end. Per-run tagging for concurrent
  runs belongs to the tegod ADR.
- **Close-on-exec.** This is a static rule (F9), so it holds in production at no run-time cost. The tegotesthooks
  build also checks `FD_CLOEXEC` on every fresh number in Own and OwnSyscall, as a second line.
- **Table check.** `testutil.NoFDLeak(t)` snapshots /proc/self/fd and fails on growth at Cleanup. It ignores the Go
  runtime's eventpoll and eventfd entries.
  - It calls `t.Setenv`, which panics in a parallel test and forbids a later `t.Parallel()`. A test that is
    parallel, which would make the table delta meaningless, therefore cannot use it.

**A9. The ratchet.** `tools/fdcheck/baseline.txt` has one line per excluded package with its count of raw sites.
Raw sites are the A4 primitives plus the F1, F4 and F5 findings.
- **fdcheck counts the sites itself.** A `//nolint` comment hides nothing.
- **It fails when:**
  - a package's count rises (since 2026-10-19 also held to the base's, by kind, under `-base`: a rise passes
    only for sites moved from another package; see that date's implementation note);
  - a package that is not listed has a raw site;
  - a listed package reaches 0 and is not removed;
  - The file and `.golangci.yml`'s shrinking exclusions do not name the same packages.
- **One rule per package.** `.golangci.yml` carries one `- path:` exclusion rule per package, never a single
  alternation regex, because FD-LATE runs several worktrees in parallel.
- **The total check.** The file's total may not exceed the merge base's.
  - `scripts/check-fd.sh --base <rev>` runs it in precommit against `git merge-base HEAD main`.
  - In CI it runs in the bench-gate job, the one with `fetch-depth: 0`. build-test stays at depth 1.
  - A commit that moves code moves its counts with it.
- **Close-out.** The file is empty when this ADR is done, and fdcheck asserts that.

**A10. The birth rule and the rest of fdcheck.** Outside the owner's files, a number becomes an owner in the
expression that creates it. This replaces the plan's deny-list check, which cannot see an int that another
package's API returns. fdcheck enumerates files as checkexits does, with `git ls-files -co --exclude-standard`, so
ignored folders, scratch worktrees among them, are never scanned.

- **F1, constructors.** A fresh number enters an owner only through these:
  - **`sys.Own(n int, err error)`.** Its argument is a direct call to a listed producer.
    - The list is generated from the module-cache sources of `x/sys/unix` and `syscall`: every function whose
      results include an `int` named fd or nfd, such as Open, Openat, Openat2, OpenByHandleAt, Socket,
      InotifyInit1, FanotifyInit, EpollCreate1, Eventfd, MemfdCreate, PidfdOpen, PidfdGetfd, Fsopen, Fsmount,
      OpenTree, Fspick, PerfEventOpen, TimerfdCreate and Signalfd.
    - The generated list is checked in, and fdcheck fails on a producer call it cannot classify.
    - IoUringSetup is excluded, because A4 forbids it.
  - **`sys.OwnSyscall(r2 uintptr, errno syscall.Errno)`.** Its argument is a direct `unix.Syscall`,
    `Syscall6`, `RawSyscall` or `RawSyscall6` call. fdcheck admits only (trap, command or flag) pairs whose result
    is a descriptor:
    - `SYS_BPF` with a first argument that is a named constant among BPF_MAP_CREATE, BPF_PROG_LOAD, BPF_OBJ_GET,
      BPF_PROG_GET_FD_BY_ID, BPF_MAP_GET_FD_BY_ID, BPF_LINK_GET_FD_BY_ID, BPF_BTF_LOAD, BPF_BTF_GET_FD_BY_ID,
      BPF_LINK_CREATE, BPF_ITER_CREATE, BPF_RAW_TRACEPOINT_OPEN and BPF_TOKEN_CREATE;
    - `SYS_SECCOMP` with SECCOMP_SET_MODE_FILTER and a flags expression that contains
      SECCOMP_FILTER_FLAG_NEW_LISTENER;
    - `SYS_LANDLOCK_CREATE_RULESET` with a flags expression that does not contain LANDLOCK_CREATE_RULESET_VERSION
      or LANDLOCK_CREATE_RULESET_ERRATA, since those return a number that is not a descriptor;
    - `SYS_MEMFD_CREATE`, `SYS_PIDFD_OPEN`, `SYS_PIDFD_GETFD`, `SYS_OPENAT2` and `SYS_PERF_EVENT_OPEN`.
  - **sys helpers for producers with other result shapes:**
    - `sys.Pipe2` (the write end is strict), `sys.Socketpair` and `sys.Accept4`;
    - `sys.ReceiveRights(oob)`, which owns every received number even when parsing fails partway;
    - `sys.DupFile(f, min)`, which takes an `*os.File`'s number under the stdlib's lease;
    - The owner forms of sys's own producers: `PidfdOpenFD`, `PidfdOpenProcessFD`, `PidfdGetfdFD`,
      `SeccompNewListenerFD` and `LandlockCreateRulesetFD`.
  - **`sys.Adopt(n, from)`,** for a number the kernel wrote into memory. Its sites are listed in adopt.txt (F4):
    - The fanotify event read in enforce/cgroup;
    - The fanotify probe in doctor;
    - The launcher's `SysProcAttr.PidFD`, which Go's clone3 fills.
  - **`sys.Inherited(n int, kind sys.Kind, name string)`,** for a number this process received at exec on
    purpose. Three run-time checks apply:
    - **Kind.** `KindDir`, `KindSocket`, `KindFIFO` and `KindRegular` are checked by fstat's S_IFMT. `KindPidfd`
      is checked by `pidfd_send_signal(n, 0, nil, 0)` answering 0, ESRCH or EPERM. `KindRuleset` is checked by
      landlock's ProbeRuleset (ENOMSG). None of the checks needs /proc.
    - **Range.** It refuses n ≤ 2.
    - **The seal.** It fails once this process has made any other owner (Own, OwnSyscall, Adopt, the helpers or
      Dup). That is one atomic flag set on the first such construction. A second owner of a live number therefore
      cannot be minted later in the process.

    Its sites are listed in inherited.txt: the child stage's entry and ReapMain. In both, the Inherited calls are
    the process's first descriptor operations, and a test pins that.
  - **Function values.** A producer, `ReleaseNumber`, `Abandon`, `Adopt`, `Inherited` or `Stdio` taken as a
    function value or a method value is a raw site. Seam variables such as `fanotifyInit = unix.FanotifyInit`
    (fanotify.go:318) therefore become owner-returning seams:
    `fanotifyInit = func(f, e uint) (*sys.FD, error) { return sys.Own(unix.FanotifyInit(f, e)) }`.

  Any other call to a listed producer is a raw site.
- **F2, leases.** A `Hold()` result is used in one of two forms.
  - **(a) Scoped.** `defer <lease>.Return()` follows the Hold in the same function.
  - **(b) Hand-off.** The lease is passed as the argument of a `go` statement whose function literal's first
    statement is `defer <param>.Return()`. The holding function does not use the lease after that statement.

  (Amended 2026-10-19) in either form the defer or the `go` statement is the statement after
  the Hold in its block, past only the Hold's own check (`if err != nil { return … }`), and in form (a) the Hold
  is in no loop of its function. (Narrowed since: the check returns only on failure, `err != nil` or `l == nil`
  joined by `||`, and a backward goto across the Hold is a loop.) The lease is returned by that defer only, never by an explicit call, and in form
  (b) the holding function does not use it at all, but for that check and the hand-off.

  A `*Lease` is never stored in a struct field, global or channel, and never captured by a function literal
  outside form (b).
- **F3, giving away the number.** `ReleaseNumber()` appears only as the direct argument of `link.NewFromFD`,
  `ebpf.NewMapFromFD` or `ebpf.NewProgramFromFD`. (Amended 2026-10-19: `n, err :=
  x.ReleaseNumber()`, and the one taker call in the statement after it in its block, past only its error check,
  narrowed since to a check that returns only on failure, `err != nil`, and the taker is that statement itself or its
  right-hand side: a call statement, an assignment, a var or a return; and the taker is not in the
  right operand of a `&&` or `||`.)
- **F4, listed sites.** abandon.txt, adopt.txt, inherited.txt, stdio.txt and sweep.txt (added by the 2026-10-17
  FD-LINT fix note) key each site by file, enclosing
  function and count, not by line. `sys.InertForTest` (A11) is called only from `_test.go` files. `*ForTest`
  accessors are called only from tests and tegotesthooks files.
- **F5, backstops for what forbidigo cannot see.**
  - any call or method value of a selector named `Fd`, which covers embedding promotion and
    `interface{ Fd() uintptr }`;
  - a call of a selector named `FD` on a receiver that is not a package (cilium);
  - a `Syscall*` whose trap is not a `SYS_` constant (package-level constants are resolved);
  - `unix.FcntlInt`, `syscall.Syscall(SYS_FCNTL, …)` and `unix.Fcntl*` whose command is not a named constant from
    an allowlist: F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETPIPE_SZ, F_SETPIPE_SZ, F_ADD_SEALS, F_GET_SEALS,
    F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW. F_DUPFD is 0, so a literal 0 duplicates a descriptor;
  - `Unshare` with CLONE_FILES. One descriptor table per process is the type's premise, and Tego unshares only
    CLONE_FS and CLONE_NEWNS today.
- **F6, coverage.** fdcheck parses every listed non-test `.go` file outside the exempt paths, whatever its build
  constraints.
- **F7, the ratchet.** The ratchet of A9.
- **F8, API shapes.** In a migrated package, an exported function, method or interface method is an error when it
  has an `int`, `int32` or `uintptr` parameter or result whose name is `fd` or ends in `fd` or `FD`. This enforces
  A11's "no API returns or takes a bare number". Unexported seam interfaces are not covered: their int parameters
  are borrowed numbers, per A11.
- **F9, close-on-exec.** A producer's flags argument is a constant expression that contains that producer's
  CLOEXEC constant: O_CLOEXEC (Open, Openat, OpenByHandleAt, the Openat2 `how.Flags` composite literal, Pipe2),
  SOCK_CLOEXEC (Socket, Socketpair, Accept4), FAN_CLOEXEC, IN_CLOEXEC, EPOLL_CLOEXEC, EFD_CLOEXEC, MFD_CLOEXEC,
  TFD_CLOEXEC, SFD_CLOEXEC, FSOPEN_CLOEXEC, FSMOUNT_CLOEXEC, OPEN_TREE_CLOEXEC, FSPICK_CLOEXEC or
  PERF_FLAG_FD_CLOEXEC.
  - Producers the kernel always makes close-on-exec are exempt from the check: pidfd_open, pidfd_getfd, bpf, the
    landlock ruleset and the seccomp listener.
  - A flags value that is not a constant is a finding.
- **F10, OwnSyscall pairs.** The pairs listed in F1.
- **F11, binary reach.** The `go list -deps` assertion of A7.

**A11. API shapes and test seams.**
- **An API that gives a descriptor** returns `*sys.FD`, which the caller owns and closes.
- **Lending.** An API that lends a descriptor across packages, off the hot path, returns `sys.Lender`, which is
  `{ Borrow(func(int) error) error; Hold() (*Lease, error) }`. `sys.Owned` is Lender plus `Close` and `CloseNow`.
  - Both are satisfied by `*sys.FD`.
  - A non-nil interface that holds a nil `*sys.FD` fails every call with `ErrClosed` and never panics, because
    every method checks its nil receiver.
- **Hot seams are concrete.** A seam that a per-notification or per-event path calls returns `*sys.FD`, never an
  interface. Its Borrows are then direct calls with no allocation. This covers the supervisor's kernel seam (T1.5),
  the fanotify listener's seams and the landlock seam.
  - A test fake builds its owners with `sys.InertForTest(n)`. That constructor sets owns and kept from birth, so
    its Close never calls close(2). fdcheck confines it to `_test.go` files (F4).
  - Through an interface, a Borrow whose closure captures locals allocates. Code that must use an interface takes
    one `Hold` and `Num` per descriptor per handler instead.
- **No API returns or takes a bare number** for its caller to keep (F8).
- **Borrowed numbers in seam calls.** A number passed into an unexported seam method is borrowed by the caller for
  that call's duration, as GetFD's pidfd argument is.
- **Typed methods.** These remove most closures, and with them most chances to copy a number out:
  - methods on `*sys.FD`, each a direct Borrow with 0 allocations: `Flock(how)` (strict only), `Fstat`,
    `Fstatat`, `Statx`, `Openat` and `Openat2` (both returning `*sys.FD`), `Futimes`, `Fsync`,
    `GetsockoptInt(level, opt)` and `ProcPath()` (`/proc/self/fd/N`, for a Readlink made under a Borrow);
  - for `*os.File`: `sys.Flock(f, how)` and `sys.FstatFile(f)`.

  `Borrow(fn)` stays for the rest.

**Per tier.** Every tier inherits the rules above. What each tier adds:

- **Tier 1 (Landlock and the supervisor).**
  - **T1.1, the held set.** Each fdSet entry owns a `*sys.FD`.
    - `owns()`'s statx and the `landlock_add_rule` it guards run under **one** Borrow of the held number. Inside
      that Borrow the ruleset is borrowed too. The check therefore covers the syscall it guards.
    - A lost number, or one of unknown identity at cleanup, is abandoned (I12). Error texts and exit codes stay
      byte-identical, including §7 "Held descriptor lost" (exit 125), and tests pin them.
  - **T1.2, the ruleset.**
    - It is born an owner through `LandlockCreateRulesetFD`.
    - `closeRuleset` and `rulesetStill` keep the ProbeRuleset check, which now runs under a Borrow, and call
      `Abandon` on a mismatch.
    - `enforce/api.Handle` gives the launcher a `Dup()`, never the Handle's number.
    - `PlaneHeld` and `PlaneListenParent` return `sys.Lender`.
  - **T1.3, the child stage.**
    - The control, report and ruleset numbers come from `sys.Inherited` with their kinds.
    - The ruleset is closed through its owner after `restrict_self`.
    - `cloexecFrom3` becomes `sys.CloexecFrom(3)`: close_range with CLOEXEC, falling back to a /proc/self/fd walk.
      If both fail, it returns an error and the stage fails, exit 125.
  - **T1.4, the notify fd.**
    - `pidfd_getfd`'s result is owned at birth and strict: `sys.Strict(sys.PidfdGetfdFD(…))`.
    - It moves launch → runtime → `supervisor.New` as a pointer, and `Child` keeps no copy.
    - The runtime may Close it at its own shutdown. That Close returns `ErrLeased` while Run holds its lease, and
      the runtime's shutdown then leaves the close to Run.
  - **T1.5, the supervisor.**
    - **What this note needs from the code the gate fix leaves:**
      - `New(listener *sys.FD, pol *Policy, sink Sink, opts Options) (*Loop, error)`;
      - `sysKernel` holds the `*sys.FD`. `New` issues `SetSyncWakeUp` under a Borrow. Run takes one Hold and binds
        the lease's number for the listener-bound methods (Wait, Recv, Send, IDValid). Those keep their shape: they
        take no descriptor argument;
      - no listener ioctl is issued outside New, Run, and goroutines that a worker joins. Then, askHeld's
        watcher is joined, notif.go's respond and valid run on workers, and relays touch only their own duplicate;
      - The kernel seam's descriptor-producing methods return `*sys.FD`: OpenPidFD, OpenPidFDProcess, GetFD, and
        TaskOf's root and cwd. Methods taking a descriptor keep `int` (borrowed). `CloseFD` goes;
      - a test builds a Loop with a nil listener and `Options.kernel` set to a fake. `New` refuses a nil listener
        without a fake kernel, and a listener that is not strict. Run with a fake takes no lease. Calling
        `handle()` directly, as the benchmarks do, needs no lease;
      - observe/continuednet_test.go:145, which passes `int(null.Fd())`, an `*os.File`'s number that Run then
        closes (the double-close shape), owns the file with `sys.Own(unix.Open("/dev/null", …))` instead.
    - **Run's lease.** Run takes one `Hold` on the listener for the workers' lifetime. After the last worker
      leaves, it returns the lease and calls `CloseNow` on the listener (E24).
    - **Per notification.** A duplicate or pidfd is a local owner. resolveSocket runs SO_TYPE, SO_PROTOCOL and
      SO_DOMAIN under one direct Borrow of the duplicate. ConnectRaw and SendToRaw are each one direct Borrow.
    - **Relays.** A relay, which may outlive Run, owns its duplicate, borrows it around each relayed syscall and
      closes it after. It never touches the listener.
    - **ADDFD.** ADDFD|SEND (ADR 0008's completion) borrows the source descriptor for the ioctl.
    - **The walkers** (execimage, walkcache, unixrelay) hold local owners that do not escape.

- **Tier 2 (cgroup: fanotify fallback, fmod_ret/lsm plane modes).**
  - **T2.1, the listener.** The group, its wake pipe and each event's fd are owners.
    - **Two group leases per loop lifetime, none per event.**
      - The read loop holds one, in form (a).
      - Before the workers start, loop takes a second for the worker pool and hands it (form (b)) to a joiner
        goroutine: `go func(l *sys.Lease) { defer l.Return(); answering.Wait(); close(workersDone) }(poolLease)`.
      - The workers use the number of that pool lease, so every response write, including those after loop has
        returned on the failing path (§6 E35), happens under a lease.
    - **groupMu goes.** It and writeResponse's closed check are deleted. A Close of the group while either lease
      is out is deferred, so a response is written to the group itself, never to a reused number. Writing to a
      group whose close is pending delivers the decision rather than a fail-open.
    - **Event fds.** Each event's fd is adopted at the read site. The response is written under a Borrow of the
      event's FD, because the response names the event by its fd number. The closer's Close of an event fd is
      therefore deferred until the response is written, and that number cannot name the next event's fd while
      this verdict is in flight.
    - **The wake pipe** comes from `sys.Pipe2`.
  - **T2.2, the arm.**
    - The group registers `OnClosed` when the first mark takes proc.Start's arm (ADR 0021 (3)).
    - The hook releases the arm and reports close(2)'s error (gap or log, as Close does today).
    - It runs after close(2) has returned, on whichever path closed the group: Detach's Close, the joiner's Close,
      or the last Return of a deferred close.
    - The CompareAndSwap latch in `fanotifyListener.Close` still makes the listener's own teardown run once. The
      arm no longer depends on which caller won it.
    - A released or abandoned group never runs the hook, so the arm stays held and proc.Start stays refused: fail
      closed.
  - **T2.3, cgroup descriptors.**
    - Cgroup directory, mount and inotify fds are owners. `members.go`'s `OpenByHandleAt` result is owned at
      birth, and its /proc readlink uses `ProcPath()` under a Borrow.
    - `launch.Start`'s cgroup fd is borrowed across proc.Start.
    - The descriptor-table reservation becomes `sys.DupFile(held, 128)` followed by Close. Its saving of the RCU
      pauses is re-measured.

- **Tier 3 (the plane, also at tier 2's plane modes).**
  - **T3.1, the fill.**
    - `heldFD` returns a Lender per path. The fill takes one `Hold` per planned descriptor before the iterator
      runs, which is a constant number per Prepare. It returns them after the kernel's report is checked.
    - A close of the Landlock set in that window is deferred, not landed.
    - R16's (mnt_id, ino) check stays, and is the re-verification A5 requires.
  - **T3.2, the iterator link.** `sys.OwnSyscall(unix.Syscall(SYS_BPF, BPF_ITER_CREATE, …))`, then
    `ReleaseNumber()` into `link.NewFromFD`.
  - **T3.3, cilium borrows.** Cilium `FD()` borrows go through internal/bpf/fdborrow.go.

- **Lifecycle and the rest.**
  - **The reaper (ADR 0020 (2)).**
    - The self-pidfd comes from `sys.PidfdOpenProcessFD(getpid)`.
    - The pidfd, the run directory and the DNS directories each `Release` into ExtraFiles.
    - ReapMain's first act is `sys.CloseInheritedFrom(first)`, followed by `sys.Inherited` with kinds
      (KindPidfd, KindDir, KindDir).
    - `CloseInheritedFrom` walks /proc/self/fd and keeps the Go runtime's eventpoll and eventfd, as
      `closeStrayFDs` does. It **returns an error** when /proc/self/fd cannot be read, where today it returns
      silently (reap.go:291-295). ReapMain then exits 125 and starts no sweep.
  - **Approvals (ADR 0008).** Pinned files and relay sockets are owners, held by the handler across the human wait.
    ask and dnsbroker receive rights through `sys.ReceiveRights`.
  - **Mechanical migrations.** These are ledger, hoststate (`Dir` holds a verified `*sys.FD`, ADR 0034), doctor,
    cli, capture, observe and pkg/spec (A2).
    - In each, every lock, flock and pipe-write descriptor is born strict.
    - The migrating commit lists its strict sites. Today these are the 25 or more flock, fstat and futimes sites in
      ledger (anchor, gc, live, reader, place, writer), enforce/cgroup (slots, builds, linger, pins, rings, plane,
      statefiles), capture/uprobe/shared.go and doctor's flight lock.

**Unchanged.** Records, verdicts (ADR 0016), compile --test, doctor output, exit codes and error texts are
unchanged. The exception is the new failure rows (`ErrClosed` or `ErrLeased` in Prepare or Start, exit 125), whose
texts each migrating commit pins. Nothing here is a model or a judgment (ADR 0003).

### Performance budget

**Method.**
- Runs use GOMAXPROCS=4, `-benchtime 200ms` and 10 rounds, compared with benchstat. They go through
  the RAM-limited job wrapper on the reference machine: i7-10870H, Linux 6.17, powersave governor, Go 1.27.1.
  The figures quoted were measured on that machine.
- **What bench-gate can enforce.** `decide()` in scripts/bench-gate.sh fails three things, and nothing else:
  - allocs/op going from 0 to non-zero;
  - B/op up more than 10%;
  - sec/op up more than 25% at p < 0.01.

  It has one absolute rule, hard-coded to BenchmarkIndexedEvaluator.
- **Kinds of budget**, used in the table's last column:
  - **pin:** a test using AllocsPerRun or `testing.Benchmark`. It runs in build-test on every runner, arm64
    included.
  - **gate:** bench-gate's three rules on the rows named.
  - **acceptance:** a reference-box comparison made and recorded by the commit named.
  - **recorded:** measured and reported, with no threshold.

| # | What | Budget | Kind |
|---|---|---|---|
| P1 | `Borrow` on a concrete `*sys.FD`, uncontended | 0 allocs/op (`TestBorrowAllocatesNothing`) | pin |
| P1 | the same | median ≤ 2.5 × `twoAtomicAdds` measured in the same process (`TestBorrowCostRatio`: `testing.Benchmark` on both, median of 5, skipped under -race and -short; since 2026-10-16 asserted in budget mode, the unit gate holding ten times it, note below). Prototype: 19–23 ns against 10.8–12.8 ns, ratio 1.6–1.9 | pin |
| P1 | internal/platform/sys joins bench-gate's package list: `^Benchmark(Borrow\|Hold\|OwnedOpenClose)$` | regressions | gate |
| P2 | `Hold` plus `Return` | ≤ 1 alloc/op (the Lease) | pin |
| P3 | `BenchmarkBorrowParallel` (4 goroutines on one FD) | prototype: 116–146 ns/op, the cost of contention | recorded |
| P4 | descriptors that hot-path goroutines share | supervisor listener: 1 Hold per Run. Fanotify group: 2 Holds per loop lifetime. 0 Holds per notification or event. Counted by `(*FD).HoldsForTest()` in TestRunTakesOneListenerLease and TestListenerTakesTwoGroupLeases | pin |
| P5 | supervisor `BenchmarkNotificationRoundTrip` allocation ceilings, pinned in supervisor/allocs_test.go | write_open 10, mkdir 10 and connect_refuse 10, all unchanged; connect_allow 25 (+2: the pidfd and duplicate owners, each escaping through the seam); execve_argv 23, unchanged | pin |
| P5 | the same, time | median ≤ +3% per row; B/op stays inside the gate's 10% (connect_allow 2,326–2,335 B today, +48–64 B expected) | acceptance (C7, C8), gate |
| P5 | `BenchmarkNotificationRoundTripRealWalk` joins the gate regex (today's `$` anchor excludes it) | allocs unchanged (10, truncate 9, via_symlink 17): the walkers' owners do not escape. Pinned. Median ≤ +3% | pin, gate, acceptance |
| P5 | new BenchmarkResolveSocketReal (integration tag, real kernel, joins the gate regex): socketpair; then per op pidfd_open(self), pidfd_getfd, SO_TYPE, SO_PROTOCOL and SO_DOMAIN under one Borrow, and two closes, through `sysKernel` | ≤ +2 allocs/op and ≤ +100 ns median against the same sequence on the commit before C8 | acceptance (C8), gate |
| P6 | enforce/cgroup `BenchmarkListenerHandle` | ≤ 23 allocs/op (22 today; +1 for the event's Adopt). groupMu's removal saves an RWMutex round trip per event | pin, plus acceptance median ≤ +2% (C11a) |
| P6 | enforce/cgroup `BenchmarkDecideEventOffTheRun` | allocs unchanged (4 and 13) | pin |
| P7 | ledger `BenchmarkAppend` | < 20 µs absolute (record-ledger.md; 4.5 µs today). 14 allocs unchanged | pin (allocs), acceptance (time, C10) |
| P8 | landlock `BenchmarkPrepare` (2.4 ms) and `BenchmarkEnumerate1000` (5.8 ms), which join the gate with ReportAllocs | at most 1 more alloc per held descriptor (pinned over a 100-path Prepare); median ≤ +5% | pin, gate, acceptance (C5) |
| P8 | `make vm-perf` warm start and fill | existing budgets hold (landlock 250 ms; cgroup and bpflsm 1000 ms); the fill row unchanged within the suite's noise; the reservation's RCU saving re-measured after C11b | acceptance |
| P9 | `BenchmarkOwnedOpenClose` against `BenchmarkRawOpenClose` | median delta ≤ 50 ns; ≤ 1 more alloc (24 B) when the owner escapes, none when it does not | recorded |

- **Two plan claims withdrawn.**
  - The plan's "Borrow/Return ≤ 5 ns" is withdrawn. One locked add costs 6.0–7.7 ns on the reference machine, so no
    correct two-atomic lease can meet it.
  - The ADR plan's "NotificationRoundTrip at 0 allocs" is a misreading. The 0-alloc pins are
    ParseSockaddr and NearestFS (allocs_test.go), and they stay.
- **Where the time costs show.** `BenchmarkNotificationRoundTrip` runs over `fakeKernel`, so its time rows cannot
  see a descriptor syscall's cost. That is why P5's real-kernel row exists.

### Why

[documented] Both bugs traced a finalizer of an `*os.File` that wrapped a number someone
else owned. The proposed decision's reasoning stands.

[inference] On the lease (A1):
- The proposed `Borrow()` ("for a syscall made while the owner lives") cannot stop a Close by another goroutine
  between the Borrow and the syscall. That is exactly the window in which the number was reused.
- A counted lease with a deferred close keeps the number in the table until the last borrower is done. Reuse under
  a borrower becomes impossible, not merely detected. Go's internal/poll does the same for blocking files.
- A public unpaired `Return()` reintroduces the class: one extra Return ends another holder's lease and closes the
  number under it. The closure-scoped Borrow and the idempotent Lease make that unreachable.
- A deferred close makes "the close has happened" a moving target. A caller who needs it must ask it of the state,
  not of its own call. Hence the done bit and CloseNow's contract: nil only after close(2) has returned.
- When the caller who needs the close is not the caller who closes, the dependency has to travel with the
  descriptor, not with one call site. Hence the hook.
  - On fanotify.go, Detach's Close may run while the loop's lease is out. A CloseNow there would get `ErrLeased`.
    The latch would then turn the joiner's later Close into a no-op, and the arm would be held for the life of the
    process.
  - With the hook, whichever path closes the group releases the arm, and only after close(2).

[documented, code]
- **fanotify.go.**
  - The workers write responses through `writeResponse` under `groupMu.RLock` (l.1243).
  - On the failing path they do so after `loop()` has returned. The group is closed by the goroutine that runs
    `answering.Wait()` and then `f.Close()` (l.486-500).
  - `Close` is latched by `closed.CompareAndSwap` (l.1407). It closes the group under `groupMu.Lock` (l.1414) and
    releases the arm afterwards.
  - A response names its event by the event fd's number.

  Hence two leases, with the pool's lease handed to the joiner, and a Borrow of the event fd around each response.
- **The listener's users.** The supervisor's relay goroutines may outlive Run, but they touch only their own
  duplicate. askHeld's watcher is joined inside the handler. `New` issues SetSyncWakeUp before Run exists
  (supervisor.go:541), hence a Borrow there.
- **The notify fd's copies.** The convention sets `r.notifyFD = -1` after New, and `Child.NotifyFD` keeps a stale
  copy of the same number after ownership has passed. hoststate's `Dir.Close` clears its int non-atomically.
- **Inherited numbers.** The launcher's pidfd is written into `SysProcAttr.PidFD` by Go's clone3. Received rights
  are close-on-exec, because `ReadMsgUnix` passes MSG_CMSG_CLOEXEC.
- **The reaper's sweep.** `closeStrayFDs` returns silently when /proc/self/fd is unreadable. It already keeps the
  runtime's eventpoll and eventfd, which a blind close_range would close under the runtime.

[documented, code] The proposed Decision's own premise ("only ownership in the type system prevents the class")
leads to the birth rule (A10).
- The plan's deny-list check lets `n, _ := h.LandlockRuleset(); sys.Own(n, nil)` through, and `PlaneHeld` would
  pass the same way. Each is a second owner over another package's number: the double close again, minus the finalizer.
- An allowlist of producers makes the wrap a lint error. Constraining its two escape hatches closes the rest:
  - Inherited, by kind, the seal and its listed sites;
  - OwnSyscall, by (trap, command) pairs.

  A raw syscall that returns 0 for "success" can then never become an owner of stdin.

[measured, golangci-lint 2.13.2 on a scratch module]
- **forbidigo with `analyze-types`** reports:
  - `unix.SYS_CLOSE`, `syscall.SYS_DUP3` and `unix.F_DUPFD_CLOEXEC`;
  - `unix.Close` taken as a value, and `f.Fd` as a method value;
  - cilium's `p.FD()` and `m.FD()`;
  - `os.NewFile`, `ParseUnixRights`, `Dup2` and `CloseRange`.

  It does not report `w.Fd()` through an embedded `*os.File`, nor an `interface{ Fd() uintptr }`.
- **Text-scoped exclusions work.** proc's `os.StartProcess` stays excluded under `text: "ADR 0021"`, and proc's
  `unix.Close` is reported under "ADR 0023".
- **Build tags.** With `tegotesthooks` added to the tagged run, the repository lints with 0 issues.
- **Fixtures need `--max-same-issues=0`.** The default of 3 collapses identical messages: a scratch module showed
  3 of 8 `syscall.Close` references.

[measured, prototype of A1's state word, -race tests and benchmarks, reference machine]
- **Tests passed:**
  - 64-goroutine close-once, 200 rounds;
  - a lease defers close: the number survives Close and is EBADF after the last Return;
  - no finalizer;
  - 2,000 rounds of 4 borrowers against a concurrent Close, with no borrowed number ever closed;
  - a panic inside Borrow's fn returns the lease (revision 2).
- **Costs.** The revision 2 figures were taken on a loaded box, so they are higher across the board, the
  calibration row included:

  | Operation | Cost |
  |---|---|
  | empty loop | 1.29 ns |
  | one atomic add | 6.0–7.7 ns |
  | two atomic adds | 10.8–12.8 ns (15.4–21.5 ns in the revision 2 runs) |
  | Load plus CAS | 9.3–12.7 ns |
  | `sync.Mutex` Lock/Unlock | 14–18 ns |
  | Borrow with `defer` on a concrete `*FD` | 18.8–28.8 ns, 0 allocs (revision 2) |
  | the same through an interface the compiler can devirtualize | 17.5–25.7 ns, 0 allocs |
  | the same through an opaque interface, closure capturing a local | 40.2–49.9 ns, **2 allocs, 24 B** |
  | the same through an opaque interface, closure capturing nothing | 17.4–18.1 ns, 0 allocs |
  | 4-way contended pair | 116–146 ns |
  | `(*os.File).SyscallConn().Control` | 49–58 ns, 2 allocs, 24 B |
  | owned open+close of /dev/null against raw | within noise (1.3–2.3 µs); no extra allocation when the owner does not escape |

[measured, benchmarks, reference machine]
- **NotificationRoundTrip.**
  - write_open: 2.56–3.04 µs, 10 allocs, 1,227–1,249 B;
  - mkdir: 1.83–2.08 µs, 10 allocs, about 1,200 B;
  - connect_allow: 5.8–8.0 µs, 23 allocs, 2,326–2,335 B;
  - connect_refuse: 2.15–2.68 µs, 10 allocs, 1,441 B;
  - execve_argv: 3.44–3.72 µs, 23 allocs, about 2,500 B.
- **RealWalk.** 2.4–3.4 µs at 9–10 allocs; via_symlink 13.2–15.2 µs at 17 allocs.
- **enforce/cgroup.** ListenerHandle: 22.9–25.3 µs, 22 allocs, 9,361–9,370 B. DecideEventOffTheRun: 1.6 µs at
  4 allocs, and 8.5 µs at 13 allocs.
- **Ledger.** Append: 4.5–4.8 µs, 14 allocs.
- **Landlock.** Prepare: 2.3–2.4 ms. Enumerate1000: 5.4–6.6 ms.

The owner's costs are in the noise of every per-event path, except a contended per-event lease (hence P4) and an
interface Borrow with a capturing closure (hence concrete hot seams, A11).

[measured, census and code] The leaf package's only motive was pkg/spec. trust.go's two descriptor uses have
standard-library replacements, so the leaf, its alias, its forwarders and three depguard rules are not needed.
Keeping the type in sys also avoids the 216 local `fd` variables that would shadow a package named `fd`.

**Security argument.**
- **What is closed by construction.** Once the exclusion list is empty, no production code outside the owner's
  files can:
  - close or dup a number it does not own;
  - wrap another owner's number;
  - mint a second owner by Inherited, or an owner of a non-descriptor by OwnSyscall;
  - keep a lease past its scope.
- **Exempt code cannot reach the binary** (A7, F11).
- **What still corrupts a grant:** a number closed by a third-party library or by the Go runtime, or a number
  copied out of a lease (residuals below).
- **The backstops are backstops, not guarantees.** I12's statx compares (dev, ino), and R16 compares (mnt_id,
  ino). Neither sees an inode number reused after the inode was freed (ext4 reuses numbers quickly) and reopened
  onto the same number. Within its reach, the plane's per-hit check compares i_generation (ADR 0025 (4)).
- **Failure modes.** A failure of the owner fails Prepare or Start, or refuses a decision. At the fanotify tier, an
  unwritable response stays the recorded fail-open GapFanotifyResponse, as before. Nothing fails silently.

### Consequences and residual limits

**What changes.** Every package with raw descriptors changes, and these signatures change:
- `enforce/api.Handle`'s descriptor methods (C5, after the TCB API work);
- `launch.Child` and `WaitNotifyFD`;
- `supervisor.New` and its kernel seam;
- The landlock Handle and seam;
- The plane fill's `heldFD`;
- The sys pidfd, seccomp and landlock producers;
- `hoststate.Dir`;
- `ledger.OpenAt`, `ask.RelayPool.Reserve` and `cgroup.Handle.GrantConnect`.

internal/ledger gains a dependency on internal/platform/sys.

**Cost.**
- One allocation of 24 B per owner that escapes: +2 per relayed connect, +1 per fanotify event, and at most +1 per
  held Landlock descriptor.
- No per-notification lease on the listener and no per-event lease on the group. Per-event Borrows on event fds
  and duplicates are direct calls with no allocation.
- CI gains one tool (fdcheck), one depguard rule, one bench-gate package line, one build tag on the tagged lint
  run, and the total check in the bench-gate job.

**Residual limits, stated plainly:**
- **Leases.** A number can still be copied out of a lease: `Borrow(func(n int) error { saved = n; … })`, or a worker
  given `lease.Num()`. fdcheck does not follow data flow. Typed methods (A11) remove most closures, and review plus
  the statx and R16 checks remain the defence. The fanotify workers' copied number is safe by structure, because
  they are joined before the pool lease returns.
- **Libraries.** Third-party code (cilium, the Go runtime, x/sys) can still close numbers it does not own. Only the
  identity backstops catch the effect, and only where a grant is made, with the limit stated in the security
  argument.
- **Exempt code** (test files, internal/testutil, tools/, test/) keeps 306 or more raw sites. A flaky test there is
  possible. The binary cannot contain that code (A7).
- **Leaked leases, and tegod.** A leaked Hold blocks its descriptor's close for the life of the process.
  - For the fanotify group, that means proc.Start stays refused **for every later run in the process**. In tegod,
    that is every run until a restart.
  - A strict FD's CloseNow reports `ErrLeased` and names the holder under testhooks.
  - The run-teardown assertion (A8) and NoFDLeak catch leaks only on the paths that tests and KVM suites cover. The
    leak counter is in-process only.
  - A daemon would need detection of its own; ADR 0042 keeps tegod unbuilt.
- **Close errors.** A deferred close of a non-strict FD with no hook drops close(2)'s error. Owners that need it are
  strict or register a hook.
- **Long blocks.** A lease held across an unbounded block delays a deferred Close for as long as the block lasts.
  The supervisor and the fanotify listener each have a wake path. Any new long-lease holder must have one too.
- **Reach of the lint.** It matches identifiers. reflect, unsafe pointer games, assembly and cgo are out of its
  reach. The TCB has no cgo, and the product builds with CGO_ENABLED=0.
- **Until the list is empty.** Until C19 the exclusion list is non-empty, and claims about unmigrated packages stay
  false. The C0 notes say which commit makes each one true.
- **Unlisted producers.** A producer fdcheck cannot classify fails lint until someone lists it. That is fail-closed
  for the lint, at a small cost to authors.
- **The reaper.**
  - Its sweep is correct only before it opens anything (a stated, tested precondition).
  - Its walk keeps any eventpoll or eventfd, including one a caller passed on purpose.
  - When /proc/self/fd is unreadable it exits 125 without sweeping. The launcher does not wait on it, so that run
    then has no reaper, and the next sweep collects it (ADR 0020's existing bound).
  - Descriptors a non-Go parent leaked to the launcher itself are owned by no one in the launcher. They are only
    made close-on-exec in the child.
- **Inode-number reuse** is outside the userspace backstops (security argument).
- **arm64** is checked only by the pins and unit tests on the hosted runner. No arm64 KVM row exists.

### Rejected options

| Option | Why rejected |
|---|---|
| The proposed plain `Borrow()` (lend while the owner lives) | It cannot stop a concurrent Close between the borrow and the syscall, which is the reuse window. |
| A public unpaired `Borrow()`/`Return()`, as plan A1 had it | An extra Return ends another holder's lease and closes the number under it. |
| A Close that waits for leases (internal/poll's blocking path) | It deadlocks when the closer holds a lease or a borrower is blocked for good. Deferral, plus CloseNow and the hook, give the same no-reuse property without waiting. CloseNow waits only for a close(2) already running. |
| Tying the fanotify arm to one caller's CloseNow | Detach's CloseNow meets the loop's lease and gets `ErrLeased`. The latch turns the joiner's later Close into a no-op, and the arm is held for the life of the process. The hook ties the arm to the close itself. |
| Relaxing F2 so that the Return is ordered before a Close in the caller | It is not needed. With the hook, a Close while a lease is out is simply deferred, and the order of Return and Close no longer matters. The hand-off form (F2 (b)) covers the workers that outlive loop(). |
| Keeping groupMu and writeResponse's closed check beside the lease | The lease subsumes both, and the check turned a decided answer into a fail-open whenever Close raced a worker. |
| Per-notification leases on the listener | 116–146 ns per contended pair at 4 workers, times about 3 listener calls per notification, against a 2–3 µs loop share. One Hold per Run costs nothing per notification. |
| A Borrow/Return budget of ≤ 5 ns | Below the cost of one locked add (6–7.7 ns). A ratio to a same-process calibration is portable. |
| Interface-typed hot seams (`sys.Owned` on the kernel seam) | A Borrow through an opaque interface with a capturing closure costs 2 allocs and 24 B (measured). That contradicts any allocation ceiling on connect rows. Concrete `*sys.FD` plus `InertForTest` fakes cost nothing per Borrow. |
| A Borrow-only `Lender` | The fill needs one lease per descriptor across the iterator. Borrow-only forces nested closures or copying numbers out, the pattern A1 exists to prevent. |
| A leaf package `sys/fd` with an alias | Its one motive, pkg/spec/config's trust.go, has standard-library replacements (`SyscallConn().Control`, Fstatat). It cost an alias, forwarders and three depguard rules, including a lax carve-out in `spec-is-pure`. |
| go/analysis via x/tools | It adds a module to go.mod when forbidigo already resolves types (measured). The rest needs only the standard-library AST, as checkexits and rulecheck do. |
| depguard `allow` in the default list mode | It does not work (measured): the allow does not override the deny, and the standard library becomes denied. Moot now that pkg/spec needs no allow. |
| The plan's deny-list fdcheck (a) | It misses an int returned by another package's API, the cross-package wrap. Replaced by the birth rule. |
| `Inherited` with only an "is it open" check | It passes exactly when the number is live and owned by another sys.FD: a second owner, the double close. Kind, seal and listed sites close it. |
| OwnSyscall admitted by trap alone | SYS_BPF, SYS_SECCOMP without NEW_LISTENER, and landlock's VERSION query return a number that is not a descriptor. An owner of 0 would close stdin. |
| `SYS_IO_URING_SETUP` as a production producer | Its only user is a test helper. io_uring's own operations close and install descriptors outside these rules, so it needs its own ADR before entering the TCB. |
| Pooling FD objects to save the 24 B | A stale pointer to a recycled FD object is the same use-after-close, one level up. The allocation is noise next to the syscall. |
| A test-only deferred-close check as the only defence for lock and group FDs (the plan's mitigation) | It sees the problem only in tests. Strict FDs and the hook make the dependency structural in production. The testhooks report stays as a second line. |
| Listing CloseNow sites in prose only | A forgotten CloseNow is a silent hang, not an error. Strictness at birth makes it structural. |
| Leaving cilium `FD()` out of scope (plan) | It is the same shape as `(*os.File).Fd`, and costs 4 sites. |
| Linting test-hook files through fdcheck alone | Adding the tag to the tagged lint run is free (0 issues) and also gives ADR 0021's rules that coverage. |
| A production finalizer or cleanup that closes a dropped FD | It is the bug class itself: closing a number at a time the garbage collector picks. |
| A blind `close_range(first, ~0, 0)` as the reaper's first act | The Go runtime may already hold its netpoll descriptors by then: they are opened lazily by the first pollable file, which os initialisation creates for a non-blocking inherited stdio. Closing them under the runtime crashes it. The kept walk distinguishes them. Fail-closed on an unreadable /proc/self/fd answers the underlying concern. |
| Comparing i_generation or a name_to_handle_at handle in I12 and R16  | statx carries no i_generation. FS_IOC_GETVERSION fails on O_PATH descriptors, and handle support varies by filesystem (overlayfs without index). Within the plane's reach, the in-kernel per-hit check already compares i_generation. The userspace checks are relabelled as backstops instead. |
| Keeping auditing by hand; the statx check alone; wrapping every descriptor in `*os.File`; three lint patterns | Rejected in the proposed text, for the reasons it gives. |

### Implementation plan

**Conventions for every commit.**
- **Gate.** `gofmt -l .` prints nothing; both lint runs pass; `make precommit` passes. Error texts, exit codes and
  doctor output are byte-identical, apart from the newly pinned failure rows.
- **Heavy runs** go through the RAM-limited job wrapper with GOMAXPROCS=4, at most 2 KVM guests at a time.
- **Each package migration also:**
  - runs its unit and integration tests with `-race`;
  - runs `scripts/fd-churn.sh <pkg> -count=500` under load (`-p 6`);
  - adds `testutil.NoFDLeak` to the package's unwind tests;
  - deletes the package's exclusion rule and baseline line;
  - meets its P rows;
  - lists its strict sites in the commit message;
  - lands the spec amendment it makes true, with a Changes entry;
  - appends any new root test to test/vm/root-must-pass.txt.

**Rows and boots.**
- "GUEST both" means `VM_BOOTS=both make vm-root-test <pkg>`: the lsm=…,bpf boot, then the host's lsm list without
  bpf.
- "Matrix" means `make vm-matrix` on every fetch-kernel.py row and the host: rhel-9 5.14, al2023 6.1,
  ubuntu-24.04 6.8, debian-13 6.12, al2023-6.12, fedora-7.0 and host 6.17, plus KMATRIX's rows once they land.
- **Kernel needs.** close_range CLOEXEC 5.11 (with a walk fallback), pidfd_open 5.3, pidfd_getfd 5.6, and
  F_DUPFD_CLOEXEC, which every supported kernel has. All are at or below the 5.14 floor. An unprivileged
  Landlock-only host needs no new privilege, syscall or kernel feature.

**FD-TYPE (additive, no caller changes).**
- **C0, docs.** This ADR's own text, plus:
  - correction-of-fact notes, each "not yet true; becomes true at Cn": ADR 0020 (C9), ADR 0024 (C5, C11b), ADR 0025
    (C11b) and ADR 0034 (C12);
  - Changes entries in enforce-plane.md near lines 1011 and 1182 (C11b), and in TIER3-PLAN T4;
  - ADR 0031's note: (a) does not wait on this ADR, because C5 edits enforce/api after the TCB API work;
  - CONTRIBUTING: the ownership rule in a few lines, and how to read an "ADR 0023" lint message.
  - Test: `go run ./tools/rulecheck` and adrindex_test.
- **C1, the owner.** Files: `internal/platform/sys/{fd.go, fd_lease.go, fd_errors.go, fd_inherited.go,
  fd_testhooks.go (tegotesthooks), fd_test.go, fd_race_test.go, fd_bench_test.go}`. Tests:
  - one test per cell of A1's table, including:
    - `TestHoldBorrowDupReleaseAfterClose`;
    - `TestHoldBorrowDupReleaseAfterAbandon`;
    - `TestCloseNowTwice`;
    - `TestCloseNowOnKeptFails`;
    - `TestAbandonCancelsDeferredClose`;
  - `TestCloseNowWaitsForRunningClose`: a hook-blocked close(2) path, then CloseNow returns nil only after it;
  - `TestCloseNowNeverNilWhilePending`: Close with a lease out, then CloseNow gives `ErrLeased`;
  - `TestOnClosedRunsAfterCloseOnEveryPath`: Close, CloseNow and the last Return; never after Release or Abandon;
  - `TestOnClosedVsCloseNowRace`: 1,000 rounds of Close, CloseNow and Return from three goroutines. The hook runs
    exactly once, after fstat on the number gives EBADF;
  - `TestCloseOnceUnderRace`: 64 goroutines; a sentinel dup3'd onto the freed number stays open;
  - `TestZeroFDOwnsNothing` (fd 0 stays open), `TestNilFD`, and `TestNilInInterface` (`ErrClosed`, no panic);
  - `TestOwnRefusesStdio`: n = 0, 1, 2 refused and left open;
  - `TestBorrowReleasesOnPanic`;
  - `TestCloseDeferredUntilLastReturn`: fstat OK under the lease, EBADF after;
  - `TestStrictCloseIsCloseNow` and `TestFlockRefusesNonStrict`;
  - `TestReleaseRefusesWhileLeased`, `TestReleaseTransfers` and `TestReleaseNumberEmpties`;
  - `TestLeaseReturnIdempotent` and `TestLeaseNumAfterReturn` (-1; a panic under testhooks);
  - `TestInheritedKinds`, `TestInheritedSealed` and `TestInheritedRefusesStdio`, run in a re-exec'd helper
    process;
  - `TestErrorsMatchErrno`: `ErrClosed` is EBADF and `ErrLeased` is EBUSY;
  - `TestNoFinalizer`: drop, GC twice, the number is still open;
  - under tegotesthooks: `TestLeakCounterCountsOne`, `TestOwnRefusesNonCloexec` and `TestHoldRecordsPC`;
  - `TestBorrowAllocatesNothing`, `TestHoldAllocatesOne` and `TestBorrowCostRatio`;
  - `TestLeaseVsCloseUnderChurn`: 2,000 rounds; a borrowed number always names its own (dev, ino);
  - benchmarks P1–P3 and P9, and `BenchmarkTwoAtomicAdds`.

  It runs on the hosted arm64 runner as well. bench-gate.sh gains the sys package line, with a fixture
  in bench-gate_test.sh.
- **C2, sys helpers and owner forms.**
  - Files:
    - `sys/pidfd.go`: the `*FD` forms; the int forms stay until C19;
    - `sys/seccomp.go`: `SeccompNewListenerFD`;
    - `sys/landlock.go`: `LandlockCreateRulesetFD`;
    - `sys/cloexec.go`: `CloexecFrom` and `CloseInheritedFrom`, both returning errors;
    - `sys/filedo.go`: `FileDo`, `DupFile`, `Flock` and `FstatFile`;
    - `sys/rights.go`: `ReceiveRights`;
    - `sys/pipe.go`: `Pipe2`, `Socketpair` and `Accept4`;
    - `sys/dupover_testhook.go` (tegotesthooks);
    - `sys/inert.go`: `InertForTest`;
    - `internal/bpf/fdborrow.go`: `ProgramFD` and `MapFD`;
    - `internal/testutil/fdcount.go`: `NoFDLeak`, which uses `t.Setenv`.
  - Tests:
    - a unit test per helper;
    - CloexecFrom's fallback when seccomp refuses close_range (the existing child_test pattern), and its error
      when both paths fail;
    - CloseInheritedFrom in a child started by proc.Start keeps exactly the listed numbers, and fails when
      /proc/self/fd is unreadable;
    - ReceiveRights owns every number of a partly parsed message;
    - NoFDLeak's negative control: one deliberate leak fails;
    - `TestNoFDLeakRefusesParallel`.
- **C4, churn.** `scripts/fd-churn.sh` and its `_test.sh`.
  - The script runs a TMPDIR create, open, close and unlink loop beside `go test -p 6 -race -count=N <pkg>`, and
    fails if either fails. The loop runs in another process, so it adds kernel and filesystem pressure. It does not
    recycle numbers inside the test process.
  - **What proves the harness** is the negative control. It is a hard gate in fd-churn_test.sh: a fixture package
    that double-closes, racing a second goroutine's open inside the test process, fails within `-count=50`. C4
    records the measured detection rate over 20 repetitions.

**FD-LINT (the baseline is generated from the tree it lands on).**
- **C3, lint.**
  - `.golangci.yml`:
    - A4's rules;
    - A7's text-scoped exclusions, plus one shrinking `- path:` rule per package;
    - `build-tags` adds tegotesthooks (scripts/lint-untagged.sh and ci.yml change with it);
    - depguard `testutil-never-in-binary`.
  - `tools/fdcheck/` (standard-library AST):
    - F1–F11;
    - The generated producer list, and adopt.txt, abandon.txt, inherited.txt, stdio.txt and baseline.txt;
    - `-edges`, which writes the edge list, checked in as edges.txt.
  - `scripts/check-fd.sh` (with `--base`). It is wired into `make lint` and `scripts/precommit.sh`, with
    `check-fd_test.sh` added to precommit's `script_tests` and to ci.yml build-test, so precommit_test.sh's
    equality holds. The total check runs in ci.yml's bench-gate job.
  - runtime-launch §5 gains **R25, descriptor ownership** (A1, A5's re-verification rule, A10, A11). §9's "Resource
    lifetimes" is amended ("closed exactly once, by whichever holder closes first"). Each change has a Changes
    entry.
  - ADR 0021 gets a dated note: its rules now see the six tegotesthooks files, and proc's exemption is
    text-scoped.
  - Tests:
    - `tools/fdcheck/fdcheck_test.go`, a fixture table with positive and negative cases for F1–F11. It includes:
      - aliased and dot imports;
      - a method value, and a producer or Abandon taken as a function value;
      - a promoted `Fd` through an embedded `*os.File`;
      - an `interface{ Fd() uintptr }` assertion;
      - a literal and a constant syscall trap;
      - `SYS_BPF` with MAP_UPDATE_ELEM (rejected) and PROG_LOAD (admitted);
      - `SYS_SECCOMP` without NEW_LISTENER (rejected);
      - landlock with the VERSION flag (rejected);
      - `FcntlInt(fd, 0, n)` (rejected);
      - a `*Lease` in a struct field and in a non-hand-off closure (rejected), and the hand-off form (admitted);
      - Open without O_CLOEXEC (rejected);
      - an exported `func X(fd int)` in a migrated package (rejected);
      - an Inherited site that is not listed;
      - `//nolint` not hiding a site;
      - a tegotesthooks file scanned;
      - a file under an ignored path not scanned;
      - a moved count;
      - a binary that links testutil (rejected).
    - `scripts/check-fd_test.sh` runs golangci-lint with `--max-same-issues=0` on a testdata module, and expects:
      - one hit per A4 primitive;
      - proc reported under ADR 0023 and not under ADR 0021;
      - a non-test file importing internal/testutil denied.
    - Both lint runs clean on the tree.

**FD-EARLY (after FD-LINT).**
- **C10, ledger.** handover.go, writer.go, live.go, blob.go, reader.go, place.go and anchor.go.
  - `OpenAt` takes a Lender.
  - Lock and durability descriptors are strict. Durability paths fsync first.
  - REPO-LAYOUT gains the ledger → platform/sys edge.
  - Gates: P7, and ledger churn at -count=500.
- **C12, hoststate.** `Dir` holds a verified `*sys.FD`, and `Dup` becomes `.Dup()`. Gates: hoststate root tests,
  GUEST both. ADR 0034's C0 note is completed.
- **C13, runtime/cgroup.** events.go (inotify), fs.go, helper.go and manager.go. Gate: GUEST both.
- **C17, cli.** ownlog.go. Gate: cli tests and the ownlog testhook.

**FD-MID (after the TCB API work).**
- **C5, enforce/landlock, in full.**
  - The changes:
    - The ruleset born through `LandlockCreateRulesetFD`;
    - fdSet entries as owners;
    - owns() and add_rule under one Borrow (T1.1);
    - `closeRuleset`, `rulesetStill` and the owns() failure ending in `Abandon`;
    - exec.go, enumerate.go and filter.go:1060;
    - the `enforce/api.Handle` methods: a Dup of the ruleset given, and PlaneHeld and PlaneListenParent lent as
      Lenders. cgroup's delegation and observe's stub change with them;
    - The landlock seam returns `*sys.FD`.
  - New root test TestHeldSetAbandonOnReuse: a number closed under the set and reused fails Prepare with the
    pinned §7 text and is not closed again.
  - Gates:
    - heldfd_test.go and heldfd_integration_test.go at -count=500 under churn;
    - the I12 texts pinned;
    - P8;
    - landlock and cgroup unit tests.
  - Docs: enforce-landlock §9 is amended, and ADR 0024's C0 note gains "landlock half true at C5".
- **C6, launch.**
  - The changes:
    - `sys.Inherited` with kinds in the child;
    - `sys.CloexecFrom(3)`, failing closed;
    - The ruleset through Dup and Release;
    - Adopt of `SysProcAttr.PidFD`;
    - `Child.PidFD` becomes `*sys.FD`, and the `NotifyFD` copy is removed.
  - Gates: launch root suite GUEST both; KT1–KT4 on the host row.
- **C7, the notify-fd handoff, launch → runtime → supervisor.**
  - The changes:
    - `WaitNotifyFD` returns a strict `*sys.FD`;
    - `r.notifyFD` becomes `*sys.FD`;
    - `supervisor.New(listener *sys.FD, …)`;
    - `sysKernel` holds the FD and binds Run's lease (T1.5);
    - Run Holds the listener, then calls CloseNow after the workers leave;
    - continuednet_test.go owns its /dev/null.
  - New tests:
    - TestRunTakesOneListenerLease;
    - TestNewRefusesNonStrictListener;
    - TestRunListenerCloseDeferredUntilWorkersLeave (integration, a real listener): a strict Close from
      another goroutine mid-run gets `ErrLeased`; notifications are still answered; the number is closed once
      (sentinel).
  - Docs: supervisor.md's §1 "Notify fd" row is amended, with a Changes entry.
  - Gates: P5's time rows on the reference machine; supervisor root suite GUEST both.
- **C9, the rest of internal/runtime.**
  - The changes:
    - reap.go: `PidfdOpenProcessFD`, Release into ExtraFiles, `CloseInheritedFrom` failing closed, and
      `Inherited` with kinds;
    - rootmark.go, dns_directory.go, lock.go, landlockaudit.go and stdio.go (`sys.Stdio`);
    - the Fd() sites.
  - Run teardown gains the tegotesthooks lease assertion (A8).
  - New root tests:
    - TestReaperInheritsExactlyItsDescriptors: /proc/self/fd is exactly 0–2, the listed numbers and the Go
      runtime's eventpoll and eventfd;
    - TestReaperRefusesWrongKind: a directory where the pidfd belongs exits 125.
  - Gates: GUEST both; KT3 with `VM_KT3=1` on rhel-9 and host.
  - Docs: ADR 0020's C0 note is completed, and its :63 departure "sys.FD … not built" is superseded.

**FD-GROUP (after the name backend, which edits fanotify.go).**
- **C11a, the fanotify listener.**
  - The changes:
    - The group born through an owner-returning `fanotifyInit` seam;
    - two group leases (read loop, and the worker pool handed to the joiner);
    - event Adopt, and responses under the event FD's Borrow;
    - groupMu and the closed check deleted;
    - The wake pipe from `sys.Pipe2`;
    - The arm released by `OnClosed`.
  - New tests:
    - TestListenerTakesTwoGroupLeases;
    - TestFanotifyArmReleasedOnlyAfterGroupClose (root): Detach's Close races the loop's return on both the
      cancelled and the failing path, 500 rounds each. proc.Start stays refused until fstat on the group's number
      gives EBADF, and is then allowed, every round;
    - TestFanotifyResponseUnderEventBorrow: a closer racing a worker never lets a response name a reused number.
  - Gates: GUEST both, with `VM_SUITE_MEM="internal/runtime/enforce/cgroup=2560M"`; `TestConformanceKernel` at cgroup
    on the host row, both boots; P6.
  - Docs: enforce-cgroup-observe gets the hook and the two leases, with a Changes entry. ADR 0021 gets a dated note:
    (3)'s arm is released by the group's close hook.

**FD-LATE.** One worktree per package, after each package's dependencies.
- **C8, the rest of the supervisor.**
  - The changes:
    - The kernel seam's producers return `*sys.FD`, and fakes use `InertForTest`;
    - `CloseFD` is removed;
    - resolveSocket's SO_* reads go under one Borrow;
    - The execimage, walkcache and unixrelay walkers move to local owners;
    - ask_open (ADDFD borrow) and ask_scopes move too.
  - Gates:
    - P5 (BenchmarkResolveSocketReal before and after, the allocation pins in allocs_test.go);
    - supervisor root suite GUEST both;
    - The conformance cells at landlock.
- **C11b, the rest of enforce/cgroup.**
  - The changes:
    - members.go (OpenByHandleAt owned, `ProcPath()`), and descriptors.go (`DupFile` 128);
    - planefill: Lenders held across the iterator, `OwnSyscall` with BPF_ITER_CREATE, and `ReleaseNumber`;
    - cilium borrows through fdborrow.go, and unpinned links and maps kept reachable (A8);
    - plane_testhook moves to `DupOverForTest`.
  - New root test TestPlaneFillLeasesDeferLandlockClose: closing the Landlock set during the fill defers the
    closes; the fill completes, and R16 passes.
  - The reuse cell (`TEGO_TEST_PLANE_FILL_REUSE`) still fails Prepare.
  - Gates:
    - GUEST both;
    - `TestConformanceKernel` at cgroup@fmod_ret, cgroup@lsm and bpflsm on the host row, both boots;
    - P8's warm-start row.
  - Docs: notes to enforce-plane R16 and ADR 0025, and ADR 0024's C0 note completed.
- **C14, ask and dnsbroker.**
  - The changes: `ReceiveRights`; agentFD via `.Dup()`; `RelayPool.Reserve` takes an owner; the relay pidfd is
    closed through its owner.
  - The earlier race probes are kept as tests with NoFDLeak: 60 SCM_RIGHTS cycles, and the ask relay pool, each at a
    constant descriptor count.
- **C15, capture and BPF.**
  - The packages: capture/uprobe (the shared.go flock sites through strict owners or `sys.Flock`),
    capture/forwarder, observe, and internal/bpf (ring.go via MapFD).
  - Gate: the uprobe root suite (tegobpf) GUEST both.
- **C16, doctor.**
  - The changes:
    - planeprobe.go, runcache.go and runcache_flight.go: Dup then Release, with strict flight locks;
    - seccomp.go: the probe's listener through `SeccompNewListenerFD`, and its memfd with MFD_CLOEXEC through
      OwnSyscall;
    - fanotify.go: Adopt;
    - programs.go:909: the load inside `MapFD`'s fn;
    - planeknown.go.
  - Gates: the doctor cache tests under churn; doctor golden output unchanged.
- **C18, pkg/spec.** After the spec split, pkg/spec/config/load/trust.go switches to the standard-library calls of A2,
  and whatever else then remains in pkg/spec migrates the same way.
  - TestCheckContainsReplaced covers a symlink, another inode and a missing name, all `reasonReplaced`.
  - Gates: compile tests and the fuzz corpora.
- **C19, close-out.**
  - Deletions and checks:
    - delete the int pidfd, seccomp and landlock producers;
    - The exclusion list and baseline.txt are empty, which fdcheck asserts;
    - abandon.txt, adopt.txt, inherited.txt and stdio.txt are reviewed.
  - Status updates:
    - ADR 0023's Status gains "implemented <date>", and its README row changes;
  - Final runs:
    - full `make precommit`;
    - `VM_BOOTS=both make vm-root-test` on every package;
    - `make vm-matrix`;
    - `TestConformanceKernel` at landlock, cgroup, cgroup@fmod_ret, cgroup@lsm and bpflsm on every row;
    - `make vm-perf` on both boots;
    - bench-gate against the commit before C5, with P1–P9.

**Size.** There are 21 commits: C0–C4, C5–C10, C11a, C11b and C12–C19. C0–C4 come to about 1,800 lines of Go and shell with tests. C5–C18 change 292 sites and 109 or
more producers.

*Amended 2026-10-05 (implementation note, FD-TYPE C1 built):* `sys.FD` is in internal/platform/sys: fd.go (the
state word, the constructors, Close, CloseNow, Abandon, Release, ReleaseNumber, Dup, OnClosed and the typed
methods), fd_lease.go (Hold, Lease, Lender, Owned, HoldsForTest), fd_errors.go, fd_inherited.go (Inherited and its
kinds) and fd_testhooks.go (the tegotesthooks leak counter, close-on-exec check, holders' PCs, deferred-close
report, `LeakedForTest`, `OutstandingLeasesForTest`, `DeferredClosesForTest`). A1's table is pinned cell by cell
(fd_test.go, fd_race_test.go), with `TestCloseOnceUnderRace` (64 goroutines, 200 rounds; it wraps the
`closeNumber` seam, close(2) itself, with a counter of the close(2)s made on the round's number and fails a round
unless that count is exactly one, and a sentinel on the freed number must also stay open),
`TestLeaseVsCloseUnderChurn` (2,000 rounds), `TestOnClosedVsCloseNowRace` (1,000 rounds) and `TestNoFinalizer`;
Inherited's kinds, seal and stdio refusal run in a re-executed helper (fd_inherited_test.go). The C1 test list in
the plan above names `TestCloseOnceUnderRace` by its sentinel alone; the sentinel sees only a second close(2) that
comes after the OnClosed hook placed it, and the hook runs once however many close(2)s run, so the per-round
`closeNumber` count is the check that holds the "close the number once" of (1) and A1, and the sentinel stays
behind it.
Departures, each kept within the decision:
- **The owner is 24 bytes.** The note's P9 and P5 expectations (one 24-byte allocation per escaping owner) hold
  only if the slow path is not in the owner, so the hook, close(2)'s error, the wait channel and the testhooks trace
  live in a struct installed on first need; a flag in the state word orders its installation with every close.
  `TestOwnerIsTwentyFourBytes` pins it. Measured (i7-10870H, GOMAXPROCS=4): `BenchmarkOwnedOpenClose` 1,134 ns,
  2 allocs, 40 B against `BenchmarkRawOpenClose` 1,125 ns, 1 alloc, 16 B: +1 alloc, +24 B.
- **P1.** `BenchmarkBorrow` 19.3 ns/op, 0 allocs; `BenchmarkTwoAtomicAdds` 10.9 ns; `TestBorrowCostRatio` measured
  1.71–1.74 against the 2.5 budget. The plan's 5 ns target, which this note withdraws, is printed as `TARGET-MISS:
  Borrow 19.45 ns/op > 5 ns` by the benchmark and the pin, so the miss stays visible. `BenchmarkHold` 34.7 ns,
  1 alloc, 24 B (P2); `BenchmarkBorrowParallel` 46–52 ns (P3, recorded).
- **bench-gate.** internal/platform/sys joins its list with `^Benchmark(Borrow|Hold|OwnedOpenClose)$`;
  OwnedOpenClose is report-only there (P9 is "recorded", and it is a real open and close per op, like the other
  syscall-bound rows the gate does not fail).
- **ProcPath takes fn.** A11's `ProcPath()` returns the path under a lease the caller holds; `ProcPath(fn)` runs fn
  with the path under its own lease, so the path, which is the number, never leaves it.
- **Seal.** Dup sets the seal, as Own, OwnSyscall and Adopt do (and C2's helpers will); Stdio does not.
- **Refusals.** The stdio guard's refusal is `sys.ErrStdio`; `ErrNotStrict`, `ErrSealed`, `ErrKind` and
  `ErrNotCloexec` name the others.

*Amended 2026-10-05 (implementation note, FD-TYPE C2 built):* the helpers and owner forms, callers untouched:
sys/pidfd.go `PidfdOpenProcessFD`, `PidfdOpenThreadFD` and `PidfdGetfdFD` (the int forms stay until C19);
sys/seccomp.go `SeccompNewListenerFD`, born strict; sys/landlock.go `LandlockCreateRulesetFD`; sys/cloexec.go
`CloexecFrom` and `CloseInheritedFrom`, both returning an error when /proc/self/fd cannot be listed (and, for
CloexecFrom, close_range was refused); sys/filedo.go `FileDo`, `DupFile`, `Flock` and `FstatFile` over
`SyscallConn().Control`; sys/rights.go `ReceiveRights`; sys/pipe.go `Pipe2` (write end strict), `Socketpair` and
`Accept4`; sys/inert.go `InertForTest`; sys/dupover_testhook.go `DupOverForTest`; internal/bpf/fdborrow.go
`ProgramFD` and `MapFD`; internal/testutil/fdcount.go `NoFDLeak`. Departures, each kept within the decision:
- **Names.** F1's `PidfdOpenFD` is `PidfdOpenThreadFD`, after the int form it wraps (`PidfdOpenThread`); the
  process form is `PidfdOpenProcessFD`. `Accept4` takes the listening socket's `*FD` and leases it for the call.
- **ReceiveRights on a malformed buffer.** It walks the messages one at a time with
  `unix.ParseOneSocketControlMessage`, owns each number as it is found, and on a later malformed message, or a
  payload that is not whole numbers, closes every number it owned and returns the error: no received number is
  left unowned, and none is handed to a caller holding an error. A message whose own header is malformed cannot
  be located; the kernel's MSG_CTRUNC stays the caller's to check.
- **CloexecFrom and CloseInheritedFrom are copies.** launch's `cloexecFrom3` and the reaper's `closeStrayFDs` stay
  until their packages migrate (C6, C9); the copies differ only in failing closed where the reaper's returned
  silently.
- **inert.go joins A7's owner files.** The 2026-10-05 note's A7 list, which is the lint-exemption list C3 builds
  from, names no file for `InertForTest`, though C2 creates sys/inert.go to hold it. That file is added to the list
  here; the note above keeps the accepted text. The reason: `InertForTest` builds an owner from a bare int with
  `&FD{num: int32(n)}` and a state store, not through one of F1's constructors, so F1 would flag it in any file
  outside the owner's files. Its callers stay under the rules: F4 keeps it to `_test.go` files.
- **The root cell.** `TestBorrowsKeepTheObjectReachable` (internal/bpf, integration and tegobpf) runs the collector
  inside each borrow of a Map and a Program that nothing else references, and is in test/vm/root-must-pass.txt.
Tests, each failing to build before its helper existed: `TestPidfdOwnerForms`, `TestSeccompNewListenerFDIsStrict`,
`TestLandlockCreateRulesetFD`, `TestCloexecFrom` (close_range, the walk when close_range is refused, the error
when both fail), `TestCloseInheritedFrom` (a child started by proc.Start keeps exactly 0–4, and the sweep fails
without a listing), `TestReceiveRights` (the numbers sent, a malformed second message and a partial payload leave
no number open), `TestPipe2WriteEndIsStrict`, `TestAccept4`, `TestFileHelpers`, `TestInertForTest`,
`TestDupOverForTest` (tegotesthooks), `TestBorrowsRefuseNoObject`, and NoFDLeak's negative control
`TestNoFDLeakFailsOnALeak` with `TestNoFDLeakRefusesParallel`.

*Amended 2026-10-05 (implementation note, FD-TYPE C4 built):* scripts/fd-churn.sh runs `go test -race -p 6
-count=500` (both settable) of the named packages beside a create, open, close and unlink loop in another process,
and fails when go test fails or the churn died before it was stopped. Its negative control is a hard gate in
scripts/fd-churn_test.sh: scripts/testdata/fdchurn's TestDoubleClose, which closes a number twice while another
goroutine opens files, fails under the harness within `-count=50`, and the same test closing once passes.
Measured detection over 20 harness runs at `-count=50` (i7-10870H, `-p 2`): 20 of 20 runs failed, and 1,000 of
1,000 counts. fd-churn_test.sh is in CI's build-test and in precommit's script self-tests, as precommit_test.sh
requires of every tracked `_test.sh`; the harness sets CGO_ENABLED=1 for `-race` whatever the environment says.

*Amended 2026-10-16, revised 2026-10-17 (implementation note):* P1's ratio is a figure on a machine,
not only on the code: two atomic adds are a fixed workload, and a busy machine does not slow Borrow as it slows them.
On the reference machine the ratio reads 1.6 to 1.9 quiet and read 2.47 to 2.50 under 16 busy loops with two test
streams beside them, by P1's method and by an interleaved least CPU time alike, so the unit gate's raw comparison
failed for the machine's sake. `TestBorrowCostRatio` now holds P1 as the tree's timing budgets are held
(docs/BENCHMARKS.md, "Timing budgets in the test suites"): with `TEGO_TIMING_BUDGETS=1` (`scripts/timing-budgets.sh`,
first in CI's bench-gate job on its own runner, and `make budgets`) by P1's method, the median of five
`testing.Benchmark` runs of each, against 2.5, printing `TARGET-MISS` against the withdrawn 5 ns target as before; in
every other run as the ratio of the two sides' own times, each the fastest of 2000 batches of 1000 calls interleaved
with the side that goes first alternating (`testutil.MinOfThread`: the wall clock less the thread's waits for a CPU,
the whole wall clock of a batch in which it blocked), against ten times it, 25, and the ratio of their wall clocks
against a hundred times it; until 2026-10-17 that was their least thread CPU time, which no wait reaches. The budget
is unchanged. `TestBorrowAllocatesNothing` and bench-gate's comparison of `BenchmarkBorrow` with the base still hold
the lease in every CI run. A Borrow slowed by 30 rounds of a multiply-add loop fails budget mode in 8 runs of 8 on
the reference machine (ratio 2.69 to 3.18, the unmodified one 1.55 to 1.80 in the same minutes) and in 21 of 22 in an
idle 4-vCPU KVM guest (2.50 to 4.37: one run read 2.50, at the limit, beside an unmodified 1.78; the unmodified 1.12
to 2.17); one slowed by 400 rounds fails the unit gate under 16 busy loops in that guest in 4 of 4 (an own-time ratio
of 44.8 to 45.9, the unmodified 2.34; on the reference machine with the CPU-time gate, 43.9 to 44.2).

*Amended 2026-10-17 (implementation note, FD-LINT C3 built):* the lint and the ratchet, whose tree the baseline counts. `.golangci.yml` carries A4's forbidigo rules, each message saying "ADR 0023";
its tagged run builds `[integration, tegobpf, tegotesthooks]` (A3; scripts/lint-untagged.sh and ci.yml rewrite
that line, and the `!tegotesthooks` file, landlock's filter_product_test.go, is linted by the untagged run);
ADR 0021's blanket exclusion is scoped to `text: ADR 0021`, so internal/platform/proc is under the descriptor rules;
A7's permanent exemptions and one `- path: ^dir/[^/]+\.go$` rule per unmigrated package are scoped to
`text: ADR 0023`; and depguard's `testutil-never-in-binary` denies internal/testutil, tools and test to every
non-test file outside them. `tools/fdcheck` (standard library only) holds F1–F11 and the ratchet, with the
checked-in producers.txt (generated), baseline.txt, edges.txt (generated, `-edges -w`) and the empty adopt.txt,
abandon.txt, inherited.txt and stdio.txt. `scripts/check-fd.sh [--base REV]` runs it in `make lint`, in
`scripts/precommit.sh` (total against `git merge-base HEAD main`) and in CI's build-test (no base, depth 1) and
bench-gate (the push's or pull request's base). Tests: `tools/fdcheck/fdcheck_test.go`, a table of 94 fixtures
over F1–F10 (positive and negative, aliased and dot imports, a split line, values and method values, a promoted
`Fd`, an `interface{ Fd() uintptr }`, literal and constant traps, `SYS_BPF` with MAP_UPDATE_ELEM and PROG_LOAD,
`SYS_SECCOMP` without NEW_LISTENER, landlock with VERSION, `FcntlInt(fd, 0, n)`, a lease stored and captured
and the hand-off form, Open without O_CLOEXEC, an exported `func X(fd int)`, unlisted Adopt, Abandon, Inherited
and Stdio sites, a `//nolint` that hides nothing, a file whose build constraints exclude every build, a
tegotesthooks file), plus the ratchet (a rise, a fall, a swap of kinds, a stale line, a migrated package's new
close, dup and os.NewFile, the list and `.golangci.yml` disagreeing, a listed site beyond its count and a stale
list entry), the total against a base (a rise fails, a moved count does not), the exemptions, F11's
classification, producer generation and edges, and `TestTreeRatchetAndPlantedSites` on the checkout itself (the
tree meets baseline.txt exactly; a close, a dup and an os.NewFile planted in internal/platform/proc, which the file
never listed, each fail on their line, and one more close in internal/ledger fails as a rise; with the unlisted
branch of the ratchet disabled the test fails); `scripts/check-fd_test.sh` runs golangci-lint on
scripts/testdata/fdlint and holds the rules to one report on each of its 32 marked primitives (30 on arm64) and
none elsewhere, the depguard denial, and ADR 0021's text scope with a negative control (without `text:` the
exclusion hides the close too). `TestLintExclusionsAreTheStartSites` (internal/platform/proc) admits a forbidigo
exclusion whose text matches no ADR 0021 message, and requires the blanket exemption's text to match every one.
The census on the tree then, by fdcheck: 602 raw sites in 23 packages (291 close, 18 dup, 41 os.NewFile, 64 `Fd()` or
cilium `FD()`, 3 ParseUnixRights, 1 NewFromFD, 166 unowned producers, 17 exported bare numbers, 1 Abandon no list
admits), against the note's 292 sites and 109 producers in 18 packages then: internal/watch/adopt,
internal/watch/procconn and internal/runtime/deputy are new, internal/platform/sys's non-owner files (its two raw producers and nine exported `fd int` wrappers) and
internal/runtime/enforce (`Handle.LandlockRuleset`'s named `fd` result) are on the ratchet because every kind
counts there. Departures, each kept within the decision:
- **Exact counts, by kind.** A9 fails a rise. baseline.txt holds each package's counts per kind and fdcheck
  requires them equal: a fall fails until the line is lowered (it prints the line), so no migration's slack can be
  spent later. Against a base, each kind's total over the packages is held (a note below), so a
  removed close cannot pay for a new os.NewFile.
- **Every finding counts.** A9's raw sites are A4, F1, F4 and F5; fdcheck counts F2, F3, F8, F9 and F10 findings
  too, per package and kind. A package not on the baseline therefore has none of any kind, which is F8's "migrated
  package", and a package on it cannot add a bare-number API while it waits. A listed kind's site that its list
  does not admit counts as well, and `-baseline` prints the counts the ratchet applies, so a baseline it writes
  passes. Two of that tree's sites are not descriptor operations, and fdcheck counts them because syntax cannot
  tell them from one: supervisor's `h.pending.Abandon()` is `deputy.Pending`'s, a result-less `Abandon` like
  sys.FD's, and the deputy's seccomp allowlist (filter.go) names `unix.SYS_CLOSE` and `unix.SYS_DUP`, which
  forbidigo reports as it reports any reference. Each waits for its package's migration, which renames the method
  or gives the allowlist an A7 exemption with its reason; neither is admitted here.
- **testdata.** fdcheck skips files under a testdata directory (the golangci fixture), and F11 refuses a testdata
  package in a binary; `.golangci.yml` needs no such exemption, since `./...` never reaches testdata.
- **F9 with a variable.** A CLOEXEC flag ORed in at the top of the expression passes whatever the rest is, as A10's
  own seam `sys.Own(unix.FanotifyInit(f|unix.FAN_CLOEXEC, e))` needs; any other operator could clear the bit and
  hides it. The same reading applies to SYS_SECCOMP's NEW_LISTENER in F10.
- **Selectors no syntax can type.** An uncalled `.Fd` or `.FD` counts only where the syntax shows a method (a
  note below: unix.PollFd, EpollEvent, the fanotify event and the plan entries have a field of that
  name); an uncalled `.Hold` is not counted (ask's hold duration); an uncalled `.ReleaseNumber` or `.Abandon` is. An `Abandon()` call counts when its result is unused: sys.FD's
  returns nothing, the ledger writer's returns an error.
- **F8's shape** also covers an unnamed int returned by a function whose name ends in `FD` or `Fd`
  (`WaitNotifyFD`). An unnamed `(int, bool)` (`PlaneHeld`, the landlock and cgroup Handles' `LandlockRuleset`) has no
  name to read, so edges.txt, generated from F8's shape, lacks PlaneHeld; A6's hand list keeps it.
- **Producers.** x/sys's `OpenTree` answers `(r int, err error)` and is listed by hand, as are `Fsmount` (fsfd) and
  `Signalfd` (newfd); generation fails on any other fd-like name it cannot classify and on a hand entry x/sys no
  longer declares. `Pipe`, `Pipe2`, `Socketpair`, `Accept` and `Accept4` are producers of another shape (raw
  everywhere; the sys helpers own them). sys's own int producers (`PidfdOpenProcess`, `PidfdOpenThread`,
  `PidfdGetfd`, `SeccompSetFilterNewListener`, `LandlockCreateRuleset`) may be wrapped by `sys.Own`; any other call
  outside the owner's files is a raw site. A raw syscall of a trap that answers a descriptor (`SYS_OPENAT`,
  `SYS_SOCKET`, ... beyond F10's admitted set) is a raw producer; one whose command or flags cannot be read is taken
  to answer one (planefill.go's `bpfLinkCreate = 28`, a literal).
- **F3 and forbidigo.** forbidigo cannot see a taker's argument, so `link.NewFromFD(x.ReleaseNumber())` still needs
  `//nolint:forbidigo // ADR 0023 F3` on its line; fdcheck judges the form itself and reads no nolint.
- **F11** lists `./cmd/...` (tego today, any later binary) under the four tag sets.
- **IoUringSetup.** x/sys v0.48.0 has no such function; its rule stays, and the fixture has no line for it.
- **check-fd.sh builds fdcheck** and runs the binary: `go run` answers 1 for every failing exit, which turned
  fdcheck's 2 (the files could not be read) into a rule failure. check-fd_test.sh holds the 2 on a directory git
  does not track; it no longer runs the whole check on the checkout, which make lint, precommit and CI's
  build-test each run as their own step and `TestTreeRatchetAndPlantedSites` runs in the unit tests.

*Amended 2026-10-17 (implementation note):* C3 left forms that passed both
gates; each is now counted, with a fixture that failed before the change.
- **The sweep is a listed site, and sealed.** `sys.CloseInheritedFrom(first)` closes every number from first up,
  close_range under another name, so any package could close numbers live owners hold. fdcheck counts each call
  (and the function taken as a value, kind funcvalue) as kind `sweep`, which F4 admits only at the sites
  `tools/fdcheck/sweep.txt` lists: empty until the reaper migrates, when ReapMain's first act is its one entry.
  At run time it is sealed like Inherited: once the process has made an owner other than through Inherited or
  Stdio, it answers ErrSealed and closes nothing (`TestCloseInheritedFromSealed`, an owner at 900 so a failing
  check closes nothing of the test binary's).
- **The total check is by kind, and holds the lists.** The check against a base (`-base REV`: precommit's merge
  base, CI's push base) compared only the grand total, and the per-package check compares the tree with the
  baseline.txt the same commit may rewrite: a commit could turn a close into a non-site, add an os.NewFile and
  rewrite the line, or ride a new site in one package on a migration in another. Each kind's total over the
  packages is now held to the base's: a move of code still passes, a swap of kinds fails. The F4 lists
  (adopt, abandon, inherited, stdio, sweep) together may admit more sites than the base's only when the raw
  total fell by at least as much in the same change: a migration that turns raw sites into listed ones pays for
  its entries, and a bare new entry fails. Rejected: holding the lists to the base outright, which would refuse
  the migrations A10 plans (the child stage's and ReapMain's Inherited entries); no check, which let any change
  admit a site by adding a line. The base is measured, not read: its Go files come from git (`ls-tree`,
  `cat-file --batch`) and are analysed by the checkout's rules with the base's own lists, so a rule that counts
  more on unchanged code (the ioctl and PidFD rules below) counts it on both sides, and a base's baseline.txt
  cannot be wrong. `TestTotalCheck` holds a swap of kinds, a swap across packages, a bare new list entry, one a
  migration pays for, and a base whose tree holds a site its baseline.txt predates.
- **Fd and FD taken as values.** An uncalled `.Fd` or `.FD` was not counted, on the reasoning that forbidigo's
  typed rule catches `(*os.File).Fd` taken as a value; but forbidigo is excluded in every package the baseline
  lists, where fdcheck is the only counter, and its typed rule misses a promoted or interface method value even
  where it runs. fdcheck now counts, as kind fd, every method expression of Fd or FD (`(*os.File).Fd`,
  `os.File.Fd`, `fder.Fd`, `interface{ Fd() uintptr }.Fd`, `(*ebpf.Map).FD`: the operand is a type) and every
  method value whose receiver's type the syntax shows has the method: a parameter, variable or package-level
  variable (of any file of the package) declared with its type or from `os.Open` and the like, `os.Stdin`, a
  field of a struct the package declares, through pointers, parentheses and the package's own type names; the
  method is `*os.File`'s Fd, any cilium type's FD, a method the package declares on its own type, an interface's
  (literal or named), or one promoted from an embedded field. A field named Fd or FD is not counted. The
  residual: a method value whose receiver is a call result (other than os's File constructors) or another
  package's struct field fdcheck cannot type without a type checker; forbidigo's typed rule still reports
  `(*os.File).Fd` there in a migrated package. `TestFdcheckMethodValues` holds 18 forms in a listed and an
  unlisted package, cilium's, and a type and a variable declared in another file; `TestTreeRatchetAndPlantedSites`
  plants a method value and a method expression in internal/ledger, where only fdcheck sees them.
- **The ADR 0023 exclusions are pinned.** `ParseShrinking` treated any ADR 0023 exclusion whose path was not one
  package's files as permanent, so a rule `- path: ^internal/` with text ADR 0023 passed both fdcheck and its
  tests while it hid every forbidigo report under internal/. It now fails on any exclusion rule that applies to
  forbidigo (or to every linter) and has no text, or a text that matches "ADR 0023", an ADR 0023 rule's message
  or the report forbidigo makes with it (its patterns expanded), unless it is one of A7's two permanent
  exemptions exactly (`permanentExclusions`, the first built from the same owner-file list as fdcheck's own
  exemption) or one package's `^dir/[^/]+\.go$` rule with linters [forbidigo] and text "ADR 0023". Another ADR's
  rule scoped to its own text (ADR 0021's, the start sites') is not affected.
- **A lent number stays in its callback.** F2 forbids storing a `*sys.Lease`, but nothing judged the number a
  callback is lent: `rc.Control(func(fd uintptr) { keep = int(fd) })` stored it past the call that ends the
  stdlib's lease, the `Fd()` hazard A4 forbids. fdcheck now judges the callback of syscall.RawConn's Control,
  Read and Write, of sys.FD's Borrow (any method of those names) and of `sys.FileDo`, when it is a function literal
  whose one parameter is a uintptr or an int: an assignment of a value that carries the number (itself, a
  conversion, arithmetic, an append or a composite literal of it) to anything the literal does not declare, a send
  of it, or its capture by a goroutine or a nested literal is kind lease. A call that takes the number as an
  argument consumes it (`e = unix.SetsockoptInt(int(fd), ...)` passes), and a local that carries it is followed.
  The residual: a call that stores its argument (`save(int(fd))`) is not followed into the callee. Fixtures: ten
  captures and three uses; the tree has none.
- **Producers of every shape.** `SYS_MQ_OPEN` (x/sys declares no `MqOpen`), `SYS_CLONE3` and `SYS_CLONE` (unless
  its flags are a constant without `CLONE_PIDFD`) join the producer traps: a raw call is a raw producer. An
  ioctl answers a descriptor for some requests (TIOCGPTPEER, NS_GET_USERNS, NS_GET_PARENT, KVM_CREATE_VM, ...), so a
  raw `SYS_IOCTL` and `unix.IoctlRetInt` must name a request from an allowlist (`ioctlAllowed`: the seccomp
  notification ioctls, whose ADDFD answers the target's number, the terminal ones and NS_GET_NSTYPE), like
  fcntl's (F5); anything else, or a request that is not a named constant, is the new kind ioctl. The ioctls that
  answer through a pointer (`IoctlGetInt`) stay a residual. os/exec's `SysProcAttr.PidFD` makes the start write a
  pidfd into an int no owner holds: a `syscall.SysProcAttr` literal with that key, or an assignment `x.PidFD =
  &n`, is a raw producer. The tree had two such sites, now on the baseline: sys's `notifIoctl` (seccomp.go, a
  request passed in a variable) and launch's `startOnKeptThread` (launcher.go, `cmd.SysProcAttr.PidFD =
  &pidfd`); the census is 604 raw sites in 23 packages. Fixtures: mq_open, clone3, clone with and without
  CLONE_PIDFD, IoctlRetInt and SYS_IOCTL with a descriptor-answering, a variable and an allowed request, and
  PidFD as a key, an assignment and another type's field.
- **A raw SYS_OPENAT2 is not admitted.** A10 F1 lists SYS_OPENAT2 among OwnSyscall's traps, but its flags sit
  in an OpenHow behind a pointer, which F9 cannot read, so `sys.OwnSyscall(unix.Syscall6(unix.SYS_OPENAT2, ...))`
  is always a cloexec finding (failing closed). The C3 note recorded no departure and the message said openat2
  "cannot make its number close-on-exec", which is false; it now says the flags cannot be read and names the
  form F9 does read, `sys.Own(unix.Openat2(dirfd, path, &unix.OpenHow{Flags: ...|unix.O_CLOEXEC}))`. Rejected:
  resolving `&how` to a local OpenHow literal, which a later `how.Flags = ...` could clear unseen.
  `TestOwnSyscallOpenat2` holds the refusal and its message.
- **The `!tegotesthooks` files.** The C3 note and `.golangci.yml`'s build-tags comment named landlock's
  filter_product_test.go as the one file the tagged run drops; a second such file, since removed, dropped out too, and
  the untagged run lints whatever drops out. The comment now states the
  `!tegobpf` stubs (all of internal/bpf's `*_stub.go`) and the `!integration` files (the leak-gate TestMains in
  sys, landlock and launch, and landlock's filter_test_bridge_test.go) as they are.

*Amended 2026-10-17 (implementation note):* more forms still passed
both gates; each is now counted or refused, with a test that failed before the change.
- **.golangci.yml is read as YAML, and every channel that hides a forbidigo report is closed.** `ParseShrinking`
  split lines and unquoted double quotes only, so `text: 'ADR 0023'`, a folded `text: >-`, a trailing `# comment`
  or a block-list `linters:` turned an earlier `^internal/` probe into a rule it skipped; it read only `rules:`,
  so `exclusions.paths` hid a file; and golangci-lint's default `generated: lax` skips any file whose header says
  it is generated, a hand-written `// Code generated by hand. DO NOT EDIT.` being enough. The earlier note's
  "forbidigo's typed rule still reports `(*os.File).Fd` there in a migrated package" was therefore not true. fdcheck
  now decodes the file with gopkg.in/yaml.v3 (in go.mod already; fdcheck is no longer standard-library only) and
  fails unless forbidigo is enabled, not disabled and `analyze-types: true`; `linters.exclusions` holds only
  `rules`, `warn-unused` and `generated: disable` (`paths`, `paths-except` and `presets` are refused, and
  .golangci.yml now sets `generated: disable`, which lints the tree's 22 generated files cleanly); every rule uses
  only golangci-lint's keys (a merge key is refused); and a rule that applies to forbidigo must either be one of
  A7's two exemptions or one package's files with exactly the keys path, linters [forbidigo] and text "ADR 0023",
  or have a text that provably matches no ADR 0023 report. golangci-lint matches a text case-insensitively as a
  regular expression, and a report quotes the Go expression it flags, which fdcheck cannot enumerate, so the old
  test (the text matches no ADR 0023 message or pattern expansion, case-sensitively) is replaced by a stricter
  one: the text is a literal with a space and no backtick or quote, found (case folded) in another rule's message
  and in no ADR 0023 message or the report's frame ("use of", "forbidden because"). ADR 0021's and the start
  sites' texts pass; `probeGetF`, `adr 0023` and `ADR 0021|x` are refused. Residual: a Go expression that contains
  such a phrase (a function literal's parameter list) could still match one; no forbidigo pattern names one.
  A `//nolint` that silences forbidigo (bare, `all`, or naming forbidigo, in any spelling golangci-lint reads, or
  a block comment) is now itself a raw site, kind nolint: fdcheck already counted the primitive under it, but not
  the typed sites only forbidigo sees. One form is admitted: `//nolint:forbidigo // ADR 0023 F3` exactly, on the
  line of F3's sanctioned `link.NewFromFD(x.ReleaseNumber())` (the C3 note's form); residual, another typed site
  on that same line. The tree has none. Fixtures: 34 refused configurations and four accepted rules in
  `TestParseShrinking`, eleven nolint cases in the table, and a generated-header file in
  scripts/testdata/fdlint, whose close check-fd_test.sh requires reported (it was not with `generated` unset).
- **A lent number's check fails closed.** It judged only a function literal, and took any store whose target's
  root the literal declares as local, so `rc.Control(cb)`, `p := &keep; *p = fd`, `copy(keep, []uintptr{fd})`
  and `for _, v := range []uintptr{fd} { keep = v }` all passed. Now a Control, Borrow or `sys.FileDo` callback
  that is not a function literal (a named function, a method value, a variable, a parameter) is kind lease, and
  so is a Read or Write callback the syntax shows is a function (those names are io's too, where the argument is
  a buffer); the tree passes only literals. Inside the literal, a store through `*p`, `p.f`, `p[i]` or `p[i:j]`
  is local only when p is fresh: every assignment to it is a composite literal, make, new, a constant, no value,
  or another fresh local or its address (a pass repeated until nothing changes, so an alias later pointed
  outward is not fresh). `copy` is an assignment to its first argument; a range over a value that carries the
  number assigns its key and value; the number as an index of a target is a store; an index or slice of a
  carrier, and min and max of one, carry it. Residuals: a call that stores its argument is still not followed,
  and a range key over a carrier counts as carrying the number (an index stored outward is reported, failing
  closed). Fixtures: seven non-literal callbacks, ten stores, and two negatives (a buffer to Write, and stores
  into storage the literal made).
- **Any PidFD assignment but a constant is a producer.** An earlier fix counted `x.PidFD = &n` only, so
  `a.PidFD = new(int)`, a pointer variable, a parameter or a call result passed, and no forbidigo rule names
  PidFD. The syntax cannot type x, so an assignment to any selector named PidFD is now a raw producer unless its
  value is nil or a constant integer (a literal, a sign or conversion of one, a package-level constant naming
  one), and so is one in a multi-value assignment; an int field of another type set from a variable is counted
  too (failing closed; the tree's only other one, launch's `c.PidFD = -1`, is a constant). The literal key stays
  typed: `syscall.SysProcAttr{PidFD: ...}`. No other unix or syscall struct the tree uses makes the kernel write a
  descriptor through a field outside a raw call that is already a producer (clone3's CloneArgs). Fixtures: new,
  a pointer variable, a parameter, a call, a multi-value result, and a negative clearing both kinds of field.
*Amended 2026-10-19 (implementation note, continued):* two more forms, each with a test that failed before the change.
- **Every x/sys ioctl wrapper runs the request allowlist.** Only `unix.IoctlRetInt` and a raw `SYS_IOCTL` were
  judged, and an earlier note called the rest "ioctls that answer through a pointer (`IoctlGetInt`)". That
  misnamed them: `IoctlSetInt`, `IoctlGetInt`, `IoctlSetPointerInt` and the others are `ioctl(fd, req, ...)` and
  drop or answer its return value, which for TIOCGPTPEER, NS_GET_USERNS or NS_GET_PARENT is a new descriptor, so
  `unix.IoctlSetInt(fd, unix.TIOCGPTPEER, unix.O_RDWR)` put an unowned number without close-on-exec in the
  table and passed. Now every wrapper whose second argument is the request (`ioctlReqWrappers`: RetInt, GetInt,
  GetUint32, GetTermios, GetWinsize, SetInt, SetPointerInt, SetString, SetTermios, SetWinsize, Ifreq) runs
  `ioctlAllowed` as a raw SYS_IOCTL does; the fixed-request wrappers that answer no descriptor are listed
  (`ioctlFixed`); `IoctlKCMClone`, whose SIOCKCMCLONE answers a new KCM socket inside its struct, joins the
  other-shape producers (every call is a raw producer; producers.txt is regenerated); and any other `Ioctl*`
  name is kind ioctl until it is classified. Generating producers.txt fails when x/sys declares an `Ioctl*`
  function in none of the three lists, so a bump of x/sys cannot add an unjudged wrapper silently. An ioctl
  wrapper, an `Fcntl*` function or `Unshare` taken as a value is now a finding of its kind, as a producer or a
  Syscall* taken as a value already was (the same hole: the value's later call was never judged). FS_IOC_GETFLAGS
  and FS_IOC_SETFLAGS (inode flags) join the allowlist for pkg/spec/agent's `IoctlGetUint32`; the tree's other
  wrapper calls name TCGETS and TIOCINQ, so the census is unchanged. Fixtures: SetInt with TIOCGPTPEER and with a
  variable request, GetInt with NS_GET_USERNS, SetPointerInt with NS_GET_PARENT, KCMClone, an unclassified
  wrapper, three allowed or fixed-request calls, and an ioctl wrapper, FcntlInt and Unshare taken as values.
- **A package's count is held to the base's, and rises only by a move.** The earlier note said the by-kind total
  closed "ride a new site in one package on a migration in another", but it did not: a new `unix.Close` in
  internal/cli and one close migrated in internal/ledger kept the close total, and the per-package check compares
  the tree with the baseline.txt the same commit rewrites, so A9's "a package's count rises" was never held
  against anything but that file. `-base REV` now also holds each package's count of each kind to the base's
  measured count, and admits a rise only for a site that moved: one whose identity (kind, enclosing function, and
  form, the primitive the finding names) left another package in the same change, each departed site paying for
  one arrival. A move of a function keeps all three and passes; a new site, or a moved one that was also renamed,
  fails with the package, the counts and the unmatched sites named (migrate it, or move it without a rename).
  Rejected: stating the hole as a residual (the per-kind total alone), which leaves a migrated package's credit
  spendable anywhere; and an identity with the file or line, which every move changes. Residuals: inside one
  package a new site can still stand in for a migrated one of the same kind (the package's count does not
  rise), and two sites of one kind and form in functions of the same name in two packages are interchangeable.
  Fixtures in `TestTotalCheck`: a site moved with its function, a new site riding on a migration elsewhere, one
  moved and one new, and another form under the moved function's name; the three negatives failed before the
  change. Against the start of the work the tree passes; against an earlier build it fails, as the
  per-kind total already did, because the supervisor and launch gained raw sites after it.

*Amended 2026-10-19 (implementation note):* more forms still passed
both gates; each is now counted or refused, with a test that failed before the change.
- **A PidFD key in any composite literal is judged as the assignment is.** The earlier note kept the literal key
  typed, so `[]*syscall.SysProcAttr{{PidFD: &a}}`, an elided map value, `type attr = syscall.SysProcAttr` with
  `&attr{PidFD: &b}`, and a defined type of SysProcAttr all passed: the start wrote a pidfd no owner held, and
  nothing counted it. Now a `PidFD:` key in any composite literal is a raw producer unless its value is nil or a
  constant integer, as `x.PidFD = e` is. The one form passed is a struct type the package declares with its own
  PidFD field (launch's `Child{PidFD: s.pidfd}`), which cannot be SysProcAttr. An unkeyed SysProcAttr literal
  (it sets PidFD by position) and the field's address `&x.PidFD` (anything can then write the pointer) are
  producers too. The census is unchanged. Fixtures: an elided slice element, an elided map value, an alias, a
  defined type, an unkeyed literal and the field's address; the negatives are a keyed nil and the package's own
  PidFD field set from a variable.
- **The lent-number check judges any parameter type and a lender taken as a value.** The earlier note said it
  "fails closed", but a literal whose parameter was an alias (`type u = uintptr`, `func(fd u)`) was not read, and
  `ctl := rc.Control; ctl(cb)`, `do := sys.FileDo` and `bw := o.Borrow` hid the callback from the call's
  judgement. Now a lender's literal is judged whatever its parameter's type syntax says; a literal whose one
  parameter is a uintptr (through the package's own type names) is judged wherever it stands, which covers a
  RawConn method value's call (`rd := rc.Read; rd(cb)`); and an uncalled `.Borrow`, `sys.FileDo`, `.Control`
  (unless the operand's type shows a field of that name, or the selector is assigned to or has its address taken,
  which no method value can be: cgroup's `rules.Control`) and a RawConn's `.Read` or `.Write` (a method
  expression, or an operand the syntax types as RawConn) are kind lease. Fixtures: three alias parameters, seven
  values or method expressions, a uintptr literal outside a call, and negatives for a Control field, io's Read
  as a value and a uintptr literal that keeps nothing.
- **A local is fresh only when everything it holds is.** A composite literal counted as fresh whatever its
  elements were, and an assignment through a selector, index or star was not read, so `s := []*uintptr{&keep};
  *s[0] = fd`, a struct or map literal holding `&keep`, `b := box{v: &keep}; q := &b; *q.v = fd` and `var b box;
  b.v = &keep; *b.v = fd` all stored the lent number outward and passed. Now a composite literal is fresh only
  when every key (but a field name) and element is (a constant, nil, make, new, a fresh local or its address, or a
  fresh literal); `x.f = v`, `x[i] = v`, `*x = v` and `copy(x, v)` are assignments to x; and the locals one
  assignment relates (`q := &b`, `s := []**T{&n}`) share their freshness, so a pointer written outward through
  either spoils both (the lent number itself relates nothing, being a value). Residual: a method call on a
  fresh local that stores an outward pointer into it (`b.set(&keep)`), the "call that stores its argument" the
  earlier note names. Fixtures: nine stores (the four forms that first got through, a field and an element pointed outward,
  copy and append from outward storage, and a two-level alias) and a negative of literals holding only fresh
  values.
- **A Read or Write callback is judged by the operand's type where the syntax shows it.** `funcShaped` took a
  selector to be a function only when the package declared a method of that name on any type, so `rc.Read(h.cb)`
  with a func-typed field passed and `w.Write(x.data)` with a []byte field was reported when an unrelated type
  had a method `data`. Now a selector whose operand's type the syntax shows is a function when the field is
  func-typed or the type has the method, and not one for any other field; another package's name (`pkg.Fn`)
  fails closed as a function (the tree passes none to Read or Write); otherwise the old method-name rule
  stands. Fixtures: a func field by value and through a pointer, another package's function, and the buffer
  field.
- **.golangci.yml is the lint's only configuration, and its parts outside linters are read too.** The earlier
  heading "every channel that hides a forbidigo report is closed" was not true. golangci-lint looks for
  .golangci.json, .toml and .yaml before .golangci.yml in the same directory, so a `.golangci.json` that enables
  govet alone made `make lint` and CI's lint step pass a planted `(*os.File).Fd` method value (the typed site
  only forbidigo sees) while fdcheck checked the file no run read; and `issues: {new: true}` (or `new-from-rev`,
  `new-from-merge-base`, `new-from-patch`, `whole-files`) hides every report outside the diff, which fdcheck
  never read. Now make lint, precommit and CI's tagged lint pass `--config .golangci.yml` (the untagged runs
  already name their copy), and fdcheck refuses a `.golangci.json`, `.toml` or `.yaml` at the root, tracked or
  not (an editor's or a bare `golangci-lint run` would read it). `ParseShrinking` now also refuses a top-level key
  golangci-lint 2 does not have, an `issues` key other than `max-issues-per-linter`, `max-same-issues` and
  `uniq-by-line` (caps on the reports shown, which leave the run failing on any), a `run` key that is not
  golangci-lint's, `run.issues-exit-code: 0`, and `run.build-tags` without integration, tegobpf and
  tegotesthooks (forbidigo's typed rules see a tagged file only with its tag on). Residual: a configuration
  in a parent directory of the checkout is read only when the checkout has none, which it always has. Fixtures:
  a shadow of each name (`TestGolangciShadow`, through `loadConfig` too) and thirteen refused and four accepted
  outer blocks in `TestParseShrinking`.
- **A package-level site moves only under its own declaration's name.** The move identity's function was
  "<package>" for every site outside a function, a closure in a package-level var included, so any package-level
  site migrated in one listed package paid for a new package-level site of the same kind and form in any other
  (the tree has eleven), and an earlier residual named only same-named functions. Now a package-level site's
  function is the declaration it is in (`<package>:closeHook`, `<package>:a,b` for one spec of two names,
  `<package>:T` in a type), which F4 lines and messages show too (adopt.txt's header says so; no list has a
  package-level line). `init` and `main`, which any package declares, carry their package in the move identity,
  so their sites never move between packages: moving one means moving its code into a named function. The
  earlier residual stands narrowed: two sites of one kind and form in functions, or package-level declarations,
  of the same name in two packages are interchangeable. Fixtures: `TestMoveScope`, the names of four
  package-level and init sites, and five moves (a named declaration moved, another name, init and main across
  packages, a function moved), whose init and main cases failed before the change.

*Amended 2026-10-19 (implementation note):* more forms kept
passing, because each fix closed the forms it was shown rather than the model that let them through. This note
records the corrected model, one part per class of finding, each with a test that failed before the change.
- **The lint's exit code is pinned, not judged.** The earlier note refused `run.issues-exit-code: 0`, but
  golangci-lint does not check the value and the OS keeps only its low byte, so 256, 512, -256 or 0x100 made a
  run with reports exit 0. A deny-list of values cannot be complete; `ParseShrinking`
  now admits the key only as the plain integer 1, golangci-lint's default, or absent. Rejected: refusing values
  outside 1..255, which still judges a value fdcheck does not interpret (viper converts a quoted "1" or a 1.0).
  `TestParseShrinking` refuses 256, 512, -256, 0x100, 2, "1" and 1.0, and accepts 1.
- **fdcheck type-checks; it no longer reads types from syntax.** The cause shared by the type findings
  (and an earlier fix's "a method value whose receiver is a call result")
  was that A3 made fdcheck an AST tool, so it guessed what an expression is (which struct a PidFD belongs to,
  whether a Read is a RawConn's, whether a callback is a function) from the syntax around it, and every guess left
  a form it guessed wrong. fdcheck now type-checks every module package with the standard library's go/types
  (`tools/fdcheck/load.go`): `go list -deps` names the packages and files of a build, `go list -export` builds the
  export data of what the module imports from outside it, and the module's own packages are checked from source in
  dependency order, each importing the others' checked packages, so an object is the same object everywhere. A3's
  "standard-library AST tool" now reads "standard-library type-checked tool": still no x/tools and no go/analysis.
  Every rule decides by object identity: a forbidden function or constant, a producer, sys's API and *sys.FD's
  methods, a taker; an Fd or FD method is any method (or func-typed field) of that name that takes nothing and
  answers an integer, through embedding and interfaces; SysProcAttr.PidFD is the field of any struct identical to
  syscall.SysProcAttr (tags aside: a defined type, an alias, a mirror struct that converts to it, a promoted
  embedding), keyed or by position, and a SysProcAttr made from an unsafe.Pointer is a producer too; F8 reads the
  parameter's type, so the package's own name for int counts; constants are resolved through any module package,
  and a flag is carried by its constant value (or ORed in at the top of an expression that is not constant).
  forbidigo is no longer the only check of any ADR 0023 site, which removes the reason an earlier and earlier
  notes policed golangci-lint's configuration for this ADR's sake; that guard stays, pinned as above, because
  ADR 0021's start-site rules and depguard have no other check. edges.txt is generated from the same types, so a
  method's users are the packages that call that method, not one of the same name (internal/runtime now uses
  enforce's Handle.LandlockRuleset through its interface).
- **F6 is coverage by build, not by parsing.** A type checker needs a build, so "every non-test file is read,
  whatever its build constraints" becomes: every in-scope file is type-checked under a build that includes it, and
  a file no build includes is a problem, never skipped. The builds are the two architectures the project ships,
  linux/amd64 and linux/arm64, each with the lint's tags (integration, tegobpf, tegotesthooks), with the release
  binary's (`make build`: tegobpf) and with none (the `!tegobpf` stubs, the `!integration` and
  `!tegotesthooks` files), cgo off as the binary is built; then, only for the packages that hold a file those six
  miss, amd64 with cgo (pkg/spec/config's libc passwd) and s390x (bpf2go's big-endian objects). A site is the same
  site under every build that finds it (its file and offset), and one only one build finds (arm64's deputy
  filter) is counted. The files judged are the ones git lists that are on disk: a tracked file deleted from the
  working tree is not refused, and a file git ignores is type-checked with its package, as go builds it, but its
  sites are not counted. Rejected: parsing every file without types beside the typed pass (two analyses that
  disagree are what earlier reviews found), and type-checking every combination of tags and architectures (sixteen
  builds for files that differ in four).
- **A lent number is held to a closed list of uses.** The cause shared by the lease findings was that fdcheck tried to prove a lent number does not escape by naming the ways it can
  (stores to outer variables, then through pointers, then "fresh" locals, then the locals related to them, ...),
  and each round named another way. `tools/fdcheck/lent.go` inverts it: the number lent to a lender's callback,
  or a `(*sys.Lease).Num()` in the Hold's function, may flow only through a conversion, arithmetic, a
  concatenation, a field, index or slice of what holds it, a composite literal, min or max, or a pure encoder
  (strconv's integer formatting, an x/sys or syscall function that answers no error, such as UnixRights); and it
  may end only in a comparison or switch, len or cap, a read index, an integer parameter of an x/sys or syscall
  function that answers an error (the kernel uses the number in the call), a listed data parameter that keeps
  nothing (poll's descriptors, sendmsg's and WriteMsgUnix's rights, the path of readlink, open and stat, which
  resolve /proc/self/fd/N at once), a parameter a module function borrows (its own body meets these rules, solved
  as a greatest fixed point, so recursion passes and a keep anywhere along a chain fails it), or a call of the
  enclosing function's own callback parameter. It may be stored only in a local slot: a variable the function
  declares, or a field or array element of one reached through no pointer, whose address is never taken (`&`, a
  slice of the array, a pointer method) and which no function literal names. Every other use is a lease site: a
  store through a pointer, a slice or a map whatever they point to, a return (the converted error and the literal), a send, a goroutine, a function literal that names it, a function value, an interface method,
  any other library call. A function literal is opaque but for one case: the callback of a lender whose contract
  runs it before returning (a RawConn's methods, sys's Borrow on *sys.FD or sys.Lender, sys.FileDo, internal/bpf's
  ProgramFD and MapFD) is judged as part of the function that calls it, so the loop lease's number used inside a
  Borrow per event (A1's P4 and the fanotify design above) and two Borrows nested pass, while a derived lender's
  callback, which its lender may keep, stays opaque. Rejected: tracking which storage is fresh (the earlier fixes);
  following any call's argument as consumed (an earlier residual "a call that stores its argument").
- **Lenders are known by type, and a function that passes its callback the number is one.** The roots are
  RawConn's Control, Read and Write and sys's Borrow, by signature (any type of that shape: an implementation, an
  interface, a wrapper), and sys.FileDo and internal/bpf's ProgramFD and MapFD by name. A function whose lender
  callback calls the function's own callback parameter with the number (ask's AlternateFile.Control), or passes
  that parameter to a lender, is a derived lender: its callers' callbacks are judged, in every package, and an
  interface method of a derived lender's name and signature lends as it does. A lender's callback is a function
  literal, or a module function or concrete method value whose parameter is borrowed (two files or two packages
  apart); anything else (a variable, a slice element, a call's result, a map value, a conversion) cannot be followed and is a site. A lender, root or derived, taken as a value is a site wherever
  its receiver comes from (`rc, _ := conn.SyscallConn(); rd := rc.Read`), as are Hold and Num taken
  as values. Rejected: judging every one-uintptr literal wherever it stands, which the typed callback
  rule makes unnecessary: a literal that never reaches a lender lends nothing.
- **A lease is used by its Num and Return.** F2's Hold rule now admits the lease only as the receiver of a Num or
  Return call, a nil comparison, and its hand-off; passing it to a function or boxing it in an interface variable
  (which no typed field rule sees) is a site, as is the hand-off goroutine's parameter used any other way.
- **F3's sanctioned form compiles.** `link.NewFromFD(x.ReleaseNumber())`, the form the C3 note named, is not Go:
  ReleaseNumber answers (int, error). F3 now reads `n, err := x.ReleaseNumber()` followed by exactly one taker
  call (link.NewFromFD, ebpf.NewMapFromFD, ebpf.NewProgramFromFD) that the number reaches through local slots;
  the number's other uses, a second taker, or none, are release sites. The taker's line still carries
  `//nolint:forbidigo // ADR 0023 F3`.
- **Code fdcheck cannot read is a site.** A `//go:linkname` reaches a symbol no import declares (syscall's
  unexported close, a library's internals), and a function declared without a Go body is assembly or linked:
  either can close or make a descriptor where no rule looks. Each is kind `opaque` in a non-exempt file; one that
  must stay needs its own review and an A7 exemption. The tree has one, internal/bpf's linkname to cilium's
  haveProbeReadKernel probe, now on the baseline.
- **The census.** 604 raw sites in 23 packages, as at the start of this work but for two: supervisor's `h.pending.Abandon()` is
  deputy.Pending's, which the C3 note counted because syntax could not tell it from sys.FD's, and internal/bpf's
  linkname is counted (opaque). The tree's other sites are the same sites; its lenders' callbacks (ask, dnsbroker, supervisor's alternate open, cgroup's
  descriptors) all pass. A run takes about 11 seconds and 300 MB on this machine with a warm build cache (35
  seconds cold), and as much again for the base under `-base`, against about one second before.
- **A site moves only with its declaration.** The move identity's name was a function's (or package-level
  declaration's) name, which two packages may both declare, so any same-named declaration took a migrated site's
  credit: an earlier note's residual, and `var _`, the name every package may
  repeat, as init and main can. A rise in a package is now paid for only by a site whose declaration moved: base's
  source package declared it and the checkout's does not, and the checkout's destination package declares it and
  base's did not (the declarations are read from the type-checked packages, every build's). init, main and a spec
  of blank identifiers only carry their package and never move. The earlier residual of same-named functions is
  closed; a function copied with its original kept, or a site taken out of a function that stays, is a new site.
  Fixtures: `TestMoveScope`'s blank, two-blank, same-named and copied cases, and `TestTotalCheck`'s site under a
  same-named function that stays (with the declaration rule removed, all five pass the check and the tests fail).
- **Residuals.** The kernel is trusted to use an integer argument in the call: a syscall that keeps one as data
  (a socket mark set to the number, a raw ptrace poke) passes, as do a kernel answer that echoes one (lseek's
  offset) and reflect; a build other than the six above is not checked, but a file only it builds is refused, not
  missed.
- **Tests.** Every row of the rounds' findings is a fixture: `TestLentNumber` (93 rows: the stores, returns,
  callbacks, values, wrappers, summaries and Num uses above, with negatives for the tree's own forms),
  `TestCallbacksAcrossFilesAndPackages` (a callback in another file, a lender and a helper in another package, and
  an interface a package it does not import implements as a lender), `TestPidFDIdentity` (positional, defined,
  mirror and unsafe forms, generated from the toolchain's own field list), `TestCoverage` (an arm64, an untagged,
  a cgo and an s390x file each found once, and an ignored one refused), the F2 and F3 rows of
  `TestFdcheckFixtures`, and `TestTotalCheck` on a base extracted and type-checked as a module. Planted together in
  internal/platform/proc, the earlier probes (four alias forms, the defined and mirror SysProcAttr, five callback
  forms, the callback in another file, the SyscallConn value, four returns) gave fdcheck at the start of this work no finding and
  give 17 now.

*Amended 2026-10-19 (implementation note):* the earlier model still let forms
through, each now a class with a test that failed before the change.
- **A forbidden constant counts at every use.** A trap or fcntl command that resolves to SYS_CLOSE, SYS_DUP*,
  SYS_IO_URING_* or F_DUPFD(_CLOEXEC) was counted only where the x/sys constant is named, so one module constant
  (`const CloseTrap = unix.SYS_CLOSE`), declared once in an unmigrated package, paid for any number of raw closes
  in any package. Each use of a module constant that names a forbidden constant (a Syscall's trap,
  an fcntl command, a comparison) is now a site of that constant's kind, in whatever package it is used; the
  declaration stays one. Fixtures: four TestFdcheckFixtures rows (a trap used
  twice, an fcntl and a raw SYS_FCNTL dup, an io_uring trap) and TestForbiddenConstantAcrossPackages (a constant
  declared in one package and used by another's Syscall and FcntlInt). The tree has no such constant, so no count
  changes. Rejected: making the declaration count once per use found anywhere, which charges the declaring package
  for another's calls.
- **F2's defer and F3's taker have a place, not just a function.** F2 counted a `defer l.Return()` anywhere in the
  Hold's function, so a defer on a branch, one after an early return, and one in a loop that never runs all passed
  and leaked the lease, whose owner's Close then never runs; F3 counted one taker call
  anywhere, so a taker in a loop made two owners of one number and one on a branch made none. Each
  is now the statement after the Hold or ReleaseNumber in its block, past only that call's own check (`if err !=
  nil { return … }`, or a nil test of the lease joined by `||`), and reached from that statement through
  expressions alone: no branch, loop, label or function literal between. A Hold whose deferred Return is in a loop
  is a site too, since each iteration's lease stays out until the function returns; a Hold and defer inside a
  function literal the loop calls pass. A Num's number was judged over the whole function with no order, so
  `l.Return()` called before the number's last use, or the hand-off goroutine started while the holder still had
  a number, ended the lease under it. The lease is now returned only by its deferred
  Return (in the hand-off goroutine too), and a holding function that hands the lease off uses it for nothing
  else. Fixtures: nine F2 rows and six F3 rows in TestFdcheckFixtures (the probes, a goto, a hand-off on a branch,
  a goroutine that returns twice, and the passing forms) and two TestLentNumber rows (H7, H8); the F3 nolint row
  now puts its misplaced nolint on the error check, since a statement before the taker is itself a site. The
  tree has no Hold or ReleaseNumber outside the owner's files, so no count changes. Rejected: a path analysis
  that admits any placement that returns the lease on every path, which is the open-ended model the design round
  replaced with closed lists.
- **Received descriptors have one decoder.** Only ParseUnixRights was forbidden, so a package could receive
  descriptors with Recvmsg and decode them by hand, with ParseSocketControlMessage or ParseOneSocketControlMessage
  and binary.NativeEndian, as sys.ReceiveRights itself does, or with its own cmsghdr walk naming SCM_RIGHTS
  (deputy's parseControl): fresh numbers no owner holds, close-on-exec only if the recvmsg asked. Both decoders (x/sys and syscall) and every reference to SCM_RIGHTS outside the owner's files are
  now A4 sites of kind rights (forbidigo's too, with fixture lines); a module constant naming SCM_RIGHTS is a site
  at each use, as the first bullet's are, which moves that rule from the Syscall and Fcntl calls to every use of
  such a constant. An x/sys or syscall Recvmsg or RecvmsgBuffers with a control buffer that is not nil carries
  MSG_CMSG_CLOEXEC in constant flags (F9, kind cloexec), and a raw SYS_RECVMSG or SYS_RECVMMSG, whose flags sit
  behind a pointer, is a raw producer. The census rises by 8 sites, every one a site that was there: ask gains 3
  (two decoders and a type test), dnsbroker 2, and deputy 3 (its hand-built send and receive messages, so its
  migration is now driven by the ratchet); 612 raw sites in 23 packages. A send names SCM_RIGHTS through
  unix.UnixRights, which the owner's rules already admit. Residual: a hand walk of the control bytes that names
  the type by its value (1) or selects no type is not seen; the recvmsg rule keeps such numbers close-on-exec, and
  each migration's NoFDLeak test counts them. Rejected: forbidding every recvmsg with a control buffer outside
  sys, which ReceiveRights' callers need (it decodes the bytes they received).
- **F11 lists every shipped build.** Reach ran `go list -deps ./cmd/...` with the inherited environment, so only
  the host's GOARCH (and its GOFLAGS and cgo setting): an _arm64.go file importing a testdata package that calls
  unix.Close linked exempt code into the arm64 binary, and fdcheck passed. Reach now lists under
  linux/amd64 and linux/arm64 with cgo off and linux/amd64 with cgo, each with the four tag sets, in goEnv's
  environment (GOFLAGS cleared, go.work off), and a problem names the build. Twelve lists add about a second to
  a run. Test: TestReachEveryArchitecture, a temporary module whose arm64-only and cgo-only files import exempt
  packages, run with the host pinned to amd64, cgo off and a GOFLAGS tag; both are found under every tag set. The
  producer list's generation found x/sys with the inherited environment too, so a GOFLAGS or go.work could change
  which x/sys it read; it now runs in goEnv's as well (TestProducerSourcesEnvironment).
- **A length and a path carry the number.** A slice bound and len or cap ended a lent number, so
  `k = len(buf[:n])` carried it out of a Borrow (L5). A slice the number bounds (low, high or max)
  now holds it, and len, cap, min and max of what holds it carry it; a comparison still ends it. ProcPath, which
  lends the number as "/proc/self/fd/N" to a callback that runs under its lease, was no lender, so its path could
  be kept, returned or reopened by a goroutine after the lease was returned. It is now a root
  lender, by name and shape like Borrow and synchronous like it, so its path meets the same closed list: it ends
  in unix.Readlink, Open, Stat and the rest of lentSinks, and in os.Readlink, but not in os.Open or os.Stat, whose
  File keeps the path as its name and whose FileInfo keeps "N" as its name. Fixtures: three slice rows and six
  ProcPath rows in TestLentNumber. The tree uses neither, so nothing changes. Residuals, added to the design
  round's: an implicit flow, where the number decides control rather than data (`for k < n { k++ }`, a branch on
  it, a lookup table indexed by it), is not followed; the closed list ends the number at the comparison, and a
  value counted out this way is a number only by coincidence of arithmetic, which no type rule can tell from a
  count.
- **The edge rule is checked, not only listed.** edges.txt was only compared with its regeneration, so a
  migrated package could use an unmigrated package's bare-number API (ask's RelayPool.Reserve, ledger's OpenAt),
  hold the int and pass it back to a helper that closes it, while A6 said the birth rule and F8 made the edge rule
  enforce itself. They stop wrapping and exporting the int only. fdcheck now fails when an edge
  API's user is a package baseline.txt does not list, naming the user and the API: the producer gives an owner or
  lends one no later than the commit that migrates the consumer, as A6 says. Every user in today's list is a
  listed package, so the tree passes. Test: TestEdgeUsers. Residual: edges.txt holds F8's shape, so an API whose
  number is named otherwise (A6's hand list keeps PlaneHeld) is not checked; F8 refuses that shape in a migrated
  package's own API.

*Amended 2026-10-19 (implementation note):* the earlier
placement rules were looser than written, and two smaller gaps remained; each is now closed with a test that failed before.
- **The skipped check is a failure check.** The check F2 and F3 step over before the defer, the hand-off or the
  taker was any `==` or `!=` comparison of the call's results with nil, so `if err == nil { return }`, `if l !=
  nil { return }` or `if l != nil || err != nil { return err }` passed: the success path returned before the
  defer and kept the lease, whose owner's Close then waits for the life of the process, or released a number that
  no taker owned. The check is now `err != nil` and, for a lease, `l == nil`, in either
  operand order, joined by `||`, with a body that only returns; any other test, including one of another
  variable, is the next statement, so the placement fails. Fixtures: six F2 rows (the inverted forms, nil first,
  another variable, and two checks in a row that pass) and two F3 rows.
- **The taker is a plain statement.** Placement walked from the taker through expressions to the next
  statement, so a taker in a for condition, re-evaluated each iteration, gave one number two owners, and a defer
  or go taker passed too. The statement is now an expression statement, an assignment, a var
  declaration or a return; an if, for or switch condition, a go and a defer are refused. Fixtures: six F3 rows
  (for, if, switch, defer, go, and a call statement that passes). The tree has no ReleaseNumber or Hold outside
  the owner's files, so no count changes.
- **A backward goto is a loop.** Form (a) was refused only inside a for or range statement, so a goto from after
  the defer to a label before the Hold took a new lease each pass, all held until the function returns.
  A goto in the Hold's function (outside its function literals) that is after the Hold
  and whose label is before it now makes the Hold a loop's. A forward goto, a goto loop that ends before the
  Hold, a goto loop around a function literal that holds, and a hand-off in a goto loop pass. F3 needs no such
  rule: a goto loop around a release and its taker gives each pass's number one owner, as a for loop around both
  already does, and no goto can enter between the two (a label there is itself the next statement). Fixtures:
  five F2 rows and one F3 row.
- **The go env file selects nothing.** goEnv set GOFLAGS empty, which the go command reads as unset and fills
  from the user's go env file, so `go env -w GOFLAGS=-tags=…` hid a file from F11's Reach and the loaders on a
  developer's box; GOAMD64, GOARM64 and GOEXPERIMENT, which set build tags too, came through from
  the environment. goEnv now sets GOENV=off and clears those three; the go env file's settings for where modules
  come from and are kept (GOPROXY, GOPRIVATE, GOMODCACHE and the rest of fetchKeys), which select no file, are
  read once with `go env` and carried over. Tests: TestReachEveryArchitecture adds a file hidden by a GOFLAGS tag
  in the default go env file (under XDG_CONFIG_HOME) and by GOAMD64=v3, GOARM64=v9.0 and GOEXPERIMENT=arenas,
  found under all twelve builds; TestProducerSourcesEnvironment adds a GOENV file holding `GOFLAGS=-mod=bogus`.
- **Mutation gaps.** Dropping ProcPath from the synchronous lenders, or the edge check from Check, failed no test.
  A TestLentNumber row uses a held number inside a ProcPath callback, and Check now takes an overlay,
  so TestTreeRatchetAndPlantedSites runs the gate's whole Check on the planted sites, among them a migrated
  package's use of sys.IsTerminal, an edge API, which must fail as A6.

*Amended 2026-10-19 (implementation note, FD-LINT):* F3's placement walked from the taker to its
statement through any expression, so a taker in the right operand of `&&` or `||` passed (`ok := flag &&
use(link.NewFromFD(n))`, `return flag || use(...)`, `m[flag || use(...)] = 1`). That operand runs only when the
left one does not settle the result, so on the other path the released number had no taker and leaked
(low: it needs a helper that takes the taker's `(T, error)` and returns a bool). The walk now fails
when it passes up from the right operand of a `&&` or `||`; the left operand always runs and still passes. Go has
no other expression that evaluates an operand conditionally, and function literals were already refused. F2 is
not affected: its defer or hand-off must be the next statement itself, with no expression walk. Fixtures: five F3
rows (right of `&&` in an assignment, right of `||` in a return and in a map key, right of a nested `&&`, which
fail, and left of `&&`, which passes). The tree has no ReleaseNumber outside sys, so no count changes.

*Amended 2026-10-19 (implementation note):* the TCB API work (ADR 0031 (a)) moved
`Handle` and its `LandlockRuleset() (fd int, ok bool)` from internal/runtime/enforce to the leaf
internal/runtime/enforce/api, so the one raw site the ratchet counted in enforce (an exported bare number, kind
`api`) moved with it. As this ADR's baseline rule has it, a move of code moves its counts: baseline.txt's
`internal/runtime/enforce api=1` is now `internal/runtime/enforce/api api=1`, the package's .golangci.yml exclusion
moved with it, and edges.txt names the producer enforce/api. No kind's total changed; C5 still owns making the
number an owner (a Dup of the ruleset). `TestTreeRatchetAndPlantedSites` and `scripts/check-fd.sh` failed on the
merge until the move and pass after it.

*Amended 2026-10-19 (implementation note):* the unix ask work was built on a base
without the ratchet and added three raw sites: cgroup's exported `Handle.GrantUnix(fd int, name)` (kind `api`, F8), and
in pkg/spec/agent `ReadPlaceLink`'s `unix.Close` (kind `close`) and its `sysOpenat2 = unix.Openat2` test hook (kind
`producer`). None is paid by a baseline rise. `GrantUnix` takes the socket's `SO_COOKIE` instead of a number: the
supervisor, whose duplicate it is, checks `SO_DOMAIN` is `AF_UNIX` and reads the cookie (`grantUnixName`), so the API
names the socket and no descriptor (edges.txt gains no entry). `ReadPlaceLink` needs `openat2` with
`RESOLVE_NO_SYMLINKS`, which pkg/spec cannot own (A2: no internal/ import, and `os.NewFile` would be a new kind), so
its two sites are paid inside the package: `x11Sockets` now opens /tmp/.X11-unix with `os.OpenFile` (O_PATH,
O_DIRECTORY, O_NOFOLLOW, as before) and lends the number to its lookups through the File's `SyscallConn`, the
standard-library owner A2 names, removing one `close` and one `producer`. pkg/spec/agent's line stays `close=9
producer=5` and cgroup's `api=2`. Rejected: raising either line (the ratchet never rises), and renaming the parameter
(F8 would no longer see a number that is still one).

*Amended 2026-10-19 (implementation note, FD-EARLY C12 built, hoststate):* `hoststate.Dir` holds its verified
directory as a `*sys.FD` (`sys.Own(unix.Open(…O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC…))`), so ADR 0034 (2)'s
"`Open()` returning a verified sys.FD" is true. `OpenFile` opens through `(*sys.FD).Openat` and hands the number to
its `*os.File` with `Release`; `Names` and `Stat` read through `sys.FstatFile` and `(*sys.FD).Fstatat`, `Unlink` under
a `Borrow`; `Dup` is the owner's `Dup()` (now at 3 or above, close-on-exec as before); `Close` is the owner's
close-once, so a racing or second Close is a no-op, and every use after it answers `sys.ErrClosed` (wrapped, with
the error texts unchanged) where it reached a cleared `-1` before. The directory is not strict: it holds no flock
(the locks are the files `OpenFile` returns, which their callers own). The package's baseline line and
`.golangci.yml` exclusion are deleted. Tests: `TestDirClosesOnceAndLendsNothingAfter` (eight racing Closes under
`-race`, then ErrClosed from OpenFile, Stat, Unlink and Dup; it failed before with a data race and EBADF) and
`TestDirUnwindsLeaveNoDescriptor` (`testutil.NoFDLeak` over every refusal of OpenAt and OpenFile, a Dup and its
Close).

*Amended 2026-10-19 (implementation note, FD-EARLY C13 built, runtime/cgroup):* `cgroup.Cgroup` holds the scope's
directory as one `*sys.FD` shared by every copy of the value Create returned (it replaces the `FD int` field and the
shared `closed *atomic.Bool`), so "closed once across copies" is the owner's close-once, and the check-then-use of
the old `dirFD()` (a copy could read "open", another copy close, and the number be reused before the openat) is a
lease: control files open through `(*sys.FD).Openat`, `ID` reads the handle and stat under a Borrow, and a copy whose
directory is closed (or a hand-built one) resolves through `Path` on `sys.ErrClosed`. Control files, the
cgroup.events inotify descriptor and the helper scope's directory are owners (the inotify one Released to its
`*os.File`). None is strict: no flock, pipe write end or durability file. *Departure from the plan (its C13 row
named only the package's files):* the edge rule (A6) reaches past them. The cgroup directory's consumer was
`launch.Start(…, cgroupFD int)`, fed by `internal/runtime` reading the old int field; with the field gone the
number exists only under a lease, and a lent number may not be stored into `SysProcAttr` (F2), so
(1) `sys.CloneIntoCgroup(dir Lender, attr *syscall.SysProcAttr, start func() error)` is added to the owner's
fd_lease.go: it sets `UseCgroupFD` and `CgroupFD` under one Borrow for `start` alone and sets `CgroupFD` back to -1
after it (UseCgroupFD stays, so `cloneFailure` still names clone3, and a second start with the attr fails EBADF);
it is T2.3's "the cgroup fd is borrowed across proc.Start" written once; (2) `launch.Start` takes the cgroup as a
`sys.Lender` (nil: the caller's cgroup) and runs its start through it, so launch's `api` count falls from 2 to 1 and
edges.txt drops `Launcher.Start`; `Cgroup.Dir()` lends the directory, nil for a hand-built Cgroup. FD-MID's C6 keeps
the rest of launch. A closed directory is now `sys.ErrClosed` from `Start` before any clone (exit 125 on Run's
path), where the int handed clone3 whatever the number named. Tests: `TestCloneIntoCgroupLendsTheNumberForTheStartOnly`
and `TestCloneIntoCgroupRefusesWithoutADirectory` (sys), `TestCgroupDirIsOneOwnerAcrossCopies` (a Close under a
lease is deferred, every copy then answers ErrClosed) and `TestCgroupUnwindsLeaveNoDescriptor` (NoFDLeak over
Create, Remove, control reads and writes through the descriptor and the path, the watcher) in runtime/cgroup,
`TestStartRefusesAClosedCgroup` (launch, NoFDLeak); the root suite's clone3 cells now start through
`sys.CloneIntoCgroup`.

*Amended 2026-10-19 (implementation note, FD-EARLY C17 built, cli ownlog):* `ownLog` holds `~/.tego` as a strict
`*sys.FD` (`sys.Strict(home.Openat(…))`: it carries the rotation flock, taken with `(*sys.FD).Flock`), nil until the
first write; the home directory is a scoped owner, `emptyDir`'s second descriptor and `tego.log` are opened through
`Openat` and Released to their `*os.File`s, and chown, chmod, mkdirat and renameat run under a Borrow. The table
check found one leak the int form had: an appender that gave the log up (a planted link, a FIFO, a loose directory,
a failed reopen after rotation) kept `~/.tego` open for the life of the process; it now closes it and the file it
held (`breakLocked`). Test: `TestOwnLogHoldsOnlyItsDirectoryAndFile` (NoFDLeak over three refusals and a write
that rotates twice, which a non-strict directory would not, since Flock refuses it); it failed before the fix with
the two refused appenders' `~/.tego` descriptors. internal/cli leaves the baseline.

*Amended 2026-10-19 (implementation note, FD-EARLY C10 first step, ledger):* every directory and file descriptor
in internal/ledger is a `*sys.FD`: the walk (`openDir`, `stepDir`, `openRunDir` return owners), the Writer's run
directory, the blobs directory (`blobStore` keeps its RWMutex so one operation's several calls name one directory,
and a closed store answers `ErrClosed`), the live index, the mirror directory and the anchor's directory; files
reach their `*os.File` by `Release`, `Dup`+`NewFile` listings became a fresh `Openat(".")`, and the flocks on
`*os.File`s go through `sys.Flock` (the lock files stay `*os.File`s, whose close the standard library makes once).
Strict sites: the Writer's run directory (Close fsyncs it, `closeDirs` logs its close), `fsyncAt`'s blob and
directory descriptors, `syncDirs`' parent, `syncDirAt`'s anchor directory, and `Sync`'s syncfs descriptor. The
test hooks `fchown` and `fsyncDir` take the owner. `OpenAt` takes a `sys.Lender` (A11) and reopens its run
directory under one lease; internal/runtime's two callers reopen their inherited number into an owner for the call
(`openLedgerAt`), and edges.txt drops `internal/ledger OpenAt`. *Departure:* one raw number stays. A `GC` or
`SweepLive` pass hands its hooks (`WithSweepHook`, `WithReclaimHook`, `WithEndedHook`, `WithBoundWriterOptions`,
all consumed by internal/runtime's sweep) the held ledger root as the string `/proc/self/fd/<n>`, valid for the
whole pass, and its pinned repository and `os.OpenRoot` resolve through the same path. A lease cannot cover that
(the path is stored and crosses a func value, F2), so `pinRoot` opens it raw beside the walk's owner and
`unpinRoot` closes it: the ledger's baseline is `close=1 producer=1`. It goes when the hooks and the pinned
repository take the held root as a descriptor (`*at()` lookups, no proc path), which is the C10 remainder.
*(The pinned repository's part is built: see the next note; the hooks' part, and with it C10: see the note after it.)*
Test: `TestLedgerDescriptorsCloseOnEveryPath` (NoFDLeak over a Writer opened by path and through a lender, closed,
abandoned and refused, its sidecar, a replaced mirror, a blob, the live index, a placed file, and a GC and
SweepLive pass), written against the Lender form of `OpenAt`, which did not compile before. The runtime suite's
`TestMain` now also fails when a test closed or replaced descriptor 0–2: a hand-built runner with a zero
`notifyFD` closed the test binary's stdin, and `sys.Own`'s refusal of a standard number then failed an unrelated
test's first open (TestAForkRefusedBeforeTheWatcherStartsStillEndsTheRunAsPids). *(The check is
`testutil.GuardedStdioLeakCheckMain`, a guarded main tools/isocheck GO-4 accepts, so the runtime `TestMain` exits
with its code untouched; `TestGuardedStdioLeakCheckMainFailsOnAClosedStdin` holds it.)*

*Amended 2026-10-19 (implementation note, FD-EARLY C10 second step, ledger):* a `GC` or `SweepLive` pass makes
every lookup of its own by an `*at()` call under the ledger root it opened (the walk's owner): the pinned
repository lists through a fresh `Openat(".")`, reads a run's ledger, contract copy and lock under the run
directory it opens there with `O_NOFOLLOW`, ages a run by `fstatat`, and retention locks the run and removes it
with `removeAllAt`, which follows no link (a link inside a run is removed, never what it names). `os.OpenRoot`
and every path through `/proc/self/fd` inside the ledger are gone, and so is `SweepLive`'s nested `GC` over that
path: its no-index fallback is the same pass (`gcPass`) over the repository it already holds.
`WithBoundWriterOptions` lends the held root as a `sys.Lender`, under which internal/runtime's sweep anchor reads
a run's owner (`fstatat`, the `/.` trick gone). *Departure, narrowed:* the hooks (`WithSweepHook`,
`WithReclaimHook`, `WithEndedHook`) still receive the held root as the path `/proc/self/fd/<n>`. Their consumers in
internal/runtime (`ProbeLock`, `OpenStopTargetFor` and its lock-holder proof, `markDir.launched`, `runStartOf`,
`sweepAdoption`, `orphanScope`) resolve paths, and fdcheck (rightly) admits neither a lent path flowing into them
(F2) nor a raw number added to internal/runtime to make one (A9: a site moves only with its declaration). So the
one raw number stays in the ledger, opened and closed by `pinHookRoot` alone, and its errors are relabelled to
the configured root as before; the ledger's baseline stays `close=1 producer=1`. It goes when those checks take
the run directory, opened under the held root, as a `sys.Lender`, which is the C10 remainder. Tests:
`TestGCRemovalFollowsNoLink` (a link to a directory and one to a file inside an aged run go; their targets
outside the root stay), `TestRemoveAllAtOfAMissingNameIsNoError`, and the held-root suite unchanged
(`TestGCSwapBackStillSweepsTheHeldRun`, `TestSweepLiveUsesHeldRootWithAndWithoutIndex`, and internal/runtime's
`TestSweepAnchorOwnershipUsesHeldRoot`, whose ownership reads now go under the lent root and fail if made by
path).
*(The hooks' part is built, and their `/proc/self/fd/<n>` path and `pinHookRoot` gone: see the next note.)*

*Amended 2026-10-19 (implementation note, FD-EARLY C10 built, ledger):* the sweep, reclaim and ended hooks
(`WithSweepHook`, `WithReclaimHook`, `WithEndedHook`) are lent the run's directory as a `sys.Lender`, opened for
the hook's call alone under the root the pass holds with `O_NOFOLLOW` (`lendRun`), instead of the held root as the
path `/proc/self/fd/<n>`. internal/runtime looks the run up under it: a `runDir` (the run's path, which names it in
messages, and the lent directory) gives the lock probe and the launcher's lock-holder proof their lock file
(`ledger.OpenRegularAt`), `runStartOf` its ledger (`ledger.OpenReaderAt`, a reader on a descriptor of its own
reopened from the lender), and `markDir.launched`, `orphanRoots`' owner check and `sameDirectory` the directory's
device, inode and owner by `fstat` of the lent directory. `tego stop`, `ask`, `RunScope` and the ledger check
keep their paths (`ProbeLock`, `OpenStopTargetFor`: a `runDir` with no lender). A directory that cannot be opened
is the sweep hook's error (the run stays lost), frees nothing for reclaim and keeps the ended entry with an error.
`pinHookRoot`, the hooks' path and the relabelling of their errors (`relabel`, `labelled`) are gone: a hook's
error names the configured root, from which runtime builds the run's path. The ledger has no raw site left: its
baseline line and its `.golangci.yml` exclusion are deleted, and internal/runtime's counts are unchanged (no site
added; `markDir.launched` reads the directory through `runDir`). Rejected: lending the held root and letting
runtime open the run under it (every check would reopen and re-resolve the run's name, so two checks of one hook
could see two directories, and runtime would need a raw producer or a new ledger export for each lookup anyway);
handing runtime the raw root number (the `stepB` draft: a raw site moved across packages, which A9 forbids); and
keeping the path (F2). Tests: `TestRunDirLooksUpUnderTheLentDirectory` (the run moved away after its directory
was opened and a decoy with a FIFO lock put at its path: through the lender the checks read the moved run's
cgroup id, identity and free lock, by path the decoy; NoFDLeak), `TestHooksAreLentTheRunDirectoryForTheCallAlone`
(each hook is lent its own run's directory, closed when it returns: a kept lender is `sys.ErrClosed`; NoFDLeak
over GC and SweepLive; without the close it fails on both), `TestGCSwapBackStillSweepsTheHeldRun` and
`TestSweepLiveUsesHeldRootWithAndWithoutIndex` (the hook is lent the held run's own directory, by device and
inode read before the swap, with its lock held by the sweep's Writer), and the sweep, reclaim and ended suites of
internal/runtime and internal/ledger unchanged but for the hooks' parameter.
*(Where the pass holds the run's lock, the hook is lent the directory that lock was taken in, not `lendRun`'s
reopening of the name: see the next note.)*

*Amended 2026-10-19 (implementation note, ledger):* a hook the pass runs under the run's lock
is lent the directory that lock was taken in, not the run's name opened again. The sweep of a lost run lends a
reopening (`Openat(".")`) of the directory its Writer locked and appends `run_end{orphaned}` to (`lendDir`); the
sweep of an empty run and `SweepLive`'s ended run open the run once under the held root and take the lock, read the
ledger (`OpenReaderAt` over it), the agent (`firstAgent`, `contractAgent`), make the anchor repair and lend the hook all under
that one descriptor (`tryLockAt` replaces the repository's `tryLock`). The comments on `WithSweepHook` and
`runDir` said the lent directory was the one the pass decided on whatever was renamed over the run's name; it was
not: the hook reopened the name after
the Writer had locked it, so a directory renamed over the name between the two fed every orphan check (the cgroup
id, the launched mark, the owner) while the locked run was ended. A hook the pass holds no lock for (reclaim, and a
lost run whose ledger cannot be ended, where the lock was free and released) is still lent the name as it stands
(`lendRun`): renaming entries inside a writable root is the separate boundary `GC` names, and the agent is
read-denied there. Rejected: lending the Writer's own `dirFD` (a lease the hook kept would hold the Writer's
descriptor open past its `Close`); and cutting the claim from the comments
alone (the binding costs one `openat` per hooked run). Test: `TestHooksAreLentTheDirectoryThePassLocked` (for each
of the three, a seam renames the run away right after the lock and makes a decoy at its name: the hook is lent the
moved directory, the sweep's `run_end` is in it, the empty and ended hooks get the locked run's agent; NoFDLeak;
before the fix all three failed, the sweep lent the decoy and the other two never ran their hook).

*Amended 2026-10-19 (implementation note, FD-MID C6 first step, launch's child stage):* the child stage's control and
report pipes (fds 3 and 4) are owned by `sys.Inherited` with `KindFIFO`, its deputy control end with `KindSocket`, as
the process's first descriptor operations (tools/fdcheck/inherited.txt lists both sites), then released into their
`*os.File`s; a number that is not the kind the launcher passed fails the stage closed (exit 125) before anything is read
from or written to it. `cloexecFrom3` is replaced by `sys.CloexecFrom(3)`, which fails the stage closed as before. The
readiness socketpair is `sys.Socketpair`, its ends lent and released, and the launcher's dup of the deputy end is
`sys.DupFile` then `Release`. launch's ratchet line falls to api=1 close=3 dup=1 newfile=1 producer=3. Left, with the
reason each one stays: the ruleset handoff (the Handle gives a bare number until C5, and `sys.RestrictSelf`'s ABI
fallback passes the number through a function value the lint cannot follow); the child's listener number, which is
written to the parent as data for pidfd_getfd, a use no lent-number rule admits; and the parent's pidfd and
`WaitNotifyFD` (C6 rest and C7), because `supervisor.New` takes an int and an owner the supervisor holds needs listener
ioctl wrappers whose bodies the lint can follow (`sys.SeccompNotif*` name the number in their error texts) or a
binding type in sys that keeps Run's lease, which F2 forbids even there. Tests: the launch unit and unprivileged
integration suites (real child stages through the new path).

*Amended 2026-10-19 (implementation note, FD-MID C6 rest and C7, the parent's pidfd and the notify-fd handoff):*
`launch.Child.PidFD` is a `*sys.FD`, set once at the start and closed by `Close`; `Kill`, `Wait`, `Signal` and the
getfd borrow it, so a `Close` racing them is deferred until they return (the old int field was cleared under them).
clone3's store through `SysProcAttr.PidFD` is owned by a new sys helper, `sys.StartWithPidfd(attr, start)`, the one
site that adopts that number (inside sys, so no adopt.txt line), which closes it when the start undid its child and
answers `ErrNoPidfd` for a child left without one. `WaitNotifyFD` returns the listener as a strict `*sys.FD` (T1.4)
and `Child.NotifyFD` is gone. `supervisor.New(listener *sys.FD, …)` takes it as a value move: `runtime` clears its
field before the call, and New owns the listener on every path, closing it itself when it refuses, so
`releaseKernelState` closes only a listener no New was given. This pulls the listener part of C8 into FD-MID, because
the design moves the notify fd into New and no lint-clean New can take an owner and keep calling the listener
through a bare number. Design chosen: the production kernel holds the owner and borrows the number per call (poll,
RECV, SEND, ID_VALID, ADDFD, SET_FLAGS), which needed the `sys.SeccompNotif*` and pidfd wrappers to name no number in
their error texts and their test seams (`notifIoctlFake`, `addfdIoctlFake`) never to receive it; fdcheck then follows
every lent number into them. A closed owner under the loop is `waitInvalid`, the failure POLLNVAL reports. Rejected:
(a) one lease held by Run for the workers' lifetime (C8's plan), because F2 forbids a Lease stored in a struct or
captured by a goroutine, even inside sys; (b) a fdcheck amendment admitting a sys binding type, because it reopens
the escape question the earlier notes closed, for a cost (two atomics per borrow, three borrows a notification)
the round-trip benchmark does not show: interleaved before/after binaries, 10 samples each on 4 pinned CPUs,
`BenchmarkSeccompNotifyRoundTrip` 40.97 µs vs 40.28 µs (p=0.74) at 14 allocs/op and 1.37 KiB/op both, and the
fake-kernel `BenchmarkNotificationRoundTrip` rows unchanged in B/op and allocs/op. The shared machine's noise (±60%)
cannot resolve C8's stricter p50 ≤ +50 ns check, which stays FD-LATE's to run on a quiet host. The rest of C8 (execimage's walker, ask_open,
unixrelay, walkcache, the heldFD seam) stays in FD-LATE. Ratchet: launch falls to close=1 dup=1 newfile=1 producer=1,
supervisor to close=77 dup=3 producer=45, runtime to close=34. Tests: TestNewValidates (a refused New closes the
listener), TestRunListenerFailures' closed-owner row, TestStartNotifyLoopFailsClosedOnAnInvalidPolicy (the runner
keeps nothing and the listener is closed), TestReleaseKernelStateClosesAListenerNoLoopEverTook (a run that failed
before startNotifyLoop), and the launch abort and handoff tests on the owner's state.

*Amended 2026-10-19 (implementation note, FD-MID C9, the runtime rest):* the reaper's descriptors are owners. The
launcher's self pidfd is `sys.PidfdOpenProcessFD` released into ExtraFiles (ADR 0020 (2)); `ReapMain`'s start-up
sweep is `sys.CloseInheritedFrom` (tools/fdcheck/sweep.txt) and it owns fds 3 to 7 through `sys.Inherited` by kind
(`inheritReapFDs`, tools/fdcheck/inherited.txt), failing closed (exit 125) on a sweep that cannot list
`/proc/self/fd` or a number of the wrong kind; `sweepRun` takes the run directory as a `sys.Lender` and opens the
ledger with `ledger.OpenAt` on it. rootmark.go's record directory and files, dns_directory.go's /tmp parent and
socket directory (made with `mkdirat` beneath the verified parent instead of `os.MkdirTemp` on its
`/proc/self/fd/N` path, which no lent-number rule admits), lock.go's `StopTarget` pidfd (Signal borrows it, so a Close
racing it no longer clears the number under it), landlockaudit.go's netlink socket, and the Fd() sites of lock.go,
run_workers.go, stdio.go and dns_reap.go (`sys.FileDo`, `sys.Flock`) all go through owners. runtime's ratchet line
falls to close=21 newfile=7 producer=9 (fd=0). Left in runtime, not in a C-step: adopt_reap.go and adopt_state.go
(ADR 0055's adoption, with `closeStrayFDs` and `openLedgerAt`, which only they still use) and run_child.go's deputy
ends (the deputy package's int API, its own migration). Tests: TestTheReaperOwnsItsInheritedDescriptorsByKind (six
helper processes: each wrong kind fails, the right sets pass), the reaper, root-mark, DNS directory and lock suites.

*Amended 2026-10-20 (implementation note, FD-MID verification):* C6, C7 and C9 as built hold as root in KVM guests
on 6.17 with and without bpf in lsm=: the root launch suite (74 pass, 3 allowed skips per boot), the supervisor and
sys suites, and internal/runtime's root-only tests with its reaper, sweep, unwind and inheritance tests (both
builds, untagged and tegobpf), with cgroup's TestPlaneLauncherKillLeavesTheRunDecidedAndTheReaperPurges. On the
host matrix row (both boots) and on rhel-9 kill tests 1, 2, 4, 5 and 6 pass in every cell the matrix runs there but
one (below). Kill test 3 measured no budgeted row on either (each NOISY on the shared machine: SKIP 77, budget
unverified, no TARGET-MISS). Kill test 7's half (b) is refused at launch on both rows with `budget-unmetered` (exit
125: its example contract declares a cost_usd budget and the harness installs no price table), a refusal this
package does not touch. rhel-9's kill test 4 pip cell at tier cgroup missed once (13 of 20 within the 2x wall
budget); alone it passed 19 of 20 at this tip twice and at the package's base once, with baseline medians from 1992
to 3903 ms between runs, so the miss is the shared machine's noise, not this change.

*Amended 2026-10-20 (implementation note):* the refusals C6 and C9 added are now pinned by
tests that run the production entry points, each shown failing against a mutation of the code it pins. The reaper's
tests run `ReapMain` itself (the test binary started as the reaper's command runs it from `TestMain`, before the
testing package opens anything, and its hold prints what it holds): TestTheReaperFailsClosedOnItsInheritedDescriptors
(a file or pipe at 3, 4, 5, 6 or 7, no handoff pipe, and a sealed sweep each end it with exit 125 and one line naming
the number, never reaching the hold) replaces TestTheReaperOwnsItsInheritedDescriptorsByKind, and the descriptor-set
tests give the reaper strays right above its last passed number, which its sweep closes (the plain layout keeps 4,
the DNS layout 4 to 6 at the hold, 7 having been read and closed). The child stage's
TestTheChildStageRefusesAWrongKindDescriptor (launch, integration build) runs `__child` with a socket, /dev/null or a
file at 3 or 4 and a non-socket at the spec's deputy number: exit 125 and one line naming the number, the spec
step's failure frame on a good report pipe, and the spec left unread in a good control pipe when the report pipe is
the one refused. `mkdirTempAt` takes its number source (rand.Uint32 in `newDNSDirectory`), so
TestMkdirTempAtRetriesATakenNameAndStopsOnAnyOtherError can take names first; TestStopTargetSignalAfterCloseIsErrClosed
pins Signal after Close as os.ErrClosed and a Close during a borrow as deferred, and
TestReapFDsCleanupDNSLendsTheHeldDirectories the reaper's DNS cleanup through its two owners. `closeStrayFDs` stays
for the adoption reaper alone (above).

*Amended 2026-10-24 (implementation note, the maze setup tool's merge):* the maze setup tool (cmd/maze,
internal/maze) ships for darwin as well as linux, and its two macOS files (internal/maze/ui/termios_darwin.go, the
termios ioctl requests; internal/maze/scan/dataless_darwin.go, Stat_t.Flags) are built by none of F6's builds, so
fdcheck failed them as uncovered. They are judged, not exempted: F6 gains a darwin/arm64 build, cgo off, as the
release builds it. It is the last of the extra builds and reads only the packages that hold a file still uncovered
after the Linux ones which it builds (go/build's file rules, the overlay's files read in place of the checkout's),
so a Linux package's other files need not compile on macOS and a Linux file no build covers stays a problem. F5's
ioctl allowlist admits TIOCGETA and TIOCSETA, macOS's TCGETS and TCSETS, which read and set a termios and answer no
descriptor. Rejected: an A7 exemption for the two files (a macOS file that later opens or closes a number would pass
unseen) and a separate Go module for maze (the tool imports pkg/spec types and shares the module's release and
lint). TestCoverage and TestDarwinTermios pin the build and the allowlist.

*Amended 2026-10-24 (implementation note, on the note above):* a darwin build judged against Linux's lists
passed macOS's own producers: unix.Kqueue, syscall.Kqueue and a raw SYS_KQUEUE, SYS_SHM_OPEN or SYS_OPEN_NOCANCEL
gave no finding, and a raw SYS_CLOSE_NOCANCEL was no close. F1's list is now generated for darwin on amd64 and
arm64 beside linux (it gains Kqueue in both packages; the unclassified-name and unclassified-ioctl failures apply
to the macOS sources too, and IoctlCtlInfo, IoctlGetIfreqMTU and IoctlSetIfreqMTU are classified as fixed
requests). producerTraps names macOS's descriptor traps (kqueue, the _nocancel, guarded, data-protection and by-id
opens, fhopen, socket_delegate, peeloff, fileport_makefd, shm_open and sem_open, the NECP and Skywalk opens, and the
receives that install SCM_RIGHTS descriptors), A4's close counts close_nocancel and guarded_close_np, fcntl_nocancel
is judged as fcntl, and under a non-Linux build any other raw trap is a finding (fail closed): the Linux trap list
says nothing about another system's syscalls. TestDarwinProducers fails without each change.

*Amended 2026-10-25 (implementation note):* the listed data parameters that keep nothing
gain `syscall.Exec`'s and `unix.Exec`'s path. execve resolves `/proc/self/fd/N` at once, as open and stat do: a failed
exec returns with nothing kept, and a successful one is a new image. internal/handoff's `Exec` needs it: it execs its
sealed memfd through that link under `ProcPath` (ADR 0100's implementation notes say why it is not a raw execveat), so
Go restores the soft RLIMIT_NOFILE first. Exec's argv and envp stay unlisted: a lent path there is still a lease site.
TestLentNumber's "proc path exec'd by syscall", "by unix" and "as exec's argument" rows fail without the change.

*Amended 2026-10-25 (implementation note):* code moved out of `internal/runtime` into the
engine's clients (ADR 0100 (7)), and its counts moved with it, as A9's ratchet allows: every kind's total is
unchanged. `internal/askclient` (new, `newfile=1 producer=1`) holds the ask socket's directory helper
(`OpenSocketDir`). The broker binds by it and the client dials by it, and its two sites left
`internal/runtime/ask`, whose line fell to `newfile=2 producer=2`. The sites sit in an unexported `socketDir`, the
name of the declaration they left, and `internal/runtime/ask` no longer declares that name, so the ratchet against
the base (`check-fd.sh --base`, as CI and `scripts/precommit.sh` run it) sees the move (a first cut
put them in `OpenSocketDir` and kept a `socketDir` wrapper in the broker, which that run refused). The package has its own A9 lint exclusion. A
client that dialled through `ProcPath` instead would hand the lent path to `net.Dialer.DialContext`, which fdcheck
cannot follow, so that is a lease site. `internal/runlock` (the run lock and the stop target, from
`internal/runtime/lock.go`) has no raw site, so it is a migrated package. A6 then refused its use of
`sys.PidfdSendSignal`, which takes a bare number, so sys gives an owner form, `PidfdSendSignalFD`: it borrows the
pidfd for the call, and a closed or nil owner is `ErrClosed`, as `StopTarget.Signal`'s own `Borrow` was. `edges.txt`
was regenerated, and `TestPidfdSendSignalFD` holds the owner form.

### C40 descriptor additions — 2026-11-03

The tty layer leases its ruleset and path owners through `FD.AddLandlockPath`. Controlling-terminal
lookup owns its `/dev/tty` open. The pty relay owns a new peer at birth with
`OwnSyscall(SYS_IOCTL, ..., TIOCGPTPEER, flags | O_CLOEXEC)` and leases both source and listener through `FD.SendSeccompDescriptor` for ADDFD/SEND;
the agent's requested close-on-exec flag is applied separately at delivery. F10 now admits only that
named descriptor-producing ioctl under OwnSyscall, and F9 requires O_CLOEXEC. F5 additionally
recognises the non-producing TIOCGDEV and TIOCGPTN queries. Bare TIOCGPTPEER and other ioctls remain
refused by the ownership checker; decision-table tests hold all three cases. No raw-site ratchet is raised.
