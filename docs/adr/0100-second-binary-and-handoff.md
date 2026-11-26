# ADR 0100: The second binary and the handoff

Status: **accepted 2026-10-24**; implemented: the second binary, its sealed handoff, the noun rule, the link gates, the
engine clients of (7), ask.sock's peer rule and the dashboard's own peer checks are built. The built-in refusals of
ADR 0113 were implemented 2026-11-03; its implementation note states the remaining limits. Section numbers are stable because code, tests and lint rules cite them (for example
"ADR 0100 (1b)").

## Context

The dashboard (`tego serve`) needs a web server for a person's browser, sign-in, sessions and page rendering. The engine
runs a privileged launcher and a supervisor that reads another process's memory. Those two must not share a binary: the
launcher is trusted computing base (`SECURITY.md`) and can run as root, and nothing the dashboard adds is needed to enforce a
contract.

Three rules hold everywhere:

- The dashboard and every other client of the engine are clients. They read the ledger, answer the ask broker over
  `ask.sock`, and act on a run through its directory and its launcher: a stop is a marker and a signal through a verified
  pidfd, and a live block is an overlay the launcher polls. They are never a second enforcement path.
- Every engine change a client needs is either a move with identical behaviour or a narrowing of what a run may do.
- The engine is Layer 1 and `tego-control` is Layer 2 (`docs/FEATURES.md`). Layer 1 never imports Layer 2.

## Decision

### 1. Process model

**(1a) Two binaries, one module, one release.** `tego` is the engine. It links no dashboard, sign-in, session or page code,
and nothing below `internal/control`. `tego-control` holds the dashboard and its commands. The line is not "no HTTP in the
engine": `tego` links `net/http` and `crypto/tls`, because the launcher runs a run's loopback forwarder
(`internal/runtime/capture/forwarder`) and its MCP relay (`internal/runtime/mcprelay`), which are HTTP servers for the agent's
own traffic. Gates hold the split: `go list -deps` link-closure tests in both directions
(`internal/control/linkgate_test.go`), a committed list of the engine's module set, and depguard rules in `.golangci.yml`.

**(1b) The sealed handoff** (`internal/handoff`). The engine reaches `tego-control` only through it:

- it opens `<dir of os.Executable()>/tego-control` with `O_NOFOLLOW`, and requires a regular file owned by root or the
  caller with no group or world write;
- it copies the file into a memfd and seals it (`F_SEAL_WRITE`, `SHRINK`, `GROW`, `SEAL`);
- it compares the SHA-256 of the sealed copy with the hash the build pinned, then runs the sealed memfd (Exec) or starts a
  child from it (Spawn);
- so a write in place or a rename after the open cannot change what runs;
- the handoff refuses to run at euid 0, and `tego-control` refuses euid 0 and any capability in every subcommand; the engine
  itself still runs under `sudo` for the root tiers. An unpinned build refuses the handoff.

**(1d) The edge.** `internal/control/web` is the code a browser reaches. It parses HTTP, renders pages and serves embedded
assets, on the listener that `tego-control serve` opened. A lint rule (`.golangci.yml`, "the edge opens no socket") bans every
dial, listen, name lookup, HTTP client call and raw socket written in that package, and a depguard rule
(`edge-holds-no-authority`) keeps `internal/ledger` and `internal/check` out of it, along with the library packages that dial.
`scripts/check-edgelint_test.sh` holds the rule to a fixture of each banned primitive, so the rule cannot shrink unnoticed.

The dashboard is not read-only. With the serving user's authority it answers held requests, stops runs, blocks actions and
changes rules. A page parses the form and calls a service below it, which holds that action's guards:
`internal/control/runact` for held requests, stops and live blocks, `internal/control/rules` for contract changes, and
`internal/control/mcpact` and `internal/control/routeact` for MCP tool rules and model routes. Those services reach a run the
way the CLI does, so they do connect (`runact` dials a run's `ask.sock`), which a lint that reads one package's names cannot
see. The checks in (3) stand in front of every action, and the run's launcher and supervisor stay the only enforcement.

**(1e) Children of the handoff.** `Spawn` starts the sealed image as a child of the caller instead of replacing it. The pin
is mandatory. The child gets its extra files at descriptors 3, 4, ... and then a read-only descriptor of the sealed memfd, and
runs `/proc/self/fd/<that slot>`. `Spawn` is a reviewed start site (ADR 0021 (6)).

### 2. CLI noun rule

- The engine owns the nouns that must work with no second binary: `run`, `status`, `events`, `ask`, `approve`, `deny`,
  `stop`, `agents`, `rule`, and the rest of the engine's commands.
- `tego-control` owns `serve`. `tego <noun>` for a `tego-control` noun runs the handoff, and `tego help` lists it as
  `(tego-control)`.
- A noun never spans both binaries; a test enforces it (`TestNoNounInBothBinaries`). The list of handed-off nouns is
  `internal/handoff`'s, and a test holds it equal to the commands `tego-control` registers.
- Commands register per noun file. In `internal/cli` and `internal/control/cli` no file edits another noun's registration.
- Every list verb has `--json`. Exit codes come only from `pkg/spec/identity`.

### 3. Peer checks

`ask.sock`, the socket the engine serves to the person, checks the peer before anything else, at the connect and again at
the packet:

- the `SO_PEERCRED` uid;
- the unified cgroup, with `SO_PEERPIDFD` liveness;
- the cgroup namespace;
- `runscope.LooksGoverned`, which refuses any run or adopt scope and any look-alike name.

Below Linux 6.5 (the rhel-9 and al2023 rows of the kernel matrix) there is no `SO_PEERPIDFD`. The check then takes
`pidfd_open` on the `SO_PEERCRED` pid and re-checks the uid, the cgroup and that the connection is still open, as ADR 0042
(vii) does. A pid reused between the connect and the `pidfd_open` is not detected there. The check marks such a peer
(`PidfdFallback`), and nothing shows that mark to a person yet.

The dashboard's listener is TCP, and a TCP peer has no `SO_PEERCRED`. It has two checks of its own, in
`internal/control/web`, and both fail closed:

- every request: the owner of the client socket in `/proc/net/tcp` and `/proc/net/tcp6` must be the serving user (`peer.go`);
- each POST and the `?t=` sign-in: the cgroup the client socket was made in, read through `sock_diag`
  (`peer.TCPSocketCgroup`), must be found, and must be outside every run by `runscope.GovernedBy` (`governed.go`). A GET
  is answered without this check, because reading is not governance.

These are narrower than `ask.sock`'s checks: they read no `SO_PEERPIDFD` and no cgroup namespace, and they do not refuse a
look-alike cgroup name. [ADR 0123](0123-dashboard-threat-model.md) says what the dashboard does not cover.

### 7. Engine changes

Behaviour-identical moves: `internal/runlock`; `pkg/spec/askproto` and `internal/askclient`, with `LedgerTarget` as the
single source of an ask's ledger form; `internal/runscope` (`GovernedBy`, `LooksGoverned`) and `internal/platform/peer`.

Narrowing changes: `ask.sock` refuses peers in any run scope or another cgroup namespace, and the broker serves only the
ledger form of a target. The built-in refusals of [ADR 0113](0113-built-in-refusals-for-tego-surfaces.md) are a further
narrowing, implemented 2026-11-03 with the limits in that ADR's implementation note.

## Rejected options

- **One binary with the dashboard linked in.** The launcher would link the dashboard's sign-in, sessions and pages, and the
  link gate could not tell trusted code from the rest. The HTTP servers it does run are a different case: each serves one
  run's agent on loopback, not a person's browser.
- **Finding `tego-control` on `PATH` or in the working directory.** Either is writable by the agent. It is looked up beside the
  running `tego` only.
- **Hashing the file while copying it, and nothing more.** A same-uid write through `/proc/<pid>/fd/N` between the copy and
  the seal would then pass. The hash is taken of the sealed copy.
- **Each package adding its own depguard rule when it lands.** A package that lands first would be ungoverned, and each
  author would write the rule they need. The rules are declared first and the packages land under them.

## Consequences

- `make build` makes the pair: `bin/tego-control` first, then `bin/tego` with that file's SHA-256 linked in. A `tego` built
  any other way refuses the handoff with `[control-unpinned]` (`docs/OPERATIONS.md`, "The control binary").
- `scripts/install.sh` installs both from a release, holds both to their checksums, and refuses a pair whose pin does not
  match.
- Every handoff refusal exits 125, Tego's own error.

## Tests

- Link gates and the split: `TestEngineLinksNoControl`, `TestControlLinksNoEngine`, `TestEngineModuleSetUnchanged`,
  `TestNoNounInBothBinaries`.
- The handoff: `TestHandoffInPlaceWriteRace`, `TestHandoffSwapRaceExecsVerifiedFile`, `TestHandoffRefusesUnpinnedBuild`,
  `TestHandoffRefusesRoot`, and as real root in the privileged suites `TestHandoffRefusesRootAsRoot`,
  `TestControlRefusesRootAsRoot` and `TestHandoffRefusesNoexecMountAsRoot`.
- The edge: `scripts/check-edgelint_test.sh`.
- The peer checks: `TestPeerCheckFallbackWithoutPeerPidfd` and `TestIdentifyReadsThePeer`, as root on every row of the kernel
  matrix, where the rhel-9 and al2023 rows take the fallback against their own kernels and fail if the kernel answers
  `SO_PEERPIDFD`; and in CI's root suites on the runner's kernel.
- The dashboard's checks: `TestPeerUIDGuardsEveryRoute`, `TestPeerUIDFailsClosed`, `TestGovernedPeerRefused` and
  `TestGovernedRealSocket`.
- The engine clients: `TestAskWireGolden`, `TestAskClientAgainstBroker`, `TestAskClientRefusesWrongServerPID`,
  `FuzzAskprotoDecode`, `TestRunlockProofsUnchanged`, `TestLedgerTargetSingleSource`, `TestEngineClientsImportNoRuntime`.

## Implementation notes

- `internal/handoff` holds `Open`, `Exec`, `Spawn` and the noun list. `Open` opens the file with
  `O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK` (so a FIFO planted at the path cannot hang the open; it is then refused as not
  a regular file), checks owner and mode on the descriptor, copies at most 256 MiB into a memfd, seals it, and only then
  hashes it, reading the sealed copy from its start.
- The refusals come in this order: euid 0 `[control-as-root]` (before anything is opened), no file
  `[control-not-installed]`, an unpinned build `[control-unpinned]`, then `[control-untrusted]` and `[control-mismatch]`. A
  kernel that refuses an executable memfd (`vm.memfd_noexec=2`) is `[memfd-noexec]`. Every code exits 125.
- `Exec` is `syscall.Exec` of `/proc/self/fd/<memfd>` under the descriptor's lease, not a raw `execveat(AT_EMPTY_PATH)`. The
  magic link names the sealed memfd's own open file, so what runs is still the verified copy, the memfd is still
  close-on-exec, and `/proc/self/exe` is still the memfd. The reason is the soft `RLIMIT_NOFILE`: `syscall.Exec` restores the
  limit the process started with, which a raw `execveat` does not, so `tego-control` and its children would otherwise
  start with the raised limit Go sets at start. `TestHandoffHandsOverTheSoftNofile` holds it.
- The memfd copy is executable whatever the source's mode or mount, so the file check also requires the execute bit of the
  caller's class, read as the kernel's mode check reads it for a file without an ACL, and refuses a file on a `noexec` mount,
  both `[control-untrusted]`. Disclosed: an ACL's named entries and a security module's exec rule on the file are not
  evaluated, since the kernel checks the memfd, not the file.
- The link gates read `go list -deps` of each main package in the plain and the `tegobpf` build. The engine bans
  `internal/control/**`; `tego-control` bans `internal/runtime/**`, `internal/policy/**`, `internal/bpf/**`, the engine's
  `internal/cli` and `internal/doctor`, cilium/ebpf and go-landlock. The engine's module set is
  `internal/control/testdata/engine-modules.txt`, with versions.
- The edge's socket ban names every `Dialer.Dial*` and `ListenConfig.Listen*` method, every name lookup, the `http.Client`
  and `http.Transport` calls that dial, `tls` dials and listens, and the raw socket calls. What the edge does stays allowed:
  `net.File*` over the descriptors it is handed, `http.Serve`, `(*http.Server).Serve[TLS]` and `http2.Server.ServeConn`. The
  lint reads names, so it cannot see a dial made inside another package's call.


### Amendment 2026-11-03: terminal rules view

`rules` is a built handoff noun: `tego rules <run>` or `tego rules --last` renders the
same `rulesview.InForce` model as the dashboard. Unique run-id abbreviations work too.
Text includes enforcement limits, sources, hits and live blocks; `--json` is a
version-1 object and omits contract bytes and environment values. It is read-only and
retains the control binary's refusal of root. The engine still links no control code.


### Measurement note, 2026-11-18: no private-namespace outside exception

A WSL 3.0.5 / Ubuntu 24.04.5 guest did not satisfy the proposed same-namespace service-manager proof. A normal
user connected to its own manager's private socket and obtained the correct UID, exact manager cgroup and a live
peer pidfd, but stat/readlink of the manager's namespace links returned EACCES. Its permitted capabilities included
CAP_WAKE_ALARM. Same UID alone is not namespace identity authority. The existing membership and peer refusals remain
unchanged; unknown membership cannot widen governance. A scope rehearsal is placement evidence only and grants no
peer, approval or scan authority. In particular, an ordinary WSL shell and a Windows browser do not acquire a
person-facing control exception. A Windows dashboard relay is separate work and is not implemented here.


### Amendment, 2026-11-18: the base-cgroup-namespace rule (built; its use on WSL is off)

This amends item (7)'s note of 2026-10-25 ("outside the initial cgroup namespace nothing can tell") and replaces
the stopped proposal the measurement note above records. That proposal compared the cgroup namespace of the user's
service manager with the caller's, which a normal user cannot read (the manager holds `CAP_WAKE_ALARM`, and the
kernel's read check on `/proc/<pid>/ns/*` wants the target's permitted set inside the caller's; the same `EACCES` was
measured on ordinary Ubuntu). The rule below needs no namespace link of another process. Its kernel facts were
checked against the source at v5.14, v6.6 and v6.18, and it was attacked before it was built.

**What it answers.** Three answers: inside (the zero value), unknown (always with one typed cause) and outside
(`runscope.Answer`, read through `Outside()` alone; the two-answer `InRun` is removed so that no caller compiles
against "inside, or an error"). The answer's fields are unexported: no other package can make an outside answer, read
a field as "permit" or decode one, `runscope.Unproven` (the one constructor other packages have) makes unknown only,
and a source check confines `Decide`, `Prove` and the diagnostic `Describe` to the rule's own packages, a diagnostic
file and tests (2026-11-19, review of round 2, findings 5 and 9). Only outside permits a governance change, an approval or the entry into a user scope.
Outside means: this process is in no run's cgroup *made inside its own cgroup namespace*. The answer is computed in
the caller's own process, so it is the refusal an honest tego gives, not a boundary.

**The order of checks, every call** (`runscope.Decide`, pure, over the reads of `internal/platform/peer`):

1. The process's own cgroup path (`/proc/self/cgroup`, `runscope.Unified`): unreadable, malformed, above the namespace
   root or `LooksGoverned` is inside, and nothing more is read.
2. Its own cgroup namespace: `/proc/self/ns/cgroup` opened for reading, `fstatfs` must say nsfs, `fstat` gives device
   and inode. Any failure is unknown. This replaces the stat of the path in both branches, so a file made to carry the
   first namespace's inode number cannot route a process into the unchanged branch.
3. The kernel's first cgroup namespace (inode `0xEFFFFFFB`): outside, unless the gate below holds it back. No fact of
   the caller beyond the path and the namespace file is read there: ordinary Linux keeps its answers, and its only
   new system calls are the open, `fstatfs` and `fstat` of step 2 in place of a stat, and the gate's `uname` and
   `lstat` of WSL's three marks when the path shows no run (amended 2026-11-19).
4. Outside the first namespace, by system call and never cached: real, effective and saved uid equal and not 0; an
   empty permitted capability set. Each failure is unknown. The seccomp mode (`PR_GET_SECCOMP`) is read next and
   recorded on the answer for a diagnostic line (`runscope.Describe`, `tego doctor`'s `run membership` line, which also
   gives the time the probe of step 8 took, measured where it ran), never
   judged: the signed rule's fact 4c (no seccomp filter) is removed, as its own condition said it would be if an
   ordinary WSL shell is filtered (amendment of 2026-11-19 below).
5. `/proc` anchored: a descriptor shown to be a procfs root (magic `0x9fa0`, inode 1); every later read is
   `openat2` beneath it with `RESOLVE_BENEATH|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS`, capped at 64 KiB; the own path
   is read again through it and judged as in step 1.
6. A proof held in memory for (nsfs device, namespace inode, uid): outside. 7. A probe that failed less than a second
   ago: that same unknown. 8. One probe (`runscope.Prove`), one at a time per process, waited for at most 500 ms:
   - (a) `NS_GET_NSTYPE` says cgroup, and `NS_GET_USERNS` on the verified descriptor returns a namespace file of the
     same device whose inode is the first user namespace's (`0xEFFFFFFD`). `ns_get_owner` answers `EPERM` unless the
     owner is the caller's user namespace or below it, so this also proves the caller is in the first user namespace,
     and only a holder of `CAP_SYS_ADMIN` there can have made the cgroup namespace. `/proc/self/ns/user` is never read.
   - (b) `1/cgroup` reads exactly `/init.scope`. No socket is touched when it does not.
   - (c') One non-blocking, close-on-exec connect to `/run/user/<uid>/systemd/private` (the fixed folder;
     `XDG_RUNTIME_DIR` is never read), nothing written or read. `SO_PEERCRED` must name this uid and a pid;
     `SO_PEERPIDFD` is required, with no `pidfd_open` fallback (below Linux 6.5 the answer is unknown); the pidfd's
     fdinfo must show that pid before and after the read of `<pid>/cgroup`, and the pidfd must not have exited (from
     Linux 6.16 the kernel hands out a pidfd for a reaped listener). The path must equal
     `/user.slice/user-<uid>.slice/user@<uid>.service/init.scope` byte for byte. No namespace link and no other file
     of the listener is opened: the kernel renders the path from the reader's own namespace root, so the exact path
     already proves where the manager sits.
9. All held: the proof is stored and the answer is outside. Otherwise unknown with the first failing cause.

Only the proof is kept, for the life of the process; it is never written to a file, the environment, an argument or a
pipe, and the re-entered process of a user-scope entry proves again. `peer.Refuse` outside the first namespace serves
a peer only when this process's own answer is outside, and in the first namespace only when the gate holds nothing
back (on WSL it serves none); its other tests are unchanged.

**Words.** Unknown keeps exit 125 `[governed]`, with words for its cause; "a governed agent" is said only when the
path shows a run. The lines a person can act on (no systemd at the top, a user session that is not up, root) come
before any wording about runs.

**The gate.** Every answer of outside meets a gate (`Facts.Withheld`, `peer`'s `selfHost.withheld`), which holds it
back as unknown where the rule is not proven yet. An ordinary build's switches for it are functions that return
a constant: true for WSL (since the commit that switched the rule on, below), false for the nested one
(`TestOrdinaryBuildCannotTurnTheWSLRuleOn`); builds with the `tegotesthooks` tag start both off and set them with
`TEGO_TEST_WSL_RULE=on` or `TEGO_TEST_NESTED_RULE=on`, for the proofs themselves.

- *Switched on 2026-11-19 (round 6).* Four rows passed in a Windows 11 guest, so where WSL shows two of its
  marks the rule answers outside like anywhere (and doctor lists nothing as unproven); where it shows one the text
  that follows holds. The rows: every `W-N2-*` row (a run refuses WSL's launcher), `W-E4-ALIAS` (the home folder's
  second name), `W-E4-DRIVE` (the Windows drive) and `W-E4-WSLG-SOCKETS` (the GUI and audio sockets), on a test build
  that set the same switch. *Run on the ordinary build 2026-11-19:* the same guest ran the ordinary build (34 of 37 rows
  passed, 3 unknown, none failed) and the six beginner steps. Not proven: a signed or HTTPS-served release, the rule where
  `/proc/self/ns/cgroup` is a FUSE file, the shell of a terminal window, and mirrored networking for the browser.
- On WSL (the kernel release names Microsoft or WSL, or `/run/WSL` or a `WSLInterop` binfmt entry is there; never an
  environment variable; a release or a mark that cannot be read counts as WSL), where only one mark shows, every
  answer of outside, in both branches, is unknown with cause `wsl-launcher-unproven`. The safety of an outside answer there rests on a run
  refusing WSL's own program launcher (`wsl.exe`, `/init` and the sockets under `/run/WSL`, ADR 0113): a process an
  agent starts through it is truly outside the run and would be served. That refusal had unit tests and no passing
  guest proof when this was written; it has one now (above). *Amended 2026-11-19 (review of round 2, finding 3):* the gate first held only beyond the first
  cgroup namespace, so a distribution with `isolateDistroCgroup=false`, which sits in the first one, took the
  unchanged branch and was answered outside; it now covers that branch too, and `peer.Refuse` asks it there, so a
  run's approval socket serves no peer on such a machine either. The cost on ordinary Linux is the gate's `uname` and
  up to three `lstat` calls, made only where the answer would be outside. Turning the rule on for WSL is the
  a later change, with its own evidence.
- *Decided 2026-11-19 (review of round 2, finding 4):* outside WSL, in a cgroup namespace that is not the kernel's
  first one (a container, a nested system with its own service manager), every answer of outside is unknown with
  cause `system-unproven` ("this kind of system has not been proven"), which is the answer tego gave there before the
  rule. No guest has measured the rule there (`L-N1-NESTED`, `L-N1-PRIVATE-NS` are not run), and the rule's residual
  4 (a whole nested system inside a run satisfies every fact) is a reason to measure before answering. The rule's code
  stays and runs (the probe still names the first failing fact); only its outside is held.
- In the first cgroup namespace outside WSL nothing is held: ordinary Linux keeps its answers.

**What the rule does not stop.**

- A process that controls the tego it starts (a tracer, a second seccomp filter, a rebuilt binary) controls the
  answer. In an enforcing run this gains nothing: tego's own writes and connects still meet Landlock and the
  supervisor, and the broker judges its peer in a process the agent does not own. Those are the boundary; this rule is
  not.
- Watch runs. Nothing is refused there, so an agent can move itself to another cgroup of the user's subtree or reach
  systemd, and a process that has left the run's cgroup that way is answered as its path and the proof say: with the
  seccomp fact removed, outside, as on ordinary Linux. A process started for the agent by something outside the run
  is truly outside. Under watch the answer is advisory. This is no worse than ordinary Linux today.
- Real root inside a run, or anything that acts as root for the agent. It can make a cgroup namespace owned by the
  first user namespace and rooted at the run's scope. Facts (b) and (c') stop it only while mount, cgroup writes and
  `/run/user` writes are refused; the filter's namespace arm now also refuses the new cgroup or process-id namespace
  itself (SEMANTICS section 10, amended the same day).
- A whole nested system. A privileged system container with its own systemd and user manager, whose cgroup sits
  inside an outer run, satisfies every fact: no fact looks above the namespace root. The outer broker in the first
  namespace still sees the run's scope in such a peer's path and refuses it. Outside WSL the gate holds every such
  outside answer back (`system-unproven`) until a guest has measured the rule there.
- The unchanged first-namespace branch: on ordinary Linux a watch-run agent in its own user and mount namespace can
  still overmount `/proc/<pid>/cgroup` and be answered outside. This is older than the rule and is not fixed here.

**Evidence, and what is owed.** Unit tables over every state (`internal/runscope`: `TestDecide*`, `TestProve`,
`TestCauseWords`, `FuzzUnified`, `FuzzFdinfoPid`), the kernel's reads against this machine (`internal/platform/peer`:
the namespace file, the anchor, `NS_GET_USERNS`, real listeners, a reaped listener, the real user manager), the cache,
back-off and time limit under an injected clock, one table of answers walked at every caller
(`TestOnlyAnOutsideAnswerPermits` in each package) and source checks that no caller names a verdict, that the probe
opens no other file of the listener, and that the two threads that call `unshare` are never handed back to the
runtime. No guest has run this rule: every WSL row, the strace on ordinary Linux and the root rows are owed, and no
document claims that WSL works.

**Amendment, 2026-11-19: fact 4c is removed.** The signed rule shipped fact 4c (no seccomp filter on the caller) only
if every ordinary shell of a default WSL install showed seccomp mode 0. The first guest run of the proof scripts
(Windows 11, WSL 2, Ubuntu 24.04; row `W-FACT-SHELLS-MIRRORED`, 2026-11-19) measured, with
`networkingMode=mirrored` in `.wslconfig`, `Seccomp: 2` and `Seccomp_filters: 1` in every ordinary shell it could
start: PowerShell and cmd through `wsl.exe`, a login shell, `wsl -e`, a non-login and an interactive non-login
shell, and root. WSL installs the filter itself. With the default NAT networking every kind showed mode 0 (row
`W-FACT-SHELLS`). So the fact would have refused every person who turns mirrored networking on, and it is removed:
the rule reads the mode after the capabilities and records it on the answer (`runscope.Describe`; `tego doctor`
prints it on its `run membership` line), and judges nothing on it. What the fact gave is gone: a descendant of a
watch-run agent that has left the run's cgroup is no longer answered unknown for its filter (see "What the rule does
not stop"). An enforcing run is unchanged: its agent cannot leave the run's cgroup, and the broker judges its peer in
a process the agent does not own.

### Amendment, 2026-11-19 (round 4): WSL is two marks, not one

The gate's test for WSL counted any one mark: a kernel release naming Microsoft or WSL, `/run/WSL`, or a `WSLInterop`
binfmt entry, with a mark that cannot be looked at counting as there. A security module that refuses `lstat` of
`/run/WSL` on an ordinary Linux machine therefore made it WSL, and the gate then withheld every outside answer there.
WSL is now at least two of three independent marks: the release suffix; the launcher folder `/run/WSL`; one of the two
binfmt entries (`WSLInterop`, `WSLInterop-late`: one mark, the same registration). A release that cannot be read and a
mark that cannot be looked at still count as their own mark, so one refused look adds one mark, never two. A WSL
distribution has all three; one with a custom kernel without the suffix has two. A distribution with interop turned
off may show only the release: it is then not WSL to the gate, which is safe because no launcher is reachable there,
and beyond the first cgroup namespace its answer is still unknown (`system-unproven`). Compile's check of WSL's
launcher (ADR 0113, amended 2026-11-19) counts the same marks. Unit-tested: `TestWSLDetection` (each one-mark case),
`TestGateInThisBuild` (an ordinary machine whose `/run/WSL` cannot be looked at keeps its outside answer),
the two-mark test of `pkg/spec/agent` (round 5 replaced it with `TestWSLRestrictionOnOneMark`). *Superseded in part by round 5 (below): one mark now holds and
restricts; two are needed only to relax.*

### Amendment, 2026-11-19 (round 4): WSL readiness and the gate are one switch

`tego doctor`'s WSL readiness hold (ADR 0142: four warnings, `pending_wsl`, finding status 1, and setup storing no
tier) was keyed on the kernel release alone, so a test build with `TEGO_TEST_WSL_RULE=on` could prove runs in a
guest but never a setup that exits 0. The hold now holds exactly while `peer.WSLGateHolds()`: the machine is WSL (two
marks, above) and the rule's gate holds there. An ordinary build is unchanged on WSL (the gate refuses setup first,
and doctor prints the four warnings). The commit that turns the rule on for WSL lifts both, so it is made only after
the launcher, home-folder alias, Windows drive and GUI and audio socket rows pass in a guest.


### Amendment, 2026-11-19 (round 5): detection of WSL is asymmetric

Round 4 made WSL two marks for every purpose, so a distribution showing one mark, which ADR 0100's own text says a
distribution with interop off may do, was ordinary Linux to tego: readiness was not held, setup could say ready, and
the gate answered outside in the first cgroup namespace. The rule is now asymmetric, for every caller:

- **Any ONE mark holds or restricts.** The readiness hold (`peer.WSLGateHolds`, doctor's four warnings and
  `pending_wsl`, setup storing no tier), the gate's withholding of an outside answer (`selfHost.withheld`), compile's
  refusal of WSL's launcher sockets (ADR 0113), and anything else that makes tego more careful apply where the kernel
  release names Microsoft or WSL, or `/run/WSL` is there (or cannot be looked at), or a `WSLInterop` binfmt entry is.
- **A relaxation needs two.** The rule's answer of outside on WSL (`wslRuleOn`, a test build's switch until the
  commit that turns it on for everyone), and every step marked ready because of it, apply only where two marks show
  the machine is the WSL whose launcher refusal was proven. With the switch on and one mark the answer stays withheld
  and readiness stays held.

The cost is stated: an ordinary Linux machine whose `/run/WSL` a security module refuses to show gives one mark and is
held as WSL is (the fail-closed side), where round 4 kept its answers. The rule is in the code next to the count
(`internal/platform/peer/self.go`, `wslMarks`; `pkg/spec/agent/compile_wsl.go`, `probeWSL`). Tests:
`TestWSLDetection` (each one-mark case holds), `TestGateInThisBuild` (one mark withheld, the first namespace included),
`TestWSLSwitchNeedsTwoMarks` (a test build: the switch relaxes two marks, never one, interop off included),
`TestWSLRestrictionOnOneMark` (compile). Guest row `W-FACT-INTEROP-OFF` (`[interop] enabled=false` in
`/etc/wsl.conf`, the distribution restarted): setup is held in an ordinary build and the switch relaxes nothing on one
mark.

### Amendment, 2026-11-19 (round 6): the rule is on for WSL

Rounds 4 and 5 said the commit that turns the rule on for WSL is made only when the guest has proven four containment
rows. They passed, in a real Windows 11 guest (WSL 3.0.5, Ubuntu 24.04.5, kernel 6.18.58.1-microsoft-standard-WSL2), on a `tegotesthooks` build with the switch set by `TEGO_TEST_WSL_RULE=on`, over two guest runs:

| What the amendment of round 4 required | Rows | Result |
| --- | --- | --- |
| a run refuses WSL's launcher (`/run/WSL/*_interop`, the Windows program launcher), with a working control outside the run | `W-N2-CONTROL`, `W-N2-DEFAULT`, `W-N2-PERSON`, `W-N2-HOST-SOCKETS`, `W-N2-UNIX-ALLOW`, `W-N2-LATE`, `W-N2-CONTRACT` | PASS: the launcher's sockets refused by every name, under the default contract and `host_sockets: true`; `unix:` allows and `/run/WSL` write grants refused at compile and at run |
| the home folder's second name | `W-E4-ALIAS` | PASS: a denied secret refused by its own path and through `/mnt/wslg/distro/home/...`, both refusals in the record |
| the Windows drive | `W-E4-DRIVE` (and `W-N3-DRIVE`) | PASS: a write on the drive refused, the allowed write works; a rules file on the drive refused before any scope opens |
| the GUI and audio sockets | `W-E4-WSLG-SOCKETS` | PASS: 21 socket paths that accept a connect outside a run, each refused inside one by path and by every other name, under the default contract and with `host_sockets: true` |

Decision, 2026-11-19. `wslRuleOn` is the constant true in every build without the `tegotesthooks`
tag, so the gate, readiness and the rule are one switch, as round 4 made them, and it is on. Where WSL shows TWO OR
MORE of its marks (round 5: the release, `/run/WSL`, a `WSLInterop` entry):

- the gate lets the rule's answer through (`selfHost.withheld`), in the kernel's first cgroup namespace and in the
  distribution's own: a process every fact of the rule holds for is outside, and `tego setup`, `run`, `watch`, `test`,
  `machine test` and the entry into a user scope proceed from an ordinary WSL shell (ADR 0142, round 4);
- `tego doctor` no longer prints its four "has not been proven" warnings, `pending_wsl` is empty, the finding status is
  the tier's, and `tego setup` stores the measured tier (`WSLGateHolds` is false there).

Where WSL shows ONE mark, nothing is relaxed: the gate withholds with `wsl-launcher-unproven`, doctor prints the four
warnings, setup stores no ready tier, and compile refuses WSL's launcher sockets (round 5). Outside WSL nothing
changes: outside in the first cgroup namespace, `system-unproven` beyond it (`nestedRuleOn` stays the constant false).
A binary built with `-tags tegotesthooks` keeps its test switches, which start off (the state of a build from before
this commit, so that a test can show both): `TEGO_TEST_WSL_RULE` sets the WSL one in `internal/cli` and
`internal/control/cli`, never under AT_SECURE. Tests: `TestOrdinaryBuildOnTwoMarkWSL` (an ordinary build; two marks
answer as the rule says in both namespaces and are not held, one mark is held in both, non-WSL machines unchanged),
`TestGateInThisBuild` and `TestWSLDetection` (both states), `TestGateSwitches` and `TestWSLSwitchNeedsTwoMarks` (a test
build's switch), `TestOrdinaryBuildCannotTurnTheWSLRuleOn` (the ordinary switch is the constant true, the nested one
false, and nothing in an ordinary build names a variable, setter or flag that could change either).

What this does not claim, and what remains unproven:

- The proof ran a test build with the switch set by its variable; the ordinary build is the same code with the switch a
  constant. *Run 2026-11-19:* the switched-on ordinary build ran in the guest;
  `W-GATE-ORDINARY` passed with the opposite of what it held (setup exit 0, doctor without the four warnings), 34 of 37
  rows passed, 3 stayed unknown, none failed, and the six beginner steps passed (docs/INSTALL.md, "Tested on").
- `/proc/self/ns/cgroup` served by FUSE (`W-RULE-FUSE`, not scripted: the unit tests and `W-RULE-FORGED-PROC` cover the
  plain-file half; `W-FACT-USERNS-FUSE` records a fact, not a verdict).
- The facts of a shell opened from a terminal window (`W-FACT-SHELLS`, `W-FACT-SHELLS-MIRRORED`: no console session ran a
  line in the guest) and `W-RULE-INSIDE-ESCAPES` (UNKNOWN).
- `W-RULE-BROKER` FAILED in run 5 (the agent's own approve and deny reached no running run through the harness's path;
  the rule answered 0 times and the ledger's read-deny stopped 4). It is not one of the four rows and the commit does
  not rest on it; it stays open.
- WSL's mirrored networking for the Windows browser's access to the dashboard (the relay refuses to bind there and says
  so), and WSL's idle shutdown.
- Everything the rule does not decide: a process inside a run that is root, or holds `CAP_SYS_ADMIN`, or escapes by a
  route the contract allows, is as it was; the answer is the refusal an honest tego gives, not a boundary.

### Amendment, 2026-11-22: the peer check admits an undumpable peer, so the dashboard can be undumpable

Decision, 2026-11-22. `tego-control serve` holds the sign-in token, the CSRF key and the acknowledgement keys. It is the operator peer of every run's ask broker, and (7)'s peer check read the
peer's `/proc/<pid>/ns/cgroup`, which a process that has the dumpable flag at 0 hides from every reader without
`CAP_SYS_PTRACE`. So the dashboard was left dumpable, and a run with no Landlock domain (`tego watch` with no `--boundary`,
`--observe`) on a Yama 0 host could read those keys from it ([ADR 0126](0126-mcp-tool-rules.md), "Amendment 2026-11-21"). The
dashboard is now made undumpable before it does anything else (`Command.HoldsSecrets` on `serve`, `sys.MakeUndumpable` with its
read-back, run by `mainWith` before the command; it does not start when that fails, exit 125 `[undumpable]`), and the peer check
admits it. Nothing on the wire, in the record or in a contract changes (`record_minor` stays 41).

**The admission.** Of the three designs the ruling named, this is the first: the peer's `SO_PEERCRED` uid, its pidfd and its
cgroup path, which `/proc` keeps readable whatever the flag. It is not a new check. It is (7)'s check with one comparison made
conditional, and every other fact judged exactly as before.

- `peer.Identify` reads what it read (the `SO_PEERCRED` uid and pid, the pidfd from `SO_PEERPIDFD` kept alive across the reads,
  the pid `/proc` shows for it, the unified cgroup of the process and of every thread, a first thread that has not exited, the
  start time). When the cgroup namespace file is hidden it asks for the reason in files that stay readable
  (`dirFS.undumpable`): the peer's `/proc/<pid>/environ` is owned by another uid than the connecting one (the kernel gives the
  per-process files of a process whose dumpable flag is not 1 to the root of its memory's user namespace,
  `task_dump_owner`), its `status` shows the connecting uid as real, effective, saved and filesystem uid, and its `CapPrm` is
  zero. Then `Peer.Undumpable` is true, `CgroupNS` stays 0, and nothing else about the peer is skipped. Anything else that hides the
  file (a process that holds capabilities this process lacks, another uid, an LSM) is read as before: `CgroupNS` 0 and
  `Undumpable` false, which `Refuse` refuses `[peer-cgroupns]`. A proof that cannot be read is `[peer-unidentified]`.
- `peer.Refuse` judges an undumpable peer in the same order as any peer: another uid `[unmapped-uid]`, a cgroup that
  `runscope.LooksGoverned` (any run's or adoption's scope, anything below one, any look-alike) `[run-member]`, a path above this
  process's cgroup namespace root, an unreadable namespace of this process itself, a non-initial cgroup namespace of this
  process whose own answer is not outside, and the WSL gate, all `[peer-cgroupns]`. The one comparison skipped is the peer's
  namespace inode against this process's, which cannot be made. `Undumpable` with a namespace shown, or on root (whose
  per-process files belong to root dumpable or not, so the files never show it), is `[peer-unidentified]`.
- The broker carries the flag (`ask.Peer.Undumpable`) from the connect and from the packet's second identification, so the
  per-packet rule that the same process (pid and start time) is judged afresh is unchanged, and `askPeerAuthorize` passes it to
  `peer.Refuse`. The local roles' owner-only reading (ADR 0154) takes its own snapshot with the namespace `fstatat`, which an
  undumpable sender fails, so a deciding role that is root and undumpable is still refused there; the dashboard never runs as
  root (`tego-control` refuses euid 0 and capabilities).

**Why an agent in a run cannot pass it.** Being undumpable adds nothing to what the admission asks of a peer, and nothing is
asked of it that it could set. What admits a peer is its position, not its flag:

1. The agent's cgroup is where the kernel put it. Every process of a run is in the run's scope or below it, from birth, and the
   path is read from this process's own namespace (`proc_cgroup_show` prints relative to the reader's cgroup namespace, not the
   peer's), so an agent that unshares a cgroup namespace, makes itself undumpable, or both, reads the same path. `[run-member]`
   refuses it, for every thread of it, and a first thread that exited is refused outright (`everyThread`).
   `TestUndumpablePeerInsideRealRunIsGoverned` runs it: the agent of a real run makes itself undumpable, is identified with
   `Undumpable` set and the run's own cgroup, and is refused `[run-member]`.
2. The uid is the kernel's `SO_PEERCRED`, and the process is the one the pidfd names; the flag changes neither.
3. The one comparison skipped is the peer's namespace inode against this process's, and it never decided where a peer is. The
   path is read in this process's namespace, so a peer in a namespace of its own shows its true place relative to this root
   (or above it, which `[peer-cgroupns]` refuses by the path), and no peer can use its own namespace to change what is read.
   Two shapes of a peer in a cgroup namespace of its own, and they differ:
   - A peer that made its user and cgroup namespace and then exec'd (a container's init, `unshare` and `bwrap` run as a
     program) owns its memory in that user namespace, which the person's uid owns, so its namespace files are readable by
     the broker: it is not hidden, no flag is set, and the comparison refuses it `[peer-cgroupns]`
     (`TestAPeerInItsOwnCgroupNamespaceIsReadAtItsTruePlace` asserts that refusal, and that the peer is read at its true
     cgroup, not at the `0::/` it sees of itself).
   - A peer that calls `unshare(CLONE_NEWUSER|CLONE_NEWCGROUP)` and does not exec keeps the initial user namespace as the
     owner of its memory. If it then sets the dumpable flag to 0 and drops every capability, the broker has no
     `CAP_SYS_PTRACE` over that memory, so the namespace is hidden, the kernel's files prove the flag, and the comparison is
     skipped: **it is served on its path alone**, as an outside peer with `--cgroupns=host` always was and as an undumpable
     process of the person in a rootful container with a private cgroup namespace is. Its path is still the true one, read in
     this process's namespace, so it gains nothing against `[run-member]`, the only fact that kept an agent of a run from
     answering; the comparison never rested on a stronger fact. The guest rows record this shape
     once, with the review's overlay test (a small C client run in the guest, not part of the tree): served, path true.
4. The proof of the flag is the kernel's, from files the peer cannot write: the owner of `environ`, the uids of `status` and its
   `CapPrm`. A hidden namespace that the files do not explain (a peer with capabilities this process lacks, an LSM's denial, root)
   is refused as before. An agent that makes itself undumpable shows the flag and nothing else.
5. What is not prevented is what was never prevented: a record-only `tego watch` agent that leaves its run's scope by a cgroup of
   its own in the person's delegated subtree, or through `systemd --user`, is outside every run and answers as the person's
   process, as the note of 2026-10-25 says. It did so dumpable, and it does so undumpable. `tego watch --boundary` closes both
   ways.

**What it closes.** An agent of a run with no Landlock domain, on a Yama 0 host, can no longer attach to the dashboard, read its
`mem`, `environ`, `fd` or `maps`, call `process_vm_readv` on it, or take one of its descriptors with `pidfd_getfd`; the keys the
dashboard holds are in memory only it can read (root and `CAP_SYS_PTRACE` apart, and the milliseconds between `exec` and
`mainWith`). The sign-in token is still in the 0600 `~/.tego/dashboard.log` that every process of the user reads (ADR 0126's
condition 1): the token alone reaches nothing, since the loopback listener refuses a request whose socket was made inside a
run (`peer/tcp.go`, `sock_diag`).

**Readers of the dashboard's `/proc`, each checked against the real process** (the table is in ADR 0126's amendment of the same
date): `tego dashboard` and `tego start` identify the dashboard by its log and an HMAC challenge over HTTP and read nothing of its
`/proc`; stopping it is `systemctl --user stop tego-dashboard`, a signal from its own manager; the doctor probes the loopback
`sock_diag` lookup and reads no dashboard `/proc`; the manager, `systemd-run --pipe` and `tego uninstall` use the unit. `tego scan` and
`tego agents` read `exe` and `environ` of every process of the user: the dashboard holds the lock `~/.tego/dashboard/lock` while it
serves (`runlock.HoldDashboard`), and a basic scan names it by that lock, proved as a launcher is by the kernel's lock table and
the pid's start time (`runlock.DashboardPID`), and does not count it among the unreadable programs, so `tego scan --check` is
not made exit 3 by a running dashboard; every other unreadable program stays counted, and a dashboard that could not take the
lock (another one holds it) is counted as before; `tego agents` runs as root and reads it. Its own reads of `/proc/self` (`exe`, `fd`, `ns/*`,
`cgroup`, `mountinfo`, `net/tcp`) are not affected, and its helpers (the draft compiler and the contracts helper, both exec
`/proc/self/exe`) are dumpable children that hold nothing.

Tests. Unit, with fakes: `TestUndumpablePeerIsJudgedByTheRest`, `TestRefuseUndumpable`, `TestStatusHoldsNothing` and
`TestDirFSUndumpableReadsTheKernelsFiles` (internal/platform/peer), `TestAskPeerAuthorizeRefusesEveryRunShape` (rows for an
undumpable peer outside every run, in this run's cgroup, below it, another run's, an adoption's, a look-alike, above the root,
another uid, root, and one that shows a namespace), `TestSecretHoldingControlCommandsAreExactlyThese`, `TestServeIsMadeUndumpableBeforeAnythingItDoes` and `TestServeThatCannotBeMadeUndumpableDoesNotRun`
(internal/control/cli). Real kernel: `TestIdentifyAnUndumpableProcess` (a real process, through `SO_PEERPIDFD` and the
fallback), `TestUndumpableOperatorIsServedAnAgentIsNot` (a real broker, socket and client: an undumpable process outside the run
approves the held operation, the same one in the run's cgroup is refused and the ask stays pending), and, in the empty-home view,
`TestDashboardJourneyOverALiveRun` with the real `tego-control serve` undumpable (`requireUndumpableDashboard`) answering a
real run's two asks. Each failed on the old source.

Not proved: a root-run broker (it reads every peer's namespace, so it never takes this path), `fs.suid_dumpable` 1 (the dashboard
makes no credential change), a kernel other than the host's and the guest's, a dashboard in a cgroup namespace of its own
(WSL's isolated distribution is judged by the same rule as every peer there: this process's own answer must be outside).

### Amendment, 2026-11-26 (public issue 84): the words of the unknown depend on where the process is; the rule does not

In a container the cause `init-not-at-root` printed "turn systemd on in /etc/wsl.conf" and "tego setup" under `tego start`. The
sentence is now one of `runscope.Words`, which a caller that knows where it is (`internal/platform/whereami`: a container by
`/.dockerenv`, `/run/.containerenv` or a `container` variable in process 1's environment, and no systemd as process 1; WSL by
this ADR's marks; else a host) may replace. In a container the cause is not a line the person acts on first (the refusal says where to
run the command instead), and the sentence says a container runs agents with `tego run` in the setup of `examples/container`. No
function of the rule reads the words, so no verdict, cause or exit code changed; a host and WSL print the sentence they printed. The
refusals of `tego rules undo` and of the peer sockets still print the table's sentence.
