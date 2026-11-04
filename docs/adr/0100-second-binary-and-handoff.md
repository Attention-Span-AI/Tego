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
