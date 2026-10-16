# ADR 0031: the TCB's dependency rule is made true and checked

Status: proposed 2026-09-23. Resolves ARCHITECTURE §16's Open condition and ADR 0014's Open item.

Compatibility bridge, 2026-09-30: external modules cannot import internal/policy/decide. Until the public
shims are removed, pkg/policy/evaluate exposes explicit forwarding functions and links the same core for
legacy methods. It is outside pkg/spec, so the spec import boundary remains intact. The bridge is an
experimental model tied to the selected Tego module version, not a stable promise about kernel behavior;
the implementation and ownership remain in internal/policy/decide.

Decision: (1) pkg/spec/agent keeps the public types and pure validation. YAML loading moves to pkg/spec/agent/load (public), and pkg/spec/config is split the same way. The I/O compiler (filesystem, ELF, mountinfo, DNS and host-socket work, and compile_net.go's goroutine) moves to internal/policy/compile. Evaluation lives in internal/policy/decide (ADR 0028); pkg/spec/agent.Evaluate is a deprecated shim for one release, then removed. internal/policy/compile and internal/policy/decide join the TCB list; TCB packages import types and decide only. (2) enforce.Handle and Listener move to a leaf package, internal/runtime/enforce/api, so internal/runtime/launch stops linking every backend and cilium/ebpf. (3) capture/uprobe emits raw TLS chunks, and httpstream, with brotli and zstd, runs in a pipeline stage outside the TCB. (4) A test runs go list -deps -tags tegobpf over the TCB packages and fails on any module outside cilium/ebpf, golang.org/x/sys and golang.org/x/net. go-landlock leaves the list and tools/deps.go unless a shipped package imports it. depguard adds 'backends never import each other' and 'provider parsers never import each other'. That test replaces REPO-LAYOUT's claim that CI fails when depguard disagrees with doc.go. (5) Isolating the parsers from root entirely needs an unprivileged helper process; that is a condition of an external security review, not of this ADR.

Why: [measured, go list] 20 non-test files in pkg/spec import os, x/sys/unix or net; gopkg.in/yaml.v3 is reachable from launch, enforce/landlock, enforce/cgroup, enforce/observe, supervisor, observe and runtime/cgroup; andybalholm/brotli and klauspost/compress are reachable from capture/uprobe; launch pulls 185 transitive dependencies through enforce; 8,187 non-comment lines sit in the named TCB against 16,493 in decision-making packages outside it; .golangci.yml has 4 depguard rules. [documented] ARCHITECTURE §16 and ADR 0014 record the mismatch as open.

Security argument: A smaller reviewed TCB with no third-party decompressor or YAML parser on root parsing paths. At tier 2 the whole binary still runs as root, so this narrows review scope rather than privilege; the helper-process condition is stated for the external review.

Options considered: Rejected: amending the text to list the real dependency set: honest and cheap, but it keeps third-party parsers and decoders on root paths and the public API heavy; the debt would be recorded, not paid.

Consequence: Public API churn in pkg/spec (moved Load functions, deprecated Evaluate). The TCB list names the policy compiler and the decision core; the dependency rule becomes a CI check instead of an open condition.

Implementation plan:

Staged, each behind ADR 0017's suite:
(a) internal/runtime/enforce/api and launch's imports: any time after ADR 0023.
(b) capture/uprobe to raw chunks with httpstream in the pipeline (closes ADR 0014 Open): independent; kill test 2 in GUEST unchanged (20 of 20 parsed); one channel hop per chunk (microseconds).
(c) pkg/spec split into types, load and internal/policy/compile, with a one-release deprecation shim for moved public symbols: after ADR 0028 S1.
(d) the go list -deps allowlist test and the depguard rules in CI.
(e) ARCHITECTURE §16 and REPO-LAYOUT updated to the checked list.
Docs: ADR 0031; ADR 0014 Open closed; ARCHITECTURE §16; REPO-LAYOUT; VERSIONING (the deprecation).

*Amended 2026-10-05 (ADR 0023's acceptance note, A6):* (a) does not wait on ADR 0023. Moving `enforce/api` and
launch's imports needs the interface in its new place, not its method types final: ADR 0023 C5 edits
`enforce/api.Handle`'s descriptor methods in place after (a) lands, and no importer
changes an import line for ADR 0023.

*Implementation note 2026-10-19, (a) built:* `Handle`, `Armer`, `Listener` and `ListenerWaiter` live in
the leaf `internal/runtime/enforce/api` (imports `context` and `x/net/bpf`); every importer names them there and
`enforce` keeps no alias. The richer optional extensions (`KernelRecorder`, `NetRefresher`, ...) stay in `enforce`:
they name `pkg/spec` types and only the engine asserts them. launch also stopped importing `internal/runtime/cgroup`,
whose `agent` and `config` imports reached yaml.v3: the cgroup.kill escalation `launch.CgroupKiller` is now
`cgroup.Killer`, and launch keeps its `Killer` interface. Measured with `go list -deps` (linux/amd64): launch fell from
205 packages (47 outside the standard library: cilium/ebpf, every backend, internal/bpf, yaml.v3) to 119 (8:
enforce/api, deputy, platform/{proc,sys}, spec/identity, x/net/bpf, x/sys/unix, launch). The plan's "< 80" target
counted the standard library and is missed (TARGET-MISS 119); it stays open, owned by the TCB check, which closes this
ADR and turns these counts into a check. What remains above it is standard library, reached two ways.
`pkg/spec/identity` links 97 packages because runid.go imports crypto/sha256 (`HostID`, about 30 packages, the FIPS
module) and regexp (the run and agent id patterns), and launch links identity twice: directly, for the exit codes,
end reasons and signal rules of exit.go (which imports only syscall), and through `internal/platform/proc`, which
names `identity.ExecID`, `NewExecID` and `RunID` from runid.go. The ChildSpec frame's encoding/json adds 12.
Measured: with an identity that linked neither crypto/sha256 nor regexp, launch would link 89; with the JSON frame
also gone, 77. Neither step needs a public-API break or an external format change. Identity's exit and id types can
move to standard-library-only leaves that identity re-exports by alias, which amends identity-config.md I1 and
identity's own standard-library-only import test (both forbid identity importing another `pkg/spec` package); or
`HostID` and the two patterns can leave runid.go. The frame is private between the launcher and its own child stage,
which run one binary, so a hand-written encoding needs runtime-launch.md case 17's amendment and a fuzzed
round-trip, not a compatibility story. Each changes a spec invariant or the decoder the child stage runs before
Landlock and seccomp, not an import line, so neither is part of (a)'s mechanical move. `TestLaunchLinksNoBackend` holds launch's non-standard closure to that allowlist on amd64 and
arm64, with and without tegobpf; the depguard rule `launch-links-no-backend` refuses the direct imports.

*Implementation note 2026-10-19, (b) step 1 built:* the run's Source contract is the
leaf `internal/runtime/source` (imports `pkg/spec/{agent,record}` only, depguard `source-is-a-leaf`): `Source`, `Sink`,
`RunRef`, `Gap`, `ProcessHook`, `ProcessStream`, `KernelFollower`, `LoopbackSource`, `MeteredSink`, `AbandonSink`,
`ReportUnmetered`, `ReportAbandoned`, `UnavailableCause` and `NewPair` with its process-wide counter. internal/runtime
imports them and keeps no alias. The plan named seven of these; the rest moved with them because uprobe or the
forwarder needs them and they are the same contract (`LoopbackSource` embeds `Source`, `ProcessStream` takes a
`ProcessHook`). No capture package imports internal/runtime any more (depguard `capture-links-no-engine` and
`capture-asks-through-forwarder` for direct imports; `TestCaptureLinksNoEngine` for the whole closure of every
package under capture/, on amd64 and arm64, with and without tegobpf, the forwarder's link to the approval broker
`ask` being the one named exception; `TestSourceLinksNoInternal` for the leaf's closure). Measured (linux/amd64, `go list -deps`):
capture/uprobe 297 → 277 packages (72 → 53 outside the standard library), the forwarder 297 → 241 (72 → 33), capture
284 → 136; none links internal/runtime, launch, the supervisor, enforce/* or dnsbroker (9 of them before).
internal/runtime/observe still imports internal/runtime (its gap names and `DecisionPlaneNamer`); the recorder is
not a step-1 target.
