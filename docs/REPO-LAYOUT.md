# Repository layout

One Go module, three binaries, one monorepo: `tego`, the engine; `tego-control`, the one-person dashboard; and `maze`, the setup tool in `cmd/maze` and `internal/maze`, which builds for macOS and Linux and reaches the engine only through the `tego` command. The tree mirrors the four layers of `docs/FEATURES.md`, and the import direction is enforced by `golangci-lint` (see `.golangci.yml`).

```
tego/
├── cmd/tego/                 the engine's binary; main.go dispatches internal helpers before internal/cli
├── cmd/maze/                 the setup tool's binary (macOS and Linux); main.go runs internal/maze/cli
├── cmd/tego-control/         the dashboard's binary; main.go runs internal/control/cli
├── pkg/spec/                  Layer 0 in Go: public types and codecs, independent of internal/ (agent, record, identity, backend, config, presets: the built-in presets)
├── pkg/policy/evaluate/       experimental, version-pinned public facade over the decision core
├── pkg/policy/httppolicy/     immutable HTTP method/path matcher; standard library only, no I/O
├── pkg/policy/execmatch/      the exec command matcher and its per-tool rows (ADR 0048); standard library only, no I/O
├── pkg/policy/socketpolicy/   ADR 0018's socket allowlist, the one Go spelling decide and internal/bpf share; standard library only, no I/O
├── pkg/policy/thishost/       which destinations are this host, however spelled: the one reading the gate, the models guard and live blocks share; standard library only, no I/O
├── spec/                      Layer 0 as published standards: JSON Schemas, docs, fixtures (agent, record, identity, reason, backend, policy, config)
├── bpf/                       kernel-side C programs (CO-RE), headers, map-logic tests; the C dual GPL-2.0-only/BSD-2-Clause (ADR 0012), the Go tests Apache-2.0
├── internal/
│   ├── maze/                  the setup tool: scan (what the machine and project hold), scope (the rules, the contract and verdicts it writes, the pre-push check), ui, cli
│   ├── policy/
│   │   └── decide/            the decision core: every tier's verdict model, pure (ADR 0028)
│   ├── runtime/               Layer 1, the engine
│   │   ├── launch/            child stage + exec under the prepared handle, uid drop, signals, exit code; links no backend
│   │   ├── cgroup/            cgroup v2 fs ops, limits, kill
│   │   ├── enforce/           Backend interface + selection
│   │   │   ├── api/           Handle, Armer, Listener, ListenerWaiter: what launch and the facade consume (ADR 0031 (a))
│   │   │   ├── landlock/      tier 1, no root
│   │   │   ├── cgroup/        tier 2, root without a boot change (cgroup socket programs + fanotify)
│   │   │   ├── bpflsm/        tier 3
│   │   │   └── observe/       record-only mode (learn, CI): tier 1's filter, supervisor record-only (supervisor.md R30)
│   │   ├── supervisor/        seccomp user-notification loop: connect decisions, record (P0)
│   │   ├── ask/               human approval on top of the supervisor: ADDFD, hold modes (P1)
│   │   ├── observe/           kernel record: tracing programs, ring buffer, process cache
│   │   ├── source/            the run's Source contract (Source, Sink, RunRef, Gap, process hooks): a leaf, ADR 0031 (b)
│   │   ├── capture/           model traffic
│   │   │   ├── uprobe/        OpenSSL uprobes
│   │   │   ├── httpstream/    HTTP/1.1 reassembly, gzip, brotli, SSE
│   │   │   └── forwarder/     localhost forwarder for bundled-TLS agents
│   │   ├── derive/            bytes → decisions, steps, threads
│   │   │   ├── anthropic/     Messages API
│   │   │   └── mcp/           JSON-RPC over stdio and HTTP
│   │   ├── limits/            token, cost, wall, stall, repeat budgets → stop
│   ├── ledger/                shared: append-only writer, hash chain, blobs, redaction, reader, gc
│   ├── bpf/                   bpf2go-generated bindings (go generate)
│   ├── platform/              Linux helpers: proc, dns, sys
│   ├── testutil/              test-only leak/real-account guards; never in the binary
│   │   ├── contracttest/      on-disk contracts compiled over private trees; explicit synthetic-fixture inventory
│   │   ├── ledgertest/        typed validated event fixtures and payload decoding; no invented hash chain
│   │   └── jsonschema/        the real JSON Schema validator, for tests; its module is never in a binary (TestValidatorNotInBinary)
│   ├── check/                 Layer 2, the read side
│   │   ├── status/  drift/  measure/  learn/  events/
│   │   ├── receipt/           the run receipt: one streaming builder for tego receipt, tego run's end summary and the dashboard's Receipt tab
│   │   ├── secretpath/        the name-based secret classifier (secretpath.Is): pure, stdlib only; the receipt and ledgerview share it
│   │   ├── syslookup/         the routine system lookup classifier (nscd, userdb, D-Bus, the run's resolvers): pure, stdlib only; the receipt and ledgerview share it
│   ├── control/               Layer 2, the dashboard: its command line, pages, and the views and actions behind them
│   ├── doctor/                machine checks in plain sentences
│   ├── registry/              an agent's name to its contract file: project registry, then user registry (agent-contract.md R26)
│   ├── adapters/              Layer 3, Go-side harness glue (claudecode, openaicodex)
│   │   └── claudecode/        `tego hook claude-code`: new refusals to Claude Code hook output, once each (ADR 0063); stdlib, x/sys/unix, pkg/spec/reason and pkg/spec/harness only (depguard claudecode-imports)
│   └── cli/               one file per subcommand (init, doctor, compile, run, stop, status, ask, approve, deny, dns, drift, measure, learn, events, watch, adopt, agents, alternate, gc, licenses, version, hidden __child; guard.go and verify.go back `agents --follow --adopt` and `events --verify`)
├── test/                      fixtures, workloads, integration (root), e2e kill tests, VM matrix
├── examples/                  contracts per common agent, quickstart; demo/ is the live demo kit (README.md, demo.sh, a rogue stand-in agent and its contracts)
├── docs/                      start at docs/README.md: engine docs, p0/, adr/, user/ (the user guide; its README states what the root tiers and adopt need, and fixes the label for what is not built yet)
├── tools/  scripts/           dev tooling; operator scripts
├── .github/                   CI, CODEOWNERS
├── go.mod  Makefile  .golangci.yml  .gitignore  README  CONTRIBUTING  SECURITY  LICENSE (Apache-2.0)
├── NOTICE  THIRD_PARTY_NOTICES.txt  LICENSES/   licensing notices, linked dependencies' notices, the GPL/BSD/LGPL texts
├── notices.go                 package tego, the module root: embeds those files for `tego licenses` and `tego-control licenses`
```

Packages added since 2026-09-22 and not drawn above: `internal/watch/` (watcher, adopt, tree, procconn, sig: watching and adopting any agent, ADRs 0054 and 0055), `internal/runtime/deputy/` (the run's open deputy, ADR 0041), `internal/runtime/dnsbroker/` (opt-in DNS transport for cooperating clients), `internal/runtime/hoststate/` (the root tiers' `/run/tego`, ADR 0034), `internal/realtego/` (the `~/.tego` directories a process could reach), `internal/selftest/` (`tego test`, Layer 2: starts the tego binary and reads its ledger, ADR 0074), `internal/check/gaps/` and `internal/check/resources/`, `internal/platform/hostaddr/` and `internal/platform/startphase/`, and `pkg/policy/gate/`, `pkg/policy/dnspolicy/`, `pkg/policy/fsplan/`.

The tree includes reserved packages for later phases (`internal/adapters/openaicodex` is one); a reserved package's presence does not mean its feature is implemented, and additional provider parsers are roadmap entries. `learn` is built (2026-10-06): `tego learn` proposes a contract from a run's ledger (docs/OPERATIONS.md). Current capability and Tier 3 status are in `spec/backend/CAPABILITIES.md` and `docs/p0/TIER3-PLAN.md`.

## Import direction

```
cmd/tego
   ├── internal helper entry points (child, reaper, linger, ring trim, uprobe detach, doctor probe)
   └── internal/cli
          ├── internal/runtime ──► internal/policy/decide, internal/ledger, internal/bpf, internal/platform, pkg/spec
          ├── internal/check   ──► internal/ledger, pkg/spec
          ├── internal/doctor  ──► internal/platform, internal/runtime/enforce
          ├── internal/registry──► pkg/spec
          └── internal/adapters──► pkg/spec (the reason file through pkg/spec/reason), golang.org/x/sys/unix and the standard library only
                                 (never the engine, the ledger, the read side, the CLI or BPF: depguard adapters-never-import-engine)
                                 internal/cli connects adapters.For (the provisioner registry) to internal/runtime's
                                 Provisioner (Deps.Harness, ADR 0062); the interface lives in the engine, its types in pkg/spec/harness
cmd/tego ──► internal/adapters/claudecode for the hidden `hook` verb, dispatched before internal/cli (no machine config, no ledger)
pkg/spec/harness ──► standard library only (depguard harness-spec-is-leaf): the harness: key, harness.Run, harness.Provision
pkg/spec/presets ──► standard library only, embed among it (depguard presets-are-data): the presets' YAML and a Source shaped
                     as agent.ProfileSource, registered by one line in internal/cli profileSources (ADR 0068)
internal/setup ──► pkg/spec/presets, pkg/spec/agent, pkg/spec/config and the standard library (never the engine: depguard
                   setup-never-imports-engine): composes and compiles offline the agent.yaml `tego init --preset` writes
                   (Draft, Create, Check: the API a dashboard page can call too); internal/cli init.go parses the flags,
                   passes the machine to check against, prints and writes it
pkg/spec ──► standard library (and yaml.v3 in pkg/spec/agent and pkg/spec/config); pkg/spec/agent also uses pkg/policy/httppolicy, pkg/policy/gate, pkg/policy/execmatch and pkg/policy/thishost
pkg/spec/reason ──► standard library and pkg/spec/record only (the reason file v1, ADR 0061; depguard reason-spec-is-leaf); written by internal/ledger, read by internal/adapters
pkg/policy/httppolicy ──► standard library only
pkg/policy/execmatch ──► standard library only (depguard execmatch-is-pure)
pkg/policy/socketpolicy ──► standard library only (depguard socketpolicy-is-pure); imported by internal/policy/decide and internal/bpf
pkg/policy/thishost ──► standard library only (depguard thishost-is-pure); imported by pkg/policy/gate, pkg/spec/agent and internal/liveblock
pkg/policy/gate ──► standard library and pkg/policy/execmatch
pkg/policy/evaluate ──► internal/policy/decide, pkg/spec
internal/policy/decide ──► pkg/spec, pkg/policy/socketpolicy and the standard library's pure packages only
internal/bpf ──► github.com/cilium/ebpf, pkg/policy/socketpolicy and the standard library (internal/bpf/doc.go)
internal/runtime/launch ──► internal/runtime/enforce/api, internal/runtime/deputy, internal/platform/{proc,sys}, pkg/spec/identity only
                            (no backend, no cilium/ebpf, no YAML: depguard launch-links-no-backend, TestLaunchLinksNoBackend)
internal/runtime/capture/** ──► internal/runtime/source for the run, never internal/runtime, launch, the supervisor,
                            enforce, the DNS broker, the recorder, limits or the deputy; only the forwarder links ask
                            (depguard capture-links-no-engine and capture-asks-through-forwarder, TestCaptureLinksNoEngine)
internal/runtime/source ──► pkg/spec/{agent,record} and the standard library only (depguard source-is-a-leaf,
                            TestSourceLinksNoInternal)
cmd/maze ──► internal/maze/cli ──► internal/maze/{scan,scope,ui}, internal/platform/proc, pkg/spec/identity
                            (never internal/runtime, internal/ledger, internal/cli, pkg/spec/agent or pkg/spec/config:
                            depguard maze-stays-outside-the-engine; the engine is run as the tego command)
the module root (notices.go, package tego) ──► embed and the standard library only: the licence files both binaries
                            carry (docs/GAPS.md B12); internal/cli and internal/control/cli print them (`licenses`)
```

- `pkg/spec` never imports `internal`; it provides the versioned public types and codecs corresponding to `spec/`. `pkg/policy/evaluate` is a separate experimental public facade over the pure decision core. External callers must pin its module version to the binary whose kernel policy they model. The decision core also registers the deprecated `pkg/spec/agent` evaluation shims (`agent.RegisterDecider`, ADR 0028); this compatibility registration is not the supported extension mechanism.
- `internal/policy/decide` is pure: no I/O, no goroutines, no clock (depguard `decide-is-pure`).
- The engine (`internal/runtime`) never imports the read side (`internal/check`); the read side never imports the engine. They meet only through the ledger and the spec types.
- `internal/ledger` is shared infrastructure, owned by neither side. It imports `pkg/spec` and, for its descriptors (ADR 0023), `internal/platform/sys`. It holds the one follower of a live run (`Follow`, `WatchLive`, record-ledger.md §4) that `tego events --follow` reads and later services are to read.
- The layer rules for the packages added since (`reason-spec-is-leaf`, `harness-spec-is-leaf`, `receipt-spec-is-a-leaf`, `adapters-never-import-engine`, `claudecode-imports`, `receipt-reads-the-ledger-only`, `setup-never-imports-engine`, `selftest-never-imports-runtime`, `tools-are-stdlib`) are all in `.golangci.yml`, and are inert until their directory exists. TestEveryLayeredDirHasARule (tools/rulecheck) fails when a directory under `internal/adapters/*`, `internal/check/*`, `internal/setup`, `internal/selftest`, `pkg/spec/*` or one of the three V1 launch tools is governed by no depguard rule, so a package is under its layer's rule the day it appears. Each package that adds a directory adds its own row to the tree above.
- Backends (`enforce/landlock`, `enforce/bpflsm`, `enforce/observe`) never import each other.
- Provider parsers (`derive/anthropic`, `derive/mcp`) never import each other.

## The dashboard's packages

`cmd/tego-control` is the dashboard's binary, in the same module ([ADR 0100](adr/0100-second-binary-and-handoff.md)). Its packages
are services above the core: clients of the engine through the ledger and the ask broker, never a second enforcement
path. `tego` reaches it only through `internal/handoff`, which runs a sealed copy whose hash the `tego` build pinned.

Each row's import rule is a depguard rule in `.golangci.yml`, named in the last column: a row that says "only" is a
strict allow list, and one that says what a package never reaches is a deny list of those layers. A package whose
imports must differ changes its row, its rule and its ADR in one change. A sub-package, or a non-Go directory
(`templates/`, `static/`, `testdata/`), beneath a row's package takes that row's layer and import rule unless a row of
its own says otherwise.

| Package | Layer | What it is and what it may import | Depguard rule |
|---|---|---|---|
| `cmd/tego-control` | entry point | `internal/control/cli` and x/sys; refuses euid 0 and any capability in every command | `control-links-no-engine` |
| `internal/control` (its own directory) | test only | the link gates of both binaries and the engine's committed module list (`testdata/engine-modules.txt`) | none |
| `internal/control/cli` | 2 | `tego-control`'s command line, one file per noun registering its command: `internal/handoff` (the noun list), `internal/buildinfo`, `internal/control/web`, `internal/control/rules`, `internal/profilesrc`, `internal/platform/proc`, `internal/platform/sys`, `pkg/spec/*`; never the engine | `control-links-no-engine` |
| `internal/control/web` | 2 | the dashboard's pages, templates and static files. It opens no socket and imports neither `internal/ledger` nor `internal/check`: it reads through `internal/control/ledgerview` and `internal/control/rulesview`, and acts through `internal/control/runact`, `internal/control/rules`, `internal/control/mcpact` and `internal/control/routeact`; never the engine | `control-links-no-engine`, `edge-holds-no-authority` |
| `internal/control/web/e2e` | test only | the dashboard's journeys; imported by no non-test package | `control-links-no-engine` |
| `internal/control/ledgerview`, `internal/control/rulesview`, `internal/control/linewords` | 2 | the read models and the glossary behind the pages: `internal/ledger`, `internal/check/*`, `pkg/spec/*`; never the engine | `control-links-no-engine` |
| `internal/control/runact`, `internal/control/rules`, `internal/control/mcpact`, `internal/control/routeact` | 2 | what the dashboard does to a live run and its rules, through the code the CLI uses: `internal/askclient`, `internal/runlock`, `internal/ledger`, `internal/liveblock`, `internal/rulefile`; never the engine | `control-links-no-engine` |
| `internal/handoff` | shared leaf | standard library, x/sys, `internal/platform/sys` (descriptor owners), `internal/platform/proc` (Spawn's one start) and `pkg/spec/identity` only: Open, Exec, Spawn of the sealed memfd, the reason codes and the noun list; linked into both binaries | `handoff-imports` |
| `internal/buildinfo` | shared leaf | standard library only: the version, commit and date both binaries print, from one set of ldflags | `buildinfo-is-stdlib` |
| `pkg/spec/askproto` | 0 | standard library only: the ask wire format (frames, codes, sentinel errors, limits, strict decoders) | `askproto-is-stdlib` |
| `internal/runlock` | 1 | `internal/ledger` (the lock file and its regular-file openers), `internal/platform`, x/sys; never `internal/runtime` | `run-clients-never-import-runtime` |
| `internal/askclient` | 1 | `pkg/spec/askproto`, `internal/runlock`, `internal/ledger` (`LedgerTarget`'s redaction), x/sys; never `internal/runtime` | `run-clients-never-import-runtime` |
| `internal/runscope` | 1 | standard library and `pkg/spec/identity` only: the one run-membership rule (`GovernedBy`, `LooksGoverned`, `InRun`, the strict cgroup reader `Unified`) | `runscope-is-a-leaf` |
| `internal/platform/peer` | 1 | `internal/runscope`, `internal/platform/sys` (the pidfd owners), `internal/platform/proc` (the stat parser), `pkg/spec/identity` and x/sys only: the one peer check every socket uses | `platform-peer-imports` |
| `internal/check/inforce` | 2 | `internal/check/livestatus`, `pkg/policy/gate`, `pkg/spec/agent`, `pkg/spec/backend`, `pkg/spec/record`, yaml.v3; pure (no `os`, no clock), never `internal/control` or `internal/liveblock` | `inforce-is-pure`, `linked-into-control-never-imports-engine` |

Two forbidigo rules go with the table: no product file names a trusted `html/template` type (`HTML`, `HTMLAttr`, `JS`,
`JSStr`, `URL`, `CSS`, `Srcset`), and no file of `internal/control/web` dials, listens, looks a name up, lists the
interfaces or makes a socket, by call, method or syscall number. Its depguard rule also denies the packages that dial or
listen inside their own calls, and `scripts/check-edgelint_test.sh` lints a fixture of each. The two link gates in
`internal/control/linkgate_test.go` hold the split as a whole:

- `cmd/tego` links no `internal/control/**`, and its module set is a committed list (`TestEngineLinksNoControl`,
  `TestEngineModuleSetUnchanged`).
- `cmd/tego-control` links no `internal/runtime/**`, `internal/policy/**`, `internal/bpf/**`, `internal/cli`,
  `internal/doctor`, cilium/ebpf or go-landlock (`TestControlLinksNoEngine`).

Commands register per noun file: in `internal/cli` and `internal/control/cli` no file edits another noun's registration,
and a noun never spans both binaries (ADR 0100 (2)).

## Where does X live

| I am looking for… | Go to |
|---|---|
| the shape of `agent.yaml` | `spec/agent/v0/` (schema) and `pkg/spec/agent` (types, validation, compile) |
| the shape of an event | `spec/record/v1/` and `pkg/spec/record` |
| the built-in presets (`tego/no-secrets`, `tego/no-prod`, `tego/repo-only-writes`), their revisions and the host groups | `pkg/spec/presets` (the YAML, `README.md` is normative), registered in `internal/cli/profiles.go`; the user's page `docs/user/presets.md` (ADR 0068) |
| `tego init --preset`: a contract from presets, folders, markers and host groups | `internal/setup` (compose.go, ecosystem.go, check.go: Draft/Create/Check; goldens in testdata/compose/), flags and printing in `internal/cli/init.go`; `docs/user/presets.md` "Start from tego init" |
| env vars a run sets | `pkg/spec/identity` |
| what a run provisions for its agent harness (`harness:`, the per-run settings files, hook-state) | `internal/runtime/harness.go` (the point), `pkg/spec/harness` (its types), `internal/adapters` (the provisioners) |
| what a backend can do | `pkg/spec/backend` and `internal/runtime/enforce` |
| the kernel programs | `bpf/` (C), bindings in `internal/bpf` |
| how a run starts | `internal/runtime/launch` |
| why something was refused | events with `verdict=refused`; the reason file and its wording, `pkg/spec/reason` (`spec/reason/`; *amended 2026-10-24*: the `internal/runtime/reason` placeholder is removed, ADR 0061) |
| what verdict a tier gives an action (`compile --test`, the advisory and inferred verdicts) | `internal/policy/decide`; external Go callers use the experimental `pkg/policy/evaluate` facade |
| how a pause for approval works | `internal/runtime/supervisor` (the loop), `internal/runtime/ask` (approvals, P1) |
| how model calls are captured | `internal/runtime/capture/*` |
| how a decision or step is derived | `internal/runtime/derive/*` |
| how the ledger is written or read | `internal/ledger` |
| status, drift, measure, learn | `internal/check/*` |
| a subcommand | `internal/cli/<name>.go` |
| a sample agent to test with | `test/workloads/` |
| a hand-checked ledger to build a view against | `spec/record/v1/fixtures/` and `test/fixtures/ledger/` |
| a decision and why | `docs/adr/` |
| the machine config | `spec/config/v0/` and `pkg/spec/config` |
| versioning, releases, licence | `docs/VERSIONING.md`, ADR 0012 |
| what to build first and in what order | `docs/P0-DESIGN.md` (the P0 base, frozen 2026-09-22) |

## Naming and conventions

- Domain nouns, used everywhere with the same meaning: **Contract** (the agent file), **Rule**, **Run**, **Thread**, **Step**, **Decision**, **Event**, **Verdict** (allow, ask, refused, observed), **Authority** (rule, gate, human), **Source** (kernel, ssl, supervisor, hook), **Backend**, **Capability**, **Gap**.
- Packages are short lowercase nouns, one concept each; no `util`, `common`, `helpers`, `models`. Types live in the package that owns the concept; the pure types that everyone shares live in `pkg/spec`.
- Interfaces are declared where they are consumed (`enforce.Backend` in `enforce`, `api.Handle` in `enforce/api`, `source.Source` in `runtime/source`), kept small.
- Packages document their purpose and boundaries in package comments, usually in `doc.go`. CI enforces the import restrictions configured in `.golangci.yml`.
- Subcommands live in `internal/cli`. The CLI owns flags, configuration discovery and trust checks, component wiring, and output; policy decisions and runtime lifecycles belong to their owning packages.
- Errors: sentinel `var ErrX` per package, wrapped with `%w`; refusal reasons are `record.Reason` values, never free strings. User-facing messages are one line in `file:line[:col]: message [code]` form; `compile` codes are `agent.Diagnostic`, refusal codes are `record.Reason`, never mixed.
- Every source file carries an SPDX header: `Apache-2.0` everywhere, `(GPL-2.0-only OR BSD-2-Clause)` on the C under `bpf/` (its Go tests are `Apache-2.0`); `vmlinux.h` and bpf2go output are exempt.
- Anything privileged (`launch`, `ask`, `bpflsm`, `observe`, `capture/uprobe`) is the trusted computing base: no third-party dependency beyond cilium/ebpf, x/sys, x/net, go-landlock.
- Tests: unit tests next to the code; `//go:build integration` for root; kill tests under `test/e2e`.

## Growth path (how this stays a monorepo)

- Today: one module, three binaries. New capability = new package under the layer it belongs to.
- Another binary: add it under `cmd/`; it reuses `internal/` packages; still one module. (*Amended 2026-10-24, [ADR 0100](adr/0100-second-binary-and-handoff.md):* the second binary is `cmd/tego-control`, the dashboard, reached from `tego` only through a sealed hash-pinned handoff; see "The dashboard's packages" above.) (*Amended 2026-10-05, ADR 0042 (7)(a):* tegod is `tego __tegod` in the one binary, not `cmd/tegod`.)
- A component with an incompatible dependency set or release cadence (a Python or TypeScript adapter package): give it its own directory and its own module, and add a `go.work` at the root. Split only when this pressure is real.
- A Rust reimplementation of the low-level runtime: `runtime-rs/` at the root, conformant to `spec/`, tested by `test/e2e`; `cmd/tego` can exec it behind the same `enforce.Backend` interface.

## If you think in models, repositories, services and middleware

Tego is not a web backend and not microservices: one run is one process, because the seccomp supervisor must be the
launcher, BPF programs are attached by one privileged process, and a syscall verdict cannot wait on a network hop.
It is a modular monolith: packages have explicit boundaries, and runtime producers feed typed events into the
ledger. The localhost forwarder is a transport boundary for agent model traffic. The familiar concepts live here:

| Backend concept | In Tego | Where |
|---|---|---|
| Models / entities / DTOs | the spec types: Contract, Rule, Event, Run, Step, Decision, Verdict | `pkg/spec/*` (public, independent of the engine); JSON Schemas in `spec/` |
| Repository / data access | the ledger writer and reader; the only store | `internal/ledger` |
| Query / read models | status, drift, measure, learn, events, each deriving its view from the ledger | `internal/check/*` |
| Services (domain logic) | the engine subsystems, with consumer interfaces and concrete lifecycle owners: `enforce.Backend`, `source.Source`, `supervisor.Loop`, `derive.Parser`, `limits.Watcher` | `internal/runtime/*` |
| Service implementations / strategies | backends and provider parsers, selected at run time by capability | `internal/runtime/enforce/{landlock,bpflsm,observe}`, `internal/runtime/derive/{anthropic,mcp}` |
| Middleware / pipeline | event stages between producers and the ledger: cgroup filter, rule and verdict stamping, step and thread attribution, redaction, blob split. Ledger transforms compose as `Stage func(next Sink) Sink` | `internal/runtime` (pipeline wiring) and `internal/ledger` (redaction, blobs) |
| HTTP middleware | the forwarder's request chain: capture, header allow-list, upstream | `internal/runtime/capture/forwarder` |
| Controllers / handlers | CLI subcommands; parse input, wire components, invoke the owning package, render | `internal/cli/*.go` |
| Application service / facade / use case | `runtime.Run(ctx, rt, cmd, deps)`; the read side has no single entry, each `internal/check/*` package exports its own function | `internal/runtime/run.go`, `internal/check/*` |
| Dependency injection / wiring | constructors with explicit parameters and `runtime.Deps`, assembled at the CLI/runtime boundary; deprecated evaluator registration is a compatibility exception | `internal/runtime/run.go`, `internal/cli/main.go` |
| Background workers | goroutines owned by the run: record/capture sources implement `source.Source`; the supervisor and limits watcher have separate run-owned lifecycles. Cancellation, joins and bounded teardown live in the owning lifecycle | `internal/runtime/*` |
| Adapters / clients to external systems | harness glue and hook payloads | `internal/adapters/*` |
| Config | the agent contract (per run) and the machine config (spec/config/v0) | `pkg/spec/agent`, `pkg/spec/config`, `internal/cli/config.go` (layer discovery, trust checks, SUDO_UID/AT_SECURE) |
| Infrastructure / platform | Linux helpers: proc, dns, syscalls, cgroups | `internal/platform/*`, `internal/runtime/cgroup` |
| API contract between services | the spec files and the event schema, versioned | `spec/`, `pkg/spec` |
| Multiple services (processes) | `tego`, `tego-control` and `maze` today (tegod, not built, would be `tego __tegod`, ADR 0042); each reuses `internal/` and reads the same ledger format; own module + `go.work` only if its dependencies diverge | `cmd/*`, root `go.work` when needed |

The interface pattern used everywhere:

```go
// internal/runtime/enforce/backend.go — declared where it is consumed
type Backend interface {
    Tier() backend.Tier
    Capabilities() backend.Set
    Prepare(ctx context.Context, rt *agent.RuleTable, run RunRef) (Handle, error)
}

// internal/runtime/enforce/landlock/landlock.go — one implementation per package
func New(opts Options) *Backend { ... }

// internal/runtime/run.go — explicit dependencies supplied by the caller
func Run(ctx context.Context, rt *agent.RuleTable, cmd []string, deps Deps) (Result, error)
```

The pipeline pattern for middleware:

```go
type Sink  func(*record.Event) error
type Stage func(next Sink) Sink
// Ledger transforms wrap the writer: redact(splitBlobs(writer.Append)).
```
