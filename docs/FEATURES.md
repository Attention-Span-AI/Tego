# Tego feature map

> The engine's features by id, each with whether it is built in this tree. **Built** means the code is here and tested.
> **Partly** means the Notes say which half. A feature id cited elsewhere with no row here has no code in this tree, and
> a contract key for one is refused. For what is enforced today, read `spec/backend/CAPABILITIES.md` and [GAPS](GAPS.md).

**No model inside Tego.** Every feature in this map is deterministic over the ledger and the contract. Learn mode (C9), the
loop detector (E37) and drift (C4) are rule-based, not model-based.

---

## 0. The core

Everything below stands on three things. If these three are right, every feature on top is a
read-side or an adapter. If they are wrong, nothing on top survives.

```
 ┌──────────────────────────────────────────────────────────────────┐
 │  Layer 3  Ecosystem: harness adapters, containers, CI, imports    │
 ├──────────────────────────────────────────────────────────────────┤
 │  Layer 2  Check & product: status, drift, measure, learn, serve   │
 ├──────────────────────────────────────────────────────────────────┤
 │  Layer 1  Engine: launcher · enforce backends · ask · kernel      │
 │           record · TLS capture · derivation · ledger · limits     │
 ├──────────────────────────────────────────────────────────────────┤
 │  Layer 0  Standards: agent contract · run record · run identity   │
 │           · reason channel · backend interface · conformance      │
 └──────────────────────────────────────────────────────────────────┘
```

The core, in one sentence each:

1. **The agent contract** (agent.yaml): what a process may write, connect to, execute and spend. Docker's Dockerfile.
2. **The engine** (`tego run`): executes any Linux process unchanged under that contract, with a pluggable enforcement backend. Docker's runtime, with the isolation tech swappable underneath.
3. **The run record** (events.jsonl): every kernel action attributed to the model decision that caused it. Docker's logs, but with a decision id on every line.

---

## Layer 0 — Standards (versioned schemas)

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| S1 | **Agent contract schema v0** (`agent.yaml`): `version`, `name`, `extends`, `command`, `fs.write/ask/deny_read/watch/deny_write` (`fs.deny_write`, ADR 0071, since 2026-10-25: blocked for ordinary commands; not race-free at the no-root tier), `net.allow/ask/http/assurance`, `docker{allow,ask,binds}`, `exec.allow/deny/ask/privileged`, `env.pass/deny/mask/set`, `mcp[]`, `models[]`, `limits{…}`, `record`, `tier`, `capture`, `containers`, `io_uring`, `gate`, `prompt`, `skills`, `visibility` | Built | Unknown fields are errors (`KnownFields`). A field a build does not implement is refused at compile. |
| S2 | **Run record schema v1** (`events.jsonl`): kinds `run_start run_end exec fs net mcp ssl_request ssl_response decision ask answer refused gap`; fields `v seq id prev ts mono_ns run thread step pid tid cgroup source authority rule verdict` | Built | Every fs/net/exec event carries `rule` and `verdict`; answers carry `ask_id`, `by`, `after_s`. *2026-10-25 (ADR 0073, record_minor 17):* `run_start` records `launcher_uid` (always), `launcher_user`, `sudo_uid`/`sudo_user`, `host`, `parent_run`, `labels`, `role` and `contract_revision`. |
| S3 | **Run identity contract**: `TEGO_RUN_ID`, `TEGO_AGENT`, `TEGO_PARENT_RUN`, `TEGO_LEDGER` env; cgroup path convention; exit code passthrough | Built | *2026-10-25 (ADR 0073):* the launcher identity (`identity.LauncherOf`), labels and role are Layer 0; a Started hook runs after `run_start` and before the agent is released. |
| S4 | **Reason channel contract**: errno always; a reason record in the ledger; optional reason file/socket; harness hook payload shape | Built | Hook adapters in Layer 3 implement it. *Note 2026-10-25 (ADR 0077):* a read Landlock refuses at tier landlock under `record: summary` or `off` has its reason record only with `reason.reads: on` or held reads; spec/reason/REASON-CHANNEL.md §2 lists the refusals still unrecorded. |
| S5 | **Backend interface + capability matrix**: enforce backends (Landlock, BPF LSM, none) and capture backends (uprobe, forwarder, hook) declare what they can do: file deny, net by port, net by host, exec by name, ask, log-allowed | Built | The runtime degrades by matrix, never silently. |
| S6 | **Policy semantics doc**: default when a section is absent, precedence, exec matching by resolved path, argv patterns, path prefix rules, symlink resolution | Built | Half a page; the compiler has nothing to validate without it. |
| S7 | **Conformance suite**: the kill tests as a runnable suite any backend must pass | Built | Lets a future backend (macOS, container) claim compatibility. |
| S8 | **Coverage/gap report format**: per run, what was not captured or not enforced and why (binary, TLS lib, backend) | Built | The honest line that keeps "any agent" true. |
| S11 | **Machine config schema v0** (spec/config/v0): ceilings (tier, capture, limits), settings (ledger_root, retention, stop_grace, resolver, ringbuf, prices, profiles, privileged_binary), layer precedence, file trust rule, exit 125 [config-untrusted] | Built | with E6 and C2. *2026-10-05, ADR 0042 (3)(d), (4):* `privileged_binary` stays parsed, `/etc` only, and is not used in this release (it warns); `users:` is honoured from `/etc` only. |
| S12 | **Versioning and release policy** (docs/VERSIONING.md): `tego version`, `run_start` provenance, ledger `v` readers, contract strictness, goreleaser + install.sh + CHANGELOG, licence split (ADR 0012) | Built | `tego version`, `run_start` provenance, ledger `v` readers. |
| S9 | **Scored gate rules** (`gate.rules` + `thresholds`): a closed set of predicates (`fs.write outside worktree`, `exec matches <pattern>`, `net to undeclared host`, …) each with a score; thresholds map score → allow / ask / deny | Built | Keep, with precedence written in S6: the allow/ask lists decide in-kernel; the gate scores only what the lists route to userspace. Implement as an enum + integer, not a parser. *Note 2026-10-05:* built as [agent-contract R22a](p0/agent-contract.md#5-business-rules) and the [gate contract](p0/gate.md): closed predicates, integer scores 0..100 summed with saturation, inclusive `allow`/`ask` thresholds, run in the supervisor after the ordinary tier decision, which it only preserves or raises (ADR 0007). *Note 2026-10-20 ([ADR 0007](adr/0007-gate-only-escalates.md)):* the bands: below `allow` allow, `allow` to `ask` ask (a score of exactly `allow` asks; `allow` is at least 1), above `ask` refused; the sum, across both fs kinds for a read-write open or a move's source, is the sum, not the highest rule. |
| S13 | **Registry object**: an agent's name resolves to its contract (`tego run retriever`, `tego compile retriever`): the working directory's `agent.yaml` or `.tego/agents/<name>.yaml`, then the user registry (`registry:`, default `~/.config/tego`), a name both hold refused as ambiguous; `skills/<name>/` reserved beside `agents/` | Built | Built 2026-10-20 (agent-contract.md R26): deterministic order, refusals with the fix, run_start's `contract_source`. |
| S14 | **Built-in presets** (`pkg/spec/presets`, ADR 0068): `tego/no-secrets` (an `env.pass` allow-list; the built-in `deny_read` list), `tego/no-prod` (`net.allow: []`), `tego/repo-only-writes` (`fs.write: [/dev/null]`), extended by name and combined in a list, pinned by revision (`@1`), a released revision frozen; host groups for `tego init` | Built | Built 2026-10-25. `tego init --preset` built 2026-10-26, no `--agent` yet. |

---

## Layer 1 — Engine (the runtime)

### 1a. Launcher and lifecycle

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E1 | `tego run <agent> -- <cmd>`: cgroup v2 per run (`CLONE_INTO_CGROUP`), exec unchanged, stdio and exit-code passthrough | Built | Works unprivileged under the user's systemd slice today. Signals are E3. |
| E2 | Privilege model: `sudo` for the launcher, drop to invoking uid before exec | Built | Required as soon as any eBPF loads (`unprivileged_bpf_disabled=2`). A file-capability copy is refused (ADR 0042 (3)). |
| E3 | **Run lifecycle** (ADR 0013): run lock (flock), signal rules, PDEATHSIG after uid drop, subreaper, fail-closed ENOSYS tree, orphan sweep in run/stop/gc, hashed pin dir + build lock, `/proc/self/exe` re-exec; concurrent runs, 100% attribution | Built | Kill test 1. |
| E4 | `tego stop <run>` via `cgroup.kill`; ledger `run_end reason=stopped` | Built | Makes `stalled` actionable. |
| E5 | Nested runs: `parent_run` from inherited env + nested cgroup path | Partly | Cross-process agent trees link; in-process subagents are threads. *2026-10-25 (ADR 0073):* `run_start.parent_run` records the run a `tego run` was started in (the enclosing run's `TEGO_RUN_ID`, else `TEGO_PARENT_RUN`), as the environment's claim; a value that is not a run id is refused; verifying the link stays here. |
| E6 | Run registry (`.tego/runs/`), ledger location policy (project vs `/var/lib/tego`) | Built | |

### 1b. Enforcement backends

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E7 | **Landlock backend** (tier 1): fs by inode from `O_PATH` fds, `deny_read` by sibling enumeration (unenforced under a writable parent), TCP declared ports only with supervisor-completed connects, unix-socket and signal scoping; degrades by ABI | Built | Exec is by inode: binaries, their ELF loader, listed scripts. UDP port rules on ABI 10+, `RESOLVE_UNIX` on ABI 9+. |
| E8 | **BPF LSM backend** (tier 3): the 20-hook set incl. `path_mknod`, `socket_bind/sendmsg`, unix hooks, `ptrace_access_check` (ATTACH only), `bpf`; `bprm_check_security` per binfmt stage (script passes, interpreter decides); per-cgroup maps; deny with reason | Built | Needs `bpf` in the LSM list (Debian 13, Fedora, RHEL, AL2023 have it; Ubuntu needs one boot line). Doctor checks the LSM list and probes every hook in BTF before loading. *Note 2026-09-29 (ADR 0024, accepted; [enforce-plane](p0/enforce-plane.md); step A built at tier 2 and at tier `bpflsm`):* covers the hook set of enforce-plane R3 (steps A to D); the remainder (`ptrace_*`, `bpf`, `socket_*`) is E54's. Tier `bpflsm` is the plane in LSM mode. Built: `file_open`, `bprm_check_security`, `path_rename`, `path_link`, `path_unlink`, `path_rmdir` (T3, `TestPlaneStepAHooksDecide`), the doctor probe (T8), the record (T9) and the run wiring in tier cgroup (T6, `TestPlaneRunEndToEnd`), plus `compile --test`'s `bpflsm` column (T10), and tier `bpflsm` itself (T7, enforce-plane §2.10): `--tier bpflsm` without LSM mode is refused with the GRUB line, and a contract the plane cannot hold is refused at Prepare. Steps B to D are built too (T13 to T15: `deny_write` mutations, `socket_create`, the exec-map hooks, the unix hooks below 6.7). The record fallback (T9b) and the guest suites and kill tests at `bpflsm` (T11) are built too (enforce-plane §2.17, §2.18). Step E is built through T16 (2026-10-04): filesystem notifications are dropped per loaded hook, and exec decisions/outcomes are delegated with a complete live kernel recorder; metadata notifications and supervisor fallback remain. *Note 2026-10-05:* the remainder named above is partly built: `ptrace_access_check` (ATTACH mode) and `ptrace_traceme`, both requiring the peer task in the same run and generation, `bpf` (every command refused inside a run), `key_permission` (optional; refused unless `keyring: true`) and, under `net.listen`, `socket_bind` (Unix names) and `socket_listen` were built on the plane on 2026-10-04 (E54's 2026-10-05 note). `socket_sendmsg` for inet stays on the cgroup programs. |
| E9 | **Observe-only backend**: no enforcement, record only | Built | For CI and for learn mode (C9). |
| E9b | **cgroup tier backend** (tier 2, root, no boot change): `cgroup/connect4,6`, `sendmsg4,6`, `bind4,6`, `connect_unix` (6.7+) for network per cgroup; fanotify `FAN_OPEN_PERM`/`FAN_OPEN_EXEC_PERM` for path-aware open/exec deny with reasons; Landlock inside the run for delete/rename/mkdir; `cgroup_mkdir` tracepoint for descendants | Built | fanotify open deny is a round trip on every open: own benchmark row. *Note 2026-09-29 (ADR 0024, accepted; built at T6):* condition added: where a plane mode (`lsm`, `fmod_ret`) loads and passes the probe, tier 2's fanotify open/exec deny is not used and the plane decides ([enforce-plane](p0/enforce-plane.md) R18, R22; `TestPlaneRunEndToEnd`); fanotify stays as the probe-selected fallback, and runs a table the plane cannot express (over the cap, E13). Nothing above is removed. **Condition (ADR 0021):** the marks are placed after the child stage's `execve` and the launcher starts no process while they exist (`proc.Start`); the two-builds and third-party-listener pairs runs ADR 0021 names are still to be recorded. |
| E10 | Default read-deny list for secrets (`~/.ssh`, `~/.aws`, `~/.netrc`, `.env`, browser profiles) | Built | |
| E11 | DNS: resolve at load, re-resolve on TTL; `HTTPS_PROXY` awareness | Partly | Hosts are re-resolved on TTL. CDN range handling is not built. |
| E12 | Implicit deny entries compiled into every ruleset, even when `fs:` is absent: the run directory, the contract file, `/sys/fs/cgroup`, `/sys/fs/bpf`; the run directory lives outside every declared write dir (`compile` reports `[contradiction]` and exits 1; `run` exits 125) | Built | Landlock cannot deny beneath an allow. Kill test: an agent whose contract declares the worktree cannot append to its own ledger or edit its contract. |
| E12b | Gate evaluator: scores an action against S9 predicates (argv patterns in the supervisor, path/host predicates in-kernel), emits `score` and `rule` on the event, routes to ask or deny by threshold | Built | The runtime half of S9. *Note 2026-10-05:* built in the supervisor, not in the kernel: every predicate, path and host included, is scored on copied syscall facts after the ordinary floor ([gate](p0/gate.md) R1 to R3), and the event carries `score`, `gate_rule` and `gate_outcome` (R5). An ask-range result completes only where gate R4's table supports it; plane parity is separate. |

### 1c. Ask (human in the loop)

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E13a | Seccomp user-notification supervisor, first half: the loop, connect decisions with supervisor-performed connects, datagram address checks, record of write-opens/exec/delete/rename, io_uring and `openat2` refused (`ENOSYS`), arch guard | Built | `internal/runtime/supervisor`. |
| E13 | Seccomp user-notification supervisor, second half: `ask` decisions with `ADDFD`+`SEND` under the target's identity, hold modes, timeouts | Built | Read-opens never leave the kernel; write-opens notify whenever `fs.ask` is non-empty, so kill test 5 is a per-tier measurement, not a given. *Note 2026-10-05 (ADR 0008's 2026-10-04 note):* `fs.ask` write-open approvals complete by `ADDFD`+`SEND` under the original credentials, `net.ask` TCP connects by the authenticated broker, with `ask.hold` and `ask.timeout` ([agent-contract R22](p0/agent-contract.md#5-business-rules)); exec, UDP and Unix approvals refuse explicitly (`spec/backend/CAPABILITIES.md`, ask row). *Note 2026-10-05:* kill test 5, what an untouched ask entry costs in each tier, is measured on every kernel-matrix row by `test/e2e/kt5-ask.sh` (what it measures: "Kill test 5 (R7)" below; the notifications the entry keeps at tiers 2 and 3: [enforce-plane R27](p0/enforce-plane.md#5-business-rules); results: `test/vm/README.md`). *Note 2026-10-19:* UDP approvals complete too: a `net.ask` `udp://` or bare `host:port` entry holds an addressed datagram or a UDP connect, relayed from its copies once approved and granted once per relayed operation at tiers 2 and 3 ([supervisor R13d](p0/supervisor.md#5-business-rules)); exec approvals still refuse. *Note 2026-10-27 ([ADR 0047](adr/0047-fs-ask-mutations-made-on-pinned-names.md)):* unlink, rmdir, mkdir, rename, symlink and link inside an `fs.ask` scope are asked too (hold `mutation`) and, once approved, made by the supervisor as the agent on the directories it pinned; a rename or link across entries is refused `EXDEV`. |
| E15 | Net ask that survives client timeouts (answer connect, hold first write; or NFQUEUE the SYN) | Partly | `ask.hold: first_write` holds the first write (E51). NFQUEUE is not built. |
| E16 | Ask transports: CLI `approve/deny`, local socket, webhook/Slack/desktop notification | Partly | The CLI, the local socket and, at tier landlock, a desktop notice are built (ADR 0122). Webhook notifications are not. |

### 1d. Kernel record

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E17 | eBPF tracepoints/kprobes for exec, exit, open, unlink, rename, connect; process cache; in-kernel cgroup filter; ringbuf | Built | Needs root, not BPF LSM. |
| E18 | Read-event aggregation (collapse startup reads per exec id and nearest rule) | Built | Required by the `summary` default (SEMANTICS §1, §7). ~118 opens before a Python agent does anything. |
| E19 | Per-event `rule` and `verdict` stamping (which declared entry matched) | Built | Drift is not computable without it. |

### 1e. Model-traffic capture

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E20 | OpenSSL uprobes: writes on `SSL_write` and `SSL_write_ex2` when present (3.3+; `SSL_write_ex` tail-calls it) else `SSL_write_ex`, never both; reads as entry+return pairs on `SSL_read` and `SSL_read_ex` (`*readbytes`); per-cgroup filter | Built | CPython 3.10+ uses only the `_ex` calls; Node, libcurl, CPython 3.9 the plain ones. Unit test: one event per call on OpenSSL 3.0 and 3.5. |
| E21 | HTTP/1.1 reassembly: keep-alive, chunked, `gzip`/`deflate`/`br`/`zstd`, SSE streaming; h2, known by its preface, recorded as `gap what=capture why=h2` (ALPN is not read; capture-derive R17) | Built | Cloudflare serves `br` to any client that offers it; httpx2 on Python 3.14 offers `zstd`. Golden test per encoding; `content_encoding` on the event. |
| E22 | **Localhost base-URL forwarder** for bundled-TLS agents (Claude Code, both Agent SDKs, Codex, uv Pythons until E23): one loopback listener per declared model endpoint, plaintext on 127.0.0.1, TLS upstream; `capture: forwarder` sets the per-harness variables (`ANTHROPIC_BASE_URL`, Codex `CODEX_HOME` config, Gemini's three) and adds the port to the compiled allow set; bypass is `refused` by `net.allow`, never silent; `NO_PROXY` appended when a proxy is passed in | Built | The capture path for Claude Code and the Agent SDKs (Bun ELF with static BoringSSL, no `SSL_*` symbols, verified 2.1.267). HTTP/1.1 is the default; explicit proxy policy also supports prior-knowledge downstream HTTP/2, where authenticated request-policy refusals stay within their stream. Peer-identity and shutdown refusals close the connection. Upstream negotiation is separate. |
| E23 | Attach the OpenSSL programs to executables that link OpenSSL statically but keep symbols: uv/python-build-standalone Pythons (local symbols in `.symtab`, verified), official Node (exported); resolve `/proc/<pid>/exe` on exec, attach once per binary path, cache | Built | Same programs at a different path; removes the forwarder for every uv-managed Python. |
| E25 | Capture-gap detection per run (which binary, which TLS lib, why) | Built | Feeds S8. |

### 1f. Derivation (bytes → decisions, steps, threads)

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E26 | Anthropic Messages API parsing: `tool_use` blocks, streaming events, `usage` (input/output/cache), `model`, `stop_reason`, `message.id`, `request-id` header | Built | Everything measure needs is here. |
| E28 | Thread and step derivation **by content** (messages prefix hash, response id, tool_use ids) | Partly | Claude Code runs up to 20 background subagents by default. Supersedes E28a per thread when it ships. 2026-10-20: the tool_use-id half is built (capture-derive R42: tool windows, `method: tool_id`); threads are still keyed by tid or lane, not by a messages prefix hash. |
| E28a | Steps by time (a model request opens a step; everything until the next belongs to it); `attribution.method: time`, `confidence: likely` with one thread, `unattributed` when calls overlap | Built | The basis for C3/C5. |
| E29 | Tool window matching: `tool_use.id` opened by a response, closed by the `tool_result` in a later request | Built | Makes `replanned/retried/aborted` decidable. Built 2026-10-20 (capture-derive R42): the request's last message is read as it is captured, `ssl_request.tool_results`. |
| E30 | Local tool attribution: exec'd children matched to open tool_use by argv/cwd; in-process fs/net by tid; candidate sets when ambiguous | Partly | 2026-10-20: in-process by tid built (capture-derive R42, `method: tid`, and `tool_id` when the thread has one window open); a child process is attributed when the run has one window open; the argv/cwd match among several windows is not built (time decides). |
| E31 | MCP: stdio server start (exec of declared command), HTTP server connect, `tools/call` taken from the model reply | Built | MCP bodies never pass SSL_write; derive from exec/net + the reply. Built 2026-10-19 (capture-derive R41): stdio start from the exec; an HTTPS server's `initialize` and `tools/call` read from its captured exchanges (`derive/mcp`, `mcp/1`); the stdio reader is built and tested on recorded bytes and reads a run's stdio once provisioning (I6d) relays it. A plain `http://` server is not captured. |

### 1g. Ledger writer

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E32 | One `write(2)` per line on `O_APPEND`, `seq`, `prev` hash chain, `ts` + `mono_ns`, readers ignore a torn last line | Built | |
| E33 | Header allow-list; never persist `x-api-key`/`authorization`/cookie, on the loopback leg too; bodies as content-addressed blobs; per-message dedup | Built | Capture never lands without the allow-list. |
| E34 | `tego gc --keep <d>` (default 30 days); orphan sweep | Built | The retention default lives here. |

### 1h. Limits (the resource caps of an agent runtime)

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E35 | cgroup cpu/mem/pids limits per run | Built | Cheap once the cgroup exists. |
| E36 | **Token and cost budget per run**, wall-time limit, `stall_after` → automatic stop | Built | *2026-10-19:* `stall_after` counts what the run does that no line carries: a per-run kernel stamp of allowed work under `record: off` at the root tiers, and of TLS calls that move bytes in every mode (limits R4). |
| E37 | Repeat/loop detector (same tool name+input N times) → alert or stop | Built | |

### 1i. Install and health

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E38a | `tego doctor` minimum: kernel version, BTF, cgroup v2, Landlock ABI (syscall probe), seccomp ADDFD/SEND self-test, and BPF LSM activation decided from `lsm_list_modules(2)` (6.8+, unprivileged), then `/sys/kernel/security/lsm`, then the kernel log, plus a functional probe when root (counting program on `file_open`, no inode-storage map in the probe); every hardened hook resolved in BTF (name and argument count) | Built | Activation is silent: LSM programs attach and never fire when `bpf` is inactive; inode-storage maps corrupt `i_security` on every kernel below 7.1.4 / 7.2-rc2 (verified). Printed fix = active list + `,bpf`. |
| E38b | `tego doctor` full: capability matrix with the machine's values, highest tier, what the next tier is missing, the exact one-line fix built from the active LSM list (or 'nothing to do' on Debian 13/Fedora/RHEL/AL2023), plain-sentence refusals, exit 211 for `--require` | Built | |
| E39 | One static binary, CO-RE object embedded with bpf2go; tested floor kernel 6.1; every feature above the floor probed at run time (Landlock ABI syscall, LSM list, ADDFD/SEND self-test, BTF), never by uname; hooks declared with 6.1 prototypes, return 0/-errno, `file_truncate` optional | Built | RHEL 9's 5.14 qualifies through its backports (Landlock ABI 6, `bpf` listed). Authoritative minimums: ARCHITECTURE §14. |
| E40 | Overhead budget (<5%) measured on the workload | Partly | Measured once, at tier landlock, in docs/BENCHMARKS.md. Re-measure before quoting. |
| E41 | Reason-back adapters: errno; reason record; Claude Code / Agent SDK hooks | Partly | Claude Code's hook is built. Implements S4. |

### 1j. Boundaries: daemons, clusters, other hosts

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E42 | Run membership as a **set of cgroups**: a run's descendant cgroups belong to the run, materialized by a `cgroup_mkdir` tracepoint program and a cgroupfs scan when the tier attaches, removed on `cgroup_rmdir` | Partly | Root tiers only. A cgroup outside the run's own tree does not join it. |
| E44 | **Identity propagation**: env `TEGO_RUN_ID`, `TEGO_PARENT_RUN`, `OTEL_RESOURCE_ATTRIBUTES` (appended, percent-encoded; SDKs merge it as secondary), `PGAPPNAME=tego:<id>` (only if unset; libpq, pgx, node-postgres honour it, a DSN wins, asyncpg ignores it; 63 bytes in `pg_stat_activity`, full in `%a`); via the forwarder `X-Tego-Run`, W3C `traceparent` (run-derived or the client's trace id, fresh parent id) and `tracestate` member `tego=<id>`; `trace_id`/`span_id`/`parent_span_id` on `ssl_request` | Built | The run id never goes inside `traceparent`. Normative table: `spec/identity/RUN-IDENTITY.md`. |

### 1k. Hardening decisions (from GAPS.md)

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E48 | **Child stage** `tego __child` (ADR 0006 as amended): `clone3(CLONE_PIDFD|CLONE_INTO_CGROUP)`, env, uid drop, `PDEATHSIG`, `no_new_privs`, Landlock, seccomp `NEW_LISTENER`, capability drop + `PR_SET_DUMPABLE=1` (else `pidfd_getfd` refuses the non-dumpable stage), notify fd number over the control pipe and `pidfd_getfd` by the parent (runc's protocol), `NOTIF_RECV` before ack, exec `/proc/self/exe`; arch/compat-ABI guard in the filter; includes the notify-fd reader loop (every notification answered `CONTINUE` until E52/E13 add readers and decisions) | Built | Part of the TCB. `privileged: true` applies Landlock and seccomp before the uid drop. |
| E49 | **Inode-ancestry path rules**: identity is the kernel inode object via fd-pinned `BPF_MAP_TYPE_INODE_STORAGE` (object id) + `{cgroup id, object id}` access map, never a `stat` pair (btrfs, overlayfs); the walk is on `(mount, dentry)` and crosses mounts; refer check on link/rename; sibling enumeration for `deny_read` in Landlock; `run` creates declared write dirs | Built | Landlock half in (E7); BPF half in with E8. Inode-storage map only after the doctor LSM check (E38a). |
| E50 | **Race-free ask**: `ADDFD`+`SEND` for opens under the target's identity (fsuid/fsgid/groups/umask, `RESOLVE_IN_ROOT`), `pidfd_getfd` connect for sockets, `ID_VALID` around every memory read; `CONTINUE` never decides; subreaper for Yama scope; non-dumpable targets → `ask-unreadable` + gap | Built | Kernel 5.14 / 5.6 minimums for the race-free paths. *Note 2026-10-05:* regular-file opens complete by `ADDFD`+`SEND` with the original inode and credentials, and ordinary TCP connects by the exact duplicated descriptor and address (root tiers add a one-shot socket-cookie credit); `CONTINUE` decides no approval ([gate](p0/gate.md) R4, ADR 0008's 2026-10-04 note). Exec, UDP, Unix and raw completions refuse. *Note 2026-10-19:* unix connect approvals complete by R11's relay as the target, to the socket the `net.ask` `unix:` entry resolved to (supervisor R11c); exec, UDP and raw still refuse. |
| E51 | `ask.hold: connect \| first_write \| request` and `ask.timeout`; HTTP asks held in the forwarder with client ceilings in mind (Claude Code 600 s and 10 retries, Python SDK 600 s and 2, Codex 300 s idle and 4–5); retries of a held request attach to the pending ask (`retry_of`); `request` timeout defaults to 4 minutes | Partly | Fixes client-timeout failures on net ask. *Note 2026-10-05:* `ask.hold` (`connect`, `first_write`, `request`) and `ask.timeout` load and compile, and `request` holds are held in the forwarder ([agent-contract R22](p0/agent-contract.md#5-business-rules)); the client-ceiling and `retry_of` details above are design, not checked by this note. |
| E52 | Unprivileged record via the seccomp supervisor: exec+argv, write-opens, connects, datagram sends, deletes, renames from the notifications (read under `ID_VALID`, then `CONTINUE`); exits via `cgroup.events` | Built | Extends E48's reader. Read-before-continue and therefore advisory against a hostile process; the capability matrix says so. |
| E53 | Datagram handling: connect-time decision for connected UDP (glibc's resolver), address-time for `sendto`/`sendmsg`/`sendmmsg` (best-effort in tier 1, race-free in the root tiers), resolver on UDP+TCP 53 from `/etc/resolv.conf`; `socket_sendmsg` in tier 3 with the inet-datagram early return; Landlock UDP port rules on ABI 10+ | Built | DNS recorded as `net proto=udp\|tcp`. |
| E54 | Complete tier-3 hook set: `path_mkdir/rmdir/symlink/link/mknod/truncate/chmod/chown`, `file_truncate` optional (6.2+), `socket_bind`, `socket_sendmsg`, `unix_stream_connect`/`unix_may_send`, `ptrace_access_check` + `ptrace_traceme` (run-tree scoped, both modes, as Landlock already does), `bpf` | Built | 6.1 prototypes only; return 0/-errno; every hook probed in BTF by doctor; `path_*` need `CONFIG_SECURITY_PATH`, `socket_*`/`unix_*` need `CONFIG_SECURITY_NETWORK`. *Note 2026-09-30 (ADR 0024 (5), accepted; built: steps A to D, T3 and T13 to T15):* the file and mutation hooks named here are steps A to D of the plane, all built ([enforce-plane](p0/enforce-plane.md) R12 to R14); the remainder (`socket_bind`, `socket_sendmsg`, `ptrace_*`, `bpf`, `key_permission`) stays open on the same plane. *Current selected extension, 2026-10-05:* the scoped ptrace/BPF/keyring controls and declared Unix bind/listen admission are implemented under actual hook readiness; the dated remainder statement above is historical. See [Tier3 plan](p0/TIER3-PLAN.md) and [network controls](p0/network-controls.md) for the supported mechanisms and limits. |
| E55 | Attribution `confidence` and `method` (`tool_id\|tid\|time\|none`) on every action event; `unattributed` bucket; tid rule for background threads | Built | Every action event carries both fields. |
| E56 | `fs.watch` list: watched and `deny_read` paths are always individual read events; aggregation elsewhere | Built | Requires E17 + E18. Unprivileged tier: individual reads only under `record: full`, else `gap what=record why=unprivileged-tier`. *Note 2026-10-25 (ADR 0077):* with `reason.reads: on` a read the Landlock ruleset refuses under `deny_read` at tier landlock is one refused line under every record mode, so the gap no longer counts an entry the ruleset enforces; an unenforced one still counts, its allowed reads unrecorded. The default `auto` is the measured off. |
| E57 | Ledger privacy: `0700` run dir, `0600` files, no bodies in `summary`, chain anchor appended to `~/.tego/chain.log` at `run_end` | Built | Retention default lives in E34. |
| E59 | `net.http` path and method rules for traffic through declared model forwarders | Built | Requires explicit forwarder capture and listener coverage. Each authenticated HTTP/1.1 request is checked before its body or upstream send; ambiguous paths and unsupported tunnels are refused. Raw sockets stay destination-based. |
| E60 | Root-tier opt-out of `no_new_privs`: the child stage applies Landlock and seccomp before dropping uid; setuid binaries work and stay Landlocked | Built | Spelled `setuid: true` in the contract (ADR 0033), root tiers only, with a compile warning. |
| E61 | Parser rot defence: golden files per provider version, `decision: unparsed` fallback, `parser_version` on events | Built | |
| E62 | Price table `~/.tego/prices.yaml`, versioned, `est.` label, override in machine config | Built | Required by the cost budget and `measure`. |
| E64 | TCB fuzz targets for path and sockaddr readers; external review; file capability instead of setuid | Partly | Fuzz targets exist. An external review has not been done. *ADR 0042 (3)(c):* never setuid; a capability copy is refused until that ADR's conditions hold. |
| E65 | `extends: <profile>` with a profile library (`extends` takes a list of 1 to 8 merged in order, and names under `tego/` are built-in profiles, since 2026-10-24, ADR 0066); learn mode writes a proposal with a diff and never removes `deny_read` | Built | |
| E66 | Overhead benchmark (`test/e2e/overhead`: pip install + pytest + npm install, hyperfine, 10 runs, all three record modes) | Built | |

### 1l. Exec command rules

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| E76 | **Exec command rules** (ADR 0048): `exec.deny` and `exec.ask` lists, and words after a command in `exec.allow`, name a whole command, a subcommand or an option set (`git push`, `rm -r`, `npm publish`; allow only `git status`, `git diff`, `git log`); one argv matcher with per-tool rows locates the subcommand behind global options, clusters, abbreviations, dashed and argv[0] forms, multicall binaries and interpreter entry points | Built | The supervisor decides on copied argv at every tier, disclosed best effort; at plane tiers the decided facts are pinned in the kernel. `exec.ask` is reserved and refuses until ADR 0044's completion is built. |

---

### 1m. Governing any agent as a black box (ADR 0054)

Tego governs the agent sessions an operator chose (the agent and its descendants), never the rest of the
host, never hides from root, and root can always see and remove what it installs.

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| W1 | `tego watch [--boundary <contract>] -- <command>`: any command as a black box, record-only (observe) or held to a contract, full interactive on a pseudo-terminal | Built | **Built 2026-10-06.** Tego never needs to know what the command is; the notice says what a record-only run still refuses and does not record. |
| W2 | Standing answers: `tego approve\|deny --always` stand for the rest of the run for the same operation, rule and exact target; each automatic answer is its own ask and answer pair, `by: standing:<ask_id>` | Built | **Built 2026-10-06.** Never for scored gate, `first_write` or `request` holds. A timeout still refuses. |
| W3 | `tego learn <run>`: propose a first contract from what a run did (C9) | Built | **Built 2026-10-06.** Deterministic, no model; only proposes. |
| W4 | `tego agents [--follow]`: name agent processes by editable signatures from the kernel's process events, follow their descendants, say whether each runs inside a governed run | Built | **Built 2026-10-06**; root; observes only. With `--adopt --uid <uid>...` it is the guard (W5). |
| W5 | Adoption: put an already-running agent's process tree in a cgroup of its own and record from the kernel, and decide where tier 2 can | Built | **Built 2026-10-06, accepted 2026-10-16** (ADR 0055): `tego adopt --pid [--uid] [--boundary]`, the guard `tego agents --follow --adopt --uid`, release by `tego stop` or `--release`, never killed; root; the agent's own tree only, under the scope guard (never pid 1, kernel threads, tego, the caller's ancestors, `init.scope`, other namespaces, governed processes, another user's without `--uid`). A boundary holds the plane's file rules and exec allow-list (no exec command rule); no network rule; the attach window and held descriptors are gaps. |
| W6 | Ask on reads of sensitive files (a held read, answered like `fs.ask`) | Built | Built at tier landlock only (`fs.ask_read`; decisions in ADR 0057); the root tiers refuse it. |
| W7 | `alternate`: a third answer that hands the agent a stand-in file instead of approving or denying | Built | Built (`tego alternate`; ADR 0057: the person's command opens the file and passes the descriptor, record_minor 9). |
| W9 | Full interactive Claude Code and Codex under a boundary: contracts and startup handling | Partly | Claude Code built and run offline against a stand-in (`test/poc/interactive-claude`); Codex: `test/poc/interactive-codex`. |

## Layer 2 — Check and product (read-side over the record)

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| C1 | `tego init` | Built | |
| C2 | `tego compile`: validate with line numbers, print the rule table, no privileges | Built | Needs S6. *2026-10-25 (ADR 0068):* `--merged` prints the merged contract, the one rule file, whose sha256 is `contract_hash`. |
| C3 | `tego status`: defined state machine (running / waiting model / waiting tool / waiting approval / stalled / done / lost) | Built | |
| C4 | `tego drift`: declared vs done per rule, unused MCP servers, config hash drift | Built | Needs E19. |
| C5 | `tego measure`: steps, refused, **tokens in/out, cache, est. cost, wall, idle_max, repeats**; `tego receipt` reports a run's asks | Built | `--json` schema adds columns, never renames. |
| C6 | `tego events <run>` / `--json` raw view | Built | `--follow` tails a live run through `internal/ledger`'s one follower. |
| C7 | `tego approve/deny` | Built | |
| C8 | Gap line in status and drift | Built | |
| C9 | **Learn mode**: run observe-only, generate the first agent file from what the run actually did | Built | Onboarding in one command. Needs E9. |
| C12 | `tego serve`: local dashboard over the ledger, with actions (`tego-control`) | Built | Answers held requests, stops runs and changes rules: docs/DASHBOARD.md. |
| C13 | Run timeline (decision → actions) | Built | |
| C14 | Run-to-run diff (same agent, two runs) | Built | In the dashboard, `internal/control/web/compare.go`. |
| C15 | Export via ids: OTel GenAI spans, LangSmith, Langfuse (`traceparent`, `request-id`) | Partly | The ids are recorded (`traceparent`, `request-id`, E26). No exporter is built. |
| C20 | `tego compile --test tests.yaml`: table-driven verdict tests for a contract | Built | Contracts get unit tests like code; runs nothing. |

---

## Layer 3 — Ecosystem and integrations

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| I1 | Zero-adapter path: system Python + httpx/anthropic SDK, LangGraph, raw SDK | Built | |
| I2 | Claude Code adapter: sets `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`; tags the residual direct connects (fast-mode check, WebFetch domain check) `expected: true`; hooks for reason-back and decision events; prefer masking `ANTHROPIC_AUTH_TOKEN` over the API key for interactive use | Built | Reason-back evidence (2026-10-25): the real Claude Code 2.1.310 under `tego run` hears of each refusal in its next model request (test/e2e/reason-claude/RESULTS.md), and a CI twin through the stand-in holds the request to the real binary's golden on every CI run. |
| I3 | Claude Agent SDK (Python) under the forwarder: `examples/agents/claude-code.yaml` (`capture: forwarder`, `env.set` switches, expected gap line) and `test/workloads/claude-sdk` | Built | Kill test 7 as named. TypeScript SDK agents that replace `options.env` without spreading `process.env` are not covered. |
| I4 | Codex CLI (forwarder via a generated `config.toml` under `CODEX_HOME`, `openai_base_url`; `chatgpt.com` upstream when logged in that way), Gemini CLI (uprobes under system or official node, forwarder via its three variables otherwise) | Built | |
| I5 | Derive `net.allow` and exec entries from `mcp[]` declarations | Built | Less to write by hand. Built: `command[0]` gets its exec grant (agent-contract R8), and since 2026-10-19 an HTTP server's `url:` its net rule `mcp[<name>]` under a `net:` section (R16a). |
| I6d | **MCP provisioning**: `mcp[]` entries launched by the run (stdio `command:`) or written into the harness's MCP config for the run; allowlists derived from them (I5) | Partly | Declared servers are not started yet; see I5 and the MCP preview in docs/user/mcp-tools.md. |
| I7 | Run inside a container as the supervisor; `--cgroup-parent` for `docker run` children | Partly | docs/user/container.md runs `tego` in a container. `--cgroup-parent` for `docker run` children is not built. |
| I9 | CI mode: Landlock tier + forwarder, no root; for hosted runners whose command line cannot be edited | Partly | Self-hosted runners can use tier 2 with sudo. See ADR 0042 (2)(a) for when that is safe. |

---

## Acceptance criteria

[P0-DESIGN](P0-DESIGN.md) lists all seven kill tests.

- **Kill test 6**: one static binary; `doctor` prints the capability matrix with the machine's values, the highest tier it allows, what the next tier is missing, and the exact one-line fix; exit 0 when any tier runs, 211 when a requested tier cannot. Acceptance on a fresh Ubuntu 24.04 LTS image with the GA kernel (6.8, Landlock ABI 4) and only the binary: (a) as the invoking user, `doctor` reports `tier: landlock` and `tego run` passes kill test 1 and a refusal carries a reason (refusal errno is EACCES in this tier, Python `PermissionError` either way); (b) with `sudo` and no boot change, `doctor` reports `tier: cgroup` and a host-level deny passes; (c) after adding `bpf` to `lsm=` exactly as printed and one reboot, `tier: bpflsm` and the host-level deny passes with the in-kernel reason. `test/vm` repeats the three halves on the 24.04 HWE kernel. A refusal reads "refused with EACCES (Landlock) or EPERM (BPF LSM) and a reason".
- **Kill test 4**: ordinary work (`pip install` + `pytest`, `npm install`, `go build`) unbroken under `examples/profiles/base/python-dev` with `record: summary` in every tier the machine allows: nineteen of twenty runs exit 0 and emit no `refused` event whose target the profile declares; broken = non-zero exit, wall time over 2× the median of five runs outside `tego`, or a `refused` event naming a declared path, host or exec.
- **Kill test 2**: uprobe path (system Python + OpenSSL, HTTP/1.1): on a 20-step run at least 95% of model request/response pairs are `ssl_request`/`ssl_response` events whose response parsed, and every missing pair is explained by a `gap what=capture` event or the `count` of a `gap what=record`. Forwarder path (Claude Code, Agent SDK, Codex): every model request is `ssl_request source=forwarder`, and every direct connect to the model host is `refused`, by host in tiers 2 and 3, by port in tier 1.
- **Kill test 5 (R7)**: the contract declares one `fs.ask` and one `net.ask` entry the workload never touches; compared with the same contract without them, the run is slower by under 1% of wall time or 1 s, whichever is larger, on the 20-step agent and on the build workload, in every tier; `run_end` carries `supervisor{notifications, held_ms}` and E66 reports it per tier and mode. *Amended 2026-10-05 (`test/e2e/kt5-ask.sh`):* the harness reads "the same contract without them" as the same text but for the two ask lines, both contracts declaring a `net:` section with one allow entry the workload never connects to (a `net.ask` cannot be declared without the section, and what the section itself costs is kill tests 3 and 4's); "the 20-step agent" is kill test 2's, through the forwarder, and "the build workload" kill test 4's `pip install` and `pytest`; the run is slower by under the larger of 1% and 1 s when the median wall time of ten runs under the ask contract is over the median of ten under the base one by less than that (the runs are pairs in alternating order, after one run of each that is not counted); every tier the machine allows is a cell, tier cgroup one for each decision plane that decided its run; a miss is a FAIL printed as `TARGET-MISS` with the figure, never a moved budget; each cell prints `run_end.supervisor{notifications, held_ms}` of both contracts, and fails when the ask contract's run touched an entry, the supervisor saw none of it, or the two runs' own `capabilities.ask` does not tell the contracts apart. E66's overhead benchmark does not print that block (open).
- **Kill test 7**: two agents complete a real local task under `examples/agents/*.yaml`, each with at least one `refused` event and no code change: (a) a Claude Agent SDK (Python) agent with `capture: forwarder` and `env.set: {CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"}`; every model request is `ssl_request source=forwarder`; a deliberate direct connect to `api.anthropic.com:443` is `refused`; the gap line reads `capture: uprobe unavailable (static BoringSSL, no symbols); forwarder active`; (b) one open-source Python agent on system Python + the Anthropic SDK with `capture: uprobe`.
