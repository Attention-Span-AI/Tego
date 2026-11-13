# Security policy

## Reporting a vulnerability

Report it privately through GitHub: open
[Report a vulnerability](https://github.com/Attention-Span-AI/Tego/security/advisories/new) on this repository's Security tab.
Please do not open a public issue, pull request or discussion for it.

A useful report says what you did, what you expected, what happened, the output of `tego version` and `tego doctor`,
and the kernel and distribution. A contract that reproduces it, with any secrets removed, helps most.

There is no promised response time. We will answer reports we can reproduce, tell you what we decide, and credit you in
the advisory if you want that.

## Supported versions

The latest release (the first is v0.1.0) and the `main` branch are supported.

## Scope

Tego runs a privileged supervisor that reads another process's memory and loads BPF. Treat these as the trusted
computing base, and as the in-scope code for a report (the authoritative list is `docs/ARCHITECTURE.md` section 16,
extended by `docs/adr/0031-tcb-dependency-rule-checked.md`):

- `internal/runtime/launch` (the launcher and the child stage)
- `internal/runtime/supervisor` (the seccomp notify supervisor, which reads the agent's memory)
- `internal/runtime/enforce/landlock` (the tier-1 Landlock ruleset and seccomp filter the child stage installs)
- `internal/runtime/enforce/bpflsm`
- `internal/runtime/enforce/cgroup` (the fanotify listener)
- `internal/runtime/observe`
- `internal/runtime/capture/uprobe`
- `internal/runtime/capture/forwarder` (the loopback forwarder, which runs in the launcher and parses the agent's
  HTTP/1.1, prior-knowledge HTTP/2, CONNECT and WebSocket traffic and applies `net.http` and `net.proxy` policy)
- `internal/runtime/dnsbroker` (the opt-in DNS broker, which runs in the launcher and parses the agent's DNS
  queries)
- `internal/runtime/mcprelay` (the MCP relay, which runs in the launcher, parses the agent's MCP traffic over HTTP and
  through the shim that stands in for a stdio server, and decides each `tools/call`)
- `internal/runtime/ask` (the authenticated approval broker the launcher hosts for `tego approve`/`deny`)
- `internal/policy/decide` (the decision core)
- `pkg/policy/httppolicy`, `pkg/policy/dnspolicy`, `pkg/policy/gate`, `pkg/policy/fsplan` and `pkg/policy/mcptool`
  (the compiled policy the forwarder, the DNS broker, the supervisor, the Landlock builder and the MCP relay decide
  with; no I/O)
- `internal/bpf` and `bpf/` (the BPF programs and their loader)

The policy compiler, `pkg/spec/agent`, is outside the list: it makes no mutating syscall (`docs/p0/agent-contract.md`
I6, checked by `TestCompileMakesNoMutatingSyscall`), though under `sudo tego run` it runs as root before launch.
It joins the list when ADR 0031 (proposed) moves its I/O into a new internal/policy/compile package.

**The privileged path** (ADR 0042). Tiers 2 and 3 run from a root launcher: `sudo tego run` runs the whole launcher
as root for the whole run, so granting sudo for tego is granting root, and a sudoers entry limited to tego is not
a supported boundary. A file-capability or setuid copy of tego, or a launcher holding a privileged capability
without being root of the initial user namespace, is refused at start with exit 125
`[privileged-path-unsupported]`; incidental inherited capabilities are cleared. `/run/tego` is root 0700 only.

**The ledger's boundary.** The hash-chained ledger and its anchor (`~/.tego/chain.log`) are tamper-evident against
an agent held by a contract, within the mount and storage limits [docs/GAPS.md](docs/GAPS.md) lists, not against
the user who launched the run, who can write both (`docs/GAPS.md` C9). A
record-only run (`tego watch` with no `--boundary`, `tego run --observe`) has no Landlock ruleset, so its agent, which
runs as that user, can write both too.

## Out of scope

The limits Tego states about itself are not vulnerabilities. They are listed in [docs/GAPS.md](docs/GAPS.md): for
example, a destination the contract allows is an open channel for data (A1), an allowed interpreter can do anything
in its own memory (A2), and a user can rewrite their own ledger (C9). A report that shows one of those is worse than
documented, or can be exploited from outside the limit, is in scope.
