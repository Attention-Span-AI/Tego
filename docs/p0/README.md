# P0 detailed component specifications

One spec per engine component. Code and tests cite these files by name, rule ID and section number thousands of
times, so **never renumber a rule or a cited section, and never rename a file**. `tools/rulecheck` checks that every
cited rule exists.

Most specs follow the eleven-section shape set out in `docs/P0-DESIGN.md` §13 (§5 holds the numbered business
rules). They are edited in the same commits as their code, so they are current, but each also carries its history:
dated `**Changes.**` lists (required by ADR 0030) and inline amendments. Read a rule's current wording first and its
amendments only when you need the why. Moving that history out would need an ADR 0030
amendment first.

## Index

| Spec | What it covers |
|---|---|
| [agent-contract.md](agent-contract.md) | The contract (agent.yaml): fields, defaults, built-in deny-read list, `fs.write`, `net.allow`, ask |
| [runtime-launch.md](runtime-launch.md) | How a run starts: `runtime.Run`, the child stage, tiers 2–3 launch, privileged path, sweep |
| [enforce-landlock.md](enforce-landlock.md) | Tier 1: Landlock rulesets, what a deny-read under a writable parent means |
| [network-controls.md](network-controls.md) | Network rules across tiers and the forwarder. Hold vs refuse is in spec/policy/SEMANTICS.md §6 |
| [record-ledger.md](record-ledger.md) | The run record and hash-chained ledger |
| [supervisor.md](supervisor.md) | The seccomp supervisor: tier-1 network and exec decisions, held opens |
| [enforce-cgroup-observe.md](enforce-cgroup-observe.md) | Tier 2: cgroup, fanotify, observe mode |
| [identity-config.md](identity-config.md) | Run identity, machine config, environment |
| [limits-check-doctor-cli.md](limits-check-doctor-cli.md) | Limits, budgets, the check commands, `doctor`, the CLI and exit codes |
| [enforce-plane.md](enforce-plane.md) | Tier 3: the kernel decision plane (BPF LSM), largely a build log by ticket |
| [capture-derive.md](capture-derive.md) | Model-traffic capture (uprobes, forwarder decoders) and derived steps and tokens |
| [gate.md](gate.md) | The scored risk gate |
| [proxy-protocols.md](proxy-protocols.md) | Protocols the model proxy speaks |
| [exec-ask-plan.md](exec-ask-plan.md) | Work packages for holding a command live for a person (ADR 0044). Unbuilt |
| [TIER3-PLAN.md](TIER3-PLAN.md) | The tier-3 build plan, finished 2026-10-04. Kept because `tools/rulecheck` and the ADR 0024/0025 tests read it |

The build-order plan that used to sit here (STEPS.md, 2026-09-23) was finished and is not published; the ADRs that cite "docs/p0/STEPS.md §1" mean that file.
