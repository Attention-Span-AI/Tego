# Docs map

## Where to look

| I want to know… | Read |
|---|---|
| **How to install Tego** | [INSTALL.md](INSTALL.md): requirements, building from source, `sudo`, uninstall |
| **How to run my first agent** | [QUICKSTART.md](QUICKSTART.md): eight commands from `tego version` to the dashboard, and how to read a receipt |
| **Which tier my machine gets** | [TIERS.md](TIERS.md): what each of the three tiers needs and gives |
| **What Tego cannot do** | [GAPS.md](GAPS.md): the known limits, each with what to do about it |
| **How to run agents under it, command by command** | [user/README.md](user/README.md): the user guide |
| **How the dashboard works** | [DASHBOARD.md](DASHBOARD.md) |
| **How the engine works** | [ARCHITECTURE.md](ARCHITECTURE.md) first, then the table below |
| **How to change it** | [../CONTRIBUTING.md](../CONTRIBUTING.md) and [REPO-LAYOUT.md](REPO-LAYOUT.md) |

## Engine docs

These change in the same commits as the code.

| Doc | What it is |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The engine's shape: tiers, the run, the trusted computing base |
| [p0/](p0/README.md) | One spec per engine component, with numbered rules that code and tests cite (never renumber) |
| [../spec/](../spec/README.md) | Versioned, language-neutral standards: the contract (`agent.yaml`), policy semantics, the record format, reason codes, capabilities per tier |
| [adr/](adr/README.md) | Why each decision was made. Kept even when superseded; the index says which apply |
| [OPERATIONS.md](OPERATIONS.md) | Running the engine: the privileged path, unattended runs, Claude Code under a boundary, crash and cleanup, threat model |
| [REPO-LAYOUT.md](REPO-LAYOUT.md) | Where code lives and the import rules |
| [VERSIONING.md](VERSIONING.md) | What is versioned and how, and how a release is made |
| [GAPS.md](GAPS.md) | Known limits of the engine |
| [CHANGELOG.md](CHANGELOG.md) | What changed, grouped by what a user gets; release tooling reads it |
| [poc/agent-watcher.md](poc/agent-watcher.md) | Design of watching and adopting any agent (ADRs 0054, 0055) |
| [spec/exec-command-rows.md](spec/exec-command-rows.md) | Command-rule rows; a design table, not a versioned standard, and `tego` prints this path to users |

## Older documents

Kept because code and tests cite them. Each says what is out of date. Skip them unless a code comment sends you there.

| Doc | What it is |
|---|---|
| [P0-DESIGN.md](P0-DESIGN.md) | The first baseline design of the engine; the specs in `p0/` and the code are current where they differ |
| [FEATURES.md](FEATURES.md) | The engine's feature catalog as first written; a test reads it |
| [BENCHMARKS.md](BENCHMARKS.md) | Overhead numbers from an early build (re-measure before quoting) and the test suites' timing budgets |

## When two docs disagree

- **Formats and wire contracts:** `../spec/` wins.
- **Engine behaviour:** the `p0/` spec wins over ARCHITECTURE and P0-DESIGN. Check the code, which is edited in the same commits.
- **Why:** the ADR, read with its amendments.

## Glossary

| Term | Meaning |
|---|---|
| **Tego** | The engine and its command, `tego` |
| **tego-control** | The second binary. `tego serve` hands off to it to start the dashboard |
| **contract / agent.yaml** | The rule file for one agent: what it may read, write, run and connect to, and its limits |
| **run** | One governed session of an agent |
| **refused** | An action Tego stopped. The run's record names the rule, except for a read refused at tier 1 under `record: summary`, which leaves no line |
| **held** | An action paused while a person decides, with a timeout. Also called an ask |
| **receipt** | The summary of a run's record: time, files, connections, sensitive files read, refusals, asks and tokens (`tego receipt`). It shows only what the record holds |
| **ledger / record** | The hash-chained file of what a run did, as far as its tier and `record:` mode can see ([TIERS.md](TIERS.md)). The only store Tego keeps |
| **drift** | What the contract allowed against what the run used (`tego drift`) |
| **tier 1 / 2 / 3** | Enforcement levels. Tier 1 (`landlock`) needs no root; tier 2 (`cgroup`) and tier 3 (`bpflsm`) need root. See [TIERS.md](TIERS.md) |
| **PRD** | The original requirements document, not published. Some specs and ADRs cite its section numbers |
| **P0** | The first build phase of the engine. The `p0/` specs keep the name |
