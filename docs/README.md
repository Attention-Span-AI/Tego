# Contributor docs

Using Tego? Read the user docs at https://attention-span.ai/docs/. Their source is [site/](site/), and the website copies those pages as they are.

This folder is for people who change Tego. Start with [ARCHITECTURE.md](ARCHITECTURE.md), then [../CONTRIBUTING.md](../CONTRIBUTING.md).

## Architecture

| Doc | What it holds |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The engine's shape: the protection levels (tiers), how a run works, the trusted computing base |
| [REPO-LAYOUT.md](REPO-LAYOUT.md) | Where code lives and which packages may import which |
| [GAPS.md](GAPS.md) | The engine's known limits, each with its status |
| [FEATURES.md](FEATURES.md) | The feature catalog with each feature's build status. A test reads it |

## Specs

| Doc | What it holds |
|---|---|
| [../spec/](../spec/README.md) | Versioned, language-neutral standards: the rules file schema (`agent.yaml`), policy semantics, the record format, reason codes, the CI receipt, capabilities per tier |
| [spec/exec-command-rows.md](spec/exec-command-rows.md) | The command-rule rows for `exec` entries. A design table, not a versioned standard |
| [spec/builtin-deny-read.md](spec/builtin-deny-read.md) | The built-in list of files no run may read |

## Decisions

[adr/](adr/README.md) holds one architecture decision record (ADR) per decision, with the reasons and the options turned down. An ADR stays when a later one replaces it; the index says which apply. ADRs 0054 and 0055 cover watching and adopting an agent Tego did not start.

## Development

| Doc | What it holds |
|---|---|
| [development/operations.md](development/operations.md) | Engine notes: start-up probes, the control binary, the privileged path, adopt, host sockets, the kernel decision plane, exec command rules, live blocks, precommit modes, Tego's own log |
| [development/dashboard.md](development/dashboard.md) | How the dashboard is built: routes, sign-in, the read model and its limits, each page's behavior |
| [development/dashboard-assets.md](development/dashboard-assets.md) | The dashboard's static assets |
| [development/baseline.md](development/baseline.md) | Status of the machine baseline (`baseline:` in the machine config) |

## Testing

| Doc | What it holds |
|---|---|
| [testing/](testing/) | Guest test scripts and their notes, such as [contracts-helper-cost.md](testing/contracts-helper-cost.md) and [prune-budget-guest.md](testing/prune-budget-guest.md) |
| [BENCHMARKS.md](BENCHMARKS.md) | Overhead numbers from an early build (measure again before quoting) and the test suites' time budgets |

## Versions and changes

| Doc | What it holds |
|---|---|
| [VERSIONING.md](VERSIONING.md) | What is versioned and how, and how a release is made |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release, grouped by what a user gets. Release tooling reads it |

## When two docs disagree

- **Formats and wire contracts:** `../spec/` wins.
- **Engine behavior:** the code wins over ARCHITECTURE.md, which changes in the same commits.
- **Why a decision was made:** the ADR, read with its amendments.

## Words

The user docs use plain names; engine docs and code use the older technical ones.

| User docs | Engine docs and code |
|---|---|
| rules file | contract, `agent.yaml` |
| session | run |
| record | ledger |
| Basic, Plus, Max | tier `landlock`, `cgroup`, `bpflsm` (tier 1, 2, 3) |
| refused | refused, denied |

A receipt is the summary of one run's record (`tego session show`), and the signed report of a CI run. PRD is the original requirements document, which is not published; some specs and ADRs cite its section numbers. P0 is the engine's first build phase.
