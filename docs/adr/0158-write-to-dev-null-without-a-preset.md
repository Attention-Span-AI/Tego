<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0158: a write to /dev/null without a preset

Status: **proposed 2026-11-24** (row N14). What is built is the words only: a line in the end-of-run summary that names the missing entry
and the one-line fix, when the run was refused `/dev/null` by the default deny. Whether a contract that writes only where `fs.write` says should also be granted
the standard data devices without naming them is a maintainers' decision and is not built. Amends nothing; touches ADR 0068
(presets) and ADR 0059 (device files).

## Context

A contract with an `fs:` key is a write allow-list (SEMANTICS R6): a write outside every `fs.write` entry is refused, at
every tier. A beginner's first rules file is `fs: {write: [./]}`. The first script the agent runs then fails, because a shell
redirect (`> /dev/null`, `2>/dev/null`) opens `/dev/null` for writing and `/dev/null` is outside every entry. The
refusal is the right answer to the rule as written and a poor one for the person: the program prints "Permission denied"
about a file that holds nothing, and the dashboard folds the refusal into "a terminal or standard device" background.

Today the grant exists in three places and nowhere by default:

| where | what it says |
| --- | --- |
| `tego/repo-only-writes` (ADR 0068 D2) | `fs.write: [/dev/null]` |
| `internal/setup/compose.go` | the starter contracts for `claude` (`/dev/null`, `/dev/tty`) and `codex` (also `/dev/ptmx`, `/dev/pts/`) |
| `internal/runtime/adopt.go` `heldWriteExempt`, `internal/check/receipt` `devices`, `ledgerview` `stdDevices` | the readers' own list of device files a write reaches no file through: `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`, `/dev/console`, `/dev/pts/*` |

The Landlock builder grants `IOCTL_DEV` only under `/dev` (`writeMask`, `landlockGrant`), so a device entry is a
different grant from a directory entry: a default would have to say which rights it gives.

## Options

- **A. Implicit grant.** Every contract with an `fs:` key also gets write on the data sinks and sources (`/dev/null`,
  `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`) as device-number-checked entries (major:minor 1:3, 1:5, 1:7, 1:8,
  1:9, compared by `fstat` and not by name, so a bind mount or a `mknod` of another device at the same name gets nothing).
  `/dev/tty` and the pseudo-terminals stay out: a write to a terminal is a write to a person's screen, and which terminal
  it is, is decided by `agent.OtherTTY` and the built-in terminal refusals (`pkg/spec/agent/builtin.go`), not by a default.
- **B. Say it clearly.** Leave the table as the contract wrote it. When the run's record holds a refusal of `/dev/null`
  by the default deny (`unmatched`), `tego run`'s end summary adds one line that names the cause and
  the fix. Built (`devNullLine`, `internal/cli/runsummary.go`). `tego watch`'s footer (`watchFooter`) does not call
  `disclosures()` and prints no such line; the refusal is in the record and `tego learn` proposes the entry.
- **B'. A compile note** ("fs.write has no entry for /dev/null") was tried and dropped: it fires on every shipped example,
  starter and test contract that has an `fs.write` and no `/dev/null`, so it changes the diagnostics golden of each
  (`TestLiveOffGolden` alone listed eight) and tells a person who never ran anything about a refusal that may never occur.
  The summary line fires only for a run that was actually refused.
- **C. Starter only.** Keep the grant in the starters and the preset (today).

## Decision

**B now. A is recommended and not built.**

B reads the receipt of a finished run and prints one line; it changes no rule, no tier's table, no record field and no
decision. The line is silent when no refusal of `/dev/null` is listed, when the refusal was made by an entry of the contract
(a `deny_write` on it) and for any other file. The count is of the refusals the receipt lists (at most
`receipt.MaxRefusals`).

A is held back because it widens a run's authority on every contract in the product, and its proof is not one this host can
give tonight:

1. Every tier's table has to carry the device entries and nothing else: the Landlock ruleset (a file-beneath rule with
   `WRITE_FILE` and `IOCTL_DEV` on five exact nodes), the root tiers' plane rows (`decide.CompilePlane`: five write rows for
   those exact files, in the identity the plane already uses for a file), the supervisor's held-open answers
   (`heldWriteExempt` already lets a held descriptor on these through), and `rulesview` (the Rules in Force page must list
   them, or the page shows less than the table holds). A test per tier table that the set of write-granting rows grows by
   exactly those five and by nothing under `/dev` (no `/dev/shm`, no `/dev/pts`, no node of another device).
2. The device-number check on the root tiers needs a guest (bpflsm and cgroup are not on this host), and one on the
   kernel with a `mknod`'d lookalike at `/dev/null`'s name.
3. The ADR 0068 `TestPresetsNeverLoosen` allow-list and every contract-byte golden that hashes a compiled table move.

When the maintainers decide A, the build is: a `defaultDevices` list in `pkg/spec/agent` compiled into `rt.FS` as `FSWrite` rows
marked built-in (so `rules in force` and the receipt name them as the product's, not the contract's), the five tier tests
above, a guest script that opens each device for writing and a lookalike for refusal, and a one-line changelog entry. The
line of B then never fires for a contract that has the default.

## Consequence

- A beginner who writes `fs.write: [./]` and is refused `/dev/null` sees, under the run's summary, why and the line that
  fixes it; the fix grants one device that holds no file. `tego learn` already proposes the entry.
- Until A is built a run may do exactly what it could do before. Nothing is widened.
- `/dev/tty`, `/dev/ptmx` and `/dev/pts/` stay explicit in every contract (the starters carry them): they are a person's
  terminals, not sinks.
