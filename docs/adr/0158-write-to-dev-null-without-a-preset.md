<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0158: the standard data devices are writable without a preset

Status: **accepted 2026-11-25** (option A built; it was proposed 2026-11-24 with option B, which stays). Amends nothing;
touches ADR 0068 (presets), ADR 0059 (device files) and SEMANTICS R6 (a contract is a write allow-list).

## Context

A contract is a write allow-list (SEMANTICS R6): a write outside every `fs.write` entry is refused, at every tier, and a
contract with `fs: {}` refuses every write; one with no `fs:` section has no write entry at all. A beginner's first rules file is `fs: {write:
[./]}`. The first script the agent runs then fails, because a shell redirect (`> /dev/null`, `2>/dev/null`) opens
`/dev/null` for writing and `/dev/null` is outside every entry. The refusal is the right answer to the rule as written
and a poor one for the person: the program prints "Permission denied" about a file that holds nothing, and the
dashboard folds the refusal into "a terminal or standard device" background (public issue 72).

Before this decision the grant existed in three places and nowhere by default:

| where | what it says |
| --- | --- |
| `tego/repo-only-writes` (ADR 0068 D2) | `fs.write: [/dev/null]` |
| `internal/setup/compose.go` | the starter contracts for `claude` (`/dev/null`, `/dev/tty`) and `codex` (also `/dev/ptmx`, `/dev/pts/`) |
| `internal/runtime/adopt.go` `heldWriteExempt`, `internal/check/receipt` `devices`, `ledgerview` `stdDevices` | the readers' own list of device files a write reaches no file through: `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx`, `/dev/console`, `/dev/pts/*` |

The Landlock builder grants `IOCTL_DEV` only under `/dev` (`writeMask`, `landlockGrant`), so a device entry is a
different grant from a directory entry: a default has to say which rights it gives.

## Decision

**Every contract with an `fs:` section grants a run write access to five character devices, without naming them, at every tier.** (A contract with no `fs:` section has no write entry at all, SEMANTICS R6, and keeps none: its writes are refused as under `fs: {}`, and the grant is laid only where the author wrote an allow-list; `fs: {}` has it.) They are the
data sinks and sources of Linux's memory devices (major number 1):

| device | major:minor | what it is |
| --- | --- | --- |
| `/dev/null` | 1:3 | discards what is written, reads as empty |
| `/dev/zero` | 1:5 | discards what is written, reads as zero bytes |
| `/dev/full` | 1:7 | every write fails with ENOSPC, reads as zero bytes |
| `/dev/random` | 1:8 | random bytes; a write mixes into the pool and grants nothing |
| `/dev/urandom` | 1:9 | the same |

The grant is by what the file is, not by its name. A device is granted only when the file at its path is a character
device with exactly those numbers, and each tier checks the object it keys, where it can:

- **compile** (`pkg/spec/agent`, `stddevice.go`) reads the file at each path with `lstat`: a link, a regular file, a
  block device with the same numbers, another character device, a directory or nothing at the path leaves that device
  without a row. The rows are `FSRule`s of kind `write` marked `StdDevice` and `BuiltIn`, with the rights `WRITE_FILE`,
  `TRUNCATE` and `IOCTL_DEV` and none on a directory (no create, remove, rename or refer), named by the rule
  `builtin.standard_devices` in every record line and view, so a record never says the contract allowed what the product
  did.
- **tier landlock** (and tier cgroup's inherited ruleset, and tier bpflsm's): the ruleset rule is made on the object
  Prepare holds, an `O_PATH` descriptor opened where the path leads now. `sameStandardDevice` compares that descriptor
  (`fstat`: type and `st_rdev`) with the device and stops the run if it is another file. Landlock's rule is on that inode,
  so a node made with `mknod` with the same numbers elsewhere, a link, a bind mount of a file that is not one of the five devices at the name or a
  `/dev` in a mount tree the run makes holds no right from it.
- **the decision plane** (tiers cgroup and bpflsm) keys its row on the inode of the same held descriptor, and
  `checkStandardDevices` asks the descriptor it is about to key the same question before the fill; a descriptor that is
  not the device stops the fill.
- **the supervisor's held open** (`gate.completion: held`, held reads): the verdict is taken on the pinned object's
  path, and `standardDeviceRefused` refuses a write the device rule allowed when the pinned object is not that device
  (rule `unmatched`, a file outside every entry). The supervisor's non-held answers are decided on the name and
  completed by the kernel, so what stands there is the ruleset or plane above.
- **other names of the device** (a container's masked paths are binds of `/dev/null`): the ruleset and the plane key the
  inode, so the grant holds under every name; the product adds no alias row at such a name (a write entry of the
  contract gets one, as every write entry does), and the supervisor's path model, which sees only the name, does not
  list it.
- **the decision core** (`decide.Evaluate`, `compile --test`, `rules in force`) reads the same rows, so what a person is
  told is what the run is held to.

**Left out, and why:**

- `/dev/tty`, `/dev/ptmx`, `/dev/console` and `/dev/pts/*`. A write to a terminal is a write to a person's screen, and
  which terminal `/dev/tty` is depends on the process that opens it (the controlling terminal of its session), not on a
  device number a check could fix: the same 5:0 is the run's own terminal for one process and a person's other session
  for another. Which terminals a run may use is decided by the run's own terminal grants and `agent.OtherTTY`
  (`builtin.other_tty`), not by a default, and the starter contracts name `/dev/tty` where a tool needs it. The need is
  small (a tool that prompts on `/dev/tty` itself) and the risk is real, so it stays explicit.
- Everything else under `/dev`: `/dev/shm`, `/dev/mqueue`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr` and `/dev/fd/*`
  (links to descriptors the run already holds), block devices, `/dev/mem`, `/dev/kmsg`, `/dev/net/tun`, and `/dev`
  itself. No right on the directory `/dev` is granted, so a node cannot be created, removed or renamed there.

**An explicit entry wins.** A device is left out of the table, so no default is laid where the author wrote an answer,
when an entry of the contract is at, over or beneath it, or is another name of the same file (a bind or a hard link of
the device): any `fs.write` entry (it decides the device already; the product adds no second row for the inode, which the
plane would refuse), `fs.deny_write`, `fs.deny_read` (a glob or a name entry that matches the
device's name included), `fs.ask`, `fs.ask_read` or `fs.watch`, and a machine baseline's entries, which merge into the
same lists. The refusal then carries the author's rule, as it did. A contract that names `/dev/null` in `fs.write` keeps
its own row and rule name, and `tego/repo-only-writes` (revision 1 is frozen) is unchanged: its entry makes the default
row redundant for `/dev/null` and nothing more.

**Nothing in the record changes shape.** An open of one of these devices is recorded as before, a `file` line with the
path; its rule is now `builtin.standard_devices` where it was `unmatched` (refused) before, and the verdict is `allow`.
A run's table lists the five rows in `compile`, `rules in force` and `compile --test`, each marked built-in.

**B stays as the second line of defence.** `tego run`'s end summary adds one line that names the cause and the fix when the
record lists a refusal of `/dev/null` by the default deny (`devNullLine`, `internal/cli/runsummary.go`). With the grant in
every table that has an `fs:` section, that refusal arises only where the grant did not apply (the host's file at the name
is not the device), under a contract with no `fs:` section, or in a record an earlier version wrote. The line is silent when the grant applied, when an entry of the contract made the
refusal (a `deny_write` on it), and for any other file.

## Options considered

- **A. Implicit grant** (chosen). The five devices, device-number checked as above.
- **B. Say it clearly** (kept, as above). Leave the table as the contract wrote it and name the missing entry when a run
  was refused; it does not stop the first run failing.
- **B'. A compile note** ("fs.write has no entry for /dev/null") was tried and dropped: it fired on every shipped example,
  starter and test contract that has an `fs.write` and no `/dev/null`, and told a person who never ran anything about a
  refusal that may never occur.
- **C. Starter only** (the state before). Keeps the grant in the starters and the preset; every hand-written contract
  meets the refusal.
- **A'. Grant `/dev/tty` too.** Rejected above.

## Consequences

- A beginner who writes `fs.write: [./]` runs a script with `> /dev/null` and `2>/dev/null` and nothing is refused. No
  preset is needed.
- What a run may do is wider by exactly five files that hold no file and no person's screen. `TestPresetsNeverLoosen`
  (a preset's own keys) is unchanged; `TestStandardDevicesAreFiveExactRulesAtTierLandlock`,
  `TestPlaneRowsOfTheStandardDevices` and `TestStandardDevicesAtEveryTier` hold each tier's table to the five and to
  nothing else under `/dev`.
- The decision plane keys five rows more per run (a table's row cap is 4096; the five are keyed on inodes already held by
  the ruleset).
- A host whose `/dev/null` is not the standard device (a container runtime that binds something else there) gets no row
  for it and the old refusal; the summary line says what to add.
- A device row is the product's: `rules in force` words it as "standard data devices" and the rules file cannot remove
  it except by naming the device in an entry that decides it (`deny_write: [/dev/null]`).

## Implementation notes

- 2026-11-25: built as decided; guest rows for tiers landlock, cgroup and bpflsm open each device for writing with no
  preset, then show a `mknod` look-alike and a link refused and a rules file that denies `/dev/null` still refusing it.
