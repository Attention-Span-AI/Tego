<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR 0171: live blocks for command words; a live block for a pattern is not built

Status: **accepted 2026-11-25**. The command-word block is built and was proved in a guest at each tier (the tests below). The
pattern block is **not built**: this ADR records why and the design that would. Amends ADR 0124 (live controls) and
ADR 0048 (exec command rules) by one kind of block and one overlay version; touches ADR 0125 (time limits) and ADR 0157
(revision 41 records). Issue 73 of the public repository.

## Context

The Change rules page saves the removal of an `exec.allow` entry that names a command with words (`git push`), or of a path
pattern, for the next run only, and says why it offers no live block ("a command entry: a live block names a whole program,
and would refuse its other commands too"; "a pattern: a live block names one path"). Both sentences are true. A live block is
`exec:<program>`, which refuses every command of that program, or a path with everything beneath it.

## Decision 1: a block on command words is the contract with that entry added to `exec.deny`

An `exec` block whose value has words (`git push`, `/usr/bin/git push`, `npm install --global *`) refuses exactly what a
contract holding the same text as an `exec.deny` entry would refuse, decided by the same code: `execmatch.Parse` with
`ListDeny`, the same rows, the same normalisation of options, wrappers, scripts and loaders, the same interpretations of
argv[0] and of the image's identity (ADR 0048). Nothing is matched a second way, so the block, `exec.allow` words, `exec.deny`
words and `compile --test` cannot disagree about what `git -C . push` is.

**Where it is decided.** At every tier the run's seccomp filter notifies `execve` and `execveat` (the notify arm of every
architecture table, `internal/runtime/enforce/landlock/filter.go`), and the supervisor decides them. At a tier whose decision
plane decides execs in the kernel the supervisor still gets the notification and may only continue it (`handOverExec`); that
fast path is taken only when nothing needs the supervisor's own decision, and `recordExec` already turns it off while any
exec block stands (`c.blocks().HasExec()`). A command-word block counts as an exec block there, so while it stands the
plane hands every exec to the supervisor's decision, never a continued one. The plane's own row answers by file identity
after that and can only refuse more. A block names no file, so the plane gets no row for it: nothing in the plane changes.

**What it is matched on.** The supervisor's copy of the argv it read (`process_vm_readv` under `ID_VALID`), by the staged read
`decideCommand` makes for command rules, so the same budget, the same `args-unreadable` and `image-unreadable` refusals
apply. It refuses with the rule `live.block[exec:<words>]`, reason `exec-not-allowed`, EACCES, never a continue. Like every
refusal of a copied argv it is exact for the exec it refuses; the kernel reads argv again after a continue, so a sibling thread
that rewrites argv after an allowed check can run the blocked command (the `exec.rules/argv` best-effort cell, ADR 0048
(6)). A run whose kernel pins execs (`plane.exec_pin`) holds the kernel to the facts decided, a refusal's twin included; any
other run's block carries the cell, and `tego block` and the dashboard say so when they place one.

**The index.** The supervisor builds a second `execmatch.Index` from the live words entries only (deny patterns), with the
running contract's identities, git candidate set and loaders where it has command rules, and the tool's file identity
resolved on the run's PATH where it has none (`agent.NewLiveCommands`). It is rebuilt when the overlay's set changes and
is read by every exec that has to be decided, on the facts the run's own index read when that read the whole vector (so a pinned
run's kernel holds what both judged), else on its own staged read. Only the entries in force now are in the index it asks (a
block past its limit or dormant under an unblock for a while is left out, so it never decides ahead of one in force). The static
index is never altered: a run's own command rules, its pin and its
lines do not change when a block is added.

**Offered when it is exact.** The Rules page offers the block for `exec.deny` words added always (a deny is read before any allow
entry, so the block is what the new contract refuses) and for `exec.allow` words removed when no remaining `exec.allow` entry
can admit something the block would refuse: every remaining entry of the same tool with
words must be provably disjoint from the removed one (`execmatch.Intersect`, the check compile makes of a deny against an
allow; `IntersectionUnknown` counts as overlapping), and no bare entry for the tool remains (a bare entry lifts the tool's
constraint). Two grants lift it without a bare name, and the offer is held back for both: the run's own implicit grants (the
contract's command, an MCP server's command, the `#!` interpreter of either, the command given to `tego run`; compile keeps
"any arguments" for each whatever the allow entries say), and a path or folder `exec.allow` entry when no entry with words of
the tool is left (compile builds command rules from the entries with words only, so the grant of the image then allows every
command; a folder may hold the tool, which the page cannot look into, so it counts). A command whose program is written with its folder (`/usr/bin/git push`) is not offered: the block names the program by
its bare name and would refuse other files of that name too. Otherwise the page says which entry, as it does for a program. A block may refuse less than the new contract
(it names one command; the new contract refuses the tool's other unlisted commands too) and never more.

**A value** is the entry's own grammar: words split on spaces, `"..."` or `'...'` keeping a word that holds a space, the program a
bare name (`execmatch.Parse` refuses a path in a deny entry's command word, since it matches every file of a name), at least one
word, normalised by one space between words unless a word is quoted (`liveblock.NormalizeWords`). An absolute exec value with a
space stays a program path, as it always was; a value with no `/` in front and a space in it is a command. The program is matched
by name, and by the identity of its file of one link found on the run's PATH or in the run's command rules' identities.

**Format.** Overlay version 6 (`VersionWords`): an exec entry's value may hold words. `Encode` writes the lowest version that
holds the content, so an overlay with no such entry stays byte for byte what it was. The launcher makes the mark `live-words`
in the run directory once its poll runs; a writer places a words block only on a run so marked (`TakesWords`) and refuses
the others in words (`ErrNoWords`, exit 1 `[launcher-too-old]`: "the run's launcher does not say it reads a block on a command's
words"), never placing the whole-program block instead, which would refuse more than the new rules do. A launcher older than this, reading version
6, refuses the whole overlay as it refuses every unknown version (`overlay version 6, want 1 to 5`): it keeps the blocks it
last put in force and writes `live-block-unreadable`, which is why the writer asks the mark. No MAC is involved: a block is a
tightening and carries none; only a lift's MAC binds anything in this file (ADR 0125).

**Record.** The `live_block` gap lines carry `kind: exec` and the words as `value`; the record's `value` is free text, so
revision 41 is unchanged and no reader changes. Time limits (`--for`, `--until`), `tego block --list`, `tego unblock`, the
dashboard's Block now and Remove, and "Also apply now" use the one path every block uses. Lifting removes the entry by its
value; the next exec is decided without it.

**Watch runs** record the block and refuse nothing, as every block does.

## Decision 2: a block on a pattern is not built

What the contract's patterns are, and where each tier answers them:

- A pattern exists in `fs.deny_read` and `fs.watch` only (`fs.write` "is not a glob", `**` is refused: `compile_fs.go`).
  Compile expands it to the files that exist when the contract is compiled (SEMANTICS §2) and, for a glob whose last
  component keeps a literal (`**` aside: `.env`, `secret*`), also makes a name entry, which the kernel's decision plane keys
  by name so that a file created later is refused at tiers cgroup and bpflsm too (ADR 0043). Tier landlock has the expansion
  only.
- A live path block is a path the supervisor matches, or, at a plane tier, rows the launcher keys in the kernel by the inode
  each walk of the path meets (`liveblock_plane.go`); the plane's file decisions are not notified to the supervisor at all.

So a block "matched as the rules file's patterns are" would need, at tiers cgroup and bpflsm, a name row in the kernel for
a file that does not exist yet and may be made under any folder of the scope: a new plane map, a new C hook path and a new
overflow rule, which the verifier and a guest alone can accept, and at tier landlock it would be the expansion the dashboard
could place as ordinary blocks now. Neither is exact on every tier that claims the block:

- expanding at the page and placing one block per file refuses less than the next run's contract at the plane tiers (later
  files), and the overlay holds 64 blocks;
- a kernel name row is enforcement-path work with no host proof available.

So nothing is built, and the page's words stay true ("a pattern: a live block names one path"). The design to build when a
guest lane is available for it: a `name` block kind holding the glob's literal and scopes exactly as compile's `NameDenyRule`
holds them; the plane's name map gains a live generation beside the contract's (rows keyed `(scope dir, name key)` for `read`
and `write`, deleted on lift); the supervisor matches the same rule on the copy at tier landlock; the page offers it for a
glob only when compile would make a name entry for it, and says "the files that exist now" for one it would not. Proof: one
guest row per tier (add, a file created later, lift, time limit), and an oracle of random names against `NameDenyRule.Matches`.

## Proof

Host: `internal/liveblock` (`TestNormalizeWords`, `TestWordsBlockNeedsItsVersion`: the file is version 6, a version 5 reader's range
ends below it, an older version holding a command is invalid, `TestTakesWords`, `TestCheckWords`), `pkg/spec/agent`
(`TestLiveCommandsRefuseWhatExecDenyRefuses`: the block's answer equals a contract's `exec.deny` of the same text),
`internal/runtime/supervisor` (`TestLiveWordsBlockRefusesTheNextCommandOnly`: under a contract with command rules and one with a
bare grant, with the kernel's handover ready and not, the next `git push` in four spellings is refused under the block's rule and
never handed over, `git status` and the rest run; red without the change; limits, dormancy, fail-closed answers; and
`TestLiveWordsBlockOnARealKernel` on a real filter, Loop and child processes), `internal/runtime` (the launcher's mark and
gap lines), `pkg/spec/record` (no new revision), `internal/control/rules` (`TestBlockOfCommandWords`: when the offer is made and
when it is held back, and why, including the implicit grants and a path or folder grant), `internal/cli`, `internal/control/runact` and `internal/control/web` (the writers' words).
Guest: `TestRootLiveBlockOnCommandWords` at root tiers landlock, bpflsm and cgroup, and
`TestRootOlderLauncherRefusesACommandBlock` with a tego built before this change, by a guest row.
