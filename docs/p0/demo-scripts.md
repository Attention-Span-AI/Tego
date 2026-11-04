# Demo scripts: command output and generated state

Current as of 2026-11-03; [ADR 0129](../adr/0129-demo-script-state.md).

## 1. Purpose and boundaries

This is the operator-script contract; it adds no engine enforcement capability.

## 5. Business rules

**R1 — Login command output.** Supply-chain command output masks both supported Claude login assignments:
`CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY`. Every command printer caller,
including both backup sides and quiet mode, uses that rule. Executed arguments
retain the original bytes, including trailing newlines and newline-only values.
Quoting must not trim them through command substitution. Codex login is copied
as a file and never printed.

**R2 — Main-demo stage ownership.** Main-demo setup, including an act's implicit setup, claims only a new or empty
stage with `.tego-demo-stage`, containing its physical path. Reset requires
that regular, nonsymlink marker. It refuses `/`, `$HOME`, the checkout, its
ancestors and the demo kit itself, including aliases resolving there. It
removes only the generated child names listed in `cmd_reset`, retaining the
stage, marker and unrelated children. Reset never creates a missing stage.

**R3 — Stand-in deletion.** `plant()` writes `.tego-demo-project` in the fake project. The mini agent's
recursive delete scene requires that marker to name its physical project.

**R4 — Supply-chain state and rotation.** Supply-chain setup claims `.tego-supply-chain-stage` only when `without`,
`with` and `api.log` do not already exist. A claimed stage may hold unrelated
siblings. Setup/reset validate both sides before deleting either, and refuse
symlinks at the generated directory names. Its ledger requires
`.tego-supply-chain-ledger` before rotation; setup claims only a new or empty
ledger. Old-ledger pruning still requires `.moved-by-demo-sh` naming the exact
old directory, with neither directory nor marker a symlink.
Rotation reserves a unique empty destination first and uses `mv -T`, so an
existing timestamped directory can never be adopted and later pruned.
Newlines in generated-state paths or old-ledger candidate names are refused;
the prune list is line-oriented and cannot safely carry those names.

**R5 — Live-modes state.** Live-modes setup claims a new or empty ledger and vault using
`.tego-live-demo-ledger` and `.tego-live-demo-vault`. Both markers name their
physical paths. Reset validates both before deleting the filled contract or
using `sudo` for generated ledger data. Protected directories are refused.

**R6 — Developer output directories.** Coverage, benchmarks, BPF toolchain and BPF scratch reuse only new/empty or
marked output directories. Their respective markers are `.tego-coverage`,
`.bench-gate`, `.tego-bpf-toolchain` and `.tego-bpf-check`. A symlink marker,
symlink output directory, home, checkout or ancestor is refused. A toolchain
`stamp` alone is insufficient. Directory-listing or marker-read uncertainty
must refuse cleanup.
The BPF check alone may migrate an unmarked directory containing only its owned,
nonsymlink, single-link, empty regular `lock`: acquire the exclusive lock,
recheck it and enumerate every other entry before writing the marker. Unmarked
generated state is never migrated, and enumeration failure still refuses.
The default toolchain cache uses `tego/bpf-toolcache` under the cache root;
the legacy unmarked `tego/bpf-toolchain` is left untouched, never adopted by stamp.
Timing-budget results separately refuse an unmarked nonempty output directory
and any directory-enumeration failure, using `.timing-budgets` as their marker.

**Changes.**

- 2026-11-03: H4/H5 and the matching script patterns fixed; scratch regressions
  added to `scripts-and-workflows` and precommit. Live agents and root-tier
  enforcement are outside these shell regressions.
- 2026-11-03, round 2: captured filename listings replaced by fixed nonnewline
  output per entry; trailing login newlines preserved by both `shq` helpers,
  with the matching main-demo `q` fix retaining bytes in other arguments too.
  Regressions first reproduced adoption/deletion and byte loss, respectively.
- 2026-11-04: NET09 integration exposed the BPF check's legacy lock-only scratch;
  migrate only that empty lock under its exclusive lock, keeping the canonical
  BTF path and the refusal of unmarked data. Shell regressions cover both.

## 8. Invariants and limits

Every claim of an empty directory includes hidden and newline-only child names.
Enumeration emits a fixed nonnewline character per immediate entry instead of
filenames, and any enumeration error refuses adoption before writing a marker.

Markers authorize regeneration of the generated children; keep personal files
outside those children. A marker can be forged by the owner, and shell checks
are not race-free against a concurrent process replacing path components. This
is a stated operator-tooling limit, not an engine security guarantee.

## 10. Tests

`./scripts/demo-credentials_test.sh`, `./scripts/demo-reset_test.sh` and
`./scripts/cleanup-guards_test.sh` exercise these rules with synthetic logins,
scratch directories and stand-ins. They run in CI
(`scripts-and-workflows`) and precommit; they do not run an authenticated agent
or a root-tier rehearsal. The rulecheck strict report indexes named Go tests;
it does not measure these shell regressions.
The three demo kit directories are global fixture inputs to `tools/affected`;
changing one selects the full gate, including the shell self-tests.
The canaries compare received bytes with `cmp`, including trailing newlines;
cleanup cases keep valuable files beneath newline-named children and inject
enumeration failures. No destructive probe uses a real data directory.
