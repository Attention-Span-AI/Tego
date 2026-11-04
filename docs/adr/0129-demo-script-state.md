# ADR 0129: Demo command output and ownership of generated directories

Status: **accepted 2026-11-03**; implemented in the demo scripts and developer cleanup tools.
Current rules: [demo-scripts.md](../p0/demo-scripts.md).

## Decision

The supply-chain demo has one command printer for launch, backup and all other
printed commands. It masks `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY`
assignments before quoting. Execution receives the original argument vector.
Quiet output uses the same printer. Login values are inserted as one argument,
including values with whitespace or newlines.

Setup claims generated state with a regular, nonsymlink ownership marker. The
demo markers contain the physical directory path. Reset validates ownership and
protected paths before stopping processes, deleting children or rotating ledgers.
The main demo removes an explicit list of generated children and retains its
stage, marker and unrelated siblings. Supply-chain setup can share the source
kit's directory, but may claim its reserved child names only when they are absent.
Neither project-shaped directories nor arbitrary `stamp` files establish ownership.
Ledger rotation reserves a unique empty destination with `mktemp` and moves
with `mv -T`; a timestamp collision must never claim an unrelated directory.
Newlines in generated-state paths or old-ledger candidates are refused before
the line-oriented prune list can split a path into another marked directory.

Developer tools which reuse configurable output directories share
`scripts/safe-output-dir.sh`: new or empty directories can be claimed; nonempty
directories require the tool's regular ownership marker. Physical home paths,
checkout roots and their ancestors are refused even with a marker. The BPF
scratch tree now needs its own marker too.

## Why

Review H4 reproduced a login in backup's command output with a synthetic
canary. H5's scratch reproduction deleted an unrelated stage directory. The
wider audit also reproduced deletion through an unmarked live-demo ledger,
lookalike supply-chain sides, colliding or newline-split rotation paths,
unmarked BPF scratch, an unrelated toolchain stamp,
symlink markers in coverage and benchmark output, and the stand-in agent's
unmarked `PROJECT/src`. Each has a retained shell regression.

## Consequences

Old unmarked generated state must be moved aside manually, or a fresh path
chosen; scripts do not silently adopt it. A newly rotated supply-chain ledger
contains its ownership marker even when it holds no runs. The stand-in agent's
delete scene requires the fake project marker written by `plant()`.

These shell checks prevent accidental selection and ordinary symlink misuse.
Markers are not authentication against another same-user process, and shell
path validation does not pin directory descriptors against concurrent renames
or symlink replacement. Keep generated state private and stop a demo before
resetting it. The scripts are operator tooling, outside the engine's adversarial
filesystem enforcement boundary.

`scripts/demo-credentials_test.sh`, `scripts/demo-reset_test.sh` and
`scripts/cleanup-guards_test.sh` run in CI's `scripts-and-workflows` job and in
precommit. Their destructive cases use scratch trees and stand-ins, including
a stand-in `rm` for the real-root refusal probe.
The three demo kit directories are global fixtures in `tools/affected`, so an
in-between gate cannot skip the shell self-tests when their copied inputs change.

## Amendment: round 2 review (2026-11-03)

Directory emptiness must not be inferred from captured filenames: shell command
substitution removes trailing newlines, so `$(ls -A ...)` can hide an entry named
only with newlines. The shared output guard, demo claim functions and timing
budget output guard now use `find` to emit a fixed nonnewline character per
immediate entry, including hidden entries, and refuse on enumeration failure.
Ledger rotation uses the same enumeration excluding only its ownership marker.
Scratch regressions preserve valuable files under newline-only child directories
and verify refusal before a marker is written. Coverage and toolchain tests first
reproduced deletion of those files; all demo claim sites are also exercised.

Both demo `shq` functions write the opening quote, escaped bytes and closing quote
directly, without an inner command substitution that trims the value. Login
regressions cover one or multiple trailing newlines and newline-only values for
both supported variables, comparing received files with `cmp`. The main demo's
matching `q` helper also preserves bytes, with a retained regression that first
reproduced its argument truncation. Redacted command
output still uses the same single printer. These fixes preserve the operator
tooling boundary above; no authenticated agent or root-tier behavior is claimed.

## Amendment: BPF scratch migration (2026-11-04)

Integrating NET09's BPF changes with the cleanup guard makes precommit reproduce
objects in the legacy fixed-path scratch directory. An old successful check
leaves only an empty `lock` there, which the new guard initially refused as
unmarked state. Changing the scratch path would change the BTF bytes.

Only the BPF caller opts into migration of this lock-only directory. After the
usual physical-path and protected-directory checks, the guard requires an owned,
nonsymlink, single-link, empty regular lock file. It acquires its exclusive lock,
rechecks it and enumerates all other entries before creating the ownership marker.
No generated tree or other data may be present; hidden and newline-only entries,
aliases, nonempty locks and enumeration failures still refuse without claiming
the directory. Other callers retain the original new/empty-or-marked rule.
`scripts/check-bpf-objects_test.sh` reproduces the migration failure and covers
those refusals. The same-user path-replacement limit above remains.

The toolchain cache contains real files, so it has no such migration. Its default
is now `tego/bpf-toolcache` under the cache root; the old unmarked
`tego/bpf-toolchain` is left untouched. A fresh default fetches the pinned,
checksum-verified toolchain and writes its marker. Explicit unmarked nonempty
paths still refuse, even with a matching stamp.

The new cache basename has the same length as the old one. With identical pinned
compiler and libc hashes, `bpf-toolchain-owned` changed four generated objects and
their adoption metadata; both the legacy path and `bpf-toolcache` reproduced all
49 generated files exactly. Custom cache paths can therefore change the output;
the fixed-path reproduction check remains the authority. No generated object was
changed for this migration.
