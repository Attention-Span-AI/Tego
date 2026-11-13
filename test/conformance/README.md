# test/conformance

ADR 0017's kernel conformance suite. No model is inside it (ADR 0003).

## Reading a cell

A handwritten cell (`cells.go`) is one action of one fixture: a contract, the files it acts on, an op (`read`,
`write-open`, `rename`, `exec`, `connect-tcp`, ...) and, per column, the verdict and rule it must get. Cells are
written in `spec/policy/conformance/*.yaml` (schema v2; its README is the reference) and loaded by `fixtures.go`. A
table's columns are `landlock`, `cgroup/fanotify` (tier cgroup on the listener) and `plane`, which tier cgroup in the
plane modes `fmod_ret` and `lsm` and tier bpflsm answer as one column (`compile --test`'s plane rows, ADR 0019). In
Go a `Want` is keyed (tier, mode): the plane column is (bpflsm, lsm). An empty rule is not checked. Every cell owns
its paths, so the runner finds its ledger line by path.

Expectations are written from SEMANTICS and the specs, never taken from Evaluate or the Landlock plan.

One expectation depends on the kernel: below Landlock ABI 3 (before 6.2, AL2023's 6.1) Landlock cannot refuse
truncation, so tier 1's filter refuses every `truncate(2)` with `EPERM`, a truncate inside a write entry included,
and no ledger line records it (docs/p0/enforce-landlock.md E31). Every tier and plane mode keeps that filter, so there
the kernel runner wants each truncate cell refused, errno `EPERM`, no line (`Cell.WantOn`, from the Landlock ABI it
reads). `compile --test` has no truncate action: a truncate cell's row is `fs.write`, which is the contract's answer
and every tier's from ABI 3, so the compile runner asks it on every kernel.

### Command-rule cells (ADR 0048)

`execrules.yaml` and `execrules-allow.yaml` hold ADR 0048 P1's command-rule grid: `execrules`, a deny-list contract (`deny: [git push, rm -r]`,
`ask: [npm install]`), and `execrules-allow`, an allow list whose path entries with words constrain git. An exec cell
there carries its whole `Argv` (compile --test's `argv:`), and a script cell its `#!` argument (`ScriptArg`,
`script_arg:`) and the interpreter its walk reaches (`Runs`). Each exec runs a copy of the actor under the ruled
tool's name in a directory of its own; the actor marks the child, which exits 0 at once, so a refusal is the exec's
own `EACCES`. P1 decides command rules in the supervisor at every tier, so each cell has one expectation for every
tier and plane mode. The `multicall-*` cells each run one actor file under two hard links (`t/mcN/ls`,
`t/mcN/xrm`), a multicall image, whose names the matcher reads for the applet upstream uutils would run (ADR 0048 (2)
4, amended 2026-11-11); their `runs:` names that applet for the invariant, and compile --test, which stats no file,
skips them. `invariants_exec.go` adds the command-rule invariant: no exec runs a program a deny or ask
entry names with that entry's words, read from the contract and the cell alone, never from the matcher.

### The exec space (ADR 0017 space 2)

`exec.yaml`, `execloader.yaml` and `execanon.yaml` hold the other spellings of an exec and of executable code, each an
op of the actor (`cmd/actor/spell.go`): the direct loader (`exec-loader`, `ld.so /usr/bin/true` with the loader the
machine's `/usr/bin/true` names, `{{LOADER}}`; refused where no exec.allow entry lists it, run where `execloader`
lists it), an exec by an `O_PATH` descriptor (`execveat-fd`, `AT_EMPTY_PATH`) and by `/proc/self/fd/N`
(`exec-proc-fd`), which follow the inode; anonymous images (`memfd-create`, `memfd-exec`, `memfd-map-exec`), refused at
creation, `EACCES` and no line, where the kernel honours `MFD_NOEXEC_SEAL`, and elsewhere refused `ENOSYS` at tiers 1
and 2 and decided by the plane (the cells' `want_where`, from the probe `Machine.MemfdNoexecSeal`), and allowed at
every tier under `exec: {anonymous: true}` (`execanon`), each memfd op first performed as the agent outside every
run, which must succeed (`memfdControl`: a `vm.memfd_noexec` of 1 or 2 would give the cells' `EACCES` with no line
itself, `TestMemfdControlSeesTheSysctl`); and ADR 0027's map spellings (`map-exec-rie`,
`mprotect-exec`, `mprotect-rie`, `execmod`, `execmem`), refused `exec-map` by the plane and decided by no mapping
hook at tiers 1 and 2. An op that changes the actor for good (an exec that replaces it, a personality) runs in the
actor's `spell` stage, whose exit carries the errno. The supervisor records an exec spelled `/proc/self/fd/N` under
that path (its allow rule names the image it resolved), so the runner finds that line by the actor's `argv[0]`.
`TestEveryTableOpHasAnActorOp` holds every op a table may name to one the actor performs.

### deny_write ancestors and TOCTOU (ADR 0017 space 4)

`denywrite-ancestors.yaml` changes a built-in `deny_write` target every way but writing it: new names inside it
(`mkdir`, `symlink`, `link`, and `mknod`'s FIFO), an `rmdir` and `rename` of the target directory and a `rename` of
`.git` above it, refused on every axis (supervisor R15c), and its attributes (`chmod`, `chown`, `setxattr`'s
`user.tego`, and `setfacl`, the minimal ACL of mode 0640 as its `system.posix_acl_access` xattr), refused only where
a plane decides (enforce-plane R12); `chmod` is recorded and let through below it. A column a cell states nothing
for names why in `unasked` (the xattr below the plane: no tier decides it, and tmpfs below 6.6 has no user xattrs).
The effect judge holds a refused attribute op to the owner, mode and xattrs the snapshot records.

`toctou.yaml` is the racing-thread harness (`cmd/actor/race.go`): one thread swaps the symlink `path` between a
benign file and the target `dest` (also the cell's `canon`) with `rename(2)`, the other opens `path` 2,000 times or
for 2 s and reads (`race-symlink-read`) or appends a byte (`race-symlink-write`). It succeeds when a byte of the target
went through, the fail-open the invariants catch, and is refused when none did, an open of the target was refused
and benign opens went through; anything else, a race that never interleaved, is no answer. One action is thousands of
opens, so its ledger check is that no line names the target with an allow, and, where the kernel's own recorder
answers (the listener, the plane), that a refused race has at least one refused line of its target. At tier landlock
the target has no line: the supervisor's lines are advisory (ADR 0016 (2)) and name the link the agent spelled, each
with the model's prediction for what the link led to when the supervisor resolved it, which the swap can change before
the kernel's open, so they disagree with the kernel both ways and go unjudged. The read race is asked on every axis;
the write race, of a `deny_write` target, on the plane axes only (best effort below, `unasked`).

### Mounts (ADR 0017 space 5)

A fixture's `mounts` are made by the root runner in a mount namespace of the run's own: the test binary, started again
with `TEGO_CONFORMANCE_MOUNTNS` under `CLONE_NEWNS` (`mountns_test.go`), mounts them, snapshots the tree for the
effect judge, runs tego as its child and snapshots it again, so the run's launcher compiles and prepares against the
mounts and the host's namespace never sees them. btrfs is the embedded empty image `testdata/btrfs-mixed-16m.img.gz`
loop-mounted, its subvolumes made with `BTRFS_IOC_SUBVOL_CREATE`. A kernel with no such filesystem fails the run when
`TEGO_CONFORMANCE_FS_REQUIRE` names it (root-suites.sh names those its guests load) and is logged `MOUNTS-ABSENT`
otherwise; without root the fixture is logged `MOUNTS ... not run`. A fixture's mounts are made together, so the bind
mounts every kernel has are `mounts-bind.yaml`'s, apart from the overlay (`mounts.yaml`) and btrfs
(`mounts-btrfs.yaml`) a row may lack, and run on every root row; `TestModuleMountsStandAlone` fails a fixture that
mixes the two.

The bind fixtures follow the startup limit in ADR 0011 and ADR 0025. Wherever tier cgroup's listener would decide a
compiled `deny_read` path entry, an alias on the same filesystem instance of its tree or part of it refuses before
the actor starts (`listener_refuses`), including after a plane falls back. This applies to `mounts-bind.yaml`'s nested read and the existing `mounts-bindmove.yaml`,
`mounts-bindhidden.yaml` and `mounts-bindsub.yaml` fixtures. `mounts-bindfile.yaml`'s file and directory aliases are
detached parts (`plane_cannot_hold`): tier bpflsm refuses before the actor starts, and tier cgroup falls back and
refuses at the listener. Selected planes retain their whole-tree handling on the same filesystem instance,
including the whole-tree fixtures that have no detached part. The second-round `mounts-bindancestor.yaml` and `mounts-bindask.yaml` fixtures cover another
ancestor route and an approval scope with the same startup refusal. These expectations check exit 125 and an
unchanged tree instead of trying an action after a refused start.

Different filesystem instances showing the same data are not recognised at any tier, and name-entry scopes receive
no alias check (GAPS C68).

The changed expectations compile and have unit checks; they are owed in a guest on Debian 13's 6.12 and Fedora's
7.0, both boots. Saved fix-round-1 guest baselines show `mounts-bindmove` and `mounts-bindhidden` failing before that
fix, while `mounts-bindsub` passed before and after. Source inspection shows that a built-in project name scope
masked its extra-device case. `TestOrdinarySubmountListenerHandoffEmitsOneRefusal` uses an ordinary denied entry and
a different-device submount outside every name scope, and asserts exactly one refusal through the actual listener's
marked-device handoff. That is unit evidence, not a new kernel result.

### A third party's refusal (ADR 0017 space 6)

`thirdparty.yaml` names a file in `third_party_deny`: the root runner starts `test/vm/cmd/permlistener -mode deny -path
<file>` (a HELPERS binary in the guest) before the run and stops it after, and a listener that refused no open is a
problem of the run. The kernel's answer is that listener's `EPERM` on every axis, while the ledger line is Tego's own
answer (ADR 0016), which the cell's want states with `ledger:`: `allow` from the supervisor at tier landlock, and where
the kernel's recorder writes the line (tier cgroup, the plane), `observed` (`by: other`) where the listener's refusal is
in security_file_open's return and the chain's `allow` where the event runs after it (`want_where: fanotify_in_chain`,
which the root runner measures before the axes run, `fanotifyInChain`: upstream up to 6.12 and 6.13 on, but Debian 13's
6.12.107 has 6.13's order; it read `kernel_max` until 2026-11-11), measured on 6.17, AL2023's 6.1 and Debian's 6.12.107. Without root the fixture is logged `THIRD-PARTY ... not
run`, since a fanotify listener needs `CAP_SYS_ADMIN`. The probe cancels on its outer deadline and joins its worker
before removing its files. Root-free unit tests cover cancellation, joining and group closure. Synchronous BPF load
and attachment calls must return before cleanup can finish, so the 30-second cancellation deadline is not a hard
completion bound; actual kernel cancellation is owed in a guest.

### Process and control calls (FEATURES E54)

`control.yaml` holds the agent's own ptrace, keyring and bpf(2) calls as a product run has them (the
actor's `cmd/actor/control.go`): an attach to a child in the run is allowed everywhere, and one to a process outside
every run (`{{HOSTPID}}`, the actor's host stage, which the runner starts with the agent's uid and which lets that
uid trace it, `PR_SET_PTRACER_ANY`, so that Yama's `ptrace_scope` 1 does not give the same EPERM; the runner's
control attaches to it as the agent outside every run first, and the fixture fails if the machine refuses that) is
Landlock's EPERM with no line, or the
plane's EACCES with a `process-scope` line on an axis whose plane answers first (`want_where: plane_first`, set per
axis by the kernel runner: fmod_ret, or bpf ahead of landlock in `/sys/kernel/security/lsm`). A TRACEME asked of the
actor is allowed; one asked of a parent outside the run, by an orphaned grandchild of the actor of the subreaper it
was reparented to, is admitted by Landlock and refused by the plane in both modes. `keyctl`, `add_key` and
`request_key` are the supervisor's keyring refusals (EPERM, rule `keyring`) unless the contract says `keyring: true`
(`control-keyring.yaml`, allowed with no verdict line); `bpf(2)` is the filter's EPERM at tiers 2 and 3, no line.
`kernel.unprivileged_bpf_disabled` gives that EPERM too, ahead of every hook, so under root on a disposable host
(`TEGO_DISPOSABLE_HOST`: every KVM guest, a GitHub Actions runner) the runner lowers its 2 to 0 for the fixture's run,
restores it when the fixture ends, and first creates the map as the agent outside every run (`bpfControl`): the
fixture fails if that is refused (1 cannot be lowered until reboot). The restore is the fixture's cleanup, which a run
that times out or is killed never reaches, so on any other machine a 2 fails the fixture, naming
`TEGO_DISPOSABLE_HOST`, and the host is never changed. Each control marks itself passed, and a fixture whose cells
ask a control that did not pass fails (`missingControls`). A
process cell's line is a refused line of its op, found for a ptrace op by the pid the actor reports as its value. The
plane's keyring and bpf hooks behind the filter (the filter-omit test seam), an attach to another run, a task root
moved out of the run and record: off stay in internal/runtime/enforce/cgroup's `plane_control_integration_test.go`.

`execrules.yaml`'s `argv-race` is ADR 0048's disclosed argv race (R5): 500 attempts or 2 s, each a stage of the actor
(`cmd/actor/argvrace.go`) that execs the ruled copy with argv[1] in a buffer another thread flips between the denied
word and `diff`; the copy reports the word it ran with. It is refused when an attempt was refused, its lines are those
whose copied argv read the denied word, none of which may say allow (the closed direction), and a refused race has at
least one refused line on every axis, tier landlock included, since they are the supervisor's own exec refusals
everywhere (ADR 0048 (3)), unlike the symlink races' advisory landlock lines; the wins, attempts that
ran the denied word after an allowed copy, are its value, logged and never judged. `execute-only-image` is a 0111 copy
(`exec_only_actors`), refused image-unreadable where the supervisor runs as the agent and by its command rule where it
is root (`want_where: supervisor_root`). `capture.yaml` connects to the capture forwarder's listener at the address
the agent's `$ANTHROPIC_BASE_URL` names (`addr: $ANTHROPIC_BASE_URL`), allowed by the runtime's grant
`net.capture[<addr>]` (the cell's rule names the address `{{PEER}}`). No table defers a cell.

### Name entries (ADR 0043's conformance space)

`names.yaml` holds the built-in `.env` pair a contract whose `deny_read` is not `[]` carries, scoped to the project
(ADR 0043 D10). Its `later` files are written by the kernel runner, a process outside the run, after the run compiled
and filled its rules and before the first cell: the actor's script starts with the runner's own `await-later` action
(never a cell), which prints `{"await":"ready"}` and waits until the file `await-go` exists; the runner reads the line
from the run's stdout, writes the later files (owned by the agent), snapshots the tree the cells find, then writes
`await-go` (`runAwaiting`, TestRunAwaitingWritesLaterFilesBetween). No compile-time expansion holds a later file, so
tier landlock allows reading and changing one (the expansion only) while the listener and its supervisor refuse it at
tier cgroup and the plane refuses it (D7): a read, a write-open, its creation (`O_CREAT`, `mknod`, a symlink, a hard
link's new name, a rename's destination), unlink, truncate and a rename from it, the folded `.ENV.Prod`, and a file a
checkout made (`.env.development`); `.env.example` (an exception), a `.env` beneath `node_modules` (a dependency
directory, D4), a directory named `.env.d` (D1 never decides a directory) and a write entry at the file's own place
(D3) are allowed everywhere; a directory renamed beneath `node_modules` leaves coverage and is refused where name
entries are enforced (D5). The model's `names` are written from the ADR, and `invariants.go`'s name invariant holds
D1 from them at tier cgroup and the plane (TestNameInvariant); `RunCapabilityCrossCheck` holds
`fs.deny_read.created_later` false wherever no plane mode decided the run and, for a model that declares its name
entries, true where one did. Every other table, and the generated spaces, name no path the built-in pair covers and
declare no `deny_read` glob (TestNoCellMeetsAnUnmodelledNameEntry), so their models need no `names`.

### ADR 0032's detector

`execcheck_integration_test.go` holds ADR 0032's revisit condition to a test rather than to memory.
`TestExecveCheckDetector` runs the actor in one governed run per tier the machine offers (landlock, and cgroup on the
listener as root), on two 0755 scripts (so the file mode answers neither). The run half,
`execveat(AT_EMPTY_PATH|AT_EXECVE_CHECK)` on a script outside exec.allow, must be the run's `EACCES` on every kernel
(the supervisor's exec arm answers before the kernel's check; Landlock's `EXECUTE` floor stands behind it). The kernel
half asks the same of a script exec.allow lists, which reaches the kernel: from 6.14 its check must pass the script
without an exec, and below 6.14 the kernel must refuse the unknown flag (`EINVAL`, logged `n/a`). Each of bash, dash,
python3 and node present runs the unlisted script with and without
`SECBIT_EXEC_RESTRICT_FILE`, which the actor's `restrict-exec` stage sets on itself. One that refuses it with the bit
and runs it without fails the test, "ADR 0032 revisit condition met"; below 6.14 every result is logged `n/a`. The
actor under the name `check-interp` is an interpreter that honours the bit, which the detector must catch (its
self-test). `TestChildNeverSetsExecRestrictBits` holds the agent's securebits 8-11 clear. Neither is a table cell:
their verdicts are facts about the row, not an allow or a refusal, and no baseline entry holds them. Both fail, as
`TestConformanceKernel` does, when `TEGO_CONFORMANCE_REQUIRE` names cgroup and the setup cannot run that tier (no root,
no tegobpf build, or `tego doctor --require cgroup` failing), rather than pass on the tier landlock axis alone
(`TestExecCheckSetupFailsARequiredAxis`).

## Generated spaces

`gen.go` generates spaces deterministically (no randomness, a fixed order), each a name in `Spaces()`. Space 1,
`fsgrid`, is every assignment of the entry kinds none, write, deny_read and watch to the nested directories `a`,
`a/b` and `a/b/c`: 64 contracts (fixtures `grid-<kind>.<kind>.<kind>`), each performing 13 actions at every depth,
each on a path of its own (read, write-open, an `O_CREAT|O_EXCL` create, an `O_TRUNC` open, truncate, unlink, mkdir,
rmdir, a rename within the directory and one to the next depth, the deepest back to `a`, a hard link, a symlink and
chmod): 39 cells a contract, 2,496 an axis. The contract and the model are rendered from the same assignment.

A generated cell has no want: the kernel is its judge (ADR 0017 D1). On every axis its run is checked
kernel == compile --test's column for the axis (`landlock`, `cgroup` on the listener, `bpflsm` for the plane modes
and tier bpflsm; runner `parity`), the ledger line against the kernel's verdict and, where the column agrees, the
column's rule (runner `ledger`), but for the known naming classes of `naming.go` (`KnownRuleNaming`; ADR 0017's
2026-10-19 note), which are counted on the axis' `AXIS` line (`namings=`) and in the
report rows (`naming`), never baselined; and against the invariants and the effect judge. The kernel, parity and ledger
checks of a cell are one function, `judgeAnswers` (judge_answers_test.go, pinned by TestJudgeAnswers), and an axis that
ran a generated fixture with a column and held no ledger rule to it (`rules-compared=0` on its `AXIS` line) fails the
test; a fixture that `-run` or `-skip` left out did not run and does not count, and its baseline entries are neither
applied nor stale on that axis (`NotRunKey`), so a run narrowed to handwritten fixtures, or to one, passes. The columns are asked once per
fixture before the axes run, outside their budgets. The unprivileged compile runner feeds every allow compile
answers for a generated cell to the invariants as if the kernel had allowed it: a violation is a
`COMPILE-OVER-GRANT`, the decide core granting what the contract refuses, and no baseline holds one. The kernel
runner logs a handwritten cell's `CELL` line always and a generated cell's only when the cell drew a judgement (a
failure, fail-open, effect, problem or finding); every generated cell's answers are in the report rows
(`TEGO_CONFORMANCE_REPORT`, below). A guest's serial console made the 2,496 lines an axis cost the landlock axis its
10 s budget.

`testdata/generated.txt` is the manifest: per space its sha256 (over the fixtures' JSON) and counts, then every cell
ID. `TestGeneratedManifest` fails on any drift; review the change, then
`go test ./test/conformance -run TestGeneratedManifest -conformance.update=fsgrid` rewrites it.

`TEGO_CONFORMANCE_SPACES` selects what both runners run: unset, the handwritten cells and every space whose
`PerPR` is set (`fsgrid` is); `all`, every space (the nightly matrix); or a comma-separated list. A run narrowed to
some spaces checks only their baseline entries and cannot write the baseline.

The self-tests: `TestJudgeCatchesAMutatedContract` (`selftest_integration_test.go`) runs contracts that grant more
than their model (a second write entry, an exec.allow directory) for real, on the landlock axis and as root on one
plane axis, and requires the report to hold exactly that fail-open; `TestJudgeCatchesSyntheticOutcomes` makes every
grid action succeed and requires every filesystem invariant class to fire at the tier where it binds.

## Runners

- `go test ./test/conformance` needs no privilege: each cell against `tego compile --test` per tier, plus the table's
  own checks and the invariants' self-test. Its tego is the `tegobpf` build (the committed objects; no kernel
  call), whose reach holds tiers cgroup and bpflsm: a landlock-only build compiles no name entry (ADR 0043
  Consequence 11) and would answer a name cell's root columns as if none existed.
- `go test -tags integration ./test/conformance` without root runs the kernel runner's tier landlock axis alone, as
  the caller (no chown, no BPF build): CI's unprivileged integration step and `make integration` run it, it fails when
  `TEGO_CONFORMANCE_REQUIRE` names an axis that needs root, and it skips only where `tego doctor --require
  landlock` fails, which the integration skip gate does not allow. It takes about a second.
- `sudo go test -tags integration ./test/conformance` (or `VM_OUT=... test/vm/root-suites.sh test/conformance`, the
  guest CI's root-suites job runs) performs each fixture's actions in one real `tego run` per tier, through the static
  `cmd/actor`, and checks the kernel's own result (the judge), the ledger line (verdict, rule, at most one line) and the
  invariants of `invariants.go`, which read only the contract's declared entries. Tier cgroup runs on the fanotify
  listener and once per decision-plane mode doctor passes (`fmod_ret`, and `lsm` where `bpf` is an active LSM), each
  pinned with the test build's `TEGO_TEST_PLANE`; a plane mode's failures are named and baselined under
  `cgroup@<mode>`. The `denywrite` fixture runs on every axis, its targets refused by the supervisor best effort
  where no plane decides; `denywrite-kernel`, the same contract under `fs.assurance: kernel`, is refused on the
  landlock and listener axes before its actor acts (exit 125, logged as `STARTUP`) and runs its cells where a plane
  decides (ADR 0041 D1 (a)). The `fs`, `link` and `denywrite` fixtures run once more as `fs-held`, `link-held` and
  `denywrite-held`: the same cells and expectations under a gate with `completion: held` whose rules can score past
  `allow` and score none of their actions, so every open of the run is completed by the run's open deputy (ADR 0041
  Stage B) and each cell is held to the answer the kernel path gives; the run's `best_effort` must not list the open
  cells (`Model.HeldOpens`), or the deputy did not start.

Both build tego with `tegotesthooks` and point its ledger, chain anchor and own log into the test directory, for
every `tego` command they start (`doctor` included), so an unprivileged run touches nothing under the caller's
`~/.tego`.

## What the kernel runner judges

Per cell and axis, besides the kernel's result, the ledger line and the parity column:

- **Invariants** (`invariants.go`), from the contract's declared entries alone. The nearest declared write or deny_read
  entry decides a read and every name a mutation touches (SEMANTICS §2), so a deny_read nested in a write entry holds a
  mutation beneath it where the tier enforces it, and a write entry nested in that deny_read grants it again. Every
  exec spelling (loader, descriptor, `/proc/self/fd`, the argv race) is held to exec.allow and the command rules, an
  anonymous image to the memfd arm, a writable mapping made executable to exec.allow where the plane decides maps, a
  ptrace to the run's boundary (an attach out of the run on every tier, a TRACEME of an outside tracer where the plane
  decides), the keyring calls to `model.keyring`, and `bpf(2)` to tiers 2 and 3's refusal. Each arm has a case in
  `TestInvariantsCatchAFailOpen` that fails when the arm is removed: an allow there is a fail-open, never a baselinable
  kernel failure.
- **Effects** (`effects.go`). The runner snapshots the project tree (lstat, size, sha256 of small files) before and
  after the run. A refused create, creat, mkdir, symlink or link leaves no new name; a refused unlink or rmdir leaves
  the name; a refused rename leaves the source and no destination; a refused exchange leaves each name holding what
  it held, and an allowed one swaps them; a refused truncate or chmod leaves the content or the mode.
  A refusal that left its effect is a fail-open on every axis, with no residue granted. Tier cgroup's fanotify
  listener on its own answers an `O_CREAT` open after the kernel created the inode, so a create it alone refuses leaves
  an empty file (docs/p0/enforce-cgroup-observe.md), but on that axis the supervisor refuses a create, a creat or any
  other mutation beneath the nested `deny_read` before the kernel acts (ADR 0021 (5)), so even an empty file a refused
  create or creat left is a fail-open. The two cells that make a file there, the fs fixture's creat and fsplan's
  `O_CREAT|O_EXCL` create, want `EACCES` (the supervisor's, and a plane hook's on the plane axes), not the `EPERM` of
  the listener's own `FAN_DENY`. A success the tree does not show (`EFFECT`) fails as well. A later
  successful rename of a directory (the fs fixture's last cell) is followed, so the earlier cells are judged where
  their names now are.
- **Capabilities** (`capability.go`). The invariants bind where the oracle's predicates (`denyReadEnforced`,
  `denyWriteEnforced`) say a tier enforces an entry, and those predicates are held to what the product reports: each
  run's `run_start` (`capabilities["fs.deny_read"]`, `best_effort` holding `deny_write/default`, the
  `decision_plane` the axis pinned, and `capabilities["fs.protected_write_targets"]`, which must be true exactly where
  that decision plane is `lsm` or `fmod_ret`, ADR 0041 D7), and, in the unprivileged runner, `tego compile --json`'s per-entry `unenforced`,
  `best_effort` and `kernel_plane_required` markers. Held reads (ADR 0069, 2026-10-25) split the deny_read predicate:
  `denyReadRulesetEnforced` is the Landlock ruleset's fact (compile's `unenforced` marker, and what decides the
  modifications beneath a nested entry), `denyReadEnforced` the reads, which tier landlock refuses beneath a write entry
  too unless the model's `reads` is `direct`; compile's `reads.landlock` must be `held` where only held reads refuse a
  declared entry, and `direct` under `fs.reads: direct`. A product that claims what the oracle says the tier lacks is a
  `capability over-claim`; an oracle that holds the tier to more than the product documents is `oracle stricter than
  product`; one side is then fixed, the oracle or the product and its docs.

Fail-opens, effects and capability problems fail the test and are never baselined. Each axis logs `AXIS <label>
runs=N wall=Xs ...`. The budget (ADR 0017) is at most 600 runs and 180 s per axis, and 10 s for the landlock axis; a
miss is logged `TARGET-MISS` with its number, and fails the test under `TEGO_CONFORMANCE_BUDGET=strict`. Nothing in
CI sets that yet: a guest run sets it by hand (test/vm/root-suites.sh passes it through).
`TEGO_CONFORMANCE_REPORT=<file>` appends one JSON line per cell and axis: `row, kernel, abi, arch, boot, axis, cell,
kernel_verdict, errno, ledger, compile, effect`; `TEGO_CONFORMANCE_REPORT=-` prints each to the test's output after
`CONFORMANCE-ROW `, which is how a KVM guest reports (its console is the only way out). test/vm/root-suites.sh passes
`TEGO_CONFORMANCE_BUDGET`, `TEGO_CONFORMANCE_REPORT` and `TEGO_VM_ROW` through to the suite when they are set, in
both host modes.

## Baseline and findings

`testdata/baseline.json` lists the (cell, runner, tier) that fail today, each with a reason. A new failure fails, and
so does an entry that now passes: drop it (`-conformance.update`, below, does). Runners are `compile`, `kernel`,
`ledger` and `parity`. A cell where the kernel allows what an invariant refuses is a fail-open: it is never baselined.
Mark it `Finding` (with `FindingAt`), and the root runner reports it and fails once it is fixed.
A stated per-tier exception of SEMANTICS §2 is no finding: mark the cell `Exception` (with `ExceptionAt`) and give that
tier the allow it has.

### Where an entry holds

An entry may carry a `where` object that says which machines it was written for. Every field that is set must match
the machine, a field left out matches any machine, and an entry with no `where` holds on all of them.

| field | matches |
|---|---|
| `kernel_min`, `kernel_max` | `uname -r`'s major.minor, inclusive, compared as numbers: `"6.1"` with `"6.1"` is every 6.1.x, and 6.17 is above 6.9. No patch level. |
| `abi_min`, `abi_max` | the Landlock ABI, inclusive. A machine with no Landlock satisfies no abi bound. |
| `arch` | `amd64` or `arm64` (GOARCH, not `uname -m`). |
| `bpf_lsm` | `true`: bpf is among the kernel's active LSMs (the `lsm=...,bpf` boot); `false`: it is not. |
| `row` | the kernel matrix row, `$TEGO_VM_ROW`, which `test/vm/root-suites.sh` sets in each guest when it is run with `TEGO_VM_ROW=<row>`. Unset on a dev box, where a `row` bound matches nothing. |
| `bpf_perf_link` | `true`: the kernel makes BPF perf links (upstream 5.15, or a backport such as RHEL 9.8's 5.14), a probe as root (`bpfPerfLink`), never the version; `false`: it does not, or the run is not root. The decision plane's exec outcome tracepoints attach only as such links. |

A run reads only the entries whose `where` matches the machine it ran on. An entry written for another machine is not
applied (the disagreement it excuses there is a new failure here) and is never stale here, so one baseline holds the
entry for 6.1 and the entry for 6.17 of a cell that disagrees on both. Each runner logs the machine it read the baseline
for (`baseline machine: kernel 6.17, Landlock ABI 7, amd64, bpf LSM true, bpf perf link true, row ""`), the facts a `where` is written
from. The file is read strictly: a field it does not know, a kernel bound that is not major.minor and a reversed range
are errors, because a misspelt `where` key dropped silently would widen the entry.

### Canonical form

`baseline.json` is its own canonical encoding: entries sorted by key (`runner|cell|tier`) and then by `where`, two-space
JSON, `<`, `>` and `&` as written, one final newline; an empty baseline is `[]`. `TestBaselineCanonical` holds the file
to it, so a hand edit that reorders or reindents it fails. Every update rewrites the file canonically, and
`go test ./test/conformance -run TestBaselineCanonical -conformance.update=<space>` does only that.

### Updating: `-conformance.update=<space>`

```
go test ./test/conformance -run TestConformanceCompile -conformance.update=<space>
sudo go test -tags integration,tegobpf ./test/conformance -run TestConformanceKernel -conformance.update=<space>
```

The flag rewrites the baseline from the run that has it. It drops the entries the run could judge (the pair of runner and
tier ran, and the entry's `where` matches this machine) that now pass; it keeps every other entry as it is; and it adds
each new disagreement of the named space's cells as an entry with the reason `TODO` and this machine's `where` (kernel,
ABI, arch, bpf LSM state, and the row inside the matrix), as narrow as the machine allows. `compile --test` makes no
kernel call, so its entries get no `where`. You then write each reason and widen each `where` to the machines the
disagreement is known to hold on: `TestBaselineIsWellFormed` fails on a `TODO` reason, so the output cannot be committed
unexplained. New cells enter the baseline only in the PR that adds their space, and a space is a name in `Spaces()`
(`baseline.go`): `handwritten` is the cells of the tables in `spec/policy/conformance`.

The update refuses, exits non-zero and writes nothing when:

- the run had a fail-open, an effect violation, a finding that changed or any other error the baseline cannot excuse
  (a failed test is an unsound one);
- a new disagreement belongs to another space or to no space, or the space does not exist;
- a disagreement is reported under a runner no baseline can hold (`invariant`);
- `-run` filters below a whole runner (`TestConformanceKernel/...`) or `-skip` is given, since the cells it did not run
  would read as entries that now pass.

It writes the file where the test runs, so run it on a dev box, not in the KVM guest, whose copy of the tree is thrown
away. A file written under `sudo` keeps its mode and owner.

To add cells: add them to a fixture with distinct paths, run both runners, and put only the disagreements that belong in
the baseline there, with their reason. A table's `deferred:` list (`Deferred()`) names what later spaces of ADR 0017 add.
