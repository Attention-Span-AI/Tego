# ADR 0074: `tego test`, a self-check of this machine's enforcement on decoys

Status: **accepted 2026-10-26**; implemented 2026-10-26. Adds a command and a hidden verb; no record, contract or config schema change.

## Context

A person installing Tego, and any demo, need one command that shows the enforcement works on this machine, not in
a test suite on someone else's. `tego doctor` says which tier the kernel offers; it does not show an action being
refused. The conformance suite proves refusals, but they need the repository, root or a VM.
About eight tricks with per-tier expectations were planned; this ships the
four that every tier refuses, and leaves out the tier-dependent ones (LD_PRELOAD/exec-map, DNS, sudo, docker.sock, cron,
git hooks).

## Decision

1. **A subcommand of the tego binary, a Layer 2 black box.** `internal/selftest` starts the tego binary that is
   running (`os.Executable`) through `internal/platform/proc` and reads only what it prints: `tego __check`, `tego
   run` and `tego events <run> --json`. It never imports the engine (depguard `selftest-never-imports-runtime`:
   no `internal/runtime`, `internal/policy/decide`, `internal/bpf`, `internal/cli`, cilium/ebpf). Its starts are
   reviewed sites (ADR 0021 (6)): tego test's process holds no fanotify group.
2. **Four harmless actions, each run twice.** In one `os.MkdirTemp` tree (mode 0700, removed at the end) it makes a
   fake home with a fake SSH key and `.env`, a project whose `out/` is the one writable folder, a copy of `/bin/true`
   and a loopback TCP listener it owns on a free port. The actions: read the fake key, write `outside.txt` beside
   the project, run the copy of `/bin/true`, connect to the listener and send a sentinel. Each runs once directly
   ("without Tego": it must succeed, or a refusal proves nothing) and once as the agent of `tego run <embedded
   contract> -- tego __check <name> <workdir>` ("under Tego": it must be refused).
3. **The hidden verb is narrow.** `tego __check` (dispatched in cmd/tego before any CLI setup, like the child stage)
   takes exactly a check name from the fixed list and a workdir that is an absolute clean path named `work` in a
   `tego-selftest-*` directory, a real directory owned by the caller, holding the marker file with its exact text.
   Its `home/`, `home/.ssh/` and `bin/` must be real directories owned by the caller too, and every final open refuses
   a link, so a tree someone else laid out cannot lead a check off it. Every path it touches is fixed below that
   workdir (the port in the port file is the one value it takes from the tree; it runs as the caller, so it reaches
   nothing the caller could not). It prints one `tego-selftest-result {json}` line.
4. **The verdict is the ledger's, checked against the effect.** A row is `refused` only when the action did not
   take effect and the run's ledger holds a `refused` line for its target (or, failing an exact target, one with the
   check's reason, which the row marks `match: reason` and the screen says), whose rule and reason the report shows. It is `allowed` when the action took effect: the check
   says so, or the effect is there (the file exists, the listener accepted a connection during the run). It is
   `unrecorded` when the action failed but no refusal was recorded. The tier is run_start's.
5. **The embedded contract** grants `fs.write` on the project's `out/` only, `deny_read`s the fake key's directory
   and `.env`, has a `net:` section that allows nothing, an exec allow-list with only its command, `env.pass: []`,
   `record: full` (tier landlock records refused reads only then), `capture: off` and `limits.wall: 1m`. It sits
   beside the workdir, outside every write entry.
6. **The runs' records stay in the tree.** Each tego process gets `$TEGO_CONFIG` pointing at a layer in the tree:
   the caller's own `$TEGO_CONFIG` layer when there is one, and only once it passes the checks tego run's Load applies
   (owner and mode, one name, an absolute path off procfs: R20, ADR 0059; a layer tego run refuses is refused with exit
   125 and `[config-untrusted]`), with `ledger_root` replaced by the tree's `tego/ledger`
   (a sibling of the workdir, since tego refuses a write entry inside its own directory). The four runs never reach
   the person's ledger or dashboard. tego's chain anchor (`~/.tego/chain.log`) gets one line per run, as for every
   run: a test build sends it to `TEGO_TEST_CHAIN_ANCHOR`.
7. **Output and exit codes (R25).** One screen: `Tego self-check: 4 actions, 4 refused at tier landlock`, a row per
   action (without Tego, under Tego, the refusal's reason and rule), what the verdict means. `--json` prints the
   object `tego.selftest/v1` (docs/user/self-check.md), which only ever adds fields. Exit 0 when every action
   succeeded directly and was refused and recorded under Tego; 1 when one took effect or went unrecorded under Tego
   (whatever else happened); 2 on usage; 125 when a check could not be judged (a baseline that failed, a run that
   did not start, a ledger that could not be read) or tego test could not run. `--tier` pins each run's tier.

## Consequences

- The command runs in well under a second on the test machine (four runs plus four direct checks).
- A machine that cannot even run the baseline (no loopback) gets exit 125 with the row's reason, never a false pass.
  Without `/bin/true` the copy is of the first `true` on `$PATH`; with none at all, making the tree fails and the whole
  command exits 125 with `make the temporary tree: ...`.
- The tree is made in `$TMPDIR` unless that lies inside the tego binary's directory, where compile_fs refuses every
  write entry; then `$XDG_RUNTIME_DIR` or the user cache directory, else exit 125 asking to set `TMPDIR` elsewhere.
- The connect check's baseline counts only once the listener has accepted its connection, so a connection still in
  the backlog is never counted against the run under Tego.
- The four checks are the ones every tier refuses; what a tier lets through is not shown yet.
- A wider contract, a real-agent run or a check that touches a real path are out of scope by design.
- *Amended 2026-11-02:* exit 1 is shown end to end, not only by unit tests over the report and the judge. A binary
  built with `-tags tegotesthooks` fills the contract template `TEGO_TEST_SELFTEST_CONTRACT` names in place of the
  embedded one (a product build has no such switch; a template it cannot read or fill fails `tego test` with exit
  125), and `TestSelftestExitsOneOnAWeakenedContract` changes one line of the embedded contract there: listing the
  unlisted program makes that row `allowed`; denying the port file stops the connect check before it connects, so the
  run records a refused read of that file and nothing of the connection, and the row is `unrecorded`. Each time the
  other three rows stay refused and the command exits 1. Only the contract is wider: the engine and `tego run` are the
  product's, as in the conformance suite's self-test.
