# Find the contracts Tego knows

Run `tego contracts` to see the rules files Tego found for you on this machine. It checks today's files without
starting an agent, adding a rule or changing a file. Use `tego contracts show <name>` to read one contract's rules
with their sources. If a name appears twice, give the file's path, such as `tego contracts show ./agent.yaml`.

The list includes your configured user registry (normally `~/.config/tego/agents/`), the current project's
`agent.yaml` and `.tego/agents/`, contract files named by recorded runs in the selected ledger root, and those
runs' project registries. It lists every place consulted, including absent and unreadable places. A contract that
fails to parse stays in the list, with its first error and the file and line. Missing, unreadable and unsafe files
stay visible too. It does not search the disk or other homes.

The shipped `tego-agent@<name>.service` example uses the user registry, so its contracts already appear there,
including ones that never ran. The list does not ask systemd for unit state or read arbitrary `ExecStart` commands.
Not built yet. A separate deployment/service registry has no implementation in this version.

Each row shows the name, file, offline check result, contract hash, newest recorded start time, that run's tier and
whether its contract hash matches today's merged contract. `never` means there is no run for this file in the
selected record. It does not mean the file never ran elsewhere. `yes` and `no` compare canonical merged contract
text, including profiles and presets. The text header says `SAME TEXT AS LAST RUN`; it does not compare effective
rules. Comments and formatting do not change that hash. `unknown` means a hash,
tier or today's source is unavailable. `not-enforced` means the last run only observed; it held no rule.

Use `-v` or `--verbose` for full hashes, run ids, working directories, file aliases and every compile warning.
Registry aliases of the same checked file are one contract, as they are when Tego resolves a name. Without that flag,
the list shows the first 12 hash digits. `show` lists each rule's source file and line, distinguishing profiles,
presets, built-in defaults and machine-config ceilings. `show -v` also prints the exact table used by `tego compile`.

These are current-source previews. DNS is deferred with an immediate resolver; no lookup is sent. Program names
use the caller's current PATH and are inspected without executing them. Relative paths use the newest recorded
working directory, or the selected project for a file that has no run. Today's invoking user's passwd home and
machine config supply the remaining context. An unavailable project, unknown recorded owner or a different owner
whose context is not selected makes checking incomplete. Historical files pass the same bounded, no-follow and
ownership guards used by the rules editor. Registry files use the registry's contained, trusted loader, which permits
relative links that stay inside its root. No system service or other user's home is searched, even when run as root.

Hashes are read from run starts without verifying their chains. Equality says nothing about a run's tier,
capabilities, runtime grants or live changes. Use `tego events <run> --verify` to check the record. Launch still checks
the contract and backend at its start. A preview cannot promise that a launch will succeed.

Both commands accept `--json`. The schema names are `tego.contracts.v1` and `tego.contracts.show.v1`, published in
[spec/contracts/v1](../../spec/contracts/v1/README.md). JSON always carries the scope footer and full hashes.

Exit 0 means every listed source checked successfully and names were unambiguous. Exit 1 is a contract finding,
missing file or ambiguous name. Exit 2 is usage. Exit 125 means unsafe or unreadable input, an incomplete check,
or an output failure. An explicit path skips discovery, but a saturated helper budget can still leave that file
unchecked. Selecting by name requires complete discovery; use a path when an unreadable registry prevents
proving the name unique.

Listings retain at most 4,096 contracts and 32 MiB of registry source bytes. Each registry lists at most 4,096
directory entries; run discovery uses the ledger view's run bound and a 32 MiB metadata estimate. Reaching a bound is explicit and returns 125.
The footer always says what is missing: contracts in folders Tego has never seen, and other users' contracts without
root. Root can see additional references in its selected ledger, but the source guards and unknown-owner checks
still apply.

The command carries a 60-second deadline, and each contract check and registry scan stops waiting after 5 seconds.
Cancellation stops waiting for filesystem work; unfinished entries say `incomplete` with a diagnostic and
return 125. Recorded-path checks run in a reexecuted helper, so the command holds no thread in that mount.
One helper serves the checks of a command in sequence. An abandoned helper or a transport/credential refusal needs a replacement.
Helpers retain the caller's credentials, checked before each request, and receive an empty exec environment.
At most 32 workers may remain alive for one effective uid in one network namespace across repeated commands
and dashboard requests. All checks for a page, including its feed, link references and guide bootstrap, share its request and worker. Each worker can briefly have one short launcher too. A kernel reservation lasts until the
worker exits, including after a command stops waiting. Further checks report incomplete when every slot is held.
Late replies are discarded. A worker blocked in a dead mount can remain until recovery. This limit allows
16 simultaneous healthy commands plus 16 slots of headroom; it does not guarantee availability under arbitrary load.
The dashboard uses the same helper from its own binary for recorded paths and user-supplied locations.
An unavailable entry stays listed with `cannot tell: this location does not answer (a disconnected or stuck mount?)`;
source-read EIO, ENOTCONN or timeout has this state even when metadata answers. Those words are used only when the
checker was running, the location did not answer within five seconds, and the checker was not simply kept off the processor by
a busy machine: Tego looks at the checker's own scheduler counters when the five seconds end, and a checker that waited for a
processor for half of them, or that was running on one for half of them, is given five more, up to 20 seconds in all for a
check or a page. If it is still starved then, the
entry says `cannot tell: Tego's checker was too slow to finish (the machine is very busy); try again` (or, for one that was
working the whole time, `cannot tell: the check was still working when its time ran out; try again`), and if Tego cannot read
the counters (a kernel without scheduler statistics) it says `cannot tell: the check did not finish in time (a stuck location,
or a very busy machine)`, which claims neither cause. If the checker was waiting for this computer's own disk to finish a
write (a busy or nearly full disk), it says `cannot tell: this computer's disk did not finish writing in time (the disk is very
busy or nearly full); try again`, after the same extra time (up to 20 seconds in all), because a slow disk answers in the end. When the machine is too busy to start the
checker at all (it has 30 seconds), the entry says `cannot tell: Tego's checker did not start in time (the machine
is very busy); try again` instead: the location was never asked, nothing was changed, and asking again is safe. If the checker
could not start at all, the entry says `cannot tell: Tego's checker could not start:` and why, and when every checker slot is
taken by helpers Tego cannot tell more about, it says how many are alive and that it cannot tell whether they are busy or
stuck. A check that you or your browser cancelled says `cannot tell: the check was cancelled before it finished`. If earlier
checks of this dashboard are still stuck on a location and hold every checker slot, the next check says so at once
(`N earlier checks are still stuck on a location`) instead of waiting. Compiling a draft does not use the five seconds of the
location: when the compile itself does not finish, the page says `cannot tell whether the new contract compiles: the
check did not finish in time (the machine is very busy); nothing was written; try again`, which does not mean the contract is
wrong. A compile child that was kept off the processor gets the same extension (to 20 seconds in all); one that ran out of time
without that evidence says `cannot tell whether the new contract compiles: the check did not finish in time; nothing was written; try
again`, a full compiler says it is busy with other checks, and a compiler that could not run says so; none of them says the
contract does not compile. The Rules page loads its
recorded view before checking the source. When that check times out, the received recorded rules, redacted
YAML and recorded hits stay visible with run-copy line positions and the unavailable reason. Source comparison
is absent; source edits and actions that trust the source are disabled. Every source/profile diagnostic is
checked, even when an ordinary error comes first. The ledger and recorded copy must themselves answer. The
fallback parses recorded text without compiler probes and makes no fresh compilation or enforcement claim.
Request cancellation closes pipe waits, leaving no handler
waiting for the mount to recover. If a change was already submitted when its reply timed out, its outcome is
uncertain; reload after recovery before trying it again. Registry creation still writes its final name directly
on this branch, so a submitted failed write may leave empty or partial bytes until recovery.
If caller-specific resolver settings cannot be reproduced for a change preview, added hostnames get a cannot-tell
warning. The next run resolves them independently when it starts.
Initial machine-config and selected-ledger loading, plus caller identity/current-directory capture, remain synchronous and require responsive locations.
Actual CLI and dashboard return on a stopped FUSE server, recovery, and root/sudo/other-uid checks are a
**MERGE BLOCKER**, **owed in a guest**. See [the guest recipe](../testing/contracts-stuck-mount.md).

Recorded hashes are emitted only as 64 lowercase hexadecimal digits; malformed hashes are omitted. Unknown tiers
read `unknown`. Invalid recorded run ids and run-only names read `unknown` until a valid contract supplies its name.
Text escapes control characters in paths; JSON preserves them through escaped strings. The offline preview uses
today's tier selection and does not restore a recorded run-command grant; sharing one compile path with `tego run`
is open work.

## General contract source

Contracts shows **General contract** first. A trusted `/etc/tego/general.yaml` is selected before
passwd-home `~/.tego/general.yaml`. Only safely verified system absence permits user fallback.
An unreadable, unsafe or malformed system source stays a visible problem. It never selects the user file.
`HOME`, project files and `TEGO_CONFIG` cannot redirect this choice. The user file is private (0600),
in a private state directory (0700); its whole placement must be owned by root or the passwd owner and
not writable by others. System placement is root-owned and not writable by others; the file must be
readable by governed users, normally 0644. Relative and absolute symlinks are accepted when the
resolved file and its descriptor-bound containing directory meet the same checks.

The read-only card shows scope, canonical profile-merged hash, exact source-byte SHA-256, selected and
unselected source states, owner, mode, resolved placement and profile digests. A comment edit changes
the raw digest while leaving the canonical hash unchanged. The status says **Source loaded; general
launch not built yet**. This is source inspection, not a compile or an enforcement claim. No editor,
general launch selector, per-agent customisation or new run-record field is included yet.

The machine baseline is shown as **Locked**, with its actual current status. Its configured entries
are **NOT YET APPLIED** to runs on this version. Neither a future general contract nor a customisation
may loosen the baseline. Agents outside a Tego run are not held to these rules. Existing own contracts
keep their rules until you choose to migrate them.

`tego contracts` includes general-source facts when a general is found or cannot be determined. With
neither general source selected it retains the existing list output and exit status. General-source
problems are observations and do not change the check result for existing standalone contracts.
Each read has one budget for the whole profile graph: 8 MiB of source, 128 profile attempts,
16 MiB of expanded work/output, and 64 diagnostics within 64 KiB. Cancellation or budget exhaustion
shows UNKNOWN without a partial loaded result. Profile edits change the merged hash. These read-side
facts do not prove that all dependencies have system publication authority. Future system-scope launches
will read policy only from fixed root-owned locations and ignore user policy overrides with a diagnostic.
Future user-scope launches retain user authority. Policy sources will be captured before compilation and
verified before child release; preparation outputs must meet compiled constraints. Production launch
selectors stay absent until the full enforcement and guest requirements close. The accepted design
requires engine-only values for its listed runtime environment names and forbids engine code-loading
paths/options on exception launches. Future finite system cost limits require a trusted exact model
price from `/etc/tego/prices.yaml` or the built-in table, never the user table. Missing prices will
block launch and system activation/save with the model, limit and repair shown. These checks are not
implemented in this read-only version.

See [ADR 0153](../adr/0153-general-contract.md) for the accepted later customisation and exception rule.


Machine baselines are compiled from the trusted machine config layers. An administrator's
refusal cannot be removed by a contract or a later layer. `tego rules check --merged` still prints the
contract alone; `tego rules check --effective` includes baseline entries expanded for the selected owner.
For a nonempty applied baseline, JSON labels `contract_hash` and `effective_hash` separately.
With no baseline or an empty one, JSON keeps its existing shape and omits `effective_hash`.
Text and JSON show each baseline entry's sources, modeled coverage, conditions and limits;
preparation must verify the actual mechanism.
Contradictory file/command grants,
protected host sockets and explicit or required environment deliveries stop the compile.

This release's compiler can check these entries, but enforcing launches with a nonempty baseline
remain refused until per-mechanism guest proof closes. Slice 6 supplies the record/receipt support.
Recording-only runs do not apply the baseline. Baseline editing commands and an editable dashboard baseline card remain later work. See [ADR 0144](../adr/0144-machine-baseline.md) for each entry's limits.
Automatic adoption guards read config and compile the current owner context before each new
adoption, after Tego creates its own directories and strictly reloads the snapshot used for compilation.
Preparation and final admission share a table of named admission checks. Final admission runs every check
in the table marked rechecked after the host-wide migration-lock wait and before any process moves,
including configuration, owner, placement and the chain-anchor file probe. Changed selected-layer identities
or bytes, a changed baseline digest, or unreadable configuration refuse and clean up the pending adoption,
even when its prepared baseline was empty. Snapshot entries retain compiled contract choices, selected
mechanism/probe results/prepared descriptors, immutable boot facts, and the recording-only target home
because it admits no file boundary. The run-directory contract check uses the compiled snapshot; the
skip-counter baseline stays fixed to count skips during the lock wait. Live plane admission is checked
before arming and again under that lock. If a ledger or chain-anchor directory changes resolved placement or device/inode identity,
restart the guard to select that location. Already adopted runs retain their snapshots.
Adoption requires root.
