# ADR 0142: The shared setup state, `tego setup` and the stored machine check

Status: **accepted 2026-11-11**; built (command-line spec slice 2: `internal/guide`, `tego setup`, `check.json`, the
installer's and `tego status`'s next line). The dashboard's Overview renders it since 2026-11-11 (amendment below). A person's path through it (fresh,
`tego watch`, the `tego learn` the guide names, the `tego run` it names, from a user-manager shell, an SSH-like shell
outside it and root) ran in a 6.17 KVM guest with a product build on 2026-11-11.

## Context

A newcomer does not know which step they are on: install, check the machine, record a run, make a contract, enforce
it. The command-line spec of 2026-11-10 (the design both judges picked) has no wizard and no prompts. That spec is a
working design note and is not in the repository; this ADR records what was taken from it, and its "spec §"
references below say only where the note said so. One small package
works out "which step is this machine on, and what is the one next step" from facts already on disk; `tego setup`
prints it, and the dashboard's guide will render the same object, so the two surfaces tell one story from the same
inputs. They differ in one input: `tego setup` reads the project registry of the folder it runs in, and the dashboard
has no working folder (it passes none), so a contract that is only in a project registry shows in the first alone.
Slice 1
(the `next:` lines, `learn --save`, the `reads:` line) is merged; this ADR records slice 2.

## Decision

1. **One package, `internal/guide`, and its import rule.** It reads the invoking user's home, the ledger root, the
   chain anchor, the registries and the machine config, and returns one object, schema `tego.setup/1`
   (`docs/user/setup.md` lists every field). Six machine-level steps: install, check, find, record, contract, enforce.
   Each has a state (`done`, `todo`, `waiting`, `blocked`, `skipped`, `not-known`), the fact that decided it, where
   that fact was read and, under `-v`, why that run or contract was taken. A fixed list of eighteen rules (thirteen
   before the amendments below), checked in order, gives the one next step (`internal/guide/next.go`); there is no score and no model. "Rules for every agent"
   (the machine baseline) is not in it. The package is named `guide`, not the spec's proposed `progress`: both
   surfaces call what renders it "the guide" (spec §3.1, §3.3), `setup` already names `tego init`'s composer
   (`internal/setup`), and "progress" reads like a percentage, which the spec rules out. `tego-control` will link it, so
   `.golangci.yml` (`guide-never-imports-engine`) keeps it off the engine, the doctor, the decision core, BPF, Landlock
   and both command layers. The probes run in `internal/cli`, which hands their answer in (`Inputs.Fresh`); the
   dashboard never runs them, because its process is in another cgroup than the person's shell and its answer would
   describe itself.

2. **`~/.tego/state/check.json`, written by `tego setup` alone.** `tego setup` runs doctor's no-root probes, the checks
   of tier landlock (`doctor.ForRun` at reach landlock: D1, D3, D4 and D5; no BPF program is loaded and no fanotify
   group made, as root too: under strace in a 6.17 KVM guest, `tego setup` as the user and as root made no `bpf()` or
   `fanotify_init` call and no `execve` but its own), in its own process: the shell's cgroup and privilege, never more. It stores one entry per
   place (`shell`, `user-manager`, `root`): the build, the boot id, the tier ("" when none runs), doctor's first fix
   and the time. **`tego doctor` writes no stored check**. The 2026-11-18 amendment permits a short-lived placement
   rehearsal; monitors use `--no-scope` to start no helper. The original decision to start no program is superseded
   only for that rehearsal. The build is the version, the commit and the running executable's device, inode, size and
   modification time, so a rebuilt or reinstalled tego is another build (the run-probe cache's rule). A check of
   another boot or another build is never used. The file is written as the repo's other state files are: a new 0600
   file, synced, renamed over the old one, the folder synced; `~/.tego/state` is made 0700. The decoder is strict and
   fuzzed (`FuzzDecodeChecks`): an unknown key, a missing key, another type, a truncated file, trailing data, another
   schema, an unknown place or tier, two entries for one place, a fix beside a tier, a character that does not print
   or a file over 16 KiB is "not known", never a default. `tego setup` refuses inside a governed run (125
   `[governed]`) and as root for another user (125 `[privilege]`), before writing anything.

3. **What the state never guesses** (spec §3.3; one test each in `internal/guide/rules_test.go`). A source it cannot
   read gives `not-known`, a null fact and a `not_known` line, and `tego setup` exits 125 for the record or a registry.
   It never says "no agents", "complete" or "clean"; `not_known` always says that agents Tego never recorded are not
   known (nothing looks for them yet). It never ticks a run that is still going: that is `waiting`. It never uses a
   check of another boot or build. It never fills in how the person starts their agent (`<the command you start it
   with>`). It counts no refusal in this slice, so none stands without `reads_notified`. It names no service from an
   address. Steps record, contract and enforce come from the hash-chained record and the registries, never from a file
   `tego setup` writes. The record and enforce steps verify their run as `tego receipt --verify` does
   (`ledger.VerifyRunDir` against the chain anchor); a run whose record does not check out is `blocked`, with `tego
   events <run> --verify` as the next step, and one that cannot be checked (no anchor named, a ledger that cannot be
   read) is `not-known`. The contract step compiles an `auto` contract that no run used with no tier named, so it
   resolves to the machine's ceiling on both surfaces; the stored check's tiers never reach the compile. An agents
   folder of the project or the user registry that exists and cannot be listed is `not-known`. The contract step
   compiles the first 20 names in name order, and a `not_known` line says when there are more.

4. **What a hostile process can make the guide show or do.** An agent held by Tego cannot write `check.json`, the
   ledger or the anchor: `~/.tego` is read-denied in every governed run and no write entry may reach it (agent-contract
   R6a, R10), and `tego setup` itself refuses inside a run. A process of the same user that Tego does not hold can
   write all of them, as it can write `~/.bashrc`. Against such a process:
   - it can make the check step say ready or not ready, with any printable fix sentence of up to 1 KiB, as a fact.
     It cannot make tego run enforce: `tego run` probes the tier again at its start and fails closed;
   - it can write a run folder; a forged run, under a contract or recorded, with no matching anchor line is
     `blocked`, never done (`TestItNeverTrustsItsOwnFilesForStepsFourToSix`,
     `TestAForgedRunNeverChoosesTheNextCommand`). One that also forges `chain.log` passes, as it does for `tego
     receipt --verify` (GAPS C9); so does a record-only run's own agent, which runs as the user and can rewrite its
     record and `chain.log` (C9). The newest run that ran a contract is the context the contract step compiles it in,
     read from its `run_start` without a chain check; it changes that step's verdict at most, never a command;
   - it can put a contract in the user registry, as it can for `tego run <name>`; the registry's own checks apply;
   - without writing `chain.log` too, it cannot choose any part of a command line the person runs. A next command is
     fixed words plus a run id (`ledger.IsRunID`), an agent name (`registry.IsName`, and its file's path when the name
     starts with `-`), and one recorded value: the working folder of the newest recorded run whose folder's base name
     is the agent's name, only when that run has ended, its record checks out against the chain anchor and the folder
     is absolute, still a folder here and prints as itself, then written as one shell word (`shellword.Quote`). The run `tego learn` is pointed at
     checks out too. Recorded commands, paths and fixes are facts, printed through `record.Printable`, never part of a
     command (`TestNextCommandsQuoteOrRefuseRecordedText`, `TestAForgedRunNeverChoosesTheNextCommand`). A stored
     check chooses between fixed commands only (amendment below: the one that opens a shell in the user manager's
     cgroup, or `tego doctor`); it never adds text to one;
   - a link at `~/.tego/state` or at `check.json`, a FIFO, a folder or a large file there is an error on read (opened
     `O_NOFOLLOW|O_NONBLOCK`, regular files of at most 16 KiB only) and never a hang; `tego setup` does not write
     through a link at `state` or into a folder another user owns or can write, and replaces a link or a FIFO at
     `check.json` by its rename, never writing through it. A folder at `check.json` is left: the check is then not
     stored, and the first `not_known` line says so. Two `tego setup` at once may lose one place's entry; the next run
     writes it again.

   So the worst such a process does is make the guide show the wrong step or a wrong fact sentence, as the spec
   says, with this one addition: the fact sentence is its choice of text. It chooses no part of a command unless it
   also writes the chain anchor, and then only the folder of the `cd` and the run `tego learn` reads (GAPS C62).

5. **The installer and `tego status`.** `tego status` with no runs prints `next: tego setup` (a stdout change the spec
   states); `tego status --json` is unchanged. The installer names `tego setup` when the installed tego's own help
   lists it, and keeps `tego doctor` for a release made before it, since it installs any tag.

## Amendment, 2026-11-11: the next step from a shell outside the user manager's cgroup

Acceptance B (two guests, Ubuntu 24.04 and AlmaLinux 9.8, a new user over SSH and on a console login) found the
`next:` lines looped: `tego setup` named `tego doctor`, whose `next:` was `tego doctor` again, and with a user-manager
check stored `tego setup` named `tego watch` and `tego run`, which exit 125 from that shell. Such a login runs in a
session scope beside `user@<uid>.service`; tier 1 places every run, a recording included, in that service's cgroup,
and the kernel lets this process move none there (runtime-launch case 41). What changed:

1. **The cause is a fact.** `cgroup.FS.CanPlace`'s refusal of a process whose own cgroup was read and lies beside a
   delegated, writable subtree also matches `cgroup.ErrBesideSubtree`. `doctor.Report.OutsideUserManager` is true
   when that refusal is the whole of tier landlock's missing list and the ceiling allows tier landlock: a shell inside
   the cgroup gets the tier. `tego setup` stores it in the shell entry of `check.json` as `"cause":
   "outside-user-manager"` (or, since acceptance 2B, `"no-user-manager"`), a key the decoder accepts only there, only beside no tier, and reads as absent when an
   older build left it out (`TestCheckCauseRoundTrips`).
2. **Four rules, seventeen in all.** `check-outside` (no place can enforce and the deciding check has that cause),
   `here-outside`, `here-root-only` and `here-elsewhere` (the next step starts a run, `guide.StartsRun` over
   `guide.RunCommands`: `tego run`, `watch` and `test`, and the asker's own check says no tier runs from here). The
   first two name the command that opens a shell in the user manager's cgroup: `guide.OpenScope`, `systemd-run --user
   --scope <shell>` with `$SHELL`'s name when it is one of a fixed list (bash, zsh, fish, sh, dash, ksh, mksh, tcsh,
   csh) and on `PATH`, else `bash`, so the environment chooses among fixed words and never supplies one (rule (4));
   none, with the reason in step 2's fact, when neither `/usr/bin/systemd-run` nor `/bin/systemd-run` is executable
   (the shared fixed-path check, amended B3-1 fix round 1), or `$XDG_RUNTIME_DIR` holds no socket
   of the user's manager (as after `su` or `sudo -u`). The dashboard, which describes no shell, names `systemd-run
   --user --scope bash`. The words say to run `tego setup` there. `here-root-only`, where only root's check can
   enforce, says that check holds a run started with sudo and names `tego doctor`; the run step's old words ("not
   from this shell; from root, run:") read as an order to run `tego run` as root. `here-elsewhere`, where the ready
   check is another place's that is not root's (a `shell` entry, which only an unusual or forged `check.json` holds),
   says only that and names `tego doctor` too. **What is tested** is that no `next:` line names the command that printed
   it, or one that fails from the asker's place, in the places below: `TestTheNextLinesNeverLoopFromAnyPlace` checks every state the acceptance walked from
   SSH, a console and a scope, for `tego setup`, `tego doctor` and the step `tego setup` names when that step starts
   no run (`tego learn --save`). `tego learn --save`'s and `tego agents`' own steps start a run (`tego run`, `tego
   watch`). From a shell where `cgroup.FS.CanPlace` refuses with `ErrBesideSubtree` (read only, and the refusal
   itself; for root, the invoking user's login cgroup against `user@<uid>.service`), they say that command in a
   guidance line, and their `next:` line opens the scope instead (`runHint`). Doctor's not-ready step is `tego setup`
   (or the sentence alone for a root report), never `tego doctor`.
3. **Exit 125 may end with that one `next:` line.** `tego run` refused a tier only for this cause (its tier pin
   allowing tier landlock), `tego watch` refused with `ErrBesideSubtree`, and `tego test` whose runs all failed with
   the probe saying this cause end with it, when automatic scope entry cannot complete
   (`TestEveryRunCommandKeepsThePlacementFallback`). The error line names the cgroup; it did not name the command that
   opens a shell in it, which a newcomer cannot guess. Hints stay off
   off a terminal, with `TEGO_HINTS=off` and inside a governed run.
4. **What step 2 says.** "Only records" is gone: a shell beside the cgroup starts no run, not even `tego watch`, and
   says so; other blocked checks say "no tier enforces from ...". `tego setup` computes the object before it stores
   its check, so a place checked before this boot is named "not checked since this machine started" (spec §3.2's
   sentence, `guide.NotCheckedSinceStart`) and a link or a file it will replace at `check.json` is said as not known
   by the same run.
5. **Steps 5 and the learn step.** With several contracts, step 5 names the one the newest ended run under a contract
   ran (its record checks out), else the one named after the recorded run's folder, else the first in name order.
   The learn step names `--allow-host <host>` only when learn's proposal from that run still allows addresses and its
   leak rule found no destination a secret may have gone to (`learn.Proposal.SuggestHosts`, read by `tego watch`,
   `tego learn` and the guide alike); `tego learn`'s refusal of a name ends with the command without it.
   The guide's read of the run for this (`guide.SuggestHosts`) is bounded by 5 s, as `tego watch`'s is, since the
   dashboard's Overview makes it on each load; past it the step is the plain form.

## Amendment, 2026-11-11 (acceptance 2B): the side paths

The second guest acceptance (Ubuntu 24.04, AlmaLinux 9.8, Fedora 44) walked the new user's path with no deviation and
found two side paths where the `next:` lines still pointed back, plus three wrong sentences. What changed:

1. **`sudo` from a shell already inside the user manager's cgroup.** Point 2's root check assumed sudo leaves the
   process in the login's cgroup. On Fedora 44 sudo's PAM stack (`pam_systemd` through `system-auth`) opens a logind
   session for root when the caller has none and moves sudo into it: measured from a `systemd-run --user` scope
   (`0::/user.slice/user-0.slice/session-c3.scope`), expected but not measured from a desktop terminal. So
   `tego agents` run through sudo sent the person to open the scope they were in, again and again. Ubuntu and AlmaLinux keep the
   scope; every guest keeps an SSH or console session. The root check (`rootBeside`) now reads the cgroup of the
   shell sudo was typed in: the process's own, unless it lies in root's own slice (`/user.slice/user-0.slice/`), then
   the nearest ancestor's outside it (`/proc/<pid>/stat`, read only, at most 16 steps). A chain it cannot read is not
   beside: the command says itself why it cannot run.
2. **No user manager running.** A user with a nologin or false shell reached through `sudo -u` or `su -s` has no
   `user@<uid>.service` cgroup. Detect said "no delegated subtree" with the delegation fix, `tego setup` named `tego
   doctor` and doctor named `tego setup`. `cgroup.ErrNoUserManager` (the only candidate is the canonical
   `user@<uid>.service`, it does not exist, and the mount holds `user.slice`) is now its own cause:
   `doctor.Report.NoUserManager`, `check.json`'s `"cause": "no-user-manager"` (accepted where
   `outside-user-manager` is), and an eighteenth rule, `check-no-manager`. Doctor and `tego setup` both name
   `sudo loginctl enable-linger <user>` (`cgroup.LingerCommand`: the name from the passwd entry, one quoted word, or
   the uid when there is no entry, the name does not print, or loginctl would read it as an option or a uid, a leading
   `-` or digits only; never the environment), a change of state, measured on Fedora 44 to make the user's scope
   ready at tier 1. The dashboard, which links no engine package, names `tego doctor` for this rule, which prints that
   command. The stored cause chooses among these fixed commands only (GAPS C62).
3. **After linger** (*second review, 2026-11-11*). The manager then runs, and `sudo -u` still leaves
   `XDG_RUNTIME_DIR` unset, so the cause is the placement and `OpenScope` named no command: a dead end. When
   `$XDG_RUNTIME_DIR` is unset or holds no socket of the user's manager, `OpenScope` now looks at the user's own
   logind folder (`config.LogindRuntimeRoot`/`<uid>`, a directory, not a link, owned by the uid, holding
   `systemd/private` or `bus` owned by the uid) and names `XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user
   --scope <shell>`: a constant folder and a number, never the environment. Otherwise it says why, as before.
4. **Tested, not claimed.** `TestTheNextLinesNeverLoopFromAnyPlace` gains these places: agents run through sudo from SSH
   and from the scope, built from the cgroups the guests logged (on Fedora 44 only the command's own cgroup was
   logged, so the chain of sudo, its monitor and the shell is reconstructed); the no-manager user on a fresh, a
   half-done and a finished machine; and the same user after linger. It checks that no `next:` command is the one
   that printed it, that a shell inside the user manager is never sent to open one, that a shell beside it is never
   sent to start a run, and that no two commands point at each other. The `sudo` and no-manager rows fail on the
   base; the after-linger rows stub `OpenScope`, whose own table (`TestOpenScopeNamesOnlyACommandThatCanWork`) fails
   on the base. Other places are not covered by it.

Not done, and why: `tego run`, `watch` and `test` do not open the scope themselves (re-running under `systemd-run
--user --scope`). The run would then start in a scope the user did not ask for, from a process that may be a
service, a container or a `sudo` shell, and the record's launcher would be another process than the one typed; the
step stays one the person sees and types.

## Amendment, 2026-11-11 (acceptance 3): whose shell, and a name systemd refuses

The third guest acceptance (Ubuntu 24.04, AlmaLinux 9.8, Fedora 44) said go for the new user's path, on the condition
that no public text claims an administrator can follow the lines alone to a service account's governed run. Two lines
stood in the way. What changed:

1. **Whose shell the scope command opens.** After linger, point 3's command,
   `XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`, is read by the administrator who typed
   setup run as svc through sudo, in their own shell. Typed there it opened the administrator's own scope on Ubuntu and
   Alma (`run-u0.scope` under `user@1000.service`; `tego setup` there said ready, for the wrong user) and failed on
   Fedora (`Failed to connect to user scope bus via local transport: Operation not permitted`). With `sudo -u svc` in
   front it opened `svc`'s shell, where `tego setup` was ready at tier 1, on all three. `guide.OpenScope` now returns
   a `guide.Opening` (the command, why there is none, and the user it opens the shell as) and decides whether the
   person who reads the line is another user (`config.StartedByAnother`) from two facts, neither read from the
   environment: the process's login uid (`/proc/<pid>/loginuid`, set by `pam_loginuid` at a login and kept by `sudo`
   and `su`) is set and is not the process's uid; or the first ancestor whose real uid is neither the process's nor
   root's (the shell `sudo` or `su` was typed in), within 16 steps and before pid 1. A process of the user cannot change its
   ancestors' owners. It can set its own login uid once while that is unset, without privilege (the kernel's
   `audit_set_loginuid_perm`; read, not run), which makes the answer true; that only selects the `sudo -u` form, and
   both forms are fixed words, the passwd name and numbers. `SUDO_UID` is not read: any process of the user can set
   it, and the two facts answer without it. Then the command is
   `sudo -u <name> XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`, always through the logind
   folder (the reader's own `XDG_RUNTIME_DIR` is theirs) and always bash (`$SHELL` is this process's, not the
   reader's, and the `fix:` line beside it names bash; integration pass 5 found `zsh` there beside a `fix:` line that
   said `bash`), the name from the passwd entry (`config.LookupPasswd`) as one
   quoted word, or `'#<uid>'` when there is none or `sudo` would not read it as the name (`config.PlainUserName`: a
   leading `-`, `#` (which `sudo -u` reads as a uid: `'#0'` is root) or `+`, digits only, a character that does not
   print). The `next:` words are "from your own shell, open a shell
   as this user; run tego setup in it:" (`guide.ScopeAsText`; the CLI's run, watch and test say "run this again in it"),
   and step 2's fact, or the CLI's guidance line, names the user and says the shell opened is that user's, not yours.
   `As.ScopeAs` carries the user in `tego setup --json` (a new key, `scope_as`, omitted when empty). A reader who is the
   user, or a process where neither fact can be read (an ancestor hidden by `hidepid` and no login uid, or an ancestor
   in another user namespace, shown as uid 65534), keeps point 3's command and words. A process whose real and
   effective uids differ gets no command. Doctor's fix for a user with no manager (`cgroup.NoManagerFix`) names the
   same command (`cgroup.ScopeAsCommand`), since an administrator reads it. So does the placement refusal's remedy
   (`cgroup.PlacementFix`, from `FS.CanPlace`) when the reader is another user (`config.ReadByAnother`): after linger
   it is the `fix:` line of doctor run as svc through sudo on stdout and the end of the error line of `tego run`, `watch`
   and `test`, and it said the bare `systemd-run --user --scope bash` beside a `next:` line that named `sudo -u` (the
   review's M1). `TestIntegrationThePlacementFixReadByAnotherUserNamesSudo` runs that path with no stub, as root in a
   KVM guest (integration pass 5, 2026-11-11): a process of uid 4242 started by one of uid 4243 got the `sudo -u
   '#4242'` remedy over the real `/proc`, and with the reader forced to the user it got the bare command and failed. The
   CLI's guidance line and step 2's fact say to type the command in your own login shell, not in one `sudo` or `su`
   opened: in a `sudo su -s /bin/bash svc` shell, the user may not use `sudo`.
2. **A name systemd refuses.** systemd's relaxed rules for user names (systemd.io/USER_NAMES, which names
   `systemd-logind` among the programs that apply them) refuse a name that is: empty, digits only (read as a uid), a
   `-` and digits only, `.` or `..`, a `:` or `/`, a control character, not UTF-8, or white space at either end
   (`config.SystemdRefusedName`). The page states the rules, not their consequence. The evidence that such a name
   gets no user manager is one guest run: for `4242` on Ubuntu, `sudo loginctl enable-linger 1004` exited 0, wrote
   `/var/lib/systemd/linger/4242`, and `user@1004.service` failed (`Trying to run as user instance, but
   $XDG_RUNTIME_DIR is not set`); `tego setup` named the same command again. For the other refused names the same
   consequence is inferred from the rules and was not run. Tego says it for all of them and names no linger command:
   if the inference is wrong for one, the line is a refusal to suggest a command that might have worked, not a
   command that loops. `cgroup.ManagerRefused` reads the name
   from the passwd entry; with it, doctor's fix says why and what an administrator can do (run the agent as an account
   whose name starts with a letter and holds only letters, digits, `_` and `-`), and names no command; doctor's
   `next:` line names none; and `tego setup`'s check step says why (`Inputs.ManagerRefused`, set by the caller, never
   from `check.json`) and its next step is a nineteenth rule, `check-no-manager-name`, with no command. The dashboard
   cannot tell (it links no engine package) and names `tego doctor`, which says it. No root path is offered: the docs
   describe no system service under the root tiers for such an account.
3. **Tested, not claimed.** `TestTheNextLinesNeverLoopFromAnyPlace` gains both places: the service account after linger
   reached from an administrator's shell (setup's and doctor's `next:` command is the `sudo -u` one and the words say
   whose shell), and a name systemd refuses (neither names a command, so nothing loops). `TestStartedByAnotherReadsTheLoginAndTheProcessTree`
   holds the decision to the process trees the guests showed (`sudo -u`, `sudo su -s`, root's `su`, the user's own
   login and scope, a system service, a hidden or foreign ancestor), built as files, not read from a guest.
   `TestThePlacementFixOpensTheShellAsThatUserForAnotherReader` (cgroup) and the loop table's doctor stdout check hold
   the `fix:` line to the same command. Only the digits-only refusal and the `sudo -u` command (with `tego setup` in
   place of the interactive `bash`) were run in guests, both before this change; the printed words were not.

## Amendment, 2026-11-11 (acceptance 4): every command the administrator reads, and the last words

A fourth guest walk (an administrator setting a service account up by Tego's lines only) found four more lines that
were right for the account and wrong for the person reading them.

1. **A Tego command in a `next:` line carries `sudo -u <account>` when another user reads it.** After the account was
   set up, setup run as svc through sudo ended with `next: tego receipt <id>`. The administrator types that in their own
   shell, where it reads their record (`no such run under /home/<admin>/.tego/runs`, exit 2). `As.ScopeAs` (the
   account's word, as `sudo -u` reads it) is now set whenever another user reads the line from outside the user's
   user manager's cgroup, whether or not a command opens a shell there (it was set only with `As.Scope`), and
   `guide.ForReader` writes any command that begins `tego ` with sudo's target-account option and
   the running binary's absolute path (`guide.SelfPath`: `os.Executable`, links followed, quoted, read once, never `PATH`),
   since sudo replaces `PATH` with its `secure_path`, which has no `~/.local/bin` and, on AlmaLinux 9.8, no
   `/usr/local/bin` (measured). A command after a folder change uses a shell as the target account to change folder
   and execute that checked binary, so the folder change is made as the account too (typed in the reader's shell the `cd` fails when the
   account's home is mode 0700); `sudo -D` would need sudo 1.9.3 and the `runcwd` option. When the path cannot be vouched
   for, the step names no command and says why. `selfbin.Named` decides, for the guide's lines, the CLI's root hints
   (`sudoSelf`, `sudoTego`) and doctor's fix lines (`sudoDoctor`): the path is absolute, links followed, valid UTF-8 and
   unchanged by `record.Printable` (no control, no bidirectional or other format character; `selfbin.Safe`), a regular
   file with the device and inode of `/proc/self/exe` (a binary unlinked and replaced by a directory or another file at
   the same path is refused), and executable by this process. No root line falls back to `sudo "$(command -v tego)"`,
   which selects whatever the reader's `PATH` finds first. The `sh -c` form needs a sudoers grant that lets the reader run
   a shell as the account; Tego cannot read the policy, so the guidance line says the line may be refused.

   A pasteable line is never altered to make it printable: `record.Printable` wrote a newline in a recorded folder's name
   as backslash and n, so `tego learn --save` named another folder. `writeHint` and `runHint` decline a command that
   `selfbin.Safe` refuses ("a name in the command that comes next cannot be shown safely"), learn says "this run's folder
   name cannot be shown safely" and gives no `cd` line, and the guide declines the same. The guide's next step passes through it (`facts.next`), and so does the CLI's `next:` block (`writeHint`, and
   doctor's check-again block) with `guide.ReaderAccount`: false for root, for a process inside the user manager's
   cgroup (the shell the person opened there, where bare is right), and wherever neither fact of
   `config.StartedByAnother` can be read. A `sudo` or `systemd-run` command is left alone. `tego setup --json` carries
   the account in `as.scope_as`, which may now stand beside a `scope_missing`. The first line the administrator types
   runs setup in the service account's login shell (docs/INSTALL.md, "A service account"): the account needs its own copy,
   since a copy in the administrator's home is closed to it when that home is mode 0700.
2. **The words for a shell `sudo` or `su` opened say how to leave it.** Step 2's fact, the guidance line of run, watch,
   test and doctor, and the `fix:` lines (`cgroup.PlacementFix`, `cgroup.NoManagerFix`) add "if you are in one, type
   exit first". In a `sudo su -s /bin/bash svc` shell, `sudo -u` fails with "svc is not in the sudoers file".
3. **`tego run`, `watch` and `test` name the linger command when no user manager runs.** They exit 125 with the `fix:`
   text at the end of the error line, and ended with no `next:` block, though `tego setup` and `tego doctor` print one.
   All four now print the same block (`noManagerHint`): `sudo loginctl enable-linger <user>`, or for a name systemd
   refuses a block with no command. A run pinned above tier landlock gets none.
4. **No socket in the logind folder.** When the user manager runs (Detect found `user@<uid>.service`) but
   `/run/user/<uid>` holds no socket of it that the user owns, `systemd-run --user` cannot reach it from another
   user's shell with `XDG_RUNTIME_DIR=/run/user/<uid>`. The `next:` line named no command there and the `fix:` line
   still named the `sudo -u` command, which fails. The placement remedy (`placementRemedy`) now says the manager keeps
   no socket and that no command opens a shell in it from the reader's, and the step and the CLI's guidance name
   whose manager it is (`ScopeAsMissingText`) instead of "your user manager".

**Measured** (AlmaLinux 9.8, kernel 5.14.0-687, systemd 252, one KVM guest, a build of this branch; its sudo has the
strict `secure_path`, so the binaries were installed in `/usr/bin`): run, watch and test launched as svc through sudo
before linger each ended with the `sudo loginctl enable-linger svc` block (point 3). After linger the step's words
carried "if you are in one, type exit first" (point 2). In the account's own scope shell setup, watch, learn and run
ended with bare `next:` commands, as before. Back in the administrator's shell, setup run as svc through sudo ended
with a receipt command naming svc and run `4mr2qb`, and step 2 said "it runs as svc (sudo -u), not as you" (point 1).
Typed as printed it printed the receipt, exit 0. After deleting `/run/user/1001/systemd/private` and
`/run/user/1001/bus` by hand while `user@1001.service` stayed active, setup, doctor and run as svc named no command
in the `fix:` and `next:` lines and said whose manager it is (point 4).

A second walk on the same guest after the review of 2026-11-11 used build `d1ee2972e`, both homes mode 0700 and
sudo's `secure_path` `/sbin:/bin:/usr/sbin:/usr/bin`. A bare Tego program name after sudo's svc option failed with
"command not found". The administrator's default installed copy under `/home/tego/.local/bin` failed with
"Permission denied". With the built binaries copied into `/home/svc/.local/bin` (the installer itself was not run),
every printed line was typed as printed. Setup named that copy's absolute path after sudo's svc option,
then the scope shell whose PATH held that folder. Back in the administrator's shell, the receipt command
named svc, the same checked binary and run `xc8d8c`, and printed the receipt. With the user manager stopped,
learn run as svc ended with a shell command that changed to `/home/svc/myagent` as svc and executed that
checked copy with `run myagent2`. Typed as printed it ran in the folder as svc and printed Tego's refusal
and the linger line. The old folder change in the administrator's shell failed with "Permission denied".

Not run in a guest, and so not proven: the `su -c` and interactive `sudo su`
shells, zsh, the two other distributions, a name systemd refuses. Unit tests check the wording and the formatting of those
lines with injected answers; they can pass while a real shell or sudoers file behaves otherwise (the strict `secure_path`
did exactly that until the review of 2026-11-11 found it).

## Left for later slices

The per-agent form (`tego setup --agent <name>`, `tego watch --name`, `--require <step>` with exit 211; spec slice
12), the scan and `~/.tego/scan/last.json` (the find step reads only the record until then; slice 5), the machine
baseline step (after question 1), the dashboard's guide page (it calls `guide.Compute` and is tested against
`guidetest`'s fixtures; built 2026-11-11, see the amendment), help changes, and a refusal count beside
`reads_notified`.

## Amendment 2026-11-11: the dashboard renders the object

The Overview (`internal/control/web` setupguide.go) calls `guide.Compute` for the user tego-control serves, with no
working folder and no shell, and shows each step's state and fact, the one next step and the not-known lines, in the
words `tego setup` prints: both print `guide.State.Words` (paths under the home as `~/`, `record.Printable`). With no
run it is the empty Overview, and under it, unfolded, the first step for any agent (`tego watch -- <the command that
starts your agent>`, the dashboard decision's first item), unless the guide's next step is that step (`record-todo`);
with runs it sits under the headline, folded to one line once every step is done. It never runs the probes.

- **The build it passes.** tego-control runs from a sealed copy after a handoff, which names no file, so it names the
  build of the tego a person types: the first `tego` in an absolute folder of its PATH, else the one beside its own
  file, with its own release's version and commit (`guide.BuildIDOf`, the rule `BuildID` keeps for `/proc/self/exe`).
  A tego of another release or another file gives another build, and the check step then says "not checked since this
  machine started", with `tego setup` next: never a check of another build. It passes that path as `Exe` to the compile
  too, as `tego setup` passes its own. A same-user process that controls the dashboard's PATH can choose which stored
  check is read, which is no more than it can do by writing `check.json` (point 4).
- **What is a command.** `Next` carries an unexported mark that `Compute` sets (`Next.Built`), and the page shows
  `Next.Command` in a copy block only when it is set; a `Next` decoded from JSON never has it. Every fact, link and
  not-known line is text through html/template.
- **Cost.** The page reuses the object while the number of runs, of ended and live runs, the newest run,
  `check.json`'s size and time and the build it names are unchanged, for at most 15 s, so a live run's lines do not
  compute it again each second; a contract just saved can take that long to show. Computation belongs to the page request and its helper session,
  with at most 20 s. A departing viewer cancels that work. Cancelled or failed results are never memoized,
  so the next viewer computes again. Fix round 4 removes the earlier detached computation.
  Scan freshness and cache-key checks use the caller's captured evaluation time, including through the helper.
  An explicit evaluation time is preserved; helper requests without one are refused.
  Amended 2026-11-13: an object with any not-known step is also shown only to that
  request. The previous memo is discarded before recomputing, so returning to an earlier key cannot resurrect its
  older result. In particular, a run's end can be read before its first chain anchor is published; a subsequent
  refresh must verify the newly available anchor rather than reuse that temporary uncertainty. A missing anchor
  stays not known and a corrupt record stays blocked. Known objects keep the existing 15 s reuse and 20 s compute
  bound; this does not make the reuse key detect every change to a known object's sources.
- **Parity.** `TestOverviewGuideParityWithSetup` renders the Overview for each of the eight `guidetest` fixtures and
  holds every step, the next step and the not-known lines to the object in `internal/guide/testdata`, which `tego setup
  --json` prints for that tree (`TestSetupParityWithTheFiles`).

## Amendment 2026-11-17: `tego start` and the terminal

`tego start` (and `tego setup` in a terminal) walks a person through four questions with Huh forms
(`internal/cli/setup_guide.go`). How it holds the terminal is decided here, because each rule below replaced a
simpler arrangement that lost keys or left the terminal unusable:

1. **One reader for the whole guide** (`internal/cli/setup_input.go`). The guide puts the terminal's input in raw mode
   once, owns one decoder and one queue from its first question to its last, and restores the saved settings when it
   returns, however it returns. A form is given one event at a time and no more once Huh has accepted its field, so
   a key typed for the next question waits in the queue. A reader per form outlived its form and took the next
   question's keys; cooked mode between questions turned an early Enter into a line feed.
2. **Secret boundaries.** After a masked answer, and on both sides of an agent's sign-in, input already in the kernel
   is decoded to its end (so Ctrl-C is still seen) and then dropped with the queue: the rest of a paste never
   answers the next question or shows in it.
3. **The agent's sign-in owns the terminal while it runs.** The reader is paused and joined, the saved settings are
   restored, and the child is made the terminal's foreground process group; afterwards the guide takes the
   terminal back and applies rule 2.
4. **Every other program runs without the terminal** (an agent's installer, a version check, `systemctl`,
   `systemd-run`): no input, its own process group, ended and joined when the guide is left. Starting the dashboard
   is bounded at twenty seconds, and a start that was interrupted stops the unit.
5. **Leaving.** Ctrl-C is a key in raw mode; SIGINT, SIGTERM and SIGHUP stay subscribed until the terminal is
   restored. Each ends the guide with the `Stopped` line and exit 1. A second signal that arrives after the
   terminal is restored ends the process as it ends any command. What was already saved stays saved: the guide is
   not a transaction.
6. **`TERM=dumb`** gets numbered questions read through the same reader, because Huh's plain prompts do not end
   when their context does. Input that is not a terminal (a pipe, a test) keeps Huh's plain prompts, one line per
   answer.

Tested with real controlling pseudo-terminals (`TestGuideInterruptRestoresTerminal`, `TestGuideHandoffBoundary`,
`TestGuideChildrenStop`, `TestGuideDumbInterrupt`, `TestLoginControllingTerminal`) and a seeded key walk over every
question (`TestGuideQuestionKeyWalks`). Not proven: a real agent's sign-in, which the tests replace with a stand-in.

## Consequences

- One object for both surfaces, tested for parity on eight fixture trees with the command in the loop
  (`TestParityFixtures`, `TestSetupParityWithTheFiles`).
- `tego setup` writes one new file in `~/.tego/state`; nothing else in Tego reads it yet.
- The contract step compiles each registry entry (the first 20 in name order) on every `tego setup`, offline, as
  `tego rule` does; the record and enforce steps each verify one run's record, as `tego receipt --verify` does.

## Amendment, 2026-11-11 (B3-1): run commands open their own user scope

The earlier decision to leave scope entry to the person is superseded for `tego run`, `tego watch` and `tego test`.
`tego setup` and `tego doctor` still check the shell that invoked them. They neither move it nor start a program.

1. **When and where.** Before command startup, ask `cgroup.Detect(os.Getuid()).CanPlace()`, the same D3 question
   doctor asks and the guide's placement cause comes from. Only `ErrBesideSubtree` permits automatic entry. There
   is no SSH, cgroup-name or environment heuristic. A root launcher and an already usable cgroup need no move.
   `tego run --service` keeps its existing unit and lifetime. All three run commands try once, before a contract
   generated by watch, test decoys, configuration restoration, a run id, ledger append or run cgroup exists.
2. **The invocation.** Start `/usr/bin/systemd-run` or `/bin/systemd-run`, whichever exists and is executable,
   with `--user --scope --quiet --no-ask-password -- <checked-tego-path> __user_scope`. Obtain that absolute
   path through the shared `selfbin.Path` check: a regular executable with the running binary's device/inode and
   a path that can be shown safely. An unreadable, unsafe or replaced path refuses the handoff. Neither executable
   is looked up on PATH. Two `sys.Pipe2(O_CLOEXEC | O_NONBLOCK)` owners supply the inherited pipes, with nonblocking
   descriptors retained for cancelable `os.File` I/O. They carry the original argv and environment with gob (including empty arguments, dollar signs and non-UTF-8 bytes), then readiness and one
   byte of permission to proceed. Passing the invocation out of band avoids systemd 254+'s argument expansion.
   The runner gets this uid's canonical `XDG_RUNTIME_DIR` and no inherited session-bus address; the re-entry restores
   the caller's original environment, removing systemd's added variables, before ordinary command startup.
3. **Terminal and lifetime.** Stdin, stdout and stderr are the original descriptors. The working directory is
   inherited. No new session, process group, pty or stream copier is introduced. A scope retains the caller's
   execution environment ([systemd-run documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-run.html));
   systemd 252's [scope implementation](https://github.com/systemd/systemd/blob/v252/src/run/run.c) execs the
   command without closing these descriptors. These source properties do not prove a complete login: actual
   terminal, foreground, interrupt and job-stop behavior is **owed in a guest** on all three distributions.
   The waiting parent observes `Wait4(WUNTRACED)` and extends R9b's existing job-control mechanism through
   `runtime.NewJobControl` / `JobControl.Follow`, sharing `answerJobStop` with the direct run. When the launcher
   stops itself after a raw-mode agent stop, the parent also stops so the login shell sees its job stop. On continuation it restores
   the appropriate foreground group and continues the launcher, using the same terminal-mode rules as a direct run.
   Before stopping with an agent in a separate foreground group, the launcher gives the foreground to its own group
   so its waiting parent can observe and follow it; after `fg`, it restores the original child foreground group.
   Each follower restores modes only if it changed them before stopping, so an outer parent cannot overwrite
   raw modes the inner launcher has already restored.
   Fix round 2 shares TakeStop's existing `procStatState` check through `launch.StillStopped`: the parent
   follows a saved stop only while the unreaped launcher is still in state T. A whole-job Ctrl-Z followed
   by `fg` can otherwise deliver an old stop after both processes continued and stop the parent again.
   INT/QUIT are not forwarded when this process group is foreground on its controlling terminal; that check uses
   the controlling terminal independently of stdin, so piped stdin cannot turn one terminal interrupt into two.
   `os/signal` provides no siginfo, so the outer process cannot tell the source of an INT or QUIT, and it no
   longer forwards them by `kill(2)` when a launcher of this build listens (interrupt provenance, amended
   2026-11-20, A51). The two processes share one stream socket (descriptor 5 of the launcher, announced by an
   `H` frame and acknowledged `A`) and both count their INT and QUIT arrivals. The outer process notes each
   arrival (`N`); after each arrival of its own or a note, the launcher drains its pending signals behind a
   real-time marker (signal 40) it sends itself, asks (`Q`) for the outer process's counts, which that process
   gives after the same drain (`R`), and takes for each signal the larger of the two counts since the last
   question. A group-directed INT, seen by both, is one interrupt; one only a process saw is one; two sends
   are two, so a deliberate repeat still escalates, and no time window decides anything. Where no launcher
   listens (an older build, a failed socket) the outer process forwards by signal as before. Two deliberate
   sends to two different processes within one round trip read as one, and a group send whose second copy lags
   the first by more than that round trip reads as two (the kernel queues a group send to all members in one
   call, so this needs the sender preempted in it); an unanswered question times out after one second and the
   launcher counts its own arrivals. The exact real-launcher result is owed in a guest. Exit status passes through.
   Before re-raising a child signal the parent resets the disposition, including signals Go handles specially;
   if still alive after the raise it returns 128 plus the signal number, never an unbounded wait.
   The starting OS thread stays locked until the child is joined. `Pdeathsig=SIGTERM` requests the launcher's normal
   `stop_grace` and `run_end` path if the parent dies, including at landlock where there is no root-tier reaper.
   If the launcher is unresponsive, parent death adds no forced-kill deadline; existing tier-specific orphan cleanup
   and a later sweep remain the fallback. `launcher_pid` and `launcher_start_ns` belong to the re-entered process,
   whose runtime creates them. No record schema changes.
4. **Guard and security.** Re-entry is a hidden command with an in-memory, single-use context mark, never an
   environment variable. Before any scope request, `runscope.InRun` must show this process outside every run;
   membership, look-alikes, an unreadable file or a private cgroup namespace all suppress automatic entry. The
   existing nested run path then keeps the enclosing run's restrictions. Re-entry itself again requires known
   outside membership and successful `CanPlace`, then waits for the parent's go-ahead before dispatch. The two
   inherited descriptor sites are listed with their entry-path and lifetime justification in `tools/fdcheck/inherited.txt`. An agent
   that preloads environment values or directly invokes the hidden command gains no move and no placement bypass.
   ADRs 0070 and 0113 continue to refuse agents the user manager's sockets; no exception is added.
5. **Visible behavior and the guide.** On a committed handoff stderr says `tego: opened a user scope for this run`
   once, even when hints are off. Successful entry prints no instruction to open one by hand. Setup and doctor
   describe their original shell; run steps can open their own scope. The manual shell remains useful to check
   that shell with setup or doctor, and as the fallback if automatic entry fails. Public docs and the installer
   retain the manual line and mark complete-login validation as owed in a guest.
6. **Failure and ADR checks.** Missing systemd-run, a refused manager, a child still outside, pipe failure or a
   ten-second startup timeout refuses the run with exit 125 and the existing placement `next:` block. The child
   cannot create run state without the go-ahead; timeout closes its pipes, kills it and joins it. Context cancellation
   during startup exits 130 without placement advice, after killing and joining the child. A manager that
   does not exist takes the old path and keeps its existing linger advice. Tego never enables lingering. Once
   committed, the timeout ends and the actual launcher's exit, even 125, is final; no second run is attempted.
   ADR 0020: the real launcher's pid and tier-specific reaper remain authoritative; parent death requests a clean
   stop through SIGTERM, with the unresponsive-launcher limit above. A manager stop or logout can end the scope
   as with a manual shell, and lingering is not enabled here. ADR 0021: the one new process start
   passes through `proc.Start` before any marks or run state, with its lint exclusion and reviewed start-site row.
   ADRs 0070 and 0113: the pre-move membership guard prevents this convenience from becoming a bus escape inside a
   governed run. The three distributions' actual manager, terminal, signal and cleanup behavior is owed in guests;
   unit stand-ins establish only the invocation, guard, handshake, timeout and exit plumbing.


## Amendment 2026-11-12 (B3-3): finish the sudo command audit

Product root command builders use `selfbin.Sudo`, which uses `Named`; the guide keeps `Named` directly.
The initial B3-3 inventory missed the adopt privilege refusal. Fix round 1 adds that hint through `sudoSelf`,
beside the privileged-copy refusal, root launch with no target account and lost-adoption recovery lines.
An unsafe or unavailable path gives a reason and no command. `guide.ForReader` keeps the same `Named` check for another account,
including its quoted `sh -c` form when a folder change is needed. The source inventory test
walks production Go files under `internal/`, including other build tags, and requires reviewed helper calls.
Source and documentation regression checks guard the printed root commands.

Install both binaries in the service account's own `~/.local/bin`, as the templates expect,
or adjust their absolute ExecStart paths for a root-owned shared installation. The agent user
unit now sets `PATH=%h/.local/bin:/usr/local/bin:/usr/bin:/bin`. A manual or automatic user
scope inherits its caller's PATH; the automatic handoff restores the original environment.
Neither scope reads a login profile or adds a binary directory. A scope opened through sudo
therefore inherits its secure_path unless the caller explicitly changes it. Contract env.pass
still limits which variables reach the agent. This does not change kernel rules or records.

Host source and rendering tests check command construction and refusal. Each printed line
is still owed in a guest on AlmaLinux 9.8, Fedora 44 and Ubuntu 24.04, for both installation
locations, quoted paths and a path with a newline or control character. The template's PATH
must also be observed in a real user service. No guest result is claimed here.


### Fix round 1: checked paths must resist replacement by another account

`Named` checks the resolved executable and each ancestor through `/`, using non-following stat calls.
Each owner must be root or the process effective uid. A file with group/world write bits, a world-writable
non-sticky directory, missing metadata or an unexpected node type yields no command. Fix round 2's
private primary/empty group exception below replaces the initial blanket directory group-write refusal.
The reason says that safe write authority cannot be verified and asks for an installation only root or you
can write. Failed stat is uncertainty, not proof that another account can replace the path.
A sticky directory permits creation, but only its owner, root or a child's owner can rename that child;
checking both owners makes a root-owned sticky `/tmp` with this user's child safe against unrelated users.
Sticky never protects file contents. Root and the effective user remain trusted. This is a point-in-time
check, not immutable custody after printing. In a root process, an invoking-user-owned installation may
conservatively give no hint; it is not trusted via an unchecked environment variable.

`Path`, used for immediate same-process re-entry, retains the identity, display and execute checks. The
extra permission rule applies to `Named` for commands a person may run later. No launch refusal is loosened.
Temp-tree tests cover safe, writable, sticky, foreign-owner and unreadable chains; ownership is injected,
so they need no root and do not claim a second-user kernel permission measurement. Positive rendering
tests inject an already-checked word rather than assume the shared Go build folders are safe.
Static docs use the single reader-shell lookup form explained in INSTALL; they cannot certify a running copy.
The documentation rule walks pages and templates and reports bad file/line pairs without per-file counts.
The real sudo and login checks, including replacement scenarios, are owed in a guest.


### Fix round 2: default install groups (2026-11-12)

The blanket group-write refusal withheld every printed root command for the default 0775 private-group
`~/.local/bin` layout. It also withheld Debian's root:staff 2775 `/usr/local/bin` with an empty staff group.
Directory group write is allowed for the effective user's private primary group, or a group with no
members and no passwd primary users, such as an empty Debian staff group. Bounded local passwd/group reads
and the standard-library account lookup determine membership; only files-only NSS sources establish an empty
group. When membership is unknown (directory services, unreadable or oversized files), only the effective
user's primary gid by id is allowed, and the folder must still be owned by that user or root. Known foreign
local members always refuse. This fallback cannot rule out an unseen account sharing that gid. Non-sticky
group-writable folders with an access ACL or unavailable ACL metadata also refuse: a named ACL writer need
not belong to that group. The executable itself must never be group/world writable.

This intentionally loosens the printed-command refusal, including the explicit primary-gid fallback on
uncertainty. It changes no launch decision or immediate re-entry check. Sticky and ownership checks remain.
`TestTrustedChainDefaultInstallLayouts` covers eight accepted default-layout fixtures and five attack
fixtures. Local database, directory-service and read-failure cases have separate table coverage. The real
host's `~/.local/bin` chain was accepted by a read-only metadata test; its NSS configuration exercises the
primary-gid fallback. These are host unit checks. The Ubuntu 24.04, Fedora 44 and AlmaLinux 9.8 walks remain
**owed in a guest**; Debian, Arch and Nix fixtures are not distribution runs.

## 2026-11-12: optional dashboard tour (A2; amended after fix round 1)

The guide wraps the existing product pages. `/guide` chooses the first teaching
stage whose fact is neither Done nor Skipped, ignoring any old remembered stage.
When every stage is done or skipped it opens Enforce. An explicit `step=` or
`guide=` changes only what the person reads. The six teaching stops are Check,
Pick, Watch, Recorded, Review and Enforce. These names stay the same in the rail
and source evidence; the unchanged fact and its source explain what each uses.
Install stays in the source evidence. Pick completes when the first run is
recorded, because the current machine-wide inputs have no separate choice fact.
With a saved contract and no run, Pick points directly to Enforce; a skipped Watch
also points there. An unknown or blocked recording opens Watch's diagnostic
instruction. Watch and Recorded share the ended, verified recording fact; the
rail says so. The original six machine facts, sources and next sentence remain
`State.Words` and `Next`, identical to setup.

The frame has one page-level heading. Its navigation landmark holds step links;
evidence, preferences and the decision group sit outside it. On phones, All steps
and the underlying real product page are native disclosures; the current question,
instruction, command when runnable and one primary action come first. No page is
cloned. The original forms, live regions and record links remain inside the real
page. Check tells the person to run `tego setup` in a terminal; its reload action
reads the stored result and never probes the dashboard's own cgroup. The stored
machine fix stays escaped text. Only runnable `Next.Built` commands get Copy;
commands containing any marked placeholder are labelled forms to fill in,
without Copy. The terminal instruction starts as a sentence and includes the
shared fix text without changing its source.

The frame polls its own named region with bounded, cancellable requests. A verified
ended recording says Step 4 is ready in the polite status region. When scripts
schedule the move, the message changes to Moving to step 4, then waits about two
seconds before advancing Watch to Recorded. It does not advance while focus is
inside the frame. Both its own follower and the shared live updater defer guide
region replacements while focus is inside. Enforce changes to its ended record
and refusals. Scripts off uses a labelled reload link and never promises an
automatic move. Leaving opens the real product page without the frame and never
changes completion. A waiting request takes priority: the frame shows its count
and opens Approvals as its one main action, including after a successful contract
save. The full request identity and decisions stay in the existing product pages.
This keeps the request reachable when the phone product disclosure is closed;
it does not place the Run page's original request controls above that disclosure.

Hide for good posts through the dashboard's normal peer, governed, Origin and CSRF
checks and stores only an HttpOnly, SameSite Strict browser preference. It hides
the automatic Overview offer and the Overview checklist only when no step is
Blocked or Not known and the machine check is Done. A finished machine receives
no Start the guide offer. Show the guide again clears the preference through the
same POST boundary and is available in the frame, More and This machine. Guide
remains reachable from More and the desktop header and always returns to the
fact-based stage. No mutable completion flag or agent-selected command is trusted.

Recorded and Review lead with three fact rows about recorded programs (or the
starting command), files and connections, with explicit empty words. These phone
rows shorten long values and point to What the run recorded for full values and
coverage limits. The starting-command summary bounds the whole joined command to
80 characters; single-path file rows use 64 characters and rename paths use 40
characters each. The disclosure includes the full recorded values and opens by default when its combined lists have at most
twelve entries. Review points to What the run recorded. Amended 2026-11-12
(fix round 2): its instruction follows the contract state and next rule. Create contract and the
learn command create a contract from the run. A compile command checks an
existing contract that needs fixing; Create contract can make another. A saved,
compiling contract offers Enforce its rules with no terminal command. Its builder
link carries `guide=review`, opens the real form on phones, and preserves that
fixed context through both mode links (including the selected mode), preview,
rejected saves and successful saves. The save form accepts only the fixed
review context. Saving clears the guide memo so source facts refresh immediately.
A successful save names the saved contract and offers Enforce its rules unless a
request needs an answer first. The real builder's name pattern also escapes its
hyphen for the browser's current regular-expression mode, retaining the existing
name rules. Review remains interim until A3 supplies the sentence editor. Pick
uses the watch form until A4 supplies scanned agent identity. The guide remains
machine-wide; it does not infer that every saved contract or run belongs to one
chosen agent. The service disclosure describes the shipped unit, registry, working
folder and environment; this change does not run or install a unit. No kernel,
launch, contract authorization or record format changes.

The retained unit checks cover rail parity over every shared guide fixture and
assert the status attributes, current step, Leave destination and scripts-off link
separately. The `chrome` tour checks cover the visual matrix, one visible H1 at
1280 px, Leave and return, Watch's announcement interval and focus hold, and the
current step's system colour in forced colours. These browser checks need explicit
invocation and remain outside CI and the private gate (DASH-G16). Browser checks
do not prove a screen reader spoke the status. Screen-reader, real-phone,
Firefox and Safari checks remain open. Service and remote-shell acceptance is
owed in a guest; package and browser fixtures are not kernel proof.

## Amendment 2026-11-18: incomplete printed-command group membership (A31 / C244)

The primary-gid fallback in fix round 2 is withdrawn for commands crossing authority.
The rule has two classes. What root or another account will run is PRIVILEGED:
the program's path is named through `Named`, the checked path, and a path that
fails the check gives a reason and no command. What the person's own shell or
service manager runs as that person is SAME USER: a group member able to replace
that user's programs already has that authority, so naming the program adds
none, and nothing is checked. This list is the whole inventory of what carries
the installed program's path, or runs later, with its class (text revised in the
review round of the same day, finding 7: the list is carried here and no other
document is needed to read it):

| Producer | What it makes | Class |
|---|---|---|
| CLI root hints: adopt refusal, agents (privilege message and the adopt it suggests next), doctor (root test, required root tier), setup refusal, privileged-copy refusal | a command to paste after `sudo` | PRIVILEGED, `Named` |
| doctor repairs: the derived fix, fanotify, plane and hook lines | `sudo <program> machine check` | PRIVILEGED, `Named` |
| the guide's two other-account forms (direct, and `sh -c` with a folder change) | a command to paste after `sudo -u <account>` | PRIVILEGED, `Named` |
| root-launch guidance of a run | `sudo <program> run` | PRIVILEGED, `Named` |
| lost-adoption guidance | `sudo <program> gc`, `sudo <program> adopt --release --pid <pid>` | PRIVILEGED, `Named` |
| system-tool lines (`loginctl enable-linger`, `systemd-run --user --scope` for another account, `modprobe tcp_diag`) | a command that names no Tego program | no path to check |
| the guide's same-user commands | a command the person runs as themselves | SAME USER (returns before `Named`) |
| automatic scope entry | an immediate re-entry of the running program | SAME USER (`Path`, the identity checks only) |
| the setup guide's dashboard start | the transient user unit `tego-dashboard` in the person's own service manager, started with the running program's path | SAME USER (unchecked by decision; the site says why) |
| the retention timer (`retain_timer.go`: `systemd-run --user --unit=tego-gc`, `systemctl --user is-active`) | the transient user timer `tego-gc`, which runs `<program> gc` daily in the person's own service manager | SAME USER (unchecked, as the dashboard's unit; the site says why) |
| `tego uninstall` (`uninstall.go`, `uninstall_scan.go`) | nothing: it names Tego's user units, shell start-up lines and `/etc/systemd/system/tego*` files to find and remove them; `systemctl --user` stops units in the person's own manager | makes nothing (reads and removes) |
| the sudo lines `tego uninstall` prints for a system-wide install (`sudo rm`, `sudo rm -r`, `sudo systemctl disable --now <unit>`, `sudo systemctl daemon-reload`) | text the person types; it runs none, and a unit name outside systemd's alphabet is quoted | no path to check: system tools, and `rm` only deletes the program's file |
| saved sign-ins | one line in the person's own `~/.bashrc` that loads their `agent.env` | SAME USER (names no program) |
| the installer | one `PATH` line in the person's own shell profile | SAME USER |
| a run's hook settings and its MCP relay entry | per-run settings naming the running program, read inside the run by the run's own user | SAME USER |
| the shipped unit templates (`examples/systemd`) | user units a person copies into their own `~/.config/systemd/user` | SAME USER (a fixed `%h/.local/bin/tego`) |

The product makes no system unit, no cron line and no desktop or autostart
entry; one that root or another account would run is privileged and takes the
checked path. A source walk (`TestRunLaterProducers`) fails on a function that
holds a producer's words and is not classed, as `TestSudoSites` does for a
printed sudo command.

A group-writable component is accepted only with complete bounded files-only
passwd/group evidence establishing a private primary group or an unused group,
with the existing owner, sticky and access-ACL checks. Directory services,
failed, truncated, oversized or malformed evidence refuse even the primary gid.
The refusal names the folder, group and missing evidence and asks for
`chmod g-w <folder>`, then rerunning the step. Complete default-layout acceptance
is retained, including a 0775 private-primary-group home and empty Debian staff.

Injected account facts include a second principal with the same primary gid
visible only through the directory source. Host tests establish policy and
rendering; an actual directory-service second principal and the real sudo/service
walks remain owed in a guest. Measured on the fixtures: the thirteen layout
fixtures keep eight acceptances and five refusals, and the six cases of a hidden
principal or incomplete evidence went from six acceptances to six refusals. The
membership lookup, as it stands after the amendments below (four reads behind
one deadline), measured about 2 µs over in-memory files and about 44 µs over
three real files of fixture size on the development machine; those figures say
what the check costs and certify nothing about a directory service, which the
check no longer asks.

## Amendment 2026-11-18: group passwords (A31 / C244, review finding 1)

A group that can be joined with a password is not a group whose membership is
completely known: `newgrp` admits an account that no file lists when it gives the
group's password. The first amendment read the member lists and ignored the
password field, so an otherwise unused group with an active password kept the
writable-group exception.

The exception is now refused when the group's password field in `/etc/group`
holds anything other than an empty field, `x`, or a locked form (a field that
starts with `!` or `*`, which equals no `crypt(3)` result). `newgrp` prefers the
shadow group file, `/etc/gshadow`, which only root can read. When the caller can
read it, a usable password in the group's entry refuses whatever the group file
says, an administrator or member listed there counts as a member of the group,
and a failed, cut or malformed read refuses as incomplete evidence. The refusal
is the named one: the folder, the group, `the group can be joined with a
password (set in <file>)`, `chmod g-w <folder>`, and to run the step again.

Residual, accepted and stated: when the shadow group file is not readable (every
caller that is not root), the exception stays for a group whose group-file field
is `x`, empty or locked. The default layouts of Debian, Ubuntu and Fedora mark
every group `x`, so refusing there would refuse every default installation. A
group password that an administrator set in the shadow group file cannot be seen
by a normal user, and Tego then prints the command. The eight default-layout
fixtures keep their acceptance; fixtures cover a hash in the group file, `x` with
a readable hash, `x` with a locked or empty entry, and `x` unreadable.

## Amendment 2026-11-18: no unbounded wait for account evidence (A31 / C244, review finding 5)

The check asked the standard library for the caller's account before it read
any file, and that lookup goes through the machine's name services: on an
account served by a directory that does not answer, a refusal or a root hint
waited without bound, even for a path with no group-writable folder.

No name service is asked now. Complete files-only evidence is the only evidence
that keeps the writable-group exception, and it names the caller's primary group
itself (the caller's `passwd` record); when the files do not establish that, the
exception is refused whatever a lookup would have said. The evidence is read
only when a folder of the path is writable by its group, so any other path reads
no account file. The local files that are read (`/etc/passwd`, `/etc/group`,
`/etc/nsswitch.conf`, and `/etc/gshadow` where readable) share one deadline of
two seconds. They are local files of at most 1 MiB each that read in tens of
microseconds (44 µs for three fixture files, measured), so two seconds is ample
for a healthy machine and short for a person waiting; a file that gives no answer in that time (an `/etc` on a mount
that hangs) refuses, and the refusal names it: `/etc/passwd could not be read:
it gave no answer within 2s`. A test injects a source that never answers and
holds both properties. Reads of the installation path itself (`lstat` of each
folder, the access-ACL query) are file-system calls with no deadline of their
own.

## Amendment, 2026-11-18: rehearse entry and retain the reporting shell

Doctor, `machine check`, setup and start may rehearse entry when the existing placement check returns
`ErrBesideSubtree` and the existing membership guard proves outside. They stay in their original cgroup and keep
its identity. `--no-scope` on doctor and setup disables the rehearsal. A failed rehearsal prints its reason and keeps
the in-place finding and exit. Run (except `--service`), watch, test and the exact `machine test` pair retain relocation.
No environment variable, WSL name or SSH indicator grants entry. If `/proc/1/cgroup` is not `0::/init.scope`, entry
is not attempted: the system manager has not been shown at the top of the visible tree.

The same single process-start site and two pipes are used, with `--collect` added to the fixed runner arguments.
The request has `Rehearse`. The child validates every environment entry and restores the first occurrence of each
name before checking membership and placement or acknowledging readiness. Invalid names, missing `=` and NUL bytes
refuse before commit. Reply bytes distinguish ready, invalid command, unproved outside membership, refused placement
and invalid environment. A rehearsing child exits after its reply and never dispatches, even if sent a go-ahead.
The waiting parent prints the scope line and sends permission only for relocation. Terminal and signal ownership
remain the existing mechanism; its guest acceptance is separate from a protocol unit result.

A successful rehearsal replaces only D3's placement failure. The caller still checks writable delegation,
controllers, a throwaway cgroup and writable `cgroup.kill`. The D3 detail says the original shell is outside and
entry was just shown to work. A successful stored check remains `where: shell`, with its enforcing tier and optional
`through_user_scope: true`; `as.in_user_cgroup` continues to describe the original shell. Older check files omit the
new key and read as false. Null or non-boolean values, or true on a root/user-manager check or a check with no tier,
are invalid. The guide says "through a user scope" in its check fact. No root-tier or peer authority comes from this
stored presentation field.

The proposed private-cgroup-namespace outside proof is **stopped** on measured WSL 3.0.5 / Ubuntu 24.04.5:
normal uid 1000 gets EACCES reading the namespace links of its own live service manager, whose permitted
capabilities include CAP_WAKE_ALARM. Same uid, exact manager cgroup and a live peer pidfd do not supply the missing
namespace identity. The existing fail-closed membership guard and peer refusals remain unchanged. Rehearsal does
not enable ordinary WSL-shell entry under this layout. Protocol, D3 and stored-check unit tables establish their
modeled cases; real SSH and WSL terminal acceptance remains required.

*Amended 2026-11-18.* The rule that replaces the stopped proof is built (ADR 0100, amendment of the same day): the
guard reads a three-valued answer through `Outside()` alone, in the caller and again, afresh, in the re-entered
process; nothing of the answer travels in the request. A caller whose path shows a run is not moved and nothing is
reported, as before. A caller beside its user's subtree that cannot be shown to be outside every run (the rule's
unknown) is not moved either and is told why: `run`, `watch`, `test` and `machine test` exit 125 `[governed]` with
the cause's words, and `doctor`, `machine check` and `start` print the same words once and go on to their in-place
report. On a WSL machine an ordinary build's answer is unknown, cause `wsl-launcher-unproven`, so the entry is not
taken there yet; that it would be taken with the gate lifted has no guest proof. *Amended 2026-11-19:* the same holds
on WSL in the kernel's first cgroup namespace (`isolateDistroCgroup=false`), and outside WSL beyond the first
namespace the answer is unknown, cause `system-unproven`, so the entry is not taken there either (ADR 0100).

The wire command validator accepts `machine check` only for rehearsal and `machine test` only for relocation.
Other second words under `machine` confer neither permission. The process-handshake table exercises both accepted pairs.

WSL readiness is separate from a measured kernel tier. While the four containment rows in GAPS remain open,
doctor prints one warning for each and returns finding status 1 (an unavailable `--require` remains 211). Its
JSON includes `pending_wsl`; setup stores no ready tier or successful scope-placement claim for that report.
The kernel release selects those diagnostic words only; it never proves outside-run membership.

## Amendment, 2026-11-19 (round 4, X1): a shell outside the user manager is no blocker when entry works

Measured: in a Windows 11 guest, an ordinary WSL shell (cgroup `0::/non-systemd`), the test build with the rule's
switch on, `tego setup --json` exited 1 although doctor in the same shell said tier landlock with entry rehearsed and
working, and `tego run` and `tego watch` exited 0 through a user scope (row `W-N3-REACH`, run 2,
`guest-proofs/runs/windows/evidence/W-N3-REACH.log`). Two things held the check step blocked: the WSL readiness hold
(`pending_wsl`), which made setup store no tier, and the fact for a shell outside the manager, which said only that
"run, watch and test can try a user scope".

Decision. Where the commands a person runs next (run, watch, test, start's steps) open a user scope themselves, a
shell outside the user manager's cgroup is not a blocker:

- When the rehearsal from the original shell worked, the stored check is a tier with `through_user_scope: true` (as
  before), and the check step is done with the fact "this shell is outside your user manager's cgroup; tego run, watch
  and test open a user scope for each run (checked)". `tego setup` exits 0, the guide goes on to the next step,
  `tego doctor`'s last line ends with the same sentence, and `tego start` goes on to its four steps and says it.
- When the rehearsal failed, its reason travels from the CLI to the report (`doctor.WithUserScopeFailure`,
  `Report.UserScopeFailure`) and is stored (`scope_error`, only beside `cause: outside-user-manager`; validated like
  `first_fix`). The step stays blocked with "this shell is outside your user manager's cgroup and tego could not open a
  user scope from it (<reason>)", and the next step is the one fix, a shell opened in the manager's cgroup
  (`RuleCheckOutside`), never run, watch or test, which would fail the same way. Doctor's last line and tier line say
  the reason; its fix line is D3's.
- With no rehearsal (`--no-scope`, or a check stored by an older build) nothing changes.
- The WSL readiness hold above is now one switch with the rule's gate (ADR 0100, amendment of 2026-11-19, round 4):
  doctor lists `pending_wsl` while the machine is WSL (two marks) and the gate holds there; a test build with the
  switch on, and the commit that turns the rule on for WSL, lift both. That commit is made only when the four rows are
  proven. *Amended 2026-11-19 (round 6):* the four rows passed and the commit is made (ADR 0100, round 6): in an
  ordinary build on WSL with two marks setup proceeds and the stored check is a tier with `through_user_scope: true`
  where the rehearsal worked; on one mark nothing a person sees changes, and setup still refuses at the gate.

The installer's line over SSH, for a tego that opens a user scope itself, now says that run, watch and test open one
for each run, that tego setup checks this from the shell, and keeps `systemd-run --user --scope bash` as the one fix.
The dashboard's machine page reads runs, not the check, and its guide tour takes the guide's state, so it agrees.
Shells inside the user manager see no change. Tests: `TestSetupOutsideTheManager`, `TestStartOutsideTheManager`,
`TestThroughScopeWordsAgree`, `TestRehearsalFailureReachesTheCheck` (internal/cli), `TestFailedRehearsalSaysWhy`,
`TestRehearsedReportKeepsTheShell`, `TestWSLQualificationDoesNotPromiseReadiness` (internal/doctor),
`TestCheckScopeErrorRoundTrips` (internal/guide), and the installer test; each failed first against the earlier code
under an overlay. Guest row: `W-N3-REACH` (setup exit 0, a supervised run).

## Amendment, 2026-11-19 (round 5, Y10): the rules file is checked before a user scope is opened

Measured: in the Windows guest (row `W-N3-DRIVE`, run 3) a rules file on the Windows drive was refused correctly
(exit 125, the line naming the drive and the Linux home), but `tego: opened a user scope for this run` was printed
first: `tego run` opened the scope, and only the re-entered process loaded the rules file. A person reads that line as
a run that started.

Decision. Every check of the rules file a command names that needs no run state is made before the command opens a
user scope (`rulesBeforeScope`, `internal/cli/run.go`), for `tego run` and `tego watch --boundary`: the name resolved
in the registries, the file read through `config.ReadRulesFile` (ADR 0059's file-system check), parsed and loaded with
what it extends, exactly as the run loads it (`loadRunContract`). A refused rules file (on such a file system, missing,
or one that does not load) is said with the run's own words and exit code, and no scope is opened. It reads the
machine config read-only (`config.Load`) and writes nothing; it prints nothing when the file loads (the run prints its
notices once, after the scope); a machine config that cannot be read is left to the run, which says why after
restoring tego's own state. Checks that need the machine as it is (the compile's mount table, the tier) stay after the
scope, where the run is. `tego test` names no rules file. Test: `TestARefusedRulesFileOpensNoScope` (a rules file on a
drvfs stand-in by path, by name and as a watch's boundary, and a missing one: no scope opened, exit 125, the refusal's
words; a rules file that loads goes on to the scope), red at `c012a53a0` (the scope opened in all four). The scope's
own tests now name a rules file that loads, and `TestScopeBeforeAnyRunState` allows the read-only config load of
`tego run` before the scope while still refusing any run state there.
