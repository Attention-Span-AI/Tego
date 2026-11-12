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
   and the time. **`tego doctor` stays read-only**: scripts and monitors run it, and a read-only check that gained a
   side effect would surprise them (the expert judge; spec §7 moves this off doctor, against the earlier dashboard
   decision D5). The build is the version, the commit and the running executable's device, inode, size and
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
   none, with the reason in step 2's fact, when `systemd-run` is not on `PATH` or `$XDG_RUNTIME_DIR` holds no socket
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
   the probe saying this cause end with it (`TestEveryRunCommandRefusesBesideTheUserManager`). The error line names
   the cgroup; it did not name the command that opens a shell in it, which a newcomer cannot guess. Hints stay off
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
   `sudo tego agents` sent the person to open the scope they were in, again and again. Ubuntu and AlmaLinux keep the
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
4. **Tested, not claimed.** `TestTheNextLinesNeverLoopFromAnyPlace` gains these places: `sudo tego agents` from SSH
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
   `sudo -u svc tego setup`, in their own shell. Typed there it opened the administrator's own scope on Ubuntu and
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
   it is the `fix:` line of `sudo -u svc tego doctor` on stdout and the end of the error line of `tego run`, `watch`
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
  compute it again each second; a contract just saved can take that long to show. Since the object is shared by every
  viewer, it is computed apart from the request that asked for it (its own 20 s bound): a request that ended would make
  a contract "not compile" and a record "not known" for the next viewer. An object whose bound ran out is shown to
  that request only and not kept.
- **Parity.** `TestOverviewGuideParityWithSetup` renders the Overview for each of the eight `guidetest` fixtures and
  holds every step, the next step and the not-known lines to the object in `internal/guide/testdata`, which `tego setup
  --json` prints for that tree (`TestSetupParityWithTheFiles`).

## Consequences

- One object for both surfaces, tested for parity on eight fixture trees with the command in the loop
  (`TestParityFixtures`, `TestSetupParityWithTheFiles`).
- `tego setup` writes one new file in `~/.tego/state`; nothing else in Tego reads it yet.
- The contract step compiles each registry entry (the first 20 in name order) on every `tego setup`, offline, as
  `tego rule` does; the record and enforce steps each verify one run's record, as `tego receipt --verify` does.
