# Where this machine is, and what to type next: `tego setup`

`tego setup` checks this machine from your shell, then lists the six steps from installing Tego to an agent held by
its own contract. Each step shows whether it is done and the fact that decided it. Last, it names the one command to
type next. It asks nothing and needs no root. It may briefly rehearse entry into a user scope; `--no-scope` skips that check. On a machine where one run was recorded (this is the
half-done test fixture's output, `internal/cli/testdata/setup-half-done.golden`):

```
$ tego setup
Tego on this machine, step by step:
  [x] 1 Install             tego v0.0.0-fixture (commit f1x7ure)
  [x] 2 Check this machine  ready: tier 1 (landlock) from a shell in your user manager's cgroup, checked 2026-11-11 09:30 UTC
  [x] 3 Find your agents    you recorded python3 bot.py --loop
  [x] 4 Record one run      run b883rx recorded python3 bot.py --loop and ended
  [ ] 5 Make its contract   no contract in the registries
  [ ] 6 Enforce it          no run under a contract has ended
Not known:
  - agents Tego never recorded: nothing here looks for them yet
  - a contract in no registry (a file given by its path) that no run used

next: make a contract from what it did, and read it before you use it:
  tego rules learn b883rx --save bot
```

Run it again after each step. The `next:` lines are on stderr, after the list, and follow the same rule as every
other command's: they are shown in a terminal, `TEGO_HINTS=on` shows them where stderr is not a terminal, and
`TEGO_HINTS=off` hides them. They never appear with `--json`. A `next:` line is meant to name neither the command that
printed it nor a command that fails from the shell you are in. Unit tests model an SSH login, a console login, a
`systemd-run --user --scope` shell, agents run through sudo from an SSH login and from such a shell (with the cgroups
Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44 showed), a user with no user manager running, the same user after linger
reached from an administrator's shell, and a user whose name systemd refuses, on a fresh, a half-done and a finished
machine (`TestTheNextLinesNeverLoopFromAnyPlace`). Those fixtures do not prove a real automatic handoff. A place outside that list is not covered.

Overview and the optional dashboard tour use the same stored facts. If a step is not known, a refresh checks it
again. An ended run stays unconfirmed until its record and chain anchor verify; an invalid record stays blocked.
With scripts off, use the reload link. Facts already checked can take up to 15 seconds to refresh.

## Over SSH, or on a console login

Automatic user-scope entry is built for `tego run`, `tego watch` and `tego machine test`. They try it when this shell
sits outside your user manager's cgroup and the manager answers. SSH, console, terminal and real-manager
validation is **owed in a guest** on Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44. Process stand-ins check the
invocation and parent/child plumbing; they do not establish that the handoff works in those logins.
The previously checked manual path remains available:

```sh
systemd-run --user --scope bash
tego setup
```

After a committed handoff, Tego says `tego: opened a user scope for this run` once on stderr. The built path
passes the original arguments, working directory, environment and standard streams to the new launcher, whose
pid the runtime writes in the record. Setup, start and doctor keep their original shell and may rehearse entry into a user scope. A successful rehearsal proves placement only; the delegated-tree checks still have to pass. Setup can name a run
step that attempts entry, such as `tego watch -- <the command you start it with>`. Doctor describes that shell's
placement and whether entry was just shown to work. `tego doctor --no-scope` and `tego setup --no-scope` check without starting a scope helper. Missing systemd-run, a refused manager, failed placement or a ten-second
startup timeout gives exit 125 and the existing `next:` line, before a run id or run record. Cancelling startup
with Ctrl-C exits 130 without fallback advice and never gives the child permission to run.

The handoff uses `/usr/bin/systemd-run` or `/bin/systemd-run` and the checked absolute path of the running Tego
binary, never PATH. An unsafe, unreadable or replaced binary path refuses the handoff. It uses
this account's user manager even after `sudo -u` and restores the original environment for normal startup. It
does not enable lingering. Logout or stopping the manager can end a scope as with a shell opened by hand.
A nested governed call keeps the existing path and cannot request a scope outside its run. `tego run --service`
keeps its unit.

The waiting parent follows the launcher's stop through the existing job-control mechanism, checking it is still
stopped so a delayed stop status after `fg` cannot stop the parent again. It avoids forwarding
INT/QUIT when its process group is already foreground on its controlling terminal, including with piped stdin.
For a deliberate INT/QUIT while the job is foreground, target the launcher or the whole job; a signal sent only
to its waiting parent is not forwarded. Without a controlling terminal, or in the background, the parent forwards it.
Known limit: `kill -INT %1` to a background job with piped stdin can deliver two interrupts and escalate immediately,
since the parent cannot distinguish a group send from a parent-only send. Target only the launcher pid for a
single graceful background interrupt.
It resets a terminating signal's disposition before raising it on itself, then falls back to exit 128 plus the
signal number if still alive. Parent death sends the launcher SIGTERM so normal `stop_grace` can finish the record.
There is no additional forced-kill timer if that launcher is unresponsive; existing tier-specific orphan cleanup
and a later sweep remain the fallback. All of these complete-login behaviors are **owed in a guest**.

## A user with no user manager (a service account)

A user whose login shell is `/usr/sbin/nologin` or `/bin/false`, reached with `sudo -u <user>` or `su -s`, often has
no user manager running at all: it never logged in, and nothing keeps one for it. Tego starts no run for it, not even
`tego watch`. An administrator sets such an account up in this order, typing every line in the administrator's own
shell (here the account is `svc`, uid 1002):

1. Create the account, with a name that starts with a letter (see below):
   `sudo useradd --create-home --shell /usr/sbin/nologin svc`. Install tego **as that account**, into its own
   `~/.local/bin` ([INSTALL.md](https://github.com/Attention-Span-AI/Tego/blob/main/docs/INSTALL.md#a-service-account)). Put the installed folder on that account's
   login-shell `PATH` in its `~/.profile` before using the explicit login-shell examples below. The lookup runs as `svc`;
   sudo's own `secure_path` need not contain the installed folder. Tego's printed commands instead name the checked
   absolute path of the running copy.
2. Start a user manager for it that runs without a login. `sudo -u svc -H sh -lc 'exec "$(command -v tego)" setup'` says "no user manager runs for
   you" and names the command:

   ```
   next: no user manager runs for you; with sudo, start one that needs no login:
     sudo loginctl enable-linger svc
   ```

3. Run `sudo -u svc -H sh -lc 'exec "$(command -v tego)" setup'` again. It names the service account's next step with
   that account and the checked absolute path of the running binary. The built run, watch and test path
   tries its own scope as `svc`; that handoff is **owed in a guest**. Tego does not enable lingering for you.
4. The existing manual path opens a shell inside that account's manager:
   `sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash`, then run `tego setup` in it.
   Type the sudo command in your own login shell. Leave a shell sudo or su opened first (`exit`), since `svc`
   may not use sudo. Doctor's manual fallback names this same account, not the administrator's.

Every other `next:` line from a command run as `svc` is for you to type in your own shell too. A Tego command
in it names `svc` with sudo's target-account option and the checked full path of the copy that printed it.
Where the command runs in a folder, a shell changes folder and executes that checked path as `svc` too.
That form needs a sudoers grant that lets you run a shell as `svc`, which Tego cannot read, so the line says it
may be refused: a grant for the `tego` binary alone refuses it, and then you run the same command from a shell
opened as `svc`. After the account's first governed run, setup points to a receipt command for `svc` and its run id.
Without the account prefix, that command reads **your** record and fails ("no such run"), or answers for the wrong user. In the account's own shell
(step 4), where nobody started `tego` for another user, such lines stay bare. Before step 2, `tego run`, `tego watch` and `tego test` end their exit 125 with the same
`next:` block as `tego setup` (the `sudo loginctl enable-linger` line), not only the `fix:` text inside their error line.

When the account's user manager runs but keeps no socket under `/run/user/<uid>`, no command can open a shell in it from
your shell. Step 2, the `next:` line and the `fix:` line then all say so and name no command (before, the `fix:` line
still named the `sudo -u` command, which fails there).

The name in these commands is the account's own, from the passwd database (never from your environment), quoted when
it is not one plain word. Where `loginctl` or `sudo` would read the name as an option or a uid (a leading `-`, or
digits only, and for `sudo -u` a leading `#` or `+`), or the name has a character that does not print, the commands
name the uid instead (`'#1002'` for `sudo -u`). `XDG_RUNTIME_DIR` is given because `sudo -u` leaves it unset, and
`systemd-run --user` reaches the user's manager through it. Typed without `sudo -u svc`, the line opens a shell in
**your own** user manager, where `tego setup` says ready for you, not for `svc` (Ubuntu 24.04, AlmaLinux 9.8), or
fails (Fedora 44). Measured in guests on 2026-11-11: with `sudo -u svc` in front, and with `tego setup` in place of
the interactive `bash` (or `bash -c` and a line that ran it), it ran `tego setup` in `svc`'s user manager, ready at
tier 1, on all three. The interactive `bash` form was not run. After linger, `tego machine check`'s `fix:` line and the
error line of `tego run`, `tego watch` and `tego machine test` name the same `sudo -u` command there.

Tego decides that you are another user from two facts, neither read from the environment: the login uid the kernel
keeps for the session (`/proc/self/loginuid`, set at your SSH, console or desktop login and kept by `sudo` and `su`),
and the owners of the processes above `tego` (`sudo` or `su`, then your shell). It does not read `SUDO_UID`. A process
of `svc` cannot change who owns the processes above it. One whose login uid is unset can set it once (the kernel
allows that without privilege; read in the kernel's code, not run), which only makes tego print the `sudo -u` form;
both forms are made of fixed words, the passwd name and numbers. When you are `svc` in its own login, the line is
`systemd-run --user --scope bash` as above, or the `XDG_RUNTIME_DIR=/run/user/1002 ...` form where `XDG_RUNTIME_DIR`
is unset. Where neither fact can be read (a process tree hidden by `hidepid` and no login uid), tego prints that same
form, and an administrator who reads it must type it as `svc`. Unit tests check both forms. A root test in a guest
ran the choice for the `fix:` line over the real `/proc`: a process of one uid started by a process of another got the
`sudo -u` form. The words, and the choice under a real `sudo` or `su`, have not yet been run in a guest.

**A name systemd refuses.** systemd's rules for user names
([systemd.io/USER_NAMES](https://systemd.io/USER_NAMES/), the relaxed rules, which `systemd-logind` applies) refuse a
name of digits only (`4242`, which it reads as a uid), a `-` and digits only, `.` or `..`, a name with `:`, `/` or a
control character, one that is not UTF-8, and one that starts or ends with white space. For `4242` on Ubuntu 24.04,
`sudo loginctl enable-linger` exited 0 and wrote `/var/lib/systemd/linger/4242`, but started no user manager
(measured). That the other refused names get no user manager either is read from those rules, not run. For all of
them `tego setup` and `tego machine check` say that systemd starts no user manager for the account, name no `next:` command,
and say what to do: run the agent as an account whose name starts with a letter and holds only letters, digits, `_`
and `-`. Ubuntu's `useradd` refused `4242` unless given `--badname`, and Fedora's refused it even then (measured on
those two; AlmaLinux was not tried). Unit tests check these lines; only the digits-only case was run in a guest,
before this change.

Linger keeps that user's processes and units running after logout and starts its manager at boot; turn it off with
`sudo loginctl disable-linger svc` when it is no longer needed.

## The steps

| # | Step | Done when | Read from |
| - | ---- | --------- | --------- |
| 1 | Install | always: it is running | the binary's build info |
| 2 | Check this machine | a check of this boot and this build says a run started from where it was made can enforce | `~/.tego/state/check.json` |
| 3 | Find your agents | Tego has recorded a run, or a fresh same-boot saved scan reports eligible own running or installed evidence; a scan is an untrusted observation | your ledger root and `~/.tego/scan/last.json` |
| 4 | Record one run | a run that enforced nothing (`tego watch`) has ended, and its record checks out now against `~/.tego/chain.log` | the record of that run and the chain anchor |
| 5 | Make its contract | a contract in your registry (`~/.config/tego/agents/`) or in this folder compiles now (the first 20 names, in name order). With several, it names the one the newest ended run under a contract ran, when that run's record checks out; else the one named after the recorded run's folder; else the first in name order | the registry |
| 6 | Enforce it | a run under a contract has ended, and its record checks out now against `~/.tego/chain.log` | the record and the chain anchor |

The marks are `[x]` done, `[ ]` to do, `[~]` waiting (a run is still going), `[!]` blocked (the check found no tier,
no contract compiles, or a record does not check out), `[-]` skipped (you wrote a contract by hand and ran it without
recording first) and `[?]` not known (its source could not be read; the "Not known" lines say which).

A step is never ticked for a run that is still going, and a check from before this machine last started, or from
another tego build, is never used. A contract with `tier: auto` that no run used is compiled at the machine's
ceiling, whatever the stored check says. Setup reads an eligible saved scan but starts no discovery itself.
It never establishes that no agents exist. It never writes the command you start your agent with: before anything is recorded, the next step is
`tego watch -- <the command you start it with>`, and you fill in the part in angle brackets.

## The check it stores

`tego setup` runs the no-root checks of `tego machine check` (the kernel, the cgroup your shell can place a run in, Landlock
and seccomp) from your shell, with your shell's privilege. It loads no BPF program. It stores the answer in
`~/.tego/state/check.json` (mode 0600, the folder 0700), one entry per place it was run from: a shell outside your user
manager's cgroup (an SSH login), a shell inside it (a desktop terminal, or `systemd-run --user --scope bash`), or root.
The dashboard's Overview reads that file to show the same step, since its own process is not your shell.
A successful entry rehearsal keeps the entry under `shell`, with `through_user_scope: true`; it does not turn
`as.in_user_cgroup` true. The check step is then done, and its fact says "this shell is outside your user manager's
cgroup; tego run, watch and test open a user scope for each run (checked)": such a shell is no blocker. When the
rehearsal fails, the entry keeps `"cause": "outside-user-manager"` and adds `scope_error`, the reason; the step stays
blocked with that reason, and the next step is the one fix, a shell inside the manager's cgroup
(`systemd-run --user --scope bash`). Older files omit both optional keys.

An entry from a shell outside your user manager's cgroup that cannot place a run says so
(`"cause": "outside-user-manager"`), and one that starts no run because no user manager runs for the user says that
(`"cause": "no-user-manager"`), so the dashboard can name the same next step; the key is left out otherwise. The
dashboard cannot build the `loginctl` command (it does not link the engine), so for that cause its next step is `tego
doctor`, which prints it.

`tego machine check` does not write it: doctor stays a read-only check. A file at `check.json` that is not one `tego setup`
wrote (another shape, a link, a FIFO) is reported as not known by the `tego setup` that finds it, and that same
`tego setup` replaces it with its own regular file, never writing through a link. A folder there is reported as not
known and left as it is. If the check cannot be stored (a folder at `check.json`, a link at
`~/.tego/state`, a folder another user can write), `tego setup` still uses its check for what it prints, and the first
"Not known" line says it was not stored.

After a reboot, a place's check from before the machine started is not used. `tego setup` checks only the place it
runs from, so step 2 names each other place as "not checked since this machine started", and the stored file then
keeps the new check alone.

When you run `tego setup` from a shell that cannot enforce (an SSH login, say) and a check stored from another place
says it can, step 2 is done and its fact says "not from ..., where you are now". A next step that starts a run
(`tego watch`, `tego run`) now names that run directly, since the built path attempts a user scope. Its login behavior is owed in a guest. When scope entry is
known to be unavailable, the existing fallback still names the manual step or says why no command opens one. When the only check that can enforce is root's, step 2 says root's check holds only
a run started as root, with sudo, and the next step is `tego machine check`, which says why this shell cannot. No stored
check chooses a command.

The learn step names `--allow-host <host>` only when the proposal from that run would still allow addresses and Tego
found no destination the run's secrets may have gone to; `tego watch` and `tego rules learn` decide the same way, from the
same record. Otherwise it is `tego rules learn <run> --save <name>`, and `tego rules learn` names `--allow-host` for the addresses
it kept.

Any program you run outside Tego runs as you and can change this file, as it can change your shell's startup files.
The worst it does to `tego setup` is make the guide show a wrong step or a wrong sentence in a fact. A next command
is built only from fixed words, a run id, an agent name and one folder Tego quotes: the working folder of a recorded
run whose record checks out against `~/.tego/chain.log`. The run `tego rules learn` is pointed at checks out too. A run
folder such a program writes without its line in `chain.log` is blocked, never used. A program that also rewrites
`chain.log` can choose that folder, as it can make `tego session show --verify` pass (ADR 0142). No other text from a file
or the record goes into a command. `tego run` checks the machine again when it starts. An agent held by Tego cannot
write `~/.tego` at all.

## Options

- `--json` prints one JSON object, schema `tego.setup/1` (below), and no `next:` lines.
- `--no-scope` checks this shell without rehearsing user-scope entry. Doctor accepts the same option.
- `-v` also prints who asks and from where, the kernel and boot, where each fact was read, the run a step is about,
  why that run or contract was taken, and the rule that chose the next step.

## Exit codes

| Code | Means |
| ---- | ----- |
| 0 | printed, and a run started from here can enforce at tier 1 |
| 1 | printed, and no tier enforces a run started from here (the check's finding). From a shell outside your user manager's cgroup, run commands try to open a user scope; setup still reports its original shell. Otherwise `tego machine check` names the fix |
| 2 | a usage error |
| 125 | the machine config, the record or a registry could not be read, or a recorded run could not be checked against the chain anchor (the list is printed first, with `[?]`); or it ran inside a tego run (`[governed]`); or it ran under sudo for another user (`[privilege]`): run it without sudo |

## JSON: `tego.setup/1`

New fields may be added within `tego.setup/1`; removing one or changing what one means makes `tego.setup/2`.

| Field | Holds |
| ----- | ----- |
| `schema` | `"tego.setup/1"` |
| `tego` | `version`, `commit` |
| `as` | who asked: `user`, `uid`, `root`, `ssh`, `in_user_cgroup`, `in_run`, `where` (`shell`, `user-manager`, `root`), and from a shell outside the user manager's cgroup `scope` (the command that opens a shell inside it) or `scope_missing` (why none does), and `scope_as` (the user `scope` opens a shell as, written as the command writes it) when `tego` was started from another user's shell through `sudo` or `su`, so `scope` begins with `sudo -u`; `null` when no shell asked (the dashboard) |
| `host` | `kernel`, `boot_id` |
| `steps[]` | after a successful rehearsal the check step is done and its fact says the shell is outside your user manager's cgroup and that run, watch and test open a user scope for each run (checked), while `as` still names the original shell; in order: `id` (`install`, `check`, `find`, `record`, `contract`, `enforce`), `title`, `state` (`done`, `todo`, `waiting`, `blocked`, `skipped`, `not-known`), `fact` (`null` when not known), `source`, and when they apply `run` (a full run id) and `link` (why that run or contract) |
| `next` | `step` (`""` when every step is done), `rule`, `text`, `command` (`""` for none), `needs_root`, `placeholder` (the command has a part in angle brackets) |
| `records_partial` | optional true when unreadable or capped run-start evidence makes the inventory incomplete |
| `agents[]` | additive rows shared with Agents: one named recorded run per recorded row, with run id/time and stages from that same checked snapshot; scan observations stay separate and have no stage ticks. Unchecked rows state the reason and next step. Arguments are not serialized; missing relations say Cannot tell |
| `not_known[]` | what Tego could not know, one sentence each; never empty |

This object comes from a test fixture of a finished machine (`internal/guide/testdata/finished.json`; `<root>` is
the fixture's folder):

```json
{
  "schema": "tego.setup/1",
  "tego": {"version": "v0.0.0-fixture", "commit": "f1x7ure"},
  "as": null,
  "host": {"kernel": "6.8.0-fixture", "boot_id": "6b1c2d3e-4f50-4a6b-8c7d-8e9fa0b1c2d3"},
  "steps": [
    {"id": "install", "title": "Install", "state": "done",
     "fact": "tego v0.0.0-fixture (commit f1x7ure)", "source": "the binary's build info"},
    {"id": "check", "title": "Check this machine", "state": "done",
     "fact": "ready: tier 1 (landlock) from a shell in your user manager's cgroup, checked 2026-11-11 09:30 UTC",
     "source": "<root>/home/.tego/state/check.json"},
    {"id": "find", "title": "Find your agents", "state": "done", "fact": "you recorded sh",
     "source": "<root>/home/.tego/runs/r-f16d05ec-0dmsa61z34x6o-b88krx",
     "run": "r-f16d05ec-0dmsa61z34x6o-b88krx", "link": "the newest run under the ledger root"},
    {"id": "record", "title": "Record one run", "state": "done",
     "fact": "run b883rx recorded python3 bot.py --loop and ended",
     "source": "<root>/home/.tego/runs/r-f16d05ec-0dms9yec6mm80-b883rx",
     "run": "r-f16d05ec-0dms9yec6mm80-b883rx",
     "link": "the newest ended run whose tier is observe (tego watch, --observe), checked against <root>/home/.tego/chain.log"},
    {"id": "contract", "title": "Make its contract", "state": "done", "fact": "bot compiles now",
     "source": "<root>/home/.config/tego/agents/bot.yaml",
     "link": "the contract the newest ended run under a contract, b88krx, ran; its record checks out; compiled as run b88krx ran it, from its folder at its tier"},
    {"id": "enforce", "title": "Enforce it", "state": "done",
     "fact": "run b88krx ran at tier landlock and ended; its record checks out now",
     "source": "<root>/home/.tego/runs/r-f16d05ec-0dmsa61z34x6o-b88krx",
     "run": "r-f16d05ec-0dmsa61z34x6o-b88krx",
     "link": "the newest ended run under a contract, checked against <root>/home/.tego/chain.log"}
  ],
  "next": {"step": "", "rule": "enforce-done", "text": "every step is done; see what the last enforced run did:",
           "command": "tego session show b88krx", "needs_root": false, "placeholder": false},
  "not_known": [
    "agents Tego never recorded: nothing here looks for them yet",
    "a contract in no registry (a file given by its path) that no run used"
  ]
}
```

## What it does not do yet

The six steps work at machine level: they say whether any run was recorded, any contract made and any run enforced.
The additive `agents[]` inventory identifies each named recorded run separately; scan observations never join a
recorded row or inherit its ticks. `tego scan` supplies bounded observations for agents Tego has never recorded,
not proof that every agent has been found. The per-agent command (`tego setup --agent <name>`) and rules for every
agent on the machine remain later work. The designs and limits are ADRs 0142 and 0145.

## On the dashboard

The dashboard's Overview shows the same steps, facts, next step and not-known lines as `tego setup`, from the same
object and in the same words: with no run yet it is the whole page, and with runs it sits under the headline until
every step is done, then folds to one line. It never runs the checks itself. It shows the check `tego setup` stored for
this boot and for the tego you type (the first `tego` on its PATH, else the one beside `tego-control`); with none it
says "not checked since this machine started" and names `tego setup` as the next step, so run `tego setup` in a
terminal after each boot. Three differences, all on purpose: it reads no project registry, since it has no working
folder (a contract only in a folder's `.tego/agents` shows in `tego setup` run from that folder, not on the page); it
has no shell, so it never adds the words `tego setup` adds for the shell it runs in ("not from a shell outside your
user manager's cgroup, where you are now" and "not from this shell; from ..., run:"); and it can take up to 15
seconds to show a contract you just saved. With no run yet, it also shows the first step for any agent, `tego watch --
<the command that starts your agent>`, under the guide's own next step, unless that is the next step. Of the guide's
text, the next step's command is the only one offered to copy; a fact, the stored fix sentence among them, is always
shown as text.


## WSL measurement limit

A Windows guest with WSL 3.0.5, Ubuntu 24.04.5 and kernel 6.18.58.1 used a private cgroup namespace. Its ordinary
shell was outside the user delegation, and the normal user could not read its service manager's namespace links.
The earlier membership guard therefore refused setup and suppressed automatic entry there. Since 2026-11-18 Tego has a
rule that tells such a shell from a process inside a run without reading another process's namespace, and since the
commit that switched it on for WSL (ADR 0100, amendment of 2026-11-19, round 6) it is on in every build where WSL shows
two of its marks (the kernel release, `/run/WSL`, a `WSLInterop` entry). The four containment checks it waited for
passed in that Windows guest: a run refuses WSL's own program launcher (`wsl.exe` and the sockets under `/run/WSL`),
the second name of your home folder (`/mnt/wslg/distro/...`), a write on the Windows drive, and the GUI and audio
sockets, under the default rules and with `host_sockets: true`. So `tego setup`, `run`, `watch` and `test` proceed
from an ordinary WSL shell, through a user scope they open for each run, and `tego doctor` no longer lists the four
checks as unproven.

What stays as it was:

- A distribution that shows only one mark of WSL (interop turned off shows its kernel release alone) keeps every hold:
  setup, run, watch and test refuse with the line that on WSL this build treats no process as outside every tego run
  yet, doctor lists the four checks, and setup stores no ready tier. Relaxing needs two marks; holding needs one.
- With `isolateDistroCgroup=false` (the shell sits in the kernel's first cgroup namespace) the two-mark rule decides
  the same way. With systemd off the line says the service manager is not at the top of the cgroup tree and how to
  turn systemd on; in the first seconds after WSL starts it says your user session is not up yet; as root it says to
  run tego as your own user, without sudo. Each refusal exits 125 and ends `[governed]`.
- Not proven: the rule's answer where `/proc/self/ns/cgroup` is served by FUSE (unit-tested for a plain file only),
  the facts of a shell opened from a terminal window (the guest could not drive one), WSL's mirrored networking
  (`networkingMode=mirrored`) for the Windows browser's access to the dashboard, which is not supported, and a real
  keyboard and mouse click, a signed executable, a real HTTPS release, ARM64 and Windows 10. The ordinary build with
  the switch on has run in a guest (2026-11-19): all six beginner steps passed on Windows PowerShell 5.1, with
  PowerShell 7 and cmd checked on a base that already had WSL, and Allow once in the browser continued a held run.
  WSL's idle shutdown also remains open.

No WSL support claim goes beyond those rows: kernel features or a successful diagnostic alone establish none. Root
tiers, which need root, also require the kernel's initial process-id namespace; updating WSL or adding `bpf` to its LSM
list does not establish that requirement. `WSL_INTEROP` is omitted from enforcing runs.

Keep your rules files in your Linux home, not on the Windows drive. Tego refuses to run from a rules file (or a file it
extends) on `/mnt/c` or another Windows drive: there the owner and permissions are made up by WSL, and any Windows
program can change the file. A project on the Windows drive is fine; its rules file goes in your Linux home, for
example `~/tego/agent.yaml`. The same refusal holds on Linux for rules files on FAT, exFAT or NTFS disks, 9p or
virtiofs shares and SMB shares.
