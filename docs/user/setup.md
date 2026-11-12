# Where this machine is, and what to type next: `tego setup`

`tego setup` checks this machine from your shell, then lists the six steps from installing Tego to an agent held by
its own contract. Each step shows whether it is done and the fact that decided it. Last, it names the one command to
type next. It asks nothing, starts no program and needs no root. On a machine where one run was recorded (this is the
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
  tego learn b883rx --save bot
```

Run it again after each step. The `next:` lines are on stderr, after the list, and follow the same rule as every
other command's: they are shown in a terminal, `TEGO_HINTS=on` shows them where stderr is not a terminal, and
`TEGO_HINTS=off` hides them. They never appear with `--json`. A `next:` line is meant to name neither the command that
printed it nor a command that fails from the shell you are in. What is tested: an SSH login, a console login, a
`systemd-run --user --scope` shell, `sudo tego agents` from an SSH login and from such a shell (with the cgroups
Ubuntu 24.04, AlmaLinux 9.8 and Fedora 44 showed), a user with no user manager running, the same user after linger
reached from an administrator's shell, and a user whose name systemd refuses, on a fresh, a half-done and a finished
machine (`TestTheNextLinesNeverLoopFromAnyPlace`). A place outside that list is not covered.

## Over SSH, or on a console login

Tego starts every run, one that only records included, in your user manager's cgroup
(`user@<uid>.service`). A login over SSH or on a console starts beside it, in a session scope, so from that shell
`tego run`, `tego watch` and `tego test` exit 125. `tego setup` says so, and its `next:` line opens a shell inside that
cgroup (`internal/cli/testdata/firstrun-fresh-ssh.golden`):

```
$ tego setup
Tego on this machine, step by step:
  [x] 1 Install             tego v0.0.0-fixture (commit f1x7ure)
  [!] 2 Check this machine  tego starts no run from a shell outside your user manager's cgroup, not even tego watch, checked 2026-11-11 09:30 UTC; a shell inside it can start one
  [ ] 3 Find your agents    Tego has recorded no run here yet
  ...

next: open a shell in your user manager's cgroup, then run tego setup there:
  systemd-run --user --scope bash
$ systemd-run --user --scope bash
$ tego setup
```

In that shell every later `next:` line works as printed. The command uses your login shell's name (`$SHELL`) when it
is one of bash, zsh, fish, sh, dash, ksh, mksh, tcsh and csh and on your `PATH`, else `bash`: a fixed list, so no
setting names another program there. When `XDG_RUNTIME_DIR` is unset or holds no socket of your user manager (as
after `su` or `sudo -u`) but `/run/user/<your uid>` is your own folder and holds that socket, the command names it:
`XDG_RUNTIME_DIR=/run/user/<uid> systemd-run --user --scope bash`, to type as that user. When `tego` was started
from another user's shell through `sudo` or `su`, it puts `sudo -u <user>` in front, names `bash` whatever `$SHELL`
says, and says to type the line in your own login shell (see "A user with no user manager" below). When
`systemd-run --user` cannot reach your user manager from your shell even so (`systemd-run` is not on `PATH`, or no
such socket is there), step 2 says why and the `next:` line names no command: log in as yourself over SSH or on the
console, or open a terminal on your desktop, which is in that cgroup already. `tego doctor` says the same from such a
shell, and `tego run`, `tego watch` and `tego test` end their exit 125 with the same `next:` line, "then run this
again there". Where `tego learn --save` (or `tego agents`) would name `tego run` (or `tego watch`), it says that
command in a line of its own, to type in the new shell, and its `next:` line opens the shell.

`sudo tego agents` decides that by the shell you typed `sudo` in, not by its own process: on Fedora 44, sudo from a
`systemd-run --user --scope` shell opened a session of root's own and moved into it (measured; a desktop terminal,
also inside the user manager, is expected to do the same, not measured). Tego reads the cgroup of the nearest parent
outside root's own sessions, so from inside the scope its `next:` line is the step itself (`tego watch -- ...`), to
type without `sudo`, and from an SSH login it opens the scope. Unit tests check this with the cgroups the guests
logged; on Fedora only the command's own cgroup was logged, so the parents' cgroups in that test are assumed.

## A user with no user manager (a service account)

A user whose login shell is `/usr/sbin/nologin` or `/bin/false`, reached with `sudo -u <user>` or `su -s`, often has
no user manager running at all: it never logged in, and nothing keeps one for it. Tego starts no run for it, not even
`tego watch`. An administrator sets such an account up in this order, typing every line in the administrator's own
shell (here the account is `svc`, uid 1002):

1. Create the account, with a name that starts with a letter (see below):
   `sudo useradd --create-home --shell /usr/sbin/nologin svc`.
2. Start a user manager for it that runs without a login. `sudo -u svc tego setup` says "no user manager runs for
   you" and names the command:

   ```
   next: no user manager runs for you; with sudo, start one that needs no login:
     sudo loginctl enable-linger svc
   ```

3. Open a shell as that user, in its user manager's cgroup. `sudo -u svc tego setup`, typed again, names the command
   and says whose shell it opens:

   ```
   [!] 2 Check this machine  tego starts no run from a shell outside your user manager's cgroup, ...; tego ran as svc, started from another user's shell through sudo or su: type the next command in your own login shell, not in one sudo or su opened; it opens a shell as svc in svc's user manager's cgroup, not in yours
   ...
   next: from your own shell, open a shell as this user; run tego setup in it:
     sudo -u svc XDG_RUNTIME_DIR=/run/user/1002 systemd-run --user --scope bash
   ```

   Type it in the shell you logged in with. In a shell that `sudo su -s /bin/bash svc` opened, leave it first
   (`exit`): `svc` may not use `sudo`.
4. Run `tego setup` in that shell. It is the service account's, so every later `next:` line works as printed there.

The name in these commands is the account's own, from the passwd database (never from your environment), quoted when
it is not one plain word. Where `loginctl` or `sudo` would read the name as an option or a uid (a leading `-`, or
digits only, and for `sudo -u` a leading `#` or `+`), or the name has a character that does not print, the commands
name the uid instead (`'#1002'` for `sudo -u`). `XDG_RUNTIME_DIR` is given because `sudo -u` leaves it unset, and
`systemd-run --user` reaches the user's manager through it. Typed without `sudo -u svc`, the line opens a shell in
**your own** user manager, where `tego setup` says ready for you, not for `svc` (Ubuntu 24.04, AlmaLinux 9.8), or
fails (Fedora 44). Measured in guests on 2026-11-11: with `sudo -u svc` in front, and with `tego setup` in place of
the interactive `bash` (or `bash -c` and a line that ran it), it ran `tego setup` in `svc`'s user manager, ready at
tier 1, on all three. The interactive `bash` form was not run. After linger, `tego doctor`'s `fix:` line and the
error line of `tego run`, `tego watch` and `tego test` name the same `sudo -u` command there.

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
them `tego setup` and `tego doctor` say that systemd starts no user manager for the account, name no `next:` command,
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
| 3 | Find your agents | Tego has recorded a run | your ledger root |
| 4 | Record one run | a run that enforced nothing (`tego watch`) has ended, and its record checks out now against `~/.tego/chain.log` | the record of that run and the chain anchor |
| 5 | Make its contract | a contract in your registry (`~/.config/tego/agents/`) or in this folder compiles now (the first 20 names, in name order). With several, it names the one the newest ended run under a contract ran, when that run's record checks out; else the one named after the recorded run's folder; else the first in name order | the registry |
| 6 | Enforce it | a run under a contract has ended, and its record checks out now against `~/.tego/chain.log` | the record and the chain anchor |

The marks are `[x]` done, `[ ]` to do, `[~]` waiting (a run is still going), `[!]` blocked (the check found no tier,
no contract compiles, or a record does not check out), `[-]` skipped (you wrote a contract by hand and ran it without
recording first) and `[?]` not known (its source could not be read; the "Not known" lines say which).

A step is never ticked for a run that is still going, and a check from before this machine last started, or from
another tego build, is never used. A contract with `tier: auto` that no run used is compiled at the machine's
ceiling, whatever the stored check says. Tego does not yet look for agents it never recorded, so it never says there are
none. It never writes the command you start your agent with: before anything is recorded, the next step is
`tego watch -- <the command you start it with>`, and you fill in the part in angle brackets.

## The check it stores

`tego setup` runs the no-root checks of `tego doctor` (the kernel, the cgroup your shell can place a run in, Landlock
and seccomp) from your shell, with your shell's privilege. It loads no BPF program. It stores the answer in
`~/.tego/state/check.json` (mode 0600, the folder 0700), one entry per place it was run from: a shell outside your user
manager's cgroup (an SSH login), a shell inside it (a desktop terminal, or `systemd-run --user --scope bash`), or root.
The dashboard's Overview reads that file to show the same step, since its own process is not your shell.

An entry from a shell outside your user manager's cgroup that starts no run only for that reason says so
(`"cause": "outside-user-manager"`), and one that starts no run because no user manager runs for the user says that
(`"cause": "no-user-manager"`), so the dashboard can name the same next step; the key is left out otherwise. The
dashboard cannot build the `loginctl` command (it does not link the engine), so for that cause its next step is `tego
doctor`, which prints it.

`tego doctor` does not write it: doctor stays a read-only check. A file at `check.json` that is not one `tego setup`
wrote (another shape, a link, a FIFO) is reported as not known by the `tego setup` that finds it, and that same
`tego setup` replaces it with its own regular file, never writing through a link. A folder there is reported as not
known and left as it is. If the check cannot be stored (a folder at `check.json`, a link at
`~/.tego/state`, a folder another user can write), `tego setup` still uses its check for what it prints, and the first
"Not known" line says it was not stored.

After a reboot, a place's check from before the machine started is not used. `tego setup` checks only the place it
runs from, so step 2 names each other place as "not checked since this machine started", and the stored file then
keeps the new check alone.

When you run `tego setup` from a shell that cannot enforce (an SSH login, say) and a check stored from another place
says it can, step 2 is done and its fact says "not from ..., where you are now". A next step that would start a run
(`tego watch`, `tego run`) is then the step that opens a shell in your user manager's cgroup, as above, never the
command that exits 125 from here. When the only check that can enforce is root's, step 2 says root's check holds only
a run started as root, with sudo, and the next step is `tego doctor`, which says why this shell cannot. No stored
check chooses a command.

The learn step names `--allow-host <host>` only when the proposal from that run would still allow addresses and Tego
found no destination the run's secrets may have gone to; `tego watch` and `tego learn` decide the same way, from the
same record. Otherwise it is `tego learn <run> --save <name>`, and `tego learn` names `--allow-host` for the addresses
it kept.

Any program you run outside Tego runs as you and can change this file, as it can change your shell's startup files.
The worst it does to `tego setup` is make the guide show a wrong step or a wrong sentence in a fact. A next command
is built only from fixed words, a run id, an agent name and one folder Tego quotes: the working folder of a recorded
run whose record checks out against `~/.tego/chain.log`. The run `tego learn` is pointed at checks out too. A run
folder such a program writes without its line in `chain.log` is blocked, never used. A program that also rewrites
`chain.log` can choose that folder, as it can make `tego receipt --verify` pass (ADR 0142). No other text from a file
or the record goes into a command. `tego run` checks the machine again when it starts. An agent held by Tego cannot
write `~/.tego` at all.

## Options

- `--json` prints one JSON object, schema `tego.setup/1` (below), and no `next:` lines.
- `-v` also prints who asks and from where, the kernel and boot, where each fact was read, the run a step is about,
  why that run or contract was taken, and the rule that chose the next step.

## Exit codes

| Code | Means |
| ---- | ----- |
| 0 | printed, and a run started from here can enforce at tier 1 |
| 1 | printed, and no tier enforces a run started from here (the check's finding). From a shell outside your user manager's cgroup no run starts at all, not even `tego watch`; the `next:` line opens a shell inside it. Otherwise `tego doctor` names the fix |
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
| `steps[]` | in order: `id` (`install`, `check`, `find`, `record`, `contract`, `enforce`), `title`, `state` (`done`, `todo`, `waiting`, `blocked`, `skipped`, `not-known`), `fact` (`null` when not known), `source`, and when they apply `run` (a full run id) and `link` (why that run or contract) |
| `next` | `step` (`""` when every step is done), `rule`, `text`, `command` (`""` for none), `needs_root`, `placeholder` (the command has a part in angle brackets) |
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
           "command": "tego receipt b88krx", "needs_root": false, "placeholder": false},
  "not_known": [
    "agents Tego never recorded: nothing here looks for them yet",
    "a contract in no registry (a file given by its path) that no run used"
  ]
}
```

## What it does not do yet

It works at machine level: it says whether any agent was recorded, any contract made and any run enforced, not which
run belongs to which agent. The per-agent form (`tego setup --agent <name>`), a scan that finds agents Tego never
recorded and rules for every agent on the machine come later. The design and its limits are ADR 0142.

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
