# Quickstart

Your first governed run, from `tego version` to the dashboard. It takes a few minutes and needs no root and no agent
account: the demo command it runs is a short shell script that shows what each rule does.

For the guided setup, run `tego start` instead ([README](../README.md#quickstart)); with no agent installed and signed
in, it offers a demonstration agent that needs no account and ends with a governed run. This page does each step by
hand and explains the output.

Run every command in a plain terminal, as yourself, not inside another `tego run`.

The output below comes from a fresh Ubuntu 24.04 cloud image, as a new user, `dana`, over SSH in a
`systemd-run --user --scope bash` shell. Your paths, ids and kernel lines will differ, and a value in angle brackets is
your own build's. These recorded examples use the checked manual path. Automatic scope entry is built for run, watch and test;
its SSH and console behavior is **owed in a guest**.

## Install

On **Linux**:

```sh
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
```

The installer does not change your `PATH`. If `~/.local/bin` is not on it yet, its next steps start with
`export PATH="/home/<you>/.local/bin:$PATH"`, with your own home folder: run that line, or log in again, or `tego`
below answers `command not found`. The installer's own last line, the next command, names `tego` by its full path in that
case, so it runs in the shell you are in.

On **macOS**, the installer sets up Lima, verifies the VM template and adds the Mac `tego` command. Follow its
printed shell restart line if needed, then use `tego start` for the guide, or `tego shell` to do the steps below inside
the VM in your user's cgroup:

```sh
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
tego shell
```

No Mac folders are shared with the VM by default, including your home and `/tmp/lima`. Keep projects inside the
VM; [explicit sharing](INSTALL.md#macos) lets an agent read files in a mount, including secrets, and change them if
the mount is writable and its contract permits it.

**Windows/WSL is not fully qualified.** The measured WSL 3.0.5 ordinary shell refused setup and automatic first-run
entry until the run-membership rule was switched on for WSL; its four containment rows then passed in the guest, and
the ordinary build passed the six beginner steps there (install, `tego start`, a supervised run, the dashboard, an
approval in the browser, uninstall). A signed executable, a real HTTPS release, ARM64 and Windows 10 are not tested. See [the installation limits](INSTALL.md#windows) before trying these steps.

The second way is to [build from source](INSTALL.md#build-from-source). [INSTALL.md](INSTALL.md) says what each way
was tested on.

## 1. Check the build

```sh
tego version
```

```text
tego=v0.0.0-<commit date>-<commit, 12 digits>
commit=<commit, 40 digits>
date=<commit date>
go=go1.27.4
contract_schema=0
record_v=1
record_readers=1
bpf_hash=<hash of the BPF objects>
parsers=anthropic
control_sha256=<hash of your tego-control>
```

The first lines are your version and commit. A build from a checkout with no release tag names its commit, as here; a
release prints its tag, such as `tego=v0.1.2`. Put these lines at the top of any bug report.

## 2. Check the machine

```sh
tego machine check
```

```text
tego=v0.0.0-<commit date>-<commit, 12 digits> commit=<commit, 40 digits> date=<commit date> go=go1.27.4 contract_schema=0 record_v=1
ok   kernel: 6.8.0-147-generic (>= 5.14.0); without: Landlock ABI 5 (ioctl_dev) (6.10.0, device ioctls are not restricted), Landlock ABI 6 (scopes) (6.12.0, abstract unix sockets and signals are not scoped), Landlock ABI 7 (audit) (6.15.0, Landlock refusals are not in the audit log)
ok   btf: /sys/kernel/btf/vmlinux (6103569 bytes); all 94 kernel types and fields the BPF programs read are present
ok   cgroupv2: /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service delegated, cgroup.kill writable, controllers: cpu memory pids
ok   landlock: ABI 4
ok   seccomp: NEW_LISTENER + ADDFD(SEND) round trip on syscall 319 returned fd 7; yama ptrace_scope=1 (the supervisor is the agent's parent, which Yama exempts)
off  lsm: lockdown,capability,landlock,yama,apparmor via lsm_list_modules(2); bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected; fix: add lsm=lockdown,capability,landlock,yama,apparmor,bpf to the kernel command line (GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then update-grub) and reboot
skip programs: requires root to test (bpf(BPF_PROG_LOAD) needs CAP_BPF; this kernel disables unprivileged BPF); decision plane: requires root to test; fix: re-run as root: <checked absolute path of the running binary, after sudo> doctor
skip fanotify: requires root to test (fanotify_init needs CAP_SYS_ADMIN); fix: re-run as root: <checked absolute path of the running binary, after sudo> doctor
ok   swap: memory.swap.max present: a run's memory cap holds swap too

summary: tier landlock; cgroup needs root; bpflsm needs root, lsm

capability matrix for tier landlock on this machine:
deny file write outside contract                   yes  yes (EACCES)
deny delete, rename, mkdir, mknod                  yes  yes (EACCES), per process tree
deny read of secret paths                          yes  by sibling enumeration; under a writable parent, held reads (the default) refuse it; `fs.reads: direct` leaves it unenforced
deny exec                                          yes  by inode (`EXECUTE` on binaries, their loader, listed scripts)
deny network by host:port                          yes  yes, supervisor-completed connects (Landlock grants declared TCP ports only)
[... 26 more rows of this table ...]

tier: landlock
missing for cgroup: root: tier cgroup needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN; fanotify: requires root to test (fanotify_init needs CAP_SYS_ADMIN)
missing for bpflsm: root: tier bpflsm needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN; fanotify: requires root to test (fanotify_init needs CAP_SYS_ADMIN); lsm: bpf is not in the active LSM list (lockdown,capability,landlock,yama,apparmor)
fix: re-run as root for the tier-2 and tier-3 probes: <checked absolute path of the running binary, after sudo> doctor

ok   dashboard: the dashboard can tell which run a connection comes from
```

`machine check` tests the kernel features Tego uses. Its `summary:` line, after the checks, says which tier this machine gets
and what each tier above it needs; the lines after the table say why, and the fix. Tier 1 (`landlock`) needs no root.
In a terminal it ends with one more line on stderr, `Ready: this shell can enforce at tier 1 (landlock), no root needed.`
or `Not ready: ...`, and the next command to type.
Without root, `machine check` cannot check everything, and it says what it could not check. The capability table is cut after five
rows above; yours prints in full. On a stock Ubuntu you will see that tier 3 is unavailable, because `bpf` is not in the boot
LSM list ([TIERS.md](TIERS.md)). That is a fact about the machine, not a fault. The last line warns only if the kernel
cannot load the `inet_diag` and `tcp_diag` modules, which the dashboard needs.
`sudo "$(command -v tego)" doctor` shows what tiers 2 and 3 would get. Automatic scope entry is built for
`tego run`, `tego watch` and `tego machine test`. SSH and console validation is **owed in a guest** on Ubuntu 24.04,
AlmaLinux 9.8 and Fedora 44. These examples keep the previously checked manual step:

```sh
systemd-run --user --scope bash
tego setup
```

The built handoff prints `tego: opened a user scope for this run` on success. Setup and doctor still check the
shell they started in. A failed handoff exits 125 before run state and retains manual `next:` advice. Tego never
enables lingering. `tego setup` shows all six steps
([user/setup.md](user/setup.md)).

## 3. Watch Tego refuse something

```sh
tego machine test
```

```text
Tego self-check: 4 actions, 4 refused at tier landlock

  ACTION                                               WITHOUT TEGO  UNDER TEGO  REFUSAL
  read a fake SSH key in a fake home                   succeeded     refused     read-denied: fs.deny_read[<tmp>/work/home/.ssh/]
  write a file outside the project's writable folder   succeeded     refused     write-outside-contract: no entry of the contract allows it
  run a program the contract does not list             succeeded     refused     exec-not-allowed: no entry of the contract allows it
  connect to a local port the contract does not allow  succeeded     refused     net-not-allowed: no entry of the contract allows it

Each action works on this machine without Tego, and Tego refused and recorded every one.
The actions ran on decoys in a temporary folder, removed now, and the four runs' records went there too.
```

Four harmless actions, run on decoy files in a temporary folder: read a fake SSH key, write outside the writable folder,
run a program the contract does not list, connect to a port it does not allow. Each works without Tego and is refused with
it, and each refusal is recorded. Nothing of yours is touched. It exits 0 when all four are refused, 1 if one was not, and
125 if it could not tell. Automatic scope entry is built; its SSH behavior is **owed in a guest**.
Use the manual scope line above for the previously checked path. A failed handoff starts no check and the
existing `next:` line names the manual fallback. A user without a manager keeps the advice for starting one.
[user/self-check.md](user/self-check.md) has the details.

## 4. Write a contract

```sh
mkdir demo && cd demo
tego rules create --preset no-secrets,repo-only-writes --write ./out
```

```text
created .tego/
created out/
created .tego/tmp/
created agent.yaml (name: demo, presets: no-secrets,repo-only-writes)
added .tego/runs/ to .gitignore
added .tego/tmp/ to .gitignore
presets:
  tego/no-secrets@1: the agent cannot read your secret files, and your secret variables never reach it
  tego/repo-only-writes@1: the agent writes only in the folders your contract names
  no-secrets passes only an allow-list of variables: an agent that needs its API key adds it to env.pass (the file says where)
  repo-only-writes: an agent that keeps state in your home (Claude Code's ~/.claude) needs --write for that folder too
next, from /home/dana/demo (the contract's paths are relative to it): tego rules check agent.yaml; tego run agent.yaml; tego session show --last
```

This makes `.tego/`, the `out/` folder and an `agent.yaml`, and adds `.tego/runs/` and `.tego/tmp/` to `.gitignore`. The contract starts from two built-in presets:
`no-secrets` keeps the agent away from credential files, and `repo-only-writes` lets it write only where you said, here
`./out`. Its `command:` is a small demo that tries each. Open `agent.yaml` and read it: it is plain YAML. Leaving
out `net:` or `exec:` refuses nothing there: this contract has no `net:` section, so every IP destination is reachable, and no `exec:` section, so
every program runs. Leaving out `fs:` is the opposite: every write is refused. The `no-prod` preset closes the network to every host your contract does not name. Without `--preset`,
`tego rules create` writes a different starter, for a `python3 agent.py` agent.

## 5. See the rules

```sh
tego rules check agent.yaml
```

```text
contract  /home/dana/demo/agent.yaml
hash      f0cd0385eb80c959f19f984837d62457cb35fad73765ae78d06b8722c9412b3f
tier      landlock
capture   forwarder
record    summary
harness   generic (auto, from the contract's command)
limits    cpu=unbounded cpu_weight=unbounded memory=unbounded memory_high=unbounded pids=unbounded tokens=unbounded cost_usd=unbounded wall=unbounded stall_after=unbounded repeats=unbounded
fs        10 entries
  KIND       PATH                        ACCESS     MOUNT           FS        DEV    NOTES
  implicit   /home/dana/.tego/runs       -          -               -         -      missing
  implicit   /home/dana/demo/agent.yaml  -          /               ext4      253:1  -
  implicit   /sys/fs/cgroup              -          /sys/fs/cgroup  cgroup2   0:28   mount-point
  implicit   /sys/fs/bpf                 -          /sys/fs/bpf     bpf       0:30   mount-point
  write      /dev/null                   write-set  /dev            devtmpfs  0:5    -
  write      /home/dana/demo/out         write-set  /               ext4      253:1  -
  write      /home/dana/demo/.tego/tmp   write-set  /               ext4      253:1  -
  deny_read  /home/dana/.ssh             -          /               ext4      253:1  built-in
  deny_read  /home/dana/.tego            -          /               ext4      253:1  built-in
  deny_read  /run/tego                   -          /run            tmpfs     0:25   built-in
reason    reason-reads-off (reason.reads: auto): a read the Landlock ruleset refuses under deny_read gets EACCES and writes no line under record: summary, so the reason file never holds it; reason.reads: on records it, each read open about 17 µs more, the offline Claude Code workload 19 % slower
exec      exec unrestricted (no exec: section); 1 entries
  SOURCE   ENTRY    PATH     KIND    INTERP                       VERDICT
  command  /bin/sh  /bin/sh  binary  /lib64/ld-linux-x86-64.so.2  allow
net       IP unrestricted, unix sockets the run's own only (no net: section); 0 entries
  RULE  PROTO  TARGET  ADDRESSES  TTL  VERDICT
env       pass=PATH,HOME,USER,LOGNAME,SHELL,LANG,LANGUAGE,LC_ALL,LC_CTYPE,LC_MESSAGES,TERM,COLORTERM,TZ,NO_COLOR,GOPATH,GOROOT,GOCACHE,GOMODCACHE,CARGO_HOME,RUSTUP_HOME,JAVA_HOME,NVM_DIR,PYENV_ROOT,VIRTUAL_ENV,CONDA_PREFIX deny=- set=TMPDIR=/home/dana/demo/.tego/tmp
path      PATH, inherited from the caller's environment
[... 34 more lines: the machine config in force, each value with the file it came from ...]
```

`rules check` checks the contract and prints the rule table: what is allowed, what is refused, and what would be held for you.
Nothing runs yet. The output above stops before the machine settings; yours prints them too.

## 6. Run it

```sh
tego run agent.yaml
```

The agent prints its own output first. With stderr piped or `-v`, Tego then prints a detailed summary. For example,
this excerpt from the piped-output fixture has two refusals and one denied ask; the demo's counts will differ.
`<run>` stands for the full run id:

```text
tego run: <run> ended (exited with code 0) · tier landlock · refused 2 (fs.ask_read 1, not allowed by any rule 1) · asked 1 (0 approved, 1 denied) · wrote 1 file · chain verified
  more: tego receipt <run>
```

This output is pinned in `internal/cli/testdata/run-421d678-pipe-stderr.golden`. Read-count limitations, missed
actions or uncertain rules add disclosures. With terminal stderr and no `-v`, Tego prints a session start line with
the rules path and dashboard page. It uses a short end line only for a successful, verified run with no disclosure;
otherwise it keeps the detailed summary. This demo's default tier-1 recording does not record refused reads, so its
end summary says so.

Tego starts the contract's `command:` under the best tier this machine has; as a normal user that is tier 1. The exit code is the
command's own (124 means Tego stopped the run on a limit, 125 means Tego itself failed). The detailed summary names the run
id, the tier it ran at (`landlock` is tier 1), the refusals its record holds, the files written, and the chain check.

## 7. Read the receipt

```sh
tego session show --last
```

```text
Receipt for run r-40c94c9f-0dmkbl68johzb-hdcxpr (demo)
  Command: /bin/sh -c echo hello > './out/tego-hello.txt' && echo 'wrote ./out/tego-hello.txt: allowed'\n(echo …
  Outcome: exited with code 0

Time taken
  5ms.

Files written
  1 written, 0 created, 0 deleted, 0 renamed.
    Wrote out/tego-hello.txt

Connections
  None recorded.

Programs run
  1 program, started 1 time.
    /bin/sh  1

Sensitive files read
  Not known: this run did not record every read, so a sensitive file may have been read.
  This run did not record the files it read, allowed or refused (record: full records them).

Refused actions (times in UTC)
  Tego refused 1 action.
       1  not allowed by any rule (write-outside-contract)
    01:05:26  open tego-outside.txt  not allowed by any rule (write-outside-contract)

Refusals over time
  Per minute from the start: 1

Stall minutes
  No quiet stretch of 5m 00s or more.
  Partial: model traffic was not captured, so time spent waiting on the model counts as quiet.

Tests result
  Not recorded: no ledger line records a tests result yet.

Times it asked you
  It never asked.

Tokens and model calls
  Not recorded: model traffic capture was off for this run.

Coverage
  record: 1 gap line: tego knows it missed some actions, so the counts are a floor.
```

The receipt is the answer to "what did it do?", as far as the record can tell. It lists the time taken, the files written,
the connections made, the programs run, any sensitive files read, the refusals the record holds with the rule that refused
each, how often the agent asked, and the tokens used with an estimated cost. Its Coverage section says what the record could
not cover, which depends on the tier.

**At tier 1, a clean receipt says nothing about reads.** Under `record: summary`, the default, Tego is not told about reads.
A read that `deny_read` refuses fails with `EACCES` and leaves no line, so `tego run` can print `refused 0`. The receipt then
says "No recorded action was refused; this run does not record refused reads", never "Nothing was refused". To see reads, set `record: full` in the contract, which makes every open slower, or run at
tier 2 or 3. To see only the refused ones, set `reason.reads: on` ([user/reason-channel.md](user/reason-channel.md)).

`tego session show --last --verify` also checks the run's hash chain against its anchor in `~/.tego/chain.log`.
`tego events <run>` prints the record as a table, one row per event; the run id is in the summary from step 6. Its last
characters are enough, four or more, when no other run's id ends with them: `tego events hdcxpr`. The record's format is in
[../spec/record/v1/README.md](../spec/record/v1/README.md).

## 8. Open the dashboard

```sh
tego dashboard
```

```text
  ✓ Started the dashboard: http://127.0.0.1:8484/?t=0ab4c708b2775be17e4d67f247ea774b
    Open the link above in your browser.
```

This starts the dashboard on `127.0.0.1:8484` as a service of your user, so it keeps running after you close the
terminal, and prints a link with a token. Open that link, not the bare address. On a Mac, `tego dashboard` opens it in
your browser. Run it again and it reuses the same dashboard; in a terminal it asks whether to open it or start a new
one. You will see your run under Runs, with its receipt and refusals.
[DASHBOARD.md](DASHBOARD.md) describes each page.

Four things catch people out:

- **Start it from a plain terminal.** A shell that itself runs under `tego run` can look at the dashboard but not press
  its buttons: a request that comes from inside a governed run is refused.
- **Never with `sudo`.** `tego-control` refuses to run as root, so the dashboard is always started as yourself.
- **If port 8484 is busy,** start it with `tego serve --addr 127.0.0.1:<port>` instead. The address must be on loopback.
- **Over SSH,** forward the same port (`ssh -L 8484:127.0.0.1:8484 <host>`) and open the printed link on your own machine.
  A different local port is refused with `wrong Host header`. In the macOS VM that is
  `ssh -F ~/.lima/tego/ssh.config -N -L 8484:127.0.0.1:8484 lima-tego`, run on the Mac ([INSTALL.md](INSTALL.md#macos)).

## Next

For Claude Code, start in a project with no `agent.yaml`, set `ANTHROPIC_API_KEY` or
`CLAUDE_CODE_OAUTH_TOKEN`, then run:

```sh
tego rules create --agent claude-code --write src/ --prompt 'Review this project'
tego rules check agent.yaml
tego run agent.yaml
```

Claude runs one task in print mode through the forwarder; without `--prompt`, it
describes the project without changing files. For the full-screen interface use
`examples/agents/claude-code-interactive.yaml`; its model bytes are not captured.
`tego rules create --list` lists agents and login setup. `--agent codex` selects Codex exec
with `CODEX_API_KEY`; ChatGPT sign-in keeps its explicit example contract. Init reads
no credentials and calls no model. The initial prompt is one literal argument.
Generated cache and state paths move with the project; run it from that folder.

For any other agent or command, record one run of it, then let Tego propose a contract from what that run did:

```sh
cd ~/myagent                                      # the folder your agent works in
tego watch -- python3 agent.py                    # records it; no rule refuses anything; Ctrl-C keeps the record
tego rules learn <run> --save myagent                   # <run>: the run id tego watch printed at the end
tego run myagent
```

`tego rules learn <run> [--save <name> | --out <file>] [--allow-host <host>[:<port>]]... [--reads on|off] [--workspace <dir>]`
reads the run's record and proposes a contract: the folders it wrote in, the programs it started, the addresses it
connected to. Without `--save` or `--out` it prints the proposal. `--save myagent` writes it to
`~/.config/tego/agents/myagent.yaml` (mode 0600, never over a file already there), where `tego run myagent` finds it;
`--out` writes it to a new file you name. A contract `--save` writes records each read it refuses, so a refused read
shows in `tego run`'s summary; each read open is about 17 µs slower, and `--reads off` leaves it out.
`--workspace` is the folder writes may be allowed under (default: the folder the run started in). `<run>` may be the
last characters of the run id (four or more) when they name one run. In a terminal, `tego watch` and `tego rules learn` end with a `next:` line that names the command to type next.
`tego run` shows `Details: tego session show <session>` after a short end line; when it needs the full summary, its
next step follows that summary. Read the proposal before you use it: it
allows only what that run did. Keep it outside the folder the agent writes in, because Tego refuses a contract its
agent could rewrite. Its
network entries are the IP addresses that run connected to, not host names. One name often has several addresses and
a program may pick another one on its next run, so a later run can be refused a connection this run made. Give the
host name the agent uses with `--allow-host <host>`, for example `tego rules learn <run> --save myagent --allow-host
example.com` for an agent that fetches https://example.com: Tego looks the name up now and writes
`tcp://example.com:443` in place of each address the run reached that the name resolves to, and refuses, writing
nothing, a name that covers no address the run reached. You can also write the host name in their place by hand.
`tego rules learn` says so too, at the top of the file and in the terminal, and its `next:` line adds `--allow-host <host>`
when the run reached addresses.

Use `tego status --agent <name>` to find its newest run, or add `--all` for its history.
`tego rules --last` shows the same rules, sources and enforcement details as the dashboard.

- Real agents: [examples/agents/](../examples/agents/README.md) has contracts for Claude Code, Codex and a custom agent. Each
  needs editing for your machine before use, and each file's header says how. Keep a contract outside the project the agent
  works in: a contract the agent can rewrite is refused.
- Tighten or loosen a contract with `tego rules learn` (it proposes one from a finished run) and `tego rule`. See what
  a change did with `tego rules history <agent>`, and take back the newest one with `tego rules undo <agent>`.
- Find what is already on this machine: `tego scan` lists your running agents, installed candidates and settings
  metadata, and `tego contracts` finds contracts and checks them without running an agent. See
  [user/scan.md](user/scan.md) and [user/contracts.md](user/contracts.md).
- Run an agent in CI and keep its record: [user/ci-receipt.md](user/ci-receipt.md).
- Remove Tego: `tego uninstall`, which keeps your records unless you say so ([INSTALL.md](INSTALL.md#uninstall)).
- Root tiers: `sudo "$(command -v tego)" run --tier cgroup agent.yaml`. The run lands in your own `~/.tego` and the dashboard
  shows it once it ends. This contract prints a `best effort` warning there, because it has no `net:` section. See
  [TIERS.md](TIERS.md).
- The user guide, [user/README.md](user/README.md), covers presets, live modes, MCP tool rules and model routes.
- What Tego does not do: [GAPS.md](GAPS.md).
