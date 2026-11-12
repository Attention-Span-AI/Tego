# Quickstart

Your first governed run, from `tego version` to the dashboard. It takes a few minutes and needs no root and no agent
account: the demo command it runs is a short shell script that shows what each rule does.

Run every command in a plain terminal, as yourself, not inside another `tego run`.

The output below comes from a fresh Ubuntu 24.04 cloud image, as a new user, `dana`, over SSH in a
`systemd-run --user --scope bash` shell. Your paths, ids and kernel lines will differ, and a value in angle brackets is
your own build's.

## Install

On **Linux**:

```sh
curl -fsSL https://github.com/Attention-Span-AI/Tego/releases/latest/download/install.sh | sh
```

The installer does not change your `PATH`. If `~/.local/bin` is not on it yet, its next steps start with
`export PATH="/home/<you>/.local/bin:$PATH"`, with your own home folder: run that line, or log in again, or `tego`
below answers `command not found`.

On **macOS**, Tego runs in a Lima VM. Install it, then do the steps below inside the VM, in a shell in your user's
cgroup:

```sh
brew install lima
limactl start --name=tego https://github.com/Attention-Span-AI/Tego/releases/latest/download/tego.yaml
limactl shell tego
systemd-run --user --scope bash
```

On **Windows**, run `wsl --install -d Ubuntu-24.04` in PowerShell, then the Linux line inside Ubuntu.

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
tego doctor
```

```text
tego=v0.0.0-<commit date>-<commit, 12 digits> commit=<commit, 40 digits> date=<commit date> go=go1.27.4 contract_schema=0 record_v=1
ok   kernel: 6.8.0-147-generic (>= 5.14.0); without: Landlock ABI 5 (ioctl_dev) (6.10.0, device ioctls are not restricted), Landlock ABI 6 (scopes) (6.12.0, abstract unix sockets and signals are not scoped), Landlock ABI 7 (audit) (6.15.0, Landlock refusals are not in the audit log)
ok   btf: /sys/kernel/btf/vmlinux (6103569 bytes); all 94 kernel types and fields the BPF programs read are present
ok   cgroupv2: /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service delegated, cgroup.kill writable, controllers: cpu memory pids
ok   landlock: ABI 4
ok   seccomp: NEW_LISTENER + ADDFD(SEND) round trip on syscall 319 returned fd 7; yama ptrace_scope=1 (the supervisor is the agent's parent, which Yama exempts)
off  lsm: lockdown,capability,landlock,yama,apparmor via lsm_list_modules(2); bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected; fix: add lsm=lockdown,capability,landlock,yama,apparmor,bpf to the kernel command line (GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then update-grub) and reboot
skip programs: requires root to test (bpf(BPF_PROG_LOAD) needs CAP_BPF; this kernel disables unprivileged BPF); decision plane: requires root to test; fix: re-run as root: sudo /home/dana/.local/bin/tego doctor
skip fanotify: requires root to test (fanotify_init needs CAP_SYS_ADMIN); fix: re-run as root: sudo /home/dana/.local/bin/tego doctor
ok   swap: memory.swap.max present: a run's memory cap holds swap too

summary: tier landlock; cgroup needs root; bpflsm needs root, lsm

capability matrix for tier landlock on this machine:
deny file write outside contract                   yes  yes (EACCES)
deny delete, rename, mkdir, mknod                  yes  yes (EACCES), per process tree
deny read of secret paths                          yes  by sibling enumeration; unenforced under a writable parent
deny exec                                          yes  by inode (`EXECUTE` on binaries, their loader, listed scripts)
deny network by host:port                          yes  yes, supervisor-completed connects (Landlock grants declared TCP ports only)
[... 26 more rows of this table ...]

tier: landlock
missing for cgroup: root: tier cgroup needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN; fanotify: requires root to test (fanotify_init needs CAP_SYS_ADMIN)
missing for bpflsm: root: tier bpflsm needs CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN; fanotify: requires root to test (fanotify_init needs CAP_SYS_ADMIN); lsm: bpf is not in the active LSM list (lockdown,capability,landlock,yama,apparmor)
fix: re-run as root for the tier-2 and tier-3 probes: sudo /home/dana/.local/bin/tego doctor

ok   dashboard: the dashboard can tell which run a connection comes from
```

`doctor` tests the kernel features Tego uses. Its `summary:` line, after the checks, says which tier this machine gets
and what each tier above it needs; the lines after the table say why, and the fix. Tier 1 (`landlock`) needs no root.
Without root, `doctor` cannot check everything, and it says what it could not check. The capability table is cut after five
rows above; yours prints in full. On a stock Ubuntu you will see that tier 3 is unavailable, because `bpf` is not in the boot
LSM list ([TIERS.md](TIERS.md)). That is a fact about the machine, not a fault. The last line warns only if the kernel
cannot load the `inet_diag` and `tcp_diag` modules, which the dashboard needs.
`sudo "$(command -v tego)" doctor` shows what tiers 2 and 3 would get. Over SSH, start a shell in your user's cgroup first,
or tier 1 has no cgroup to use: `systemd-run --user --scope bash` ([INSTALL.md](INSTALL.md#check-the-machine)).

## 3. Watch Tego refuse something

```sh
tego test
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
125 if it could not tell, which is what you get over SSH outside your user's cgroup (step 2).
[user/self-check.md](user/self-check.md) has the details.

## 4. Write a contract

```sh
mkdir demo && cd demo
tego init --preset no-secrets,repo-only-writes --write ./out
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
next, from /home/dana/demo (the contract's paths are relative to it): tego compile agent.yaml; tego run agent.yaml; tego receipt --last
```

This makes `.tego/`, the `out/` folder and an `agent.yaml`, and adds `.tego/runs/` and `.tego/tmp/` to `.gitignore`. The contract starts from two built-in presets:
`no-secrets` keeps the agent away from credential files, and `repo-only-writes` lets it write only where you said, here
`./out`. Its `command:` is a small demo that tries each. Open `agent.yaml` and read it: it is plain YAML. Leaving
out `net:` or `exec:` refuses nothing there: this contract has no `net:` section, so every IP destination is reachable, and no `exec:` section, so
every program runs. Leaving out `fs:` is the opposite: every write is refused. The `no-prod` preset closes the network to every host your contract does not name. Without `--preset`,
`tego init` writes a different starter, for a `python3 agent.py` agent.

## 5. See the rules

```sh
tego compile agent.yaml
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
path      /home/dana/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/usr/local/go/bin
[... 34 more lines: the machine config in force, each value with the file it came from ...]
```

`compile` checks the contract and prints the rule table: what is allowed, what is refused, and what would be held for you.
Nothing runs yet. The output above stops before the machine settings; yours prints them too.

## 6. Run it

```sh
tego run agent.yaml
```

```text
wrote ./out/tego-hello.txt: allowed
/bin/sh: 2: cannot create ./tego-outside.txt: Permission denied
write ./tego-outside.txt: refused by repo-only-writes
no secret variable reached the agent: no-secrets
tego run: r-40c94c9f-0dmkbl68johzb-hdcxpr ended (exited with code 0) · tier landlock · refused 1 (not allowed by any rule 1) · asked 0 · wrote 1 file · chain verified
  more: tego receipt r-40c94c9f-0dmkbl68johzb-hdcxpr
```

Tego starts the contract's `command:` under the best tier this machine has; as a normal user that is tier 1. The exit code is the
command's own (124 means Tego stopped the run on a limit, 125 means Tego itself failed). The run ends with a summary: the run
id, the tier it ran at (`landlock` is tier 1), the refusals its record holds, the files written, and the chain check.

## 7. Read the receipt

```sh
tego receipt --last
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
A read that `deny_read` refuses fails with `EACCES` and leaves no line, so `tego run` can print `refused 0` and the receipt can
say "Nothing was refused" after it. To see reads, set `record: full` in the contract, which makes every open slower, or run at
tier 2 or 3. To see only the refused ones, set `reason.reads: on` ([user/reason-channel.md](user/reason-channel.md)).

`tego receipt --last --verify` also checks the run's hash chain against its anchor in `~/.tego/chain.log`.
`tego events <run>` prints the record as a table, one row per event; the run id is in the summary from step 6. Its last
characters are enough, four or more, when no other run's id ends with them: `tego events hdcxpr`. The record's format is in
[../spec/record/v1/README.md](../spec/record/v1/README.md).

## 8. Open the dashboard

In a second terminal, as the same user:

```sh
tego serve --open
```

```text
Tego dashboard: http://127.0.0.1:8484/?t=0ab4c708b2775be17e4d67f247ea774b
  ledger: /home/dana/.tego/runs (from default), 1 run
  chains: checked against /home/dana/.tego/chain.log
tego-control serve: --open: exec: "xdg-open": executable file not found in $PATH; open the URL above
```

This starts the dashboard on `127.0.0.1:8484` and opens it in your browser, signed in. On a machine with no browser, like the
one above, it says so and keeps serving. It prints a link with a token (`http://127.0.0.1:8484/?t=...`); open that link, not
the bare address, in any other browser. You will see your run under Runs, with its receipt and refusals.
[DASHBOARD.md](DASHBOARD.md) describes each page.

Four things catch people out:

- **Start it from a plain terminal.** A shell that itself runs under `tego run` can look at the dashboard but not press
  its buttons: a request that comes from inside a governed run is refused.
- **Never with `sudo`.** `tego-control` refuses to run as root, so the dashboard is always started as yourself.
- **If port 8484 is busy,** pass `--addr 127.0.0.1:<port>`. The address must be on loopback.
- **Over SSH,** forward the same port (`ssh -L 8484:127.0.0.1:8484 <host>`) and open the printed link on your own machine.
  A different local port is refused with `wrong Host header`. In the macOS VM that is
  `ssh -F ~/.lima/tego/ssh.config -N -L 8484:127.0.0.1:8484 lima-tego`, run on the Mac ([INSTALL.md](INSTALL.md#macos)).

## Next

For Claude Code, start in a project with no `agent.yaml`, set `ANTHROPIC_API_KEY` or
`CLAUDE_CODE_OAUTH_TOKEN`, then run:

```sh
tego init --agent claude-code --write src/ --prompt 'Review this project'
tego compile agent.yaml
tego run agent.yaml
```

Claude runs one task in print mode through the forwarder; without `--prompt`, it
describes the project without changing files. For the full-screen interface use
`examples/agents/claude-code-interactive.yaml`; its model bytes are not captured.
`tego init --list` lists agents and login setup. `--agent codex` selects Codex exec
with `CODEX_API_KEY`; ChatGPT sign-in keeps its explicit example contract. Init reads
no credentials and calls no model. The initial prompt is one literal argument.
Generated cache and state paths move with the project; run it from that folder.

Use `tego status --agent <name>` to find its newest run, or add `--all` for its history.
`tego rules --last` shows the same rules, sources and enforcement details as the dashboard.

- Real agents: [examples/agents/](../examples/agents/README.md) has contracts for Claude Code, Codex and a custom agent. Each
  needs editing for your machine before use, and each file's header says how. Keep a contract outside the project the agent
  works in: a contract the agent can rewrite is refused.
- Tighten or loosen a contract with `tego learn` (it proposes one from a finished run) and `tego rule`.
- Root tiers: `sudo "$(command -v tego)" run --tier cgroup agent.yaml`. The run lands in your own `~/.tego` and the dashboard
  shows it once it ends. This contract prints a `best effort` warning there, because it has no `net:` section. See
  [TIERS.md](TIERS.md).
- The user guide, [user/README.md](user/README.md), covers presets, live modes, MCP tool rules and model routes.
- What Tego does not do: [GAPS.md](GAPS.md).
