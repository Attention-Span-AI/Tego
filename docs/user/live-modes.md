# Locked and Adjustable: changing a running agent's rules

This page says how an agent's rules can change while it runs, and what each of the two modes promises.

Every agent runs in one of two modes, which its contract
(`agent.yaml`) chooses under `live:`. **Locked** is the default: the contract's file, program and network rules are fixed when the run starts,
you can tighten a running agent (block, pause), and you loosen it from its next run. **Adjustable** ("Adjustable (live
both ways)" in the dashboard) lets you loosen and tighten it while it runs, inside a fence you name in advance.
You choose; neither is better for every agent. The table below weighs them.

## The two modes compared

| | Locked (default) | Adjustable (live both ways) |
|---|---|---|
| What holds the fixed rules | The whole contract: Landlock and Tego's supervisor at every tier, plus fanotify and BPF at tiers cgroup and bpflsm. At tier landlock the supervisor, not the kernel, decides hosts, command rules are best effort, and `deny_write` is blocked for ordinary commands; not race-free at the no-root tier ([spec/backend/CAPABILITIES.md](../../spec/backend/CAPABILITIES.md)) | The fence: the contract plus every fence entry, at tiers cgroup and bpflsm. Inside the fence, Tego's live layer refuses each entry until you lift or grant it |
| Loosen while it runs | No: from the next run. MCP tool switches and model routes are the exception, below | Yes, fence entries only, each one previewed, confirmed and recorded, optionally for a time. MCP tool switches and model routes are the same exception |
| Tighten while it runs | Yes: live blocks and pause | Yes: the same, plus Restore |
| Time limits | Blocks and unblocks | Blocks, unblocks, lifts and grants |
| What a compromised agent can do | What the contract allows. A live block on a file or a program can be raced with a symlink; reads that Tego holds cannot be | The same, plus: it can dodge an exec fence entry not yet granted by copying the program to a place where it can write and run. Read fence entries (no fence path may be or pass through a link) and TCP net fence entries cannot be raced; UDP is never fenced, so it stays refused. It can never lift its own rules |
| If Tego's supervisor stops | Notified calls fail and the run ends; what the kernel holds stays held | Notified calls fail and the run ends. Every open, connect and exec is notified, so none reaches a fence entry in between. Files already open work until the run is killed |
| Tiers | All | cgroup and bpflsm, which need root; refused at landlock (a policy choice) |
| Performance | Baseline | With read entries, each read open costs about 0.1 ms more. The plane modes run the full seccomp filter |
| What the ledger proves | Every refusal, under contract rules or `live.block[...]`, and every block change | The mode and the fence's digest when the run starts; every lift, restore, expiry and refused lift as Tego applied it; every action under `live.fence[...]`. It does not prove that the kernel enforced the live policy: the live layer did |
| Who can loosen it while it runs | Nobody for file, program and network rules. MCP tool switches and model routes: you, from outside every run, with confirmation | You, from outside every run, with confirmation; never the agent. A process of yours outside every run that reads the run's key can too |

In plain words: for file, program and network rules, Locked is the stronger promise, "never looser than its contract
while it runs". It does not yet cover MCP tool switches or model routes: a person outside every run can still loosen
those on a Locked run, with confirmation, because the mode check is not built (docs/GAPS.md C39). Adjustable is weaker
by exactly the fence: what you list there is held back by Tego, not by the kernel, until you lift it. Pick Adjustable
for an agent that runs for days or weeks and whose access you expect to change; keep Locked for everything else.

## Choose a mode

Locked needs nothing: a contract with no `live:` key, or with `live: {mode: locked}`, is Locked.

Adjustable needs root, because it runs only at tier cgroup or bpflsm (see Tiers below). It names the fence: what Tego
may grant while the run runs. Every entry is refused when the run starts.
```yaml
fs:
  deny_read: [~/billing-exports]   # the contract refuses it...
live:
  mode: adjustable                 # locked (the default) | adjustable
  fence:                           # what you may grant while it runs; every entry starts refused
    read: [~/billing-exports]      # ...and you may lift that refusal while it runs
    net:  [api.stripe.com:443]     # new access you may grant
    exec: [/usr/bin/psql]
```

`tego init --live-mode adjustable` writes a new `agent.yaml` with an empty fence to fill in, and a comment that says
what each mode does; `--live-mode locked`, the default, writes the file `tego init` always wrote. It works with
`--preset` too.

`tego compile agent.yaml` prints the mode, the fence with its digest, and what each entry is refused by at start.

## What a fence entry can be

There are three kinds, each one Tego can refuse without a race, or says plainly when it cannot:

- `read`: a path and everything beneath it, for reads only. Tego allows reading everywhere except under
  `fs.deny_read`, so a read entry names one of your `deny_read` entries exactly: the fence takes that refusal out of
  what the kernel enforces, and Tego's live layer refuses it instead until you lift it. While the fence has a read
  entry, every read open of the run is held (`fs.reads: held`), so the refusal is checked on the file Tego opened, and
  a swapped symlink does not get through. The entry itself may not be or pass through a link: name the path it leads
  to, so the kernel's refusal and Tego's are about the same place.
- `net`: a host or address with its port, such as `api.stripe.com:443` or `10.0.0.5:5432`, for TCP only. It is
  refused on the connection Tego makes for the agent, which the agent cannot race. UDP to it stays refused by the
  kernel, lifted or not: Tego relays a single datagram, but it decides a batch of addressed datagrams (`sendmmsg`)
  and then lets the kernel send it, and another thread of the agent could rewrite an address in between. So a UDP
  destination is not something a fence can hold back, and the fence leaves UDP out. The contract needs a `net:`
  section.
- `exec`: a program's absolute path, such as `/usr/bin/psql`. This one is **best effort**: Tego decides it on the
  program's name and file, so a copy of the program under another name runs wherever the agent can write and run
  files. If your contract's `exec.deny` names the program, the fence takes that refusal out. `exec.deny` refuses a
  name, every program called that wherever it is, so taking it out lets every one of them past the kernel: Tego's live
  layer then refuses every program of that name until you lift the entry (`tego compile` says "refused by name"),
  and the lift allows them all. Under an `exec.allow` list the program is added to it. The path may not be a link:
  name the program it leads to. Some programs run a second copy of themselves from another place: git runs
  `/usr/lib/git-core/git` and helpers such as `git-remote-https`. Those files are fenced with the entry: Tego refuses
  them until you lift it, and the ledger names them after the entry.

There is no write kind: a file change other than an open cannot be held back without a race yet.

`tego compile` refuses a fence entry that:
- the contract already allows (to refuse something for a while, block it with a time limit instead);
- is a read entry at, inside or around a write or ask folder (a file could be renamed out from under it);
- is a read entry inside or around a `deny_read` entry other than the one it names, or at, inside or around a
  program or folder `exec.allow` grants (running a program reads it); a read entry also needs an `exec.allow` list;
- reaches Tego's own files, or one of the built-in credential refusals (`~/.ssh`, `~/.aws` and the rest): those are
  never part of a fence;
- is a unix socket (the user bus and the systemd, docker and tmux sockets can start programs outside the run), a
  range of addresses, or has no port;
- is a program path that is not absolute or names no file, or a program inside a write or ask folder (the agent
  could rewrite it in place and rename it past Tego's check);
- is a program, or one of its helper programs (git's), inside one of the fence's own read entries (lifting the program
  alone would run it, and so read it, inside the folder the fence still refuses);
- would make the fence longer than 64 entries.

A local destination (`localhost`, `127.0.0.1`, a link-local address) gets a warning: a local service may run commands
outside the run, and Tego cannot tell.

Taking out your last `deny_read` entry never turns the built-in credential refusals off; they stay in force.

A fence takes out only your contract's own refusals. A `deny_read` or `exec.deny` entry a profile you extend declares
is refused as a fence entry, even if your contract repeats it: a profile's refusals are a floor.

A `live:` key in a profile you extend is refused: only your own contract chooses its mode.

## Change a running agent

The words are the same in the dashboard and at the terminal:

- **Block** refuses something more, and **unblock** ends such a block, back to what the contract allows. They work in both
  modes.
- **Lift** allows a fence entry that names one of the contract's refusals.
- **Grant** allows a fence entry that is new access. Lift and grant are one operation.
- **Restore** refuses a lifted or granted entry again.

Lift and grant ask for a confirmation: the terminal asks you to type the word or pass `--yes`. Neither works from inside a
run, so the agent can never loosen its own rules. Unblock is refused from inside a run too. Block and restore need no
confirmation, because they narrow. From inside a run, `tego block` and `tego restore` can name only that run, and the
dashboard refuses every change sent from inside a run.

For file, program and network rules, nothing outside the fence loosens while the run runs. Such a change applies from
the next run. MCP tool switches and model routes are the exception in the table above.

**Today these are terminal commands, under `sudo`.** Adjustable runs only at tier cgroup or bpflsm, so its launcher is
root, and while a root run is live its folder under the ledger root, the run's key included, is root's (mode 0700). The
dashboard runs as you and never as root, so it cannot open a live Adjustable run. Use `sudo tego lift`, `sudo tego grant`
and `sudo tego restore`; the same goes for block, unblock and stop on any live run started with `sudo`. When the run ends,
Tego hands its folder to you, and the dashboard shows the run with every change.

The dashboard's own controls are built, but no product run reaches them yet. On a run it can open, an Adjustable run's
Rules page lists its fence under "Live policy inside the fence", each entry
Refused or Lifted (until when), with Lift… or Grant… and a time limit, and Restore once lifted. Lift… opens a preview
that says what the run will be able to do and until when; you tick "I understand this run gets this access now" and
confirm. The preview is bound to that one change: if anything else changed on the run meanwhile, the confirm does
nothing and asks you to preview again. Every Rules page says which mode its run is in. In the dashboard,
"permanently" makes the change now and opens Change rules, where you save the matching edit of `agent.yaml` yourself;
until you save it, the next run starts without it.

## Time limits

A block, an unblock, a lift or a grant can last:

- **for** a while: `45m`, `72h`, `3d`, `7w` (1 minute to 400 days); in the dashboard, 2, 4, 15 or 30 minutes, 1
  hour, 1 day, 3 days or 1 week, or **for…** and any duration typed as `--for` takes it (`45m`, `4m`, `72h`, `3d`,
  `1d12h`, `7w`);
- **until** a time: `2026-11-14 17:00`, `Fri 17:00`, `17:00`;
- with no end: the rest of the run;
- **permanently** (dashboard only): the change is made now with no end, and Change rules opens, where you save the
  matching edit of `agent.yaml` yourself (previewed, confirmed, journaled and undoable). Until you save it, the next run
  starts without it.

The dashboard counts a preset or a typed duration from your click, to the second: Block now's click, or for a lift or a grant the Lift… or
Grant… click, whose preview shows the end; confirming keeps that end, so confirm a 2-minute preview within a minute
(after that its limit is under the 1 minute floor and the confirm asks you to preview again). The dashboard's
**until…** takes a whole minute: "until 20:33" picked at 20:31:51 lasts 69 seconds, so pick a preset for a short limit.

When a limit ends, the change ends by itself and the ledger says so. A limit is judged on two clocks, so moving the
system clock never makes a loosening last longer or a block end sooner.

What a time limit does not take back: Linux cannot take back what the agent already has. Data it read or copied, files
it still holds open and connections it already made stay. A limit stops new access only.

## Tiers

Adjustable runs at tier cgroup or bpflsm, which need root.
`tego compile` refuses it when the contract or the machine pins tier landlock, and `tego run` refuses a run whose
`tier: auto` lands at landlock. This is a policy choice: at cgroup and bpflsm the live refusals can move into kernel
checks Tego already runs there, so one mode keeps one promise. Locked runs at every tier.

## What an Adjustable run checks and records

An Adjustable run needs root (tier cgroup or bpflsm), and so does what follows.
- **At start.** Tego refuses every fence entry before the agent's first instruction. It refuses to start the run
  (exit 125, naming why) with `--observe`, at tier landlock, when no supervisor would serve it, with `io_uring: true`
  (a ring's connects and opens never reach the supervisor; `tego compile` refuses the pair too), when a decision
  plane would decide opens where Tego cannot see them, when the fence has read entries and the run does not hold its
  read opens, or when the run's folder under the ledger root is readable to the run (the ledger root holds the
  project, HOME or a write entry, compile's `ledger-readable` warning): the agent could then read the run's key. `tego adopt` never adopts an agent under Adjustable: the agent started before Tego could refuse
  anything.
- **The run's key.** Each run gets a 32-byte key (`live-key`, mode 0600) in its folder under the ledger root, which
  no run can read: an Adjustable run whose folder a built-in `deny_read` entry does not cover does not start. A lift is applied only when it carries a MAC under that key; any other lift is refused and
  recorded (`live-lift-refused`, with why: `mac`, `outside-fence`, `until` or `locked`). A refused lift that names
  no fence entry is recorded under `live.lift[<kind>:<value>]`, the request, never under a `live.fence[...]` rule
  (a ledger an earlier build wrote may name `live.fence[...]` there; both read as valid).
- **In the ledger.** `run_start` names the mode and the fence (`live_mode`, `live_fence` with its digest; each entry
  with the fields the digest covers, so you can recompute it). Every
  refusal by a fence entry, and every action allowed only because the entry is lifted, carries the entry's rule
  `live.fence[<kind>:<value>]`. For reads and execs this is checked through the real binary as root at tiers cgroup and
  bpflsm in a KVM guest, and as a user at tier landlock with a test build, since the product refuses Adjustable there. For
  connects it was checked once, in a manual run of that test build; at tiers cgroup and bpflsm it is not yet checked. While the fence has an exec entry, every
  exec is decided and recorded by Tego's supervisor, never handed to the decision plane, so its line can name the
  entry. The same holds while the fence has a read entry: running a program under a read entry that is not lifted
  is refused under that entry's rule, since running a program reads it. Each lift, restore and end of a time limit has its own line, written from what took
  effect (`live-rule-lifted`, `live-rule-restored`, `live-lift-expired`).
- **When something breaks.** If the run's overlay file cannot be read, is removed, or loses changes, every lift is
  dropped and each fence entry is refused again. If Tego's supervisor stops while the agent still runs, the run is
  ended.

## Switching mode

Switching between Locked and Adjustable, and changing the fence, applies from the next run: the fence is built into
the kernel's rules when the run starts. A run that started Locked stays Locked to its end.
