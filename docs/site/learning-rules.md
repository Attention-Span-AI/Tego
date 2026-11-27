---
title: Learning rules
description: "Record a real session of your agent with tego watch, then let tego rules learn propose a rules file that allows what it did and nothing more."
summary: "Turn what an agent did in one session into a rules file you review."
section: Advanced usage
order: 2
---

Record one session of your agent doing its normal work, then run `tego rules learn` on it. Tego reads the session's record and proposes a rules file that allows the folders it wrote, the programs it started and the hosts it reached, and nothing more. The proposal is a draft: you read it, edit it and check it before any session runs under it.

## 1. Record a session

Run the agent under `tego watch`. No rule refuses anything; Tego only records:

```
tego watch -- claude
```

Use the agent the way you normally do, then exit. `tego session list` shows the session's name. [Finding agents](/docs/finding-agents/#record-an-agent-tego-watch) covers `tego watch` and its flags.

You can also learn from a session that ran under rules, and from one still running: the proposal then covers the session so far.

## 2. Get a proposal

```
tego rules learn claude-a1b2
```

The proposal prints to the terminal. To keep it, pick one:

```
tego rules learn claude-a1b2 --out agent.yaml
tego rules learn claude-a1b2 --save my-agent
```

| Flag | What it does |
|---|---|
| `--out <file>` | Writes a new file, mode 0600. Refuses to replace a file that exists. |
| `--save <name>` | Saves the proposal as the agent `<name>` in `~/.config/tego/agents/<name>.yaml`, so `tego run <name>` finds it. Refuses a name that is taken. |
| `--allow-host <host>[:<port>]` | Writes this host name in place of the addresses the session reached for it. Repeat it, up to 8 times. |
| `--workspace <dir>` | The folder writes are allowed under. Default: the folder the session ran in. |
| `--reads on\|off` | `on` adds `reason: {reads: on}`, so a read the rules refuse at Basic leaves a line in the record. `--save` adds it unless you pass `--reads off`. |

Keep the rules file outside every folder the agent writes. Tego refuses a rules file its own agent could rewrite, and `--save` refuses to write one inside a folder the proposal lets the agent write.

### Name hosts, not addresses

The record holds the address the agent connected to, never the name it looked up. A service's addresses change, so a proposal of addresses can refuse the next session. Name the service instead:

```
tego rules learn claude-a1b2 --save my-agent --allow-host api.anthropic.com
```

Tego looks the name up now, within 2 seconds, and writes `tcp://api.anthropic.com:443` in place of every address the session reached that the name resolves to. When the name does not resolve, or covers no address the session reached, Tego writes nothing and exits 1.

## 3. Review the proposal

Read every entry. The proposal holds everything the agent did while it was recorded.

| Section | What the proposal holds |
|---|---|
| `command` | The command the session ran |
| `fs.write` | The folders under the workspace the session wrote to, plus `/dev/null` and `/dev/tty` if it opened them. A write outside the workspace is listed in a comment, never allowed. |
| `exec.allow` | Every program the session started, as an absolute path, except the agent's own first program |
| `net.allow` | Every TCP and UDP destination the session connected to |
| `limits` | Suggestions in comments only: about twice the peak memory, four times the process count, three times the duration |

What it never does:

- **Allow a dangerous socket.** The D-Bus buses, systemd's private socket, ssh-agent and gpg-agent sockets, X11, and the Docker, Podman and containerd sockets are listed as `observed, not allowed`.
- **Allow a place reached right after a secret read.** Tego withholds a destination the session first reached within 5 seconds of reading a secret file. The file then opens with a `# WARNING` line. If that destination is the agent's own service, add it back by hand.
- **Touch `fs.deny_read`, `env`, `models` or the protection level.** The built-in list of secret files still applies. The proposal has no `env.pass`, so the agent gets your whole environment: add one yourself ([Secrets](/docs/secrets/)).
- **Propose a refused action.** Only what the session did is proposed.

## 4. Check it and run it

```
tego rules check agent.yaml
tego run agent.yaml
```

[Testing rules](/docs/testing-rules/) covers what `tego rules check` prints.

## Adjust one rule from a session

When a session under the rules is refused something it needs, or does something you want refused, turn that one record line into a rule. Find the line number with `tego events`:

```
tego events claude-c3d4 --verdict refused
tego rule claude-c3d4 42 --allow
```

`--allow`, `--block` or `--ask` says what the next session does. `--folder` widens a file to its folder, `--command` names the program's command (`git push`) and `--host` names the whole host on every port. `--dry-run` prints the change and writes nothing. Tego checks the new rules before it writes them and keeps the old file as `<file>.bak`; `tego rules undo` gives it back.

## Next steps

- [Testing rules](/docs/testing-rules/): check and test the proposal
- [Secrets](/docs/secrets/): add `env.pass` and your own secret paths
- [Rules file fields](/docs/rules-reference/): what each section of the proposal means
