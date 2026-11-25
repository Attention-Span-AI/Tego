---
title: How Tego works
description: "How Tego works: a rules file says what an agent may do, the Linux kernel enforces it from outside the agent, and each session leaves a record."
summary: "Rules file, session, kernel enforcement and record, on one page."
section: Get started
order: 3
---

Tego starts your AI agent under a rules file, has the Linux kernel enforce those rules from outside the agent, and writes a record of what the agent did and what Tego refused. The agent doesn't have to cooperate, and it can't turn the rules off.

```text
  rules file ──> tego run ──> agent, and every program it starts
                    │                │  files, programs, connections
                    │                v
                    │           Linux kernel: refuses what the rules don't allow
                    v
                  record ──> tego session show, dashboard
```

## The parts

**Agent.** Any program Tego starts for you: Claude Code, Codex, a Python script, a bot. Tego doesn't change the agent's code and never calls an AI model itself.

**Rules file.** A YAML file that says what the agent may do: the files it may write and never read, the programs it may run and the hosts it may reach. It also says which actions wait for a person, and how long or how much the agent may run. `tego start` writes one for you. See [Rules files](/docs/rules-files/).

**Session.** One run of an agent under Tego, from `tego run` until the agent exits. Each session has a name, such as `tego-sample-6hbm` ([Sessions and records](/docs/sessions-and-records/)).

**Record.** What Tego writes about a session: every refusal with its rule, and the agent's actions. Each line carries the hash of the line before it, so a changed line shows. See [Sessions and records](/docs/sessions-and-records/).

**Protection level.** How much of the rules the kernel enforces on this machine: Basic with no root, Plus and Max with root. See [Protection levels](/docs/tiers/).

## What happens when you run an agent

1. `tego run` reads the rules file and checks it. A rules file that doesn't check stops the session before the agent starts.
2. Tego hands the rules to the Linux kernel, then starts the agent under them. Every process the agent starts is under the same rules.
3. The agent works as usual. The kernel checks each file it opens, program it runs and connection it makes, and refuses what the rules don't allow. A Tego process outside the agent answers what the kernel can't decide alone, such as an action that waits for a person.
4. When the agent exits, Tego ends the session and closes its record.

The rules live in the kernel and in Tego's own process, so nothing the agent does from inside the session removes them. By default a session's rules stay fixed until it ends; [Live changes](/docs/live-changes/) covers the sessions you can adjust while they run.

On a Mac or Windows PC, all of this happens inside the small Linux VM the installer set up ([Install](/docs/install/)).

## When a rule applies

Each action the agent takes ends one of four ways:

- **Allowed.** The action goes ahead.
- **Refused.** The action fails with an ordinary permission error, and the agent keeps running. The record names the rule that refused it. [Refusals](/docs/refusals/) shows what each agent sees.
- **Waits for a person.** An `ask:` rule holds the action until someone approves or refuses it on the dashboard or with `tego approve` and `tego deny`. No answer in time counts as refused. See [Approvals](/docs/approvals/).
- **Over a limit.** When the session passes a limit in its rules file, such as time, tokens or cost, Tego ends the session. See [Budgets](/docs/budgets/) and [Exit codes](/docs/exit-codes/).

What Tego doesn't stop, such as what an allowed program does or what the agent sends to an allowed host, is on [Security and limits](/docs/security-and-limits/).

## Next steps

- [Quickstart](/docs/getting-started/): run an agent and see a refusal.
- [Rules files](/docs/rules-files/): what a rules file holds and what a missing section means.
- [Protection levels](/docs/tiers/): what this machine can enforce.
