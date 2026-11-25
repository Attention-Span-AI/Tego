---
title: FAQ
description: "Short answers about Tego: what it is, root, macOS and Windows, which agents work, what happens on a refusal, the record, your data and the license."
summary: "Short answers, each with a link to the page that has the details."
section: Reference
group: Help
order: 2
---

Short answers to the questions people ask first. Each answer links to the page with the details.

Claude, Codex and other product names are trademarks of their owners; Tego is not affiliated with or endorsed by them.

## About Tego

### What is Tego?

Tego runs your AI agent under a rules file that says which files, hosts and programs it may use, and the Linux kernel enforces those rules from outside the agent. Every session leaves a record you can check. [How Tego works](/docs/concepts/) explains the model.

### Does Tego use an AI model to decide?

No. Tego never calls a model; your rules file decides, and the kernel and Tego's supervisor enforce it. See [How Tego works](/docs/concepts/).

### Does Tego hide the machine from the agent?

No. The agent works in your real project and can read any path your rules and the [built-in refusals](/docs/built-in-refusals/) do not refuse. [Security and limits](/docs/security-and-limits/) says where the line is.

### Who makes Tego?

Attention Span. Tego is open source under Apache-2.0, on [GitHub](https://github.com/Attention-Span-AI/Tego), and [About Attention Span](/about/) says how to reach us.

### Is Tego free, and under which license?

Yes. Tego is open source under Apache-2.0, and its kernel programs are dual licensed GPL-2.0-only or BSD-2-Clause. The code is on [GitHub](https://github.com/Attention-Span-AI/Tego).

## Setting it up

### Does Tego need root?

No. The Basic protection level runs without root; root through `sudo` adds Plus and Max. [Protection levels](/docs/tiers/) shows what each level enforces.

### Does Tego run on macOS or Windows?

Yes, through Linux: on a Mac, Tego runs in a small Lima VM; on Windows, in its own WSL2 distribution, at Basic. [Install](/docs/install/) has the commands, and [Supported systems](/docs/supported-systems/) the requirements.

### Which agents work with Tego?

Claude Code and Codex have ready setups in `tego start`, and any other program or script runs under `tego run`. See [Claude Code](/docs/claude-code/), [Codex](/docs/codex/) and [Other programs](/docs/other-programs/).

### Can Codex keep its own sandbox on inside Tego?

No. A sandbox the agent starts itself, such as Codex's bubblewrap sandbox, cannot start inside a Tego session, so Codex runs with its sandbox off and Tego enforces the rules. [Codex](/docs/codex/) shows the setup.

### Does Tego work in CI?

Yes. Tego ships the `tego/ci` preset and reusable GitHub workflows, and Basic needs no root on a hosted runner. See [CI](/docs/ci/).

### Can I run Tego inside Docker?

Yes, at Basic, with a few container settings. [Containers](/docs/containers/) lists them.

## What it protects

### What happens when the agent breaks a rule?

The action fails with an ordinary error, such as "permission denied", and the record names the rule that refused it. [Refusals](/docs/refusals/) explains what each agent is told.

### Can an action wait for my answer?

Yes. An `ask:` rule holds the action until you approve or refuse it in the dashboard or with `tego approve` and `tego deny`. See [Approvals](/docs/approvals/).

### Can Tego keep an agent away from my SSH keys and .env files?

Yes. Every rules file refuses reads of SSH keys, cloud logins, token stores and `.env` files unless it sets `deny_read: []`, and the `tego/no-secrets` preset keeps secret variables out of the agent's environment. A file shown through a separate file system, or mounted after the session starts, is outside these rules: see [File aliases and mount limits](/docs/security-and-limits/#file-aliases-and-mount-limits). See [Built-in refusals](/docs/built-in-refusals/) and [Secrets](/docs/secrets/).

### Can Tego stop data leaving my machine?

Partly. Tego refuses hosts your rules do not allow, but every allowed host is a way out for anything the agent can read. [Security and limits](/docs/security-and-limits/) explains how to narrow that.

### Can the agent change the record?

An agent under your rules cannot change its record without the change showing, because each line carries the hash of the one before it. The person who started the session can. See [Sessions and records](/docs/sessions-and-records/).

### How do I stop an agent that is running?

Run `tego session stop <session>`, or use Stop in the dashboard. [Session control](/docs/session-control/) also covers pause and live blocks.

## Your data

### Does Tego send my code or data anywhere?

No. Tego has no telemetry, no update check and no crash reports, and each record stays on your machine. [Security and limits](/docs/security-and-limits/) lists the network traffic Tego makes.

### How do I report a security problem?

Privately, through a GitHub security advisory on the Tego repository, never in a public issue. [Security and limits](/docs/security-and-limits/) says what to include.

### How do I remove Tego?

Run `tego uninstall`; [Install](/docs/install/#uninstall) says what it keeps on each system.

## Commands

### Do the old command names still work?

Yes. Each older name runs the same command, with the same flags and exit codes. [Commands](/docs/commands/#older-names) lists each one with its new name.

## Next steps

- [Quickstart](/docs/getting-started/): run a first session end to end.
- [Troubleshooting](/docs/troubleshooting/): fixes for common errors.
- [Commands](/docs/commands/): every command and its flags.
