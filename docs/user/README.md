# Tego user guide

These pages are for the person who runs agents under Tego. They say what a command does and what it needs. The
specifications, the architecture decision records and the design notes under `docs/` are for the people who change
Tego; the guide does not repeat them.

## What a page says about requirements

Tier cgroup, tier bpflsm and adopt need root. Tier landlock, the default, needs no privilege. The root tiers also need a
kernel that offers them (cgroup v2, BPF and fanotify for tier cgroup, and `bpf` in the boot LSM list for tier bpflsm), and `tego
machine check` says what a machine gives. The release binary and a build from source (`make build`) both carry the root tiers.
A paragraph of these pages that names tier cgroup, tier bpflsm, adopt or the root tiers says in the same paragraph, in
words and not only in a code block, that it needs root; TestUserDocsNameRootRequirement in `tools/rulecheck` fails the
build when one does not.

A statement about something that does not exist yet carries one fixed label, written exactly as below, in the same
paragraph as the statement. The label opens the paragraph that defines it.

Not built yet. No code for the feature exists. The page says what is planned and never what works, and it
gives no command to run.

## Pages

Every page in this directory is listed here with one line saying what it answers. A page that is not listed
fails TestUserDocsIndexListsEveryPage, and a link to a page that does not exist fails the repository's link
check.

| Page | It answers |
| ---- | ---------- |
| [built-in-refusals.md](built-in-refusals.md) | Which host, Tego and terminal surfaces does every enforcing run refuse? |
| [contracts.md](contracts.md) | Which contracts did Tego find, do they compile now, and where did their rules come from? |
| [agents.md](agents.md) | Where does the found list come from, what do run stages mean, and how do I repair unreadable scan state? |
| [scan.md](scan.md) | What can a basic snapshot find, what stays private, and what does CI learn? |
| [commands.md](commands.md) | Which command does what? Agents, sessions, approvals, presets and the dashboard, and the older commands. |
| [setup.md](setup.md) | Which step is this machine on, and what do I type next? (`tego setup`) |
| [self-check.md](self-check.md) | Does Tego refuse what it should on this machine? (`tego machine test`) |
| [reason-channel.md](reason-channel.md) | Why was my agent refused, and how does the agent learn why? (a draft) |
| [mcp-tools.md](mcp-tools.md) | How do I allow, hold for approval or deny single tools of an MCP server, and change that live? |
| [container.md](container.md) | How do I run an agent under Tego in a container on a server, which tiers work there, and where do the record and its anchor live? |
| [model-routes.md](model-routes.md) | How do I send a running agent's model calls to another approved backend, and back, without stopping it? |
| [ci-verification.md](ci-verification.md) | How do I check exact CI bundles, identities and retained record bytes? |
| [ci-receipt.md](ci-receipt.md) | How do I run an AI agent in CI, retain a record and explicitly consent to optional signing? |
| [presets.md](presets.md) | Which ready-made rules can my contract start from, how do I combine and pin them, and what does each not cover? (a draft) |
| [live-modes.md](live-modes.md) | Can I change a running agent's rules, both ways and for a while, and what does Locked or Adjustable promise? (a draft) |
| [business-rules.md](business-rules.md) | What submitted-refund declaration is checked, and why do business-bearing runs refuse to start? |
| [local-approvals.md](local-approvals.md) | How can an administrator require a separate root terminal for each approval? |
| [baseline.md](baseline.md) | What baseline configuration is parsed today, and why does it add no enforced rule yet? |
