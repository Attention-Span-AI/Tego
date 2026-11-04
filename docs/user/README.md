# Tego user guide

These pages are for the person who runs agents under Tego. They say what a command does and what it needs. The
specifications, the architecture decision records and the design notes under `docs/` are for the people who change
Tego; the guide does not repeat them.

## What a page says about requirements

Tier cgroup, tier bpflsm and adopt need root. Tier landlock, the default, needs no privilege. The root tiers also need a
kernel that offers them (cgroup v2, BPF and fanotify for tier cgroup, and `bpf` in the boot LSM list for tier bpflsm), and `tego
doctor` says what a machine gives. The release binary and a build from source (`make build`) both carry the root tiers.
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
| [self-check.md](self-check.md) | Does Tego refuse what it should on this machine? (`tego test`) |
| [reason-channel.md](reason-channel.md) | Why was my agent refused, and how does the agent learn why? (a draft) |
| [mcp-tools.md](mcp-tools.md) | How do I allow, hold for approval or deny single tools of an MCP server, and change that live? |
| [container.md](container.md) | How do I run an agent under Tego in a container on a server, which tiers work there, and where do the record and its anchor live? |
| [model-routes.md](model-routes.md) | How do I send a running agent's model calls to another approved backend, and back, without stopping it? |
| [presets.md](presets.md) | Which ready-made rules can my contract start from, how do I combine and pin them, and what does each not cover? (a draft) |
| [live-modes.md](live-modes.md) | Can I change a running agent's rules, both ways and for a while, and what does Locked or Adjustable promise? (a draft) |
