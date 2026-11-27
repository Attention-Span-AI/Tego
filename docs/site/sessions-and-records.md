---
title: Sessions and records
description: "How Tego names each session, where it keeps the session's record, what a record line holds, how the hash chain shows a change, and how long records stay."
summary: "Session names, where records live, the hash chain, and what a record proves."
section: Core concepts
order: 2
---

A session is one run of an agent under Tego, from `tego run` until the agent exits. Its record is the file Tego writes about it: what the agent did, what Tego refused and the rule behind each refusal. Each line of the record carries the hash of the line before it, so a change to the record shows when you check it.

## Session names

A session's name is its agent's name, a dash and four characters, such as `tego-sample-6hbm`. The four characters are the end of the session's run ID, a longer ID such as `r-1a2b3c4d-…-…6hbm` that names the session's folder on disk.

Every command that takes a session accepts its name or its run ID:

```sh
tego session list
tego session show tego-sample-6hbm
tego session show --last
```

## Where records live

Each session has a folder under `~/.tego/runs/`, named by its run ID:

| Path | What it holds |
|---|---|
| `~/.tego/runs/<run ID>/events.jsonl` | The record: one JSON object per line, one line per event |
| `~/.tego/runs/<run ID>/blobs/` | Large bodies, such as model requests and responses, stored by their hash |
| `~/.tego/runs/<run ID>/receipt.json` | A copy of the session's summary, what `tego session show <session> --json` prints, written once when the session ends |
| `~/.tego/chain.log` | One line per ended session: its run ID and the hash of its last record line |

The folders are readable only by you (`0700`, with files `0600`). The agent runs as you, but every session refuses its reads of `~/.tego`. On a Mac or Windows PC, records live inside Tego's Linux.

The rules file's `record:` setting sets how much a record keeps. `full` writes a line for every read, write and connection. `summary`, the default, keeps refusals and a digest of the rest. `off` keeps only the refusals. See [Rules file fields](/docs/rules-reference/).

## What a record line holds

Every line starts with the same fields, then the fields of its kind. The ones you read most:

| Field | Meaning |
|---|---|
| `seq` | The line's number in the record |
| `id` | The hash of this line |
| `prev` | The hash of the line before it |
| `ts` | The time of the event |
| `run` | The session's run ID |
| `agent` | The agent's name |
| `pid` | The process that acted |
| `kind` | What happened: `run_start`, `exec`, `fs`, `net`, `mcp`, `refused`, `ask`, `answer`, `limit`, `run_end` and others |
| `rule` | The rule that decided the action, when a rule decided |
| `verdict` | `allow`, `ask`, `refused` or `observed` (recorded, nothing enforced), when a rule decided |

`tego events <session>` prints a session's lines. `tego session show <session>` and the dashboard summarize them.

## How tampering shows (hash chain)

Tego writes each line with the hash of the line before it. Change one character in a line, and its hash changes, so the next line no longer points to it. Remove lines from the end, and the record no longer ends with the hash that `~/.tego/chain.log` holds for that session.

To check a session's record:

```sh
tego events tego-sample-6hbm --verify
```

It checks every line's hash, every link to the line before, and the last line against `~/.tego/chain.log`. It prints one line that says how many lines it verified and whether the record matched its `chain.log` entry. A session that is still running has no `chain.log` entry yet, and the line says so. When the record doesn't verify, it names the first problem and exits with code 1 ([Exit codes](/docs/exit-codes/)).

`tego session show <session> --verify` runs the same check, then compares the session's `receipt.json` with the record. It prints `Kept receipt: <path> matches the record.`, or exits 1 with `[receipt-differs]` and what differs. The copy is a convenience, not proof: whoever can write the session's folder can write both. Tego keeps no `receipt.json` for a session that was interrupted or whose record could not be completed, and never replaces a file already there.

## What a record proves

A record that verifies shows that nobody changed it after Tego wrote it, as long as that somebody is the agent. The agent can't read `~/.tego` or change the files in it, so it can't rewrite a record and its `chain.log` entry to match.

A record doesn't protect against the person who started the session. You own `~/.tego`, so you, or anyone with your account or root, can rewrite a record and its `chain.log` line so they match again. A record also holds only what Tego saw at the session's protection level. [Security and limits](/docs/security-and-limits/) covers what Tego doesn't see.

## How long records stay

`tego gc` removes the records of sessions older than the machine's retention, 30 days unless an admin changed it, and the folders of sessions that ended without closing:

```sh
tego gc --dry-run
tego gc
tego gc --keep 7d
```

`--dry-run` lists what it would remove. `--keep` sets another retention for this one pass, such as `12h` or `7d`. `tego gc` never removes a session that is running.

Tego removes old records on its own only when the machine's `gc_interval` setting is set ([Machine settings](/docs/machine-settings/)). Otherwise records stay until you run `tego gc`. `tego uninstall` keeps your records unless you tell it to delete them ([Install](/docs/install/#uninstall)).

## Next steps

- [Dashboard](/docs/dashboard/): read sessions and their records in your browser.
- [Session control](/docs/session-control/): stop, pause or change a running session.
- [CI](/docs/ci/): a signed report of a session, for a CI job.
