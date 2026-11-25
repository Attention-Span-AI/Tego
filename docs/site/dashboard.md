---
title: Dashboard
description: "Open Tego's dashboard with tego dashboard: what each page shows, how to answer approvals, change rules and stop a session, and how to reach it over SSH."
summary: "Open the dashboard and find your way around its pages."
section: Core concepts
order: 6
---

The dashboard is a web page on your own machine that shows every session, what Tego refused, and the questions waiting for you. You open it with `tego dashboard`. It listens on `127.0.0.1:8484` and only you can sign in to it.

## Open it

Run this in a terminal as yourself, not with `sudo` and not inside a session:

```sh
tego dashboard
```

`tego start` starts the dashboard for you. It keeps running in the background as a service of your user, so tabs you have open stay signed in.

- **Linux:** `tego dashboard` prints a sign-in link of the form `http://127.0.0.1:8484/?t=<token>`. Open that link in your browser. The bare address without the token asks you to sign in.
- **macOS:** `tego dashboard` forwards the port from Tego's Linux VM and opens the dashboard in your browser.
- **Windows:** `tego dashboard` in PowerShell opens the dashboard in your browser through a small relay. `tego dashboard --stop` ends the relay.

If a dashboard is already running, `tego dashboard` asks:

```text
Open it, or start a new one?
```

**Open it** keeps your open tabs signed in. **Start a new one** stops the running dashboard and signs out its tabs. With no terminal to ask in, `tego dashboard` reuses the running one.

### Run one in the foreground

On Linux, `tego serve` starts a dashboard in the current terminal, and Ctrl-C stops it:

```sh
tego serve --open
```

| Flag | Meaning |
|---|---|
| `--addr` | Loopback address and port to listen on. Default `127.0.0.1:8484`. Port `0` picks a free port. |
| `--open` | Open the dashboard, signed in, in your browser once it listens. |
| `--ledger` | The folder of records to show. Default: the folder Tego writes sessions to. |
| `--preview` | Also list the preview pages, MCP tools and Model routes, in the menu. |

If port 8484 is busy, see [Troubleshooting](/docs/troubleshooting/).

## The pages

The menu shows Agents, Overview, Runs, Approvals and Logs. **More** holds Contracts, Detections and This machine.

- **Agents**: agents running on this machine and those `tego scan` found, with a way to record one. [Finding agents](/docs/finding-agents/) covers the scan.
- **Overview**: what needs you first, then questions waiting, sessions running now, recent refused actions and the record check.
- **Runs**: every session, running ones first, with its status and protection level.
- **A session**: open one from Runs. It has six tabs:
  - **Timeline**: every line of the session's record, in order.
  - **Refused**: every refused action, grouped or line by line.
  - **Processes**: the programs the session started.
  - **Receipt**: the session's summary (not the CI receipt).
  - **Tighten**: the smallest change to the rules file this session suggests.
  - **Unused**: rules the session was given and never used.
- **Approvals**: questions waiting for an answer, and a History tab of past answers. [Approvals](/docs/approvals/) explains the buttons.
- **Logs**: every line across every session, with search, filters and a CSV download.
- **Contracts**: the rules files in use, in plain sentences, with **Change rules** and **New contract**. Contracts is the dashboard's name for rules files.
- **Detections**: refused actions that matter, ranked High, Medium, Low and Routine.
- **This machine**: "Can this machine enforce rules?", with the [protection levels](/docs/tiers/) past sessions used here. Run `tego machine check` for a current answer.
- **Guide**: a step-by-step setup tour, from checking the machine to enforcing an agent's rules.
- **Glossary**: the words the dashboard uses.

With `tego serve --preview`, the menu also shows **MCP tools** and **Model routes**. [MCP tools](/docs/mcp-tools/) and [Model routes](/docs/model-routes/) cover them.

## Act on a running session

A running session's page has these buttons:

- **Block now**: refuse a program, a host, or a file or folder from the next action on. The rules file does not change.
- **Pause**: freeze the agent where it stands. **Resume** lets it carry on. Pause waits while a question is open: answer it first.
- **Stop run**: end the session.

[Session control](/docs/session-control/) has the same actions as commands.

## Change rules

On **Contracts**, choose **Change rules** and pick a rules file. Edit it, check the result, then save:

- A saved change applies from the next session.
- **Apply now to** a running session places the change on that session too, within about a second.
- **Undo**, from the change's History, puts the previous text back.

A session in Locked mode, the default, refuses changes that loosen its rules while it runs. [Live changes](/docs/live-changes/) explains Locked and Adjustable mode.

## Open it from another machine

To reach the dashboard on a server, forward the same port number over SSH, then run `tego dashboard` on the server and open the printed link in your local browser:

```sh
ssh -L 8484:127.0.0.1:8484 <host>
```

A different local port is refused, because the dashboard checks that the address in the request is its own.

[Security and limits](/docs/security-and-limits/#the-dashboard) says who the dashboard answers.

## Next steps

- [Approvals](/docs/approvals/): what the buttons on the Approvals page do.
- [Session control](/docs/session-control/): the dashboard's actions as commands.
- [Sessions and records](/docs/sessions-and-records/): what the Timeline tab shows.
