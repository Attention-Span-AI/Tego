---
title: Dashboard
description: "Open Tego's dashboard with tego dashboard: what each page shows, how to answer approvals, change rules and stop a session, and how to reach it over SSH."
summary: "Open the dashboard and find your way around its pages."
section: Core concepts
order: 6
---

The dashboard is a web page on your own machine that shows every session, what Tego refused, and the questions waiting for you. You open it with `tego dashboard`. It listens on `127.0.0.1:8484` and only you can sign in to it.

## Open the dashboard

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

### Run it in the foreground

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

## What each page shows

The menu shows Agents, Overview, Runs, Approvals and Logs. **More** holds Rules files, Detections and This machine.

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
- **Rules files**: the rules files in use, in plain sentences, with **New rules file**, and **Edit rules file** on each file.
- **Detections**: refused actions that matter, ranked High, Medium, Low and Routine.
- **This machine**: "Can this machine enforce rules?", with the [protection levels](/docs/tiers/) past sessions used here. Run `tego machine check` for a current answer.
- **Guide**: a step-by-step setup tour, from checking the machine to enforcing an agent's rules.
- **Glossary**: the words the dashboard uses.

With `tego serve --preview`, the menu also shows **MCP tools** and **Model routes**. [MCP tools](/docs/mcp-tools/) and [Model routes](/docs/model-routes/) cover them.

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/tego-dashboard-overview-light.png"><img src="/assets/docs/dashboard/overview-light.png" width="1440" height="900" loading="lazy" decoding="async" alt="The dashboard Overview in its light theme: a card reading release-notes-bot is waiting for you, wants to read ./confidential/plan.md, with Allow once and Deny; the heading 1 request needs you; a red line reading 1 run leaked secrets; Record verified, 3 ended runs checked; and release-notes-bot running now."></a>
<a class="shot-frame only-dark" href="/assets/docs/tego-dashboard-overview-dark.png"><img src="/assets/docs/dashboard/overview-dark.png" width="1440" height="900" loading="lazy" decoding="async" alt="The dashboard Overview in its dark theme: a card reading release-notes-bot is waiting for you, wants to read ./confidential/plan.md, with Allow once and Deny; the heading 1 request needs you; a red line reading 1 run leaked secrets; Record verified, 3 ended runs checked; and release-notes-bot running now."></a>
<figcaption><b>Overview.</b> What needs you first, then questions waiting, sessions running now, refused actions and the record check.</figcaption>
</figure>

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/dashboard/session-timeline-light.png"><img src="/assets/docs/dashboard/session-timeline-light.png" width="1440" height="900" loading="lazy" decoding="async" alt="The page of the ended session notes-app in its light theme: a red banner reading Protected: 1 secret read and 1 send to 127.0.0.1:8801 refused, the counts 2 refused and 347 events, a Verified, 347 lines badge, the tabs Timeline, Refused, Processes, Receipt, Tighten and Unused, and the newest timeline lines marked Recorded and Allowed."></a>
<a class="shot-frame only-dark" href="/assets/docs/dashboard/session-timeline-dark.png"><img src="/assets/docs/dashboard/session-timeline-dark.png" width="1440" height="900" loading="lazy" decoding="async" alt="The page of the ended session notes-app in its dark theme: a red banner reading Protected: 1 secret read and 1 send to 127.0.0.1:8801 refused, the counts 2 refused and 347 events, a Verified, 347 lines badge, the tabs Timeline, Refused, Processes, Receipt, Tighten and Unused, and the newest timeline lines marked Recorded and Allowed."></a>
<figcaption><b>A session, Timeline tab.</b> The session's verdict, its record check and every line of its record, newest first.</figcaption>
</figure>

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/dashboard/session-refused-light.png"><img src="/assets/docs/dashboard/session-refused-light.png" width="1440" height="1065" loading="lazy" decoding="async" alt="The Refused tab of the session notes-app in its light theme: 2 High, 0 Medium, 0 Low, then two High refusals: open of the project's .env file, marked Secret and refused by the rule Never read, and a connection to 127.0.0.1:8801 marked After a secret read."></a>
<a class="shot-frame only-dark" href="/assets/docs/dashboard/session-refused-dark.png"><img src="/assets/docs/dashboard/session-refused-dark.png" width="1440" height="1065" loading="lazy" decoding="async" alt="The Refused tab of the session notes-app in its dark theme: 2 High, 0 Medium, 0 Low, then two High refusals: open of the project's .env file, marked Secret and refused by the rule Never read, and a connection to 127.0.0.1:8801 marked After a secret read."></a>
<figcaption><b>A session, Refused tab.</b> Each refused action with its severity and the rule that refused it.</figcaption>
</figure>

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/dashboard/approvals-light.png"><img src="/assets/docs/dashboard/approvals-light.png" width="1440" height="1189" loading="lazy" decoding="async" alt="The Approvals page in its light theme: 1 request waiting, a card reading Let release-notes-bot read this file? with the exact target confidential/plan.md, why it asked (your rules ask before any read under ./confidential/plan.md), the time left, Allow once, Deny and More choices."></a>
<a class="shot-frame only-dark" href="/assets/docs/dashboard/approvals-dark.png"><img src="/assets/docs/dashboard/approvals-dark.png" width="1440" height="1189" loading="lazy" decoding="async" alt="The Approvals page in its dark theme: 1 request waiting, a card reading Let release-notes-bot read this file? with the exact target confidential/plan.md, why it asked (your rules ask before any read under ./confidential/plan.md), the time left, Allow once, Deny and More choices."></a>
<figcaption><b>Approvals.</b> A read waiting for an answer, with the rule that asked.</figcaption>
</figure>

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/dashboard/detections-light.png"><img src="/assets/docs/dashboard/detections-light.png" width="1440" height="900" loading="lazy" decoding="async" alt="The Detections page in its light theme: a red banner reading Secrets left: .env sent to 127.0.0.1:8801 for a watched-only session, the filters High 4, Medium 0 and Low 0, and a table of four High refusals: connections to 127.0.0.1:8802 and 127.0.0.1:8801 and reads of ~/.ssh/id_ed25519 and the notes-app .env file, each with its agent and time."></a>
<a class="shot-frame only-dark" href="/assets/docs/dashboard/detections-dark.png"><img src="/assets/docs/dashboard/detections-dark.png" width="1440" height="900" loading="lazy" decoding="async" alt="The Detections page in its dark theme: a red banner reading Secrets left: .env sent to 127.0.0.1:8801 for a watched-only session, the filters High 4, Medium 0 and Low 0, and a table of four High refusals: connections to 127.0.0.1:8802 and 127.0.0.1:8801 and reads of ~/.ssh/id_ed25519 and the notes-app .env file, each with its agent and time."></a>
<figcaption><b>Detections.</b> Refused actions that matter, ranked by severity, and any session that let a secret leave.</figcaption>
</figure>

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/dashboard/machine-light.png"><img src="/assets/docs/dashboard/machine-light.png" width="1440" height="900" loading="lazy" decoding="async" alt="The This machine page in its light theme: the heading Can this machine enforce rules?, a card saying Basic worked in a recorded run and suggesting tego machine check, and Protection checks listing Basic as used before and Plus and Max as not checked."></a>
<a class="shot-frame only-dark" href="/assets/docs/dashboard/machine-dark.png"><img src="/assets/docs/dashboard/machine-dark.png" width="1440" height="900" loading="lazy" decoding="async" alt="The This machine page in its dark theme: the heading Can this machine enforce rules?, a card saying Basic worked in a recorded run and suggesting tego machine check, and Protection checks listing Basic as used before and Plus and Max as not checked."></a>
<figcaption><b>This machine.</b> The protection levels past sessions used here, and the command that checks the machine now.</figcaption>
</figure>

## Stop or pause a session

A running session's page has these buttons:

- **Block now**: refuse a program, a host, or a file or folder from the next action on. The rules file does not change.
- **Pause**: freeze the agent where it stands. **Resume** lets it carry on. Pause waits while a question is open: answer it first.
- **Stop run**: end the session.

[Session control](/docs/session-control/) has the same actions as commands.

## Change a rules file

On **Rules files**, open a rules file and choose **Edit rules file**. Edit it, check the result, then save:

- A saved change applies from the next session.
- **Apply now to** a running session places the change on that session too, within about a second.
- **Undo**, from the change's History, puts the previous text back.

<figure class="shot">
<a class="shot-frame only-light" href="/assets/docs/dashboard/rules-file-light.png"><img src="/assets/docs/dashboard/rules-file-light.png" width="1440" height="900" loading="lazy" decoding="async" alt="The rules file of notes-app in its light theme: Basic (Landlock), the buttons New rules file and Edit rules file, Can read any other file except the ones under Never reads, and a Can change table listing ./src/, ./tests/, ./libs/ and ./tmp/ as Allowed and enforced by the operating system, with the number of hits in the session and the line of agent.yaml each comes from."></a>
<a class="shot-frame only-dark" href="/assets/docs/dashboard/rules-file-dark.png"><img src="/assets/docs/dashboard/rules-file-dark.png" width="1440" height="900" loading="lazy" decoding="async" alt="The rules file of notes-app in its dark theme: Basic (Landlock), the buttons New rules file and Edit rules file, Can read any other file except the ones under Never reads, and a Can change table listing ./src/, ./tests/, ./libs/ and ./tmp/ as Allowed and enforced by the operating system, with the number of hits in the session and the line of agent.yaml each comes from."></a>
<figcaption><b>A rules file.</b> Its rules in plain sentences, how many times each applied, and <b>Edit rules file</b>.</figcaption>
</figure>

A session in Locked mode, the default, refuses changes that loosen its rules while it runs. [Live changes](/docs/live-changes/) explains Locked and Adjustable mode.

## Open it from another machine

To reach the dashboard on a server, forward the same port number over SSH, then run `tego dashboard` on the server and open the printed link in your local browser:

```sh
ssh -L 8484:127.0.0.1:8484 <host>
```

A different local port is refused, because the dashboard checks that the address in the request is its own.

[Security and limits](/docs/security-and-limits/#who-can-use-the-dashboard) says who the dashboard answers.

## Next steps

- [Approvals](/docs/approvals/): what the buttons on the Approvals page do.
- [Session control](/docs/session-control/): the dashboard's actions as commands.
- [Sessions and records](/docs/sessions-and-records/): what the Timeline tab shows.
