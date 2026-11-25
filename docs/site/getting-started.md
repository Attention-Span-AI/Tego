---
title: Quickstart
description: "Run Claude Code under Tego for the first time: set it up with tego start, run a session, see the actions Tego refused, and open the dashboard."
summary: "Run your first agent under rules and see Tego refuse an action."
section: Get started
order: 2
---

In this tutorial you run Claude Code under Tego on a small test project, watch Tego refuse a hidden attempt to steal a secret, and read what happened. You need Tego installed ([Install](/docs/install/)) and a Claude subscription or an Anthropic API key.

The test project is a small notes app. One of its dependencies is poisoned on purpose: when the tests import it, it reads the project's `.env` file and tries to send it to a server. The secret is fake and the server is `127.0.0.1:8801` on your own machine, where nothing listens.

## 1. Set up with tego start

```sh
tego start
```

On a Mac or Windows PC, type it in your own terminal; the `tego` command runs it inside Tego's Linux.

`tego start` first checks what this machine can enforce, then asks four questions. Press Enter at each one to take the recommended answer:

1. **Agent:** `Which agent do you want to supervise?` Choose **Claude Code**. If Claude Code isn't installed, `tego start` offers to run its installer.
2. **Login:** choose **Claude subscription** to log in with your Claude account in a browser, or **Anthropic API key** to paste a key. `tego start` asks whether to save the login for later sessions.
3. **Project:** choose **Tego test project**. It creates `~/tego-sample`.
4. **Rules:** choose **Base development**. Claude Code may edit and test the project, and never reads secrets.

It saves a rules file for the agent `tego-sample`, starts the dashboard, and ends with what it set up and what to type next:

```text
  Ready
    Agent       tego-sample · Claude Code
    Project     ~/tego-sample
    Rules       Base development
    Dashboard   http://127.0.0.1:8484/?t=…

  Next steps
    Run Claude Code under Tego    cd /home/me/tego-sample && tego run tego-sample
    List your sessions            tego session list
    Show the last session         tego session show --last
    Edit the rules                tego rules edit tego-sample
```

`tego start` never starts the agent. You do that next.

On a Mac or Windows PC, `tego start` leaves you in a shell inside Tego's Linux, with a `Shell` row in the panel. Type the next commands there. `exit` returns you to your own terminal.

## 2. Run Claude Code under Tego

Type the first line under **Next steps**:

```sh
cd ~/tego-sample && tego run tego-sample
```

Claude Code starts as usual. From now until it exits, Tego holds it to the rules in its rules file.

Ask Claude Code:

```text
Run the project's tests.
```

The tests pass. While they run, the poisoned dependency tries to read `.env` and to connect to `127.0.0.1:8801`. Tego refuses both, and the dependency gets an ordinary permission error.

## 3. End the session

Exit Claude Code. Tego prints one line for the session:

```text
  ✓ Session tego-sample-6hbm ended · 2 actions blocked
      Details: tego session show tego-sample-6hbm
```

A session is one run of an agent under Tego. Yours ends in other characters.

Tego prints this short line when the agent exited with code 0 and the session's record checks out. Otherwise it prints a longer summary of the session.

## 4. See what Tego refused

```sh
tego session show --last
```

It shows what the session did: its time, files, connections, secrets read, refusals, held requests and tokens. Find the two refusals: the read of `.env` and the connection to `127.0.0.1:8801`, each with the rule that refused it.

## 5. Open the dashboard

```sh
tego dashboard
```

On Linux it prints the dashboard's link; open it in your browser. On a Mac or Windows PC it opens your browser. Open **Runs**, choose your session, and open the **Refused** tab: the same two refusals are there.

You ran an agent under rules it couldn't change, saw Tego refuse a secret read and a connection, and read both in the session's record.

## Next steps

- [How Tego works](/docs/concepts/): what happened during the session, and why the agent couldn't get around it.
- [Claude Code](/docs/claude-code/): run Claude Code on your own project.
- [Rules files](/docs/rules-files/): what the Base development rules contain and how to change them.
- [Dashboard](/docs/dashboard/): every page of the dashboard.
