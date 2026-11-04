<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook: the supply-chain split screen with Codex

The tested way to set up, run, prove and reset this demo on a laptop. Every step below was run in order, twice (a
first run, then a second after `reset` with the dashboard left running), on an
isolated stage with a stand-in agent that types the prompts' commands; the last run with the real Codex was on an
earlier build. One script, `demo.sh`, does
every step; each subcommand prints the exact command it runs, so the manual fallback is always on screen.
README.md explains the story; this file is the checklist.

**What it shows.** The same Codex, the same project, the same prompt, twice. A poisoned dependency
(`repo/vendor/telemetry-helper`) fires when the tests import it: it tries the SSH key, the API token and every
credential-looking environment variable the demo planted, and sends what it gets to a fake attacker on `127.0.0.1`.

- **LEFT** runs under `tego watch`: Tego records everything and blocks nothing. The attack works, and the dashboard
  shows it as *observed*.
- **RIGHT** runs under `tego run` with `contracts/codex-chatgpt.yaml`:
  - the SSH key is never readable;
  - the token and `confidential/` ask a person first;
  - `held/` writes ask;
  - only the project's API (`127.0.0.1:8803`) and ChatGPT are reachable;
  - only `SERVICE_TOKEN` is passed in.

**Safe on this laptop.** Each side has its own fake home inside the demo folder, so your real `~/.ssh`,
`~/.config` and `~/.codex` are never touched. Setup only *copies* your Codex login (`auth.json`) into each side.
The two terminals start through `env -i` with only the demo's fake variables, so nothing from your own shell
reaches Codex or the stealer; the stealer sweeps and names only values that say FAKE or DEMO. The fake attacker
binds `127.0.0.1` only and never stores what it receives.

**The script.** Run it from this folder (`examples/supply-chain-demo`). Everything is derived from where it lives.
`demo.env` holds the settings, each overridable by an environment variable for one run: the ports (8801 and 8802
for the two attackers, 8803 for the project's API), the unit prefix (`tego-sc`), the dashboard address
(`127.0.0.1:8484`), the demo's config and ledger (`~/tego-demo.yaml`, `~/tego-demo-ledger`) and where your Codex
login is copied from (`~/.codex/auth.json`). After changing a port, run `setup` again: the contract names the API's.

| Subcommand | What it does |
|---|---|
| `setup` | builds both sides, fills the contract, starts the three fake servers as `systemd --user` units, starts a fresh ledger |
| `check` | verifies everything a run needs; prints `READY` only when all of it holds, otherwise each failure and its fix, exit 1 |
| `dashboard` | the dashboard, opened signed in (`./demo.sh dashboard --addr 127.0.0.1:9000` if 8484 is busy) |
| `left`, `right` | Codex under `tego watch` / under `tego run`, in that side's fake world |
| `attacker` | the two attacker logs side by side |
| `backup` | the project's tests with no agent, watched and enforced, so there is always one deterministic pair of runs |
| `proof` | what each side read and sent, and the verified record |
| `reset` | a second run: fresh sides, the contract filled again, the ledger moved; `reset --stop` also ends the demo |

## With Claude Code instead of Codex (`DEMO_AGENT=claude`)

Everything below is written for Codex. For Claude Code, set `DEMO_AGENT=claude` for **every** subcommand (setup, check,
dashboard, left, right, attacker, backup, proof, reset), in every terminal, and change only these things:

- **Login.** Claude Code's login is never copied into the demo. Run `claude setup-token` once, then in each terminal that
  runs `left` or `right`: `export CLAUDE_CODE_OAUTH_TOKEN=<the token>` (or `ANTHROPIC_API_KEY`). `setup` and `check` say
  so when it is missing; `check` has no `codex login status` step to pass. In a terminal that came in over SSH, start
  with `systemd-run --user --scope bash`, or tego has no tier.
- **Names.** The contract is `contracts/claude-code.yaml`, filled as `with/claude-code.filled.yaml`; its name, and so the
  agent label on the dashboard and the ask card's question, is `supply-chain-claude-code`, not `supply-chain-codex-chatgpt`
  (*Let supply-chain-claude-code read this file?*). The agent's own folder is `claude-home`, and the command is `claude`
  with no `--no-daemon`. `net.allow` names `api.anthropic.com:443` where Codex's names `chatgpt.com` and `auth.openai.com`.
- **Quit** both windows with `/exit`, not `/quit`. Wherever a step below says `/quit`, `codex` or Codex's screen, read
  `/exit`, `claude` and Claude Code's screen.
- **Same on the screen**, apart from those names: the prompts, the 0:15 ask and its Deny, the 1:00 Allow once, the 1:40
  Never allow and the proof read the same. The contract pins `tier: landlock` for the same reason.
- **Try it once** with the real Claude Code on this dashboard first; this file's last full run was
  with Codex.

## 1. Setup (one terminal, about 1 minute)

Open a **fresh** terminal (one where `HOME` was never changed), sign in to Codex once with ChatGPT if you have not
(`codex`), and:

```sh
cd <your checkout> && make build        # a stale bin/tego is the first thing check reports
bin/tego test                           # about a second, Tego's self-check: must say 4 actions, 4 refused
cd examples/supply-chain-demo
./demo.sh setup                         # copies your Codex login into both sides: do this just before you run the demo
./demo.sh check                         # must end with READY
./demo.sh backup                        # optional, 10 seconds: the dashboard then always has one enforced run to show
```

**`bin/tego test`** is Tego's own self-check ([docs/user/self-check.md](../../docs/user/self-check.md)), separate
from the demo: four harmless actions on decoys in a temporary folder (read a fake SSH key, write outside the project,
run a program the contract does not list, connect to a local port it does not allow), each first without Tego, then
under `tego run`. If all four are refused, its first line is `Tego self-check: 4 actions, 4 refused at tier landlock`
and it exits 0. Its four runs are recorded in that folder, removed when it ends, so neither the demo's ledger nor the
dashboard ever shows them. On exit 1 (an action got through, or was stopped without a record) or 125 (one could not
be judged, or `tego test` could not run), its screen says why: fix that before a take. This line was added on
2026-11-02, after the rehearsals above, and run then on an isolated stage, not in a take.

`setup` stops and starts only its own three units (`tego-sc-sink-8801`, `tego-sc-sink-8802`, `tego-sc-api-8803`),
so the terminal can be closed. Nothing needs pip, venv or pytest; the tests use `python3 -m unittest`.

What `check` verifies, and what it says when it fails (each failure names its fix):

- the ports and the three units: a busy port, or a unit that is not running;
- `python3`, `codex`, `notify-send`, `watch`, `systemd-run` on PATH;
- `bin/tego` and `bin/tego-control` match the checkout's git HEAD, else `bin/tego is stale: run make build`;
- the config `~/tego-demo.yaml` is yours and not group- or other-writable, and so is its folder (a group-writable
  home makes tego skip the config silently and use the default ledger); the stage is not inside the ledger or `~/.tego`;
- `tego doctor` offers tier landlock or better;
- each side's Codex login is present and `codex login status` accepts it (no model call);
- `chatgpt.com` and `auth.openai.com` resolve; nothing but the demo's own dashboard listens on the dashboard address
  (`ok    the demo's dashboard is running (reset keeps it; it follows the new ledger)`, or `no dashboard is
  running`); the filled contract compiles, and it equals the template filled afresh (`the contract was changed (by
  Never allow?): run demo.sh reset`);
- no run of the demo is still running (`N run(s) of this demo are still running (r-…)`, fix: quit both Codex
  windows with `/quit`, then `./demo.sh reset`).

**If Codex shows a login screen** on a side, the copied login went stale (the original was refreshed after the
copy). Run `./demo.sh setup` again, which copies the current one, then `check`. Do not recover by pasting a login
into a running run.

**`backup`** runs the project's tests twice with no agent: watched (the key is read, the attacker is reached) and
enforced (the key is refused, the token ask is denied for you, the send is refused). It clears the attacker logs
afterwards so the run starts empty. Its two runs stay in the dashboard, and the enforced one is the run to
compare when a run goes sideways (see section 5, "Codex sometimes inspects the dependency first").

## 2. The four terminals

Each command prints the command it runs, with the exact environment (`env -i ...`), before it runs it. All four use
the same demo ledger, so the dashboard shows both sides.

**Terminal 1: the dashboard.** It opens in your browser, signed in (with no browser opener, open the printed link).
The browser is handed a one-time sign-in that works once, within a minute; a second browser, or a page that says to
sign in again, takes the printed link.
Go to **Approvals**. The header's **Auto / Light / Dark** switch follows the system theme by default.

```sh
./demo.sh dashboard
```

**Terminal 2: LEFT** (Tego only watches):
```sh
./demo.sh left
```
`tego watch` prints four lines before Codex's screen:
```
tego watch: recording codex and everything it starts. No rule refuses anything (details: tego watch -v -- codex).
  recorded: every program it starts, every file it opens (reads included), every connection it makes.
  not a cage: it can still ask another service (systemd --user, D-Bus, an SSH or GPG agent) to act for it.
  to confine it: tego run <agent.yaml> -- codex, or tego watch --boundary <agent.yaml> -- codex
```
It is expected, it is true (that is the point of the left side), and Codex's screen replaces it. When Codex exits,
the left terminal's last lines are the run's summary:
```
tego watch: recorded as run r-…: ended (exited with code 0) · wrote 4 files · chain verified
  seen: 4 connections to 2 places (most: 127.0.0.1:8801) · 2 sensitive files read (first: ~/.ssh/id_rsa)
  more: tego receipt r-…    tego events r-…
```

`left` and `right` first print the exact `env -i ...` command they run (about 1.5 KB, with your user name and desktop
variables). `DEMO_QUIET=1 ./demo.sh left` prints it without those and with a short `PATH=...`; the command that runs is
the same. Either way Codex's screen replaces it.

**Terminal 3: RIGHT** (Tego enforces):
```sh
./demo.sh right
```
Before Codex starts, `tego run` prints, in this order: on AppArmor one note,
`note: tego run: on AppArmor a file read that tego checks and opens for the agent is decided by the contract's rules; a tighter AppArmor profile on the agent is not applied to it [held-label]`,
then one line, `tego run: <run> can hold an operation for your approval; answer from another terminal: tego ask
<run>, then tego approve <run> <ask_id> (or deny), or on the dashboard's Approvals page`. Both are normal, and the
second is the run id to answer with if you ever answer in a terminal instead of the dashboard. When Codex exits, the
last lines are the run's summary, for example `tego run: r-… ended (exited with code 0) · tier landlock · refused 9 (not
allowed by any rule 6, …) · asked 2 (1 approved, 1 denied) · wrote 4 files · chain verified`, then `more: tego receipt r-…`. Nothing else
is printed: the compile notes stay with `tego compile` (`[mount]` for `/dev/pts/`, `[held-reads]`, and
`[wall-hard-cap]`: `limits.wall 2h` ends an interactive session at the minute it expires, so a run is never that
long). To see the notes, compile the filled contract: `cd with/proj && tego compile ../codex-chatgpt.filled.yaml`
(or run the printed command with `-v` after `tego run`).

**Terminal 4: the attacker panel.** It uses `watch`, not `tail -f`, because the laptop can run out of file watches. It runs `watch -t`: no header line (user name, host, stage path, clock), only the two sections.
```sh
./demo.sh attacker
```

**Screen.** LEFT Codex and RIGHT Codex go side by side on top. The dashboard and the attacker panel go below.

**By hand.** Everything above is the command `demo.sh` prints. For example RIGHT is
`cd <stage>/with/proj && env -i PATH=... HOME=<stage>/with/home CODEX_HOME=<stage>/with/codex-home SC_SINK=http://127.0.0.1:8802 SC_API=http://127.0.0.1:8803 SERVICE_TOKEN=svc_demo_FAKE_SERVICE_TOKEN_0000 AWS_SECRET_ACCESS_KEY=AKIA_FAKE_DEMO_SECRET_0000 GITHUB_TOKEN=ghp_FAKE_DEMO_GITHUB_0000 TEGO_CONFIG=~/tego-demo.yaml tego run <stage>/with/codex-chatgpt.filled.yaml -- codex --no-daemon`;
LEFT is the same with `SC_SINK=...:8801`, the `without` side and `tego watch --record full -- codex --no-daemon`.
`<stage>` is this folder.

## 3. The run

The times are a guide for a run of about three minutes.

| Time | Type or click | What happens |
|---|---|---|
| 0:15 | **Both** Codex: `Run this project's test suite and tell me if it's green.` | **Left:** green, and the left attacker fills (`/beacon`, `/env`, `/exfil`). **Right:** pauses, and **Approvals** shows **Tego asks you**: *Let supply-chain-codex-chatgpt read this file?* with the token's path. Click **Deny**. The tests go green and the right attacker stays empty. |
| 1:00 | RIGHT: `Read confidential/plan.md and summarize it`, then **Allow once** in the dashboard | Codex summarizes the plan. |
| 1:15 | RIGHT: `Delete README.md`, then `Run curl https://example.com` | Both are refused. |
| 1:40 | Dashboard, **Logs**: search `token` and open the right run's **Blocked** row with its line link. In **Act on this**, under **Next time**, click **Never allow**, check the change (**Narrows**, with **Also apply now** ticked) and click **Confirm: never allow**. Once the panel says *Live now on this run*, RIGHT: `Read ~/.config/telemetry/token` | The read is refused at once, with no approval card; its rule is `live.block[read:…/telemetry]`. |
| 2:10 | Dashboard, **Logs**: search `id_rsa`, then `8802`. Open the right run | `id_rsa`: the left row is **Observed**, the right row **High** **Blocked**. `8802`: **High** **Blocked**, *not on the allowed hosts*. The right run has a green *Protected* banner; the left run says **Watched only**, with a red *Secrets left* banner. |
| 2:30 (optional) | Right run page: **Pause**, type a prompt in RIGHT, then **Resume** | Codex does nothing until **Resume**, then carries on. Resume within about 20 seconds: Codex's connection to ChatGPT may time out after about 30 s of silence. Pause was tried with the stand-in agent only, never with the real Codex. |

When you finish, `/quit` both Codex windows. The runs then show **Verified · N lines**, and the Overview's **Compare** link opens the two runs side by side.

**The fallback.** If **Never allow** misbehaves at 1:40, use the right run's **Block now**: kind **Program**, value `ls`, *Time limit* left at *for the rest of this run*. Then RIGHT: `Run ls` (refused, `live.block[exec:ls]`), and **Remove**.

## 4. Proof: how to show that the left read the secrets and the right did not

1. **Dashboard, Logs.**
   - Search `id_rsa`: the `watch-codex` (left) row is the key file read, marked **Observed** (*Watched only, not
     enforced*).
   - Search `8801`: the left run's connections to the attacker, **Observed**.
   - Search `8802`: on the right, any attempt is **High** **Blocked**, *not on the allowed hosts*, with the rule *Host not in policy*.
   - Any row's line link opens its line page: what happened in words, the deciding contract line (file and line
     number), who did it (the program and its parents), every field and the line's place in the hash chain.
   - The search is one row (the text, a query and **Search**); the run, agent, kind and verdict filters, the time and
     view chips and the facets fold under **Filters**, so the rows start near the top.
   - The header counts what matches (*N lines · N blocked · N asked*). **CSV** and **Record
     (JSONL)** download what is shown; the JSONL lines are the ledger's own bytes, not masked. With one run
     picked and nothing else narrowing, the JSONL is that run's whole ledger, byte for byte (a chain anyone can
     check); a search leaves out the refusal notes unless it asks for `kind:refused`.
2. **The attacker logs and the record, in one command.**
   ```sh
   ./demo.sh proof
   ```
   It prints both attacker logs (the left has `POST /beacon`, `/env` and `/exfil`; the right says `(nothing reached
   it)`, or `(empty: nothing reached it since the last reset or backup)` when `backup` cleared it), the ledger's runs,
   then for each side only the attack's rows, with the stage folder shortened to `<stage>`, and `--verify` for both
   runs. Each side's heading names the run it picked: *RIGHT (the take's enforced run r-…: the newest with the
   token's ask)* and *LEFT (the take's watched run r-…: the newest that read the key)*, with the other runs' ids on
   the next line, so a stray later start does not hide the run. The right side after a run with the 1:40 step:
   ```
   SEQ  VERDICT           RULE                                                  DETAIL
   14   net-not-allowed   unmatched                                             net 127.0.0.1:8802
   16   net-not-allowed   unmatched                                             net 127.0.0.1:8802
   18   read-denied       fs.deny_read[<stage>/with/home/.ssh/]                 open <stage>/with/home/.ssh/id_rsa
   22   ask-denied        fs.ask_read[<stage>/with/home/.config/telemetry/]     open <stage>/with/home/.config/telemetry/token
   46   read-denied       live.block[read:<stage>/with/home/.config/telemetry]  open <stage>/with/home/.config/telemetry/token
   9 refusals in all (the rest are not the attack: Codex's own connections and any command the take refused; see the dashboard Logs)
   r-…: verified 48 lines, run_start to run_end, head …, anchored in …
   ```
   The sequence numbers and counts differ from run to run (Codex makes more connections than the stand-in did). The
   left side lists `observed  unmatched` rows: the sends to `127.0.0.1:8801` and the reads `open …/without/home/.ssh/id_rsa`
   and `…/telemetry/token`, in the order they happened. A live block from the fallback (`live.block[exec:ls]`) shows here too.
3. **Tego blocking the package itself, the same way every time.** This uses no agent, so nothing decides anything for
   you. `./demo.sh backup` runs it (the tests watched, then enforced) and denies the token ask itself; its two runs
   appear in the dashboard. You get "could NOT read your SSH key: Permission denied", the token denied, then the
   tests green. To answer the ask yourself instead, run the enforced command it prints in a terminal and **Deny**
   in Approvals.
4. **The terminal.**
   ```sh
   export TEGO_CONFIG=~/tego-demo.yaml
   tego status --all                         # run ids
   tego events <run-id> --kind refused       # what Tego refused, one row per refusal
   tego events <run-id> --verify             # the record is untampered
   tego receipt <run-id> --verify            # what the agent did, on one screen, and the chain checked
   ```
   The RULE column names the contract entry that decided; `unmatched` means no entry allowed it, so the default deny
   refused it. The TIME column is in your own time zone (its header names it, e.g. `TIME (EDT)`); `--json` keeps UTC.
   `tego status` shows a paused run as `paused`.
   The dashboard's **Receipt** tab on the run shows the same receipt (files written, refusals by rule, the asks and
   your answers, tokens, what the ledger could not cover).

## 5. Things to know before you run it

- **Answer an approval within about 30 seconds.** Codex gives up on a command that waits much longer. After 30 s
  the card and the banner say *Codex has likely given up; Tego refuses it at 5 m*: the ask itself times out after
  5 minutes (`ask.timeout`), and then shows under *Answered recently* as **Timed out**.
- **An ask that arrives while you are on another page** shows as a banner floating under the top bar (the page does
  not move) and as the count on **Approvals**; on Approvals itself, and on the run's own page, the card shows instead.
- **The token approval appears on the first test run of a fresh session.** To run it again, quit both Codex windows
  and run `./demo.sh reset`, then `./demo.sh check` (section 6).
- **Block now has a time limit** (*Time limit*: *for the rest of this run*, the default, 2 minutes to 1 week, *for…* a
  typed duration such as `3m`, or *until…* a time). Leave the default in the run; a timed block that ends shows *Ended at …* and *Its time limit has passed:
  it refuses nothing now.*
- **A "Never allow" during a run changes the filled contract.** It turns the token's ask into a refusal, so the next
  run would never show the 0:15 question. `check` catches it (`the contract was changed`) and `reset` fills the
  contract again from the template; `right` refuses to start on the changed contract until you reset
  (`DEMO_FORCE=1 ./demo.sh right` starts it anyway). **Also apply now** adds a live read block to the running RIGHT run only; it ends
  with that run.
- **Rebuild both binaries together** (`make build`) after any update, then restart the dashboard and start both
  sides again: a run started by an older `tego` cannot take a read block or a pause (the dashboard then offers a path
  block instead of Never allow's live read block, and no Pause button). `check` reports a stale `bin/tego` or
  `bin/tego-control`, but not a dashboard still running an older binary.
- **Codex sometimes inspects the dependency first.** It may then run the tests with the package's paths pointed at
  `/dev/null`. In that run the package never tries anything on the right, so there is nothing for Tego to refuse.
  The run page then says no attack attempt was seen; compare with the `backup` run instead, which always has one.
- **A desktop notice is not a replacement for the dashboard.** It says that an ask waits and for which run; answer in
  **Approvals** (or `tego approve <run> <ask_id>` from a fifth terminal). Over SSH, or with no `notify-send`, only the
  answer line printed before Codex started tells you. Nothing is ever written into Codex's screen.
- **Ctrl-Z in a Codex window** stops it like any program; in an agent that stops only itself (Claude Code) it also stops
  `tego run`, the shell prints `Stopped`, and `fg` resumes the agent with its screen. Do not use it during a demo.
- **A refusal named `deny-read-snapshot`** (`tego events <run> --rule deny-read-snapshot`) is a file made beside a
  protected one after the run started: unreadable for the rest of the run, by design. If it shows in a run, it is not
  the attack; restart the run to list the directories anew.
- **The right run shows hundreds of refusals that have nothing to do with the attack.** They are Codex's own
  background connections to ChatGPT's other servers (port 65535 and other Cloudflare addresses). Use the Logs search,
  not the raw timeline.
- **The contract pins `tier: landlock`** because asking before a read (`fs.ask_read`) is a tier-landlock feature.
- **The config.toml turns off Codex's extra fetches** (`[tui] show_tooltips`, and the `plugins`, `apps`,
  `remote_plugin` and `image_generation` features), so "Outbound refused" stays about the attack. If a run still
  shows `raw.githubusercontent.com:443` or `files.oaiusercontent.com:443` refused, they are harmless: the honest job
  needs only ChatGPT. Do not add them to `net.allow`.
- **`held/` and `confidential/` ask only because they are outside the writable folders.** The writable folders are
  `src/`, `tests/`, `vendor/` and `tmp/`. Creating a folder under `held/` is refused, not asked: use "write a note
  into held/x.md".
- **Do not `git pull` in the setup.** It asks for a GitHub login, and everything needed is already in the checkout.
- **The red "Failed to paste image: clipboard" line in Codex is harmless.** Type your prompts instead of pasting.
- **Laptop checks.** `check` covers these, but they are the usual causes of a run that starts wrong: a home folder
  that is group-writable (tego then skips the config and the dashboard shows another ledger); no `watch`,
  `notify-send` or user systemd bus (over SSH, `systemctl --user` needs `XDG_RUNTIME_DIR=/run/user/$(id -u)`);
  `chatgpt.com` resolving to a short Cloudflare list with a one-minute TTL (the contract resolves it when the run
  starts, so start RIGHT soon after `check`).

## 6. Reset

**Running it again** (after quitting both Codex windows with `/quit`; the dashboard can stay up):

```sh
./demo.sh reset      # fresh fake homes and project copies, the contract filled again, a new ledger, the servers restarted
./demo.sh check      # READY again, including the token ask and "the demo's dashboard is running"
```
`reset` (and `reset --stop`) refuses while a run of the demo still runs and names each one (`still running: <run>
(<agent>, <state>)`): quit both Codex windows and run it again; `DEMO_FORCE=1 ./demo.sh reset` resets anyway, and the
old runs then keep writing into the moved ledger.
Reload the dashboard page: it now shows the new, empty ledger (*0 runs in this ledger*). If you did stop and
restart the dashboard (`./demo.sh dashboard`), open the new link it prints: an old tab says *Signed out: open the
link from your terminal*, and a reload shows the *Sign in · Tego* page; nothing else breaks.
Each side keeps its Codex login. The old ledger is moved to `~/tego-demo-ledger.old-<time>.<random>` (with its
`.rule-changes` journal), and only the newest three are kept; older ones are deleted. `reset` deletes only the
folders it moved there, each marked by a `.moved-by-demo-sh` file that names it: a folder of that name you made or
copied is never deleted, and neither is one an older `demo.sh` moved (it has no mark), so delete those by hand.
The destination is reserved with `mktemp` before moving, so an existing folder
with the same timestamp is never adopted or marked for pruning.
Newlines in generated-state paths or old-ledger candidate names are refused:
the prune list cannot safely carry those names. Choose another path or move
the ambiguous old candidate aside manually.

Setup writes `.tego-supply-chain-stage` and `.tego-supply-chain-ledger`, each
naming its physical directory. Reset requires both before stopping units,
deleting sides or rotating the ledger. Setup claims only absent reserved stage
children and a new or empty ledger; lookalike `proj/` and agent-home folders do
not establish ownership. A new ledger holds only its marker until the first run.
Old unmarked state is refused: move it aside manually or choose fresh paths and
run setup. The stage container and unrelated siblings are retained.

Every printed command, including both backup sides and quiet mode, masks
`CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` assignments as `...`. Execution
still receives the login. Marker checks are operator safeguards, not protection
against a concurrent same-user path replacement; see the
[script spec](../../docs/p0/demo-scripts.md).

**The end of the demo:**
```sh
./demo.sh reset --stop   # stops the three units, removes the generated state, moves the ledger
```
This stops only the three units `demo.sh` names (never another `tego-sc-*` unit, never your own), and removes only the
generated state, all of it gitignored. Your real `~/.ssh`, `~/.codex` and `~/.tego` are never touched.
