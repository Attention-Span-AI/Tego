<!-- SPDX-License-Identifier: Apache-2.0 -->
# Supply-chain demo — real agent, poisoned package, split screen

> **To run it, follow [RUNBOOK.md](RUNBOOK.md).** It drives everything through one script,
> `./demo.sh setup | check | dashboard | left | right | attacker | backup | proof | reset`, and holds the
> steps and what to watch for. This page is the overview; the commands live in the
> script and the RUNBOOK, so the two cannot drift apart. The script's settings (ports, unit names, dashboard
> address, ledger) are in `demo.env`.

A known kind of attack, reproduced: a poisoned dependency that reads your SSH key, your API token and every
credential-looking environment variable, and sends them out when the project's tests import it. The package here,
`repo/vendor/telemetry-helper`, is a defanged stand-in written for this demo. You run a real coding agent (**Codex**) on an ordinary project and say *"run the tests."* Side
by side: the **left** Codex under `tego watch` (recorded, nothing blocked) and the **same Codex under `tego run`**
on the right. Same project, same package, same prompt; only the behavior differs. The agent is never told to do
anything bad, and the attack is ordinary Python that fires on import, as a real one does.

Any other agent works the same way; this demo uses Codex because it is common.

## Safety on your own laptop

The demo **never touches your real `~/.ssh`, `~/.config` or `~/.codex`.** Each side gets its own fake home inside
the demo (`without/home`, `with/home`) holding obviously fake credentials, and its terminal points `HOME` at it, so
the package still reads "`~/.ssh/id_rsa`" but finds the demo's fake file. Setup only copies your Codex login into
each side's own `codex-home`. The two terminals start through `env -i` with only the demo's fake variables, and the
poisoned dependency sweeps and names only variables whose value says FAKE or DEMO, so no variable of your own shell
is read, named or sent. The "attacker" is a loopback sink on `127.0.0.1` that never stores what it receives.

## The project, honestly

The tests legitimately need **one** secret, `SERVICE_TOKEN`, to call the project's own API on `127.0.0.1:8803`.
Your shell also holds secrets this job does not need (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`). The demo answers:
*how do you give an agent the one credential its job needs, and nothing else?*

## What the right side's contract says

`contracts/codex-chatgpt.yaml` is a template; `demo.sh setup` fills its placeholders (the folders, the Codex host,
python3 and the project API's address) into `with/codex-chatgpt.filled.yaml`, and `demo.sh reset` fills it again,
so a "Never allow" made during one take cannot change the next (`demo.sh right` refuses to start on a changed contract
until you reset).

- **`fs.write`:** only `src/`, `tests/`, `vendor/` and `tmp/`, the pty devices and Codex's own home. Nothing else.
- **`fs.deny_read`:** the fake SSH key, by exact path. Never readable, no question asked.
- **`fs.ask_read`:** the API token and `confidential/`. A person decides each read in the dashboard's Approvals.
- **`fs.ask`:** `held/`. A file written there waits for a person (Allow once, Deny, or for this run under More choices). `held/` and
  `confidential/` ask only because they sit outside the writable folders.
- **`net.allow`:** the project's API (`127.0.0.1:8803`), `chatgpt.com:443` and `auth.openai.com:443`. The attacker
  sink (`127.0.0.1:8802`) is on no line. Codex's optional fetches (announcements, plugins) are switched off in the
  setup's `config.toml`; any that remain stay refused rather than allowed.
- **`env.pass`:** `SERVICE_TOKEN` and the machinery the agent needs. `AWS_SECRET_ACCESS_KEY` and `GITHUB_TOKEN`
  are never passed.
- **`tier: landlock`:** pinned because `fs.ask_read` is a tier-landlock feature.

## With Claude Code instead of Codex

Set `DEMO_AGENT=claude` for every subcommand. Both sides then run Claude Code under
`contracts/claude-code.yaml`, which has the same rules for the project, Claude Code's own host
(`api.anthropic.com`) and its own folder in each side (`claude-home`, with onboarding and permission prompts off:
tego is the cage). Claude Code's login comes from your shell, never from a file in the demo:

```sh
claude setup-token                          # once: your Pro/Max subscription as a token
export CLAUDE_CODE_OAUTH_TOKEN=<the token>  # or ANTHROPIC_API_KEY, in each terminal that runs left or right
export DEMO_AGENT=claude
./demo.sh setup && ./demo.sh check
```

`left` and `right` pass the login to the agent and print it as `CLAUDE_CODE_OAUTH_TOKEN=...`. In a terminal that
came in over SSH (a VM), start a shell in your user's cgroup first, or tego has no tier: `systemd-run --user --scope bash`.

## What each side shows

- **Left (watched):** the tests pass **and** the attack rides in on the import. The left sink log fills with
  `/beacon`, `/env` and `/exfil`; the dashboard shows the key read and the sends as *Observed*. Codex says "all
  green." Nobody noticed the key and every shell secret leave.
- **Right (enforced):** the tests **still pass**. The token read waits for a person and is denied; the key is
  *Secret, never readable*; the env sweep finds only `SERVICE_TOKEN` and cannot send even that. The right sink
  stays silent.

## What the person sees while it runs

Before Codex starts, `tego run` prints one line with the run id and the commands that answer an ask (`tego ask`,
`tego approve`, or the dashboard's Approvals page); a held request also raises a desktop notice at tier landlock
where a root-owned `notify-send` exists; on AppArmor a one-line `[held-label]` note comes first. `tego run` is
otherwise quiet (`-v` adds the compile notes). The left side's `tego watch` prints a four-line banner (nothing is
blocked) before Codex's screen. When either side ends, its terminal's last lines summarise the run and say whether
its chain verified. The dashboard is
`./demo.sh dashboard` (`tego-control serve --open`), with an Auto / Light / Dark switch, and labels each run by how
it was started (Interactive here). From a refused line, **Never allow** with **Also apply now** writes the refusal
into the contract for every later run and puts a live block on the running one at once; the run page also has
**Block now**, **Pause** and **Resume**, and every Logs row opens a page that explains its line. On every page green
means Tego stopped it and red means it got through: the watched run carries a red *Secrets left: id_rsa, token sent
to 127.0.0.1:8801*, the enforced one a green *Protected: …*, and Compare opens on the two side by side. The watched run's **Make a policy** link (the run header) proposes a policy that
leaves the leak's destination out (`# NOT allowed`, under a red notice): a contract learned from a leaking run never
allows where the secrets went. A read refused because a file was made beside a protected one after the run started is named
`deny-read-snapshot` in the ledger. RUNBOOK.md has the commands and the cautions.

## The proofs

The RUNBOOK's section 4 shows them: the dashboard **Logs** (search `id_rsa`, `8801`, `8802`), `./demo.sh proof` (the
two sink logs, each side's attack rows with the rule that decided, and the verified record), `./demo.sh backup` (a no-agent run of the tests, watched and enforced, the
same result every time), and `tego events <run> --verify` (the record is a hash chain; edit one word and it fails).

## What this demo does not show

`env.mask` is not built: `tego compile` refuses it, so `env.pass` gives the agent the real `SERVICE_TOKEN`, and
Approvals / `fs.ask` is the live lever.

## Reset

RUNBOOK section 6: after both Codex windows quit (`reset` refuses while a run of the demo still runs), `./demo.sh reset` is a retake (fresh sides, the contract filled again, a new ledger; the old
ones are kept, newest three; the dashboard can stay up and follows the new ledger); `./demo.sh reset --stop` also stops the three user services and removes the generated
state (`without/`, `with/`, `api.log`, all gitignored). Your real files are untouched.

## The one takeaway

> Same project, same package, same prompt. Watched, your key is gone and the agent said "all green." Under tego,
> the tests still pass and the attack got nothing, because the job never needed your key, so the key was never
> readable.
