# A custom agent under tego: unattended, in compressed time, and for hours

Tego governs an agent it knows nothing about: Claude Code and Codex are two examples, a script you wrote is another.
This directory is the proof for the one you wrote. It has a custom agent (a coding-bot work loop), a second agent that
goes wrong in six ways, and the harness that holds each to a contract, lets it run with nobody there, and reads the
ledger back to check what happened. Nothing here is a
real model: the "model" is the stand-in `test/workloads/model-stub/server.py`, and the only network is 127.0.0.1.

```
test/poc/custom-agent/run.sh              # scenarios i, a-h, j-m: about 6 minutes, no root
test/poc/custom-agent/run.sh negative     # each scenario again with one rule or limit removed: its check must FAIL
NEG_ONLY="no-cost_usd no-forwarder" test/poc/custom-agent/run.sh negative   # only those controls
TEGO_BIN=<tego> SOAK_DIR=<dir> test/poc/custom-agent/soak.sh start full       # a 2-hour soak, sampled every minute
```

It needs `go` (or `TEGO_BIN=<tego built with -tags tegotesthooks>`), `python3`, `openssl`, `bash`, and a Linux with
Landlock and a cgroup v2 delegated to your user (`tego doctor` says; tier `landlock` is the highest tier a non-root
user gets). Everything happens under `$DEMO_ROOT` (a temporary directory by default): its own machine config, ledger,
price table, chain anchor and log, redirected by the `tegotesthooks` build, so the real `~/.tego` is never read or
written (`run.sh` lists it before and after).

## The pieces

| File | What it is |
|---|---|
| `agent.py` | The custom agent, standard library only. Each step it asks the model what to do next (a `POST /v1/messages` to `$ANTHROPIC_BASE_URL`), then does it: reads the source tree, edits a file (write a temporary file, rename it over the original), runs the test script (a program of its own, `bash tests/run_tests.sh`), appends to a notes file; it sleeps a little and goes on, task after task. Every `--bad-every` steps it also does one thing a contract should stop, cycling through `--bad`: read a fake credential, run a stand-in `git push`, connect to a port nobody allowed, write outside its workspace, write into an `fs.ask` directory. A refusal (`EACCES`, `EPERM`) is counted, reported to the model as the tool's result, and the loop goes on. |
| `runaway.py` | The second agent, one misbehaviour per mode, each bounded by a cap of its own: `loop` (the same tool call forever), `hang` (silent), `read` (busy, but only reading), `memhog` (to 96 MiB), `forkbomb` (a stand-in: children that only sleep, to 60), `cpu` (a busy loop); and two probes, `flood` (what recording an open costs) and `direct` (a connection round the forwarder). Without the limit that should stop it, a misbehaviour ends by itself and prints `NOT STOPPED`. |
| `model_script.py` | What the stand-in model says: one coding task of nine steps, or the same tool call sixty times. |
| `contract.yaml` | The contract, as a template; every entry says what it is for. `examples/agents/custom-agent.yaml` is the same contract with the values of a real night. |
| `verdicts.yaml` | The contract's own test: `tego compile <contract> --test verdicts.yaml`, eight hypothetical actions and the verdict each must get; nothing runs. |
| `lib.sh`, `run.sh`, `report.py` | The harness. `report.py` reads a run's ledger and the stand-in's own request log; every claim of a scenario is a `PASS`/`FAIL` line against ledger events, and trusts nothing the agent printed. |
| `soak.sh`, `soak_sample.py`, `soak_analyze.py` | The soak: an unattended run for hours, sampled every minute into a CSV, then analysed and extrapolated to 20 hours. |
| `project/` | The toy project the agent maintains (`run_tests.sh`) and the harmless stand-in `git`. |

## Putting YOUR agent under tego: the checklist

`run.sh i` does every step on this agent and prints what each shows.

1. **Find what it needs: run it with no boundary.** `tego watch -- <your agent and its arguments>`. It only records,
   in a scratch copy of the project with no credential in reach: a record-only run is not a cage, and the agent can do
   everything you can. Read it with `tego status|events|drift <run>`. Default `record: full` (reads included) is what
   you want here.
2. **Let tego draft the boundary: `tego learn <run> --out ../contract/agent.yaml`.** It proposes `fs.write` (the
   directories under the workspace the run wrote to), `exec.allow` (the programs it started), `net.allow` (the
   endpoints it connected to) and suggested limits, deterministically, with no model. **It allows what the run did,
   and no more, and the run may have done what you do not want**: on this agent, the proposal allowed the `git push`
   and the connection to the port nobody should reach, because the record-only run did both (scenario i).
   It never touches `fs.deny_read` beyond the built-in list, and it knows nothing of models, limits, `ask` or
   `record`.
3. **Trim and complete it.** Delete every entry you did not mean to grant. Add what only you know:
   - `fs.deny_read`: the secrets in reach, beside the built-in list (`~/.ssh`, `~/.gnupg`, the browsers' profiles);
   - `models:` and `capture: forwarder`, and remove the model host from `net.allow`: the forwarder is how tego counts
     what the run spends and sees what the model asks for. Your agent must honour `ANTHROPIC_BASE_URL` (or the
     provider's own variable): a connection straight to a declared model host is refused even when `net.allow` names
     it (f4), so the agent has to use the forwarder, where it is counted;
   - `limits:` (below), `ask.timeout`, `record`, and `env.pass`, so that no credential you did not mean reaches it.
4. **Test it before it runs.** `tego compile agent.yaml` from the workspace: read every warning. A
   `[budget-unmetered]` warning about a limit means nothing can count it (no `models:` entry, no price table for
   `cost_usd`), and every run of the contract is refused, exit 125 (f3); a
   `[path-missing]` error in a proposal is a PATH-search miss `learn` listed as a program (it varies from run to run:
   delete the line). Then `tego compile agent.yaml --test verdicts.yaml`: one row per action the boundary must refuse
   or allow, and `exit 1` when one is wrong. Run the table against the proposal too: three of its eight rows fail,
   which is the point.
5. **Run it attended once.** `tego watch --boundary agent.yaml -- <agent>`, with a second terminal for `tego ask`,
   `tego approve` and `tego deny`. Look at `tego drift <run>`: what it was refused (an agent that does not tolerate
   a refusal shows here), what was declared and never used, and the `gaps:` line of `tego status` (a
   `budget-unmetered` gap means a limit a machine ceiling sets counted nothing; one the contract declares is refused).
6. **Then leave it.** The section "Unattended runs: what to put in the contract" of `docs/OPERATIONS.md`; in the morning, `tego
   status <run>`, `tego events <run> --last` and `tego drift <run>`.

## What each scenario shows

| | What the agent does | What the contract does | The check, against the ledger |
|---|---|---|---|
| i | the checklist above, on this agent | `tego learn` drafts it, `compile --test` tests it | the proposal allows what the record-only run did, so three of four forbidden actions happen again under it |
| a | works for 20 s and tries four forbidden things every fourth step | refuses each, with the rule; `repeats: 8` and `stall_after` never fire on a healthy loop | every refusal carries its reason and rule, no forbidden action was allowed, the model's calls are all recorded and match the stand-in's own count |
| h | (after a) | | what `tego status`, `events`, `measure`, `drift` and `--verify` each show |
| b | writes to `held/` with nobody to answer | `fs.ask` with `ask.timeout: 3s` | each try is held 3 s, then refused `ask-timeout`; the next try is held again; the agent goes on |
| c | writes to two files in `held/`, over and over | a person runs `approve --always` on one and `deny --always` on the other, once each | 2 human answers; every repeat answered at once by `standing:<ask id>`, each its own ask and answer |
| d | would run 20 s | `limits.wall: 12s` | `limit` event `wall`, `run_end reason=limit`, exit 124 |
| e1 | the model asks for the same tool call again and again | `limits.repeats: 6` | stopped at the sixth identical decision |
| e2 | works, then blocks forever | `limits.stall_after: 5s` | stopped 5.5 s after its last event |
| e3 | busy, but only reading | `stall_after: 5s` under `record: summary` and `full` | under summary it is ended as stalled (its reads are not events); under full it is not |
| f1, f2 | spends tokens | `limits.tokens: 300`, `limits.cost_usd: 0.002` | the limit's value equals the sum of the ledger's own `ssl_response` usage, priced for cost |
| f3 | a tokens budget on an agent with no `models:` entry | `limits.tokens: 300`, nothing to count | refused before it starts: `compile` warns `[budget-unmetered]`, the run exits 125 `[budget-unmetered]` with the `models:` fix and leaves no run |
| f4 | connects straight to the model's own address | `models:` declared, and `net.allow` names the same address | refused by `models[127.0.0.1:<port>]`: the forwarder guard beats the allow entry, so a budgeted agent cannot go round its meter |
| g1, g2, g3 | a memory hog, a fork stand-in, a busy loop | `limits.memory: 40MiB`, `limits.pids: 16`, `limits.cpu: 0.25` | the kernel kills at 40 MiB (`oom`, 137); a refused fork ends the run (`pids`, 137); the loop is throttled to a quarter of a core |
| j, k, l | | a full ledger, a model outage, the launcher killed | the run is stopped, not left unrecorded; the retries keep it alive; the agent dies with its launcher and `tego gc` ends the run `orphaned` |
| m | opens one file 20000 times | unconfined, then `record: summary`, then `full` | an open costs about 6 us unconfined, 1 us more under summary, 50 to 75 us more under full (the busier the box, the more); every open recorded, no gap, also at 200000 (`FLOOD_COUNT=200000`) |

Seconds stand for hours: `wall: 12s` here is `wall: 20h` in `examples/agents/custom-agent.yaml`. The watcher checks a
monotonic clock once a second, whatever the value, so what the scenarios show about *how* a limit ends a run does not
depend on its size; that it holds for 20 real hours is what the soak is for.

## The soak: hours, not seconds

`soak.sh` runs the agent unattended for hours, as a transient user service (`systemd-run --user`; under `nohup` where
there is none, or with `SOAK_NOHUP=1`), so that it outlives the shell that started it, and a sampler writes one row a
minute to `$SOAK_DIR/<arm>/samples.csv`: tego's and the agent's resident memory, cpu and open descriptors, the run's
cgroup, the ledger's size and its events by kind (counted as they are appended, so a restarted sampler carries on). An
arm is a record level with an optional label; each has its own tego (machine config, ledger, chain anchor, log),
workspace and stand-in model, so arms run side by side.

```
export TEGO_BIN=<tego built with -tags tegotesthooks> SOAK_DIR=<a directory with room: about 150 MB an hour under full>
test/poc/custom-agent/soak.sh start full 7200            # record: full, two hours
test/poc/custom-agent/soak.sh start summary 7200         # record: summary, side by side
SOAK_AGENT_ARGS="--sleep 0 --read-files 40 --bad-every 400 --bad cred,push,connect,outside,ask-a" \
  SOAK_TOKENS=1000000000 SOAK_COST_USD=100000 test/poc/custom-agent/soak.sh start full-fast 3600   # 12 times the events
test/poc/custom-agent/soak.sh status                     # state, segments, the last sample
test/poc/custom-agent/soak.sh analyze                    # the CSV's trends and the 20-hour extrapolation
test/poc/custom-agent/soak.sh resume full                # after a stop, a kill or a reboot: a new run, a new segment
test/poc/custom-agent/soak.sh selftest                   # a one-minute arm, stopped half way and resumed, checked
```

The contract an arm carries is the real one: every limit set far above a healthy night (`wall`, `stall_after: 5m`,
`repeats: 8`, `tokens`, `cost_usd`, `memory`, `pids`, `cpu`), so that the soak also shows that none of them raises a
false alarm over hours; the agent does a forbidden thing every 40 steps (one in five of them an `fs.ask` write that
nobody answers, held 5 s). At the end of a segment the script re-reads the whole ledger and times `status`, `measure`,
`drift`, `events --last`, `events --kind refused` and `events --verify` on it (`segment-N.verify`).

## Reading the log afterwards (scenario h)

`tego status <run>` is the one-line answer: state (`done`, `lost` when the launcher died, `waiting approval`), how
long idle, model steps, events, how it ended (`exit (0)`, `limit (124)`, `oom (137)`), then `gaps:` (what the record
could not capture; `budget-unmetered` means a limit a machine ceiling sets counted nothing) and the run's own resource peaks. `tego events
<run>` is the full record, one line per event, with `--kind`, `--rule`, `--verdict`, `--source`, `--step` and `--last`
to slice it (the last refusal, gap or limit); `--json` prints the stored lines byte for byte, and the file itself is
`<ledger_root>/<run>/events.jsonl`. `tego drift <run>` sets the contract against what happened, per rule: allowed,
asked, refused, observed, and the entries that were declared and never used. `tego measure <run>` is the budget's
view: model steps, refusals, tokens, estimated cost (`est.`, to the cent), wall time, peaks. `tego events <run>
--verify` re-reads the whole hash chain and checks it against the anchor kept outside the ledger. Counting what the
agent did needs care: a program started by name is one event per directory of `PATH` the agent's own search tried, so
a refused `git push` is one refusal per directory (133 for 7 pushes in scenario a) and `exec[bash]` shows 25 allowed
and 300 observed for 25 spawns; count actions from the agent's own log and the `decision` events, and refusals by
`tego events --kind refused` and the reasons.

## Which limits are enforced where

| Limit | What enforces it | At tier 1 (no root) | Needs |
|---|---|---|---|
| `wall` | the budget watcher, a monotonic clock, once a second; then `cgroup.kill` | yes (d) | nothing |
| `stall_after` | the same watcher: no event for that long. A held ask, and a model response that is streaming, count as activity | yes (e2, e3) | events: `record: full` for an agent that reads without writing |
| `repeats` | the watcher, over the `decision` events the model's own replies produce | yes (e1) | model traffic captured: `models:` and `capture: forwarder` |
| `tokens` | the watcher, over the `usage` of every `ssl_response` (input plus output; cache tokens do not count) | yes (f1) | the same |
| `cost_usd` | the same, priced by the machine config's price table (`prices:`); a model the table does not name counts at the dearest price it has | yes (f2) | the same, and the price table |
| `memory` | the run's cgroup, `memory.max`: the kernel kills inside it | yes (g1) | cgroup v2 delegated to the user, with the `memory` controller |
| `pids` | the run's cgroup, `pids.max`: a refused fork ends the run, reason `pids` | yes (g2) | the same, `pids` |
| `cpu` | the run's cgroup, `cpu.max`: throttles, never kills | yes (g3) | the same, `cpu` |

Every run, tier 1 included, lives in a delegated user cgroup (`tego doctor`: `cgroupv2: ... delegated, ...
controllers: cpu memory pids`; docs/p0/limits-check-doctor-cli.md says tier `landlock` needs it "because every run is
created in the delegated cgroup it checks and is stopped through that cgroup's `cgroup.kill`"). So the three resource
limits do not need root. Where the controller is not delegated the run is refused, naming it
(docs/p0/runtime-launch.md case 31; not reproducible here). What a root tier adds is not another limit but another way
to count: `capture: uprobe` reads the model traffic of an agent that speaks TLS straight to its provider on the system
OpenSSL, which tier 1 cannot, so `tokens`, `cost_usd` and `repeats` there need an agent that can be pointed at the
forwarder (documented; no root tier was run here: this box has no BPF LSM at boot and the run was unprivileged).

## What this does not show

- A real model, a real provider, or a real agent: the model is a script and the agent is a stand-in. What it exercises
  is tego's side of an unattended run, which does not look inside either.
- Twenty hours. The soak is two hours; its numbers are extrapolated, not measured.
- A root tier, KVM, Windows, macOS, containers. Tier `landlock` only: the tier a user without sudo gets, and the one a
  rootless agent on a laptop would run at.
- Anything about stopping a hostile agent: this agent cooperates, in the sense that it does what its script says and
  treats a refusal as a result. Tego's guarantees against one that does not are in the security documents, not here.
