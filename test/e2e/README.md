# Kill tests (P0-DESIGN §10, §12)

| Script | Kill test | Halves and what each needs |
|---|---|---|
| `kt1-identity.sh` | two concurrent runs that meet while both are live, 100% attribution, no cross-run leakage | `$KT_TIER` (default landlock); root under sudo for cgroup |
| `kt2-capture.sh` | R8: forwarder half (20 model calls through the forwarder, each an `ssl_request source=forwarder` with a parsed response; a direct connect to the model host refused) and uprobe half (19 of 20 pairs read from the system libssl with parsed responses, every miss explained by a gap) | forwarder: python3 and openssl, any tier; uprobe: root under sudo for tier cgroup |
| `kt3-overhead.sh` | overhead per record mode against §9's budgets | tiers landlock and observe; cgroup as root under sudo; go, or `--tego` and `--workload-bin`; npm+node; a quiet machine |
| `kt4-ordinary.sh` | R18: `pip install` + `pytest`, `npm install` and `go build`, each under a contract extending `examples/profiles/base/python-dev`, 19 of 20 runs unbroken per kind and tier | pip: `test/e2e/pydeps.sh`'s cache; npm+node; go; tiers landlock, and cgroup as root under sudo |
| `kt5-ask.sh` | R7: what an untouched `fs.ask` and `net.ask` entry costs, in every tier: the 20-step agent (kill test 2's, through the forwarder) and the pip build (kill test 4's), each run under one contract with and without the two entries (the two contracts differ in those two lines and nothing else), `KT5_RUNS` (10) pairs in alternating order after one run of each that is not counted; a cell passes when the median wall time under the ask contract is under the base contract's by less than 1% of it or 1 s, the larger, and a miss is a FAIL printed as `TARGET-MISS` with the figure; each cell reports `run_end.supervisor{notifications, held_ms}` for both contracts and fails when the ask contract's run touched an entry, the supervisor saw nothing of it, or `run_start`'s `capabilities.ask` is not true for the contract that declared the entries and false for the other | agent20: python3 and openssl; pip: `test/e2e/pydeps.sh`'s cache; tier landlock, and cgroup (a cell per decision plane that decided the run, named in the cell) and bpflsm as root under sudo; `KT5_TIERS`, `KT5_KINDS`, `KT5_RECORDS`, and `KT5_PLANES` (pins tier cgroup's plane through `TEGO_TEST_PLANE`, which only a `-tags tegotesthooks` binary honours: an unmet pin is a named skip) |
| `kt6-fresh-vm.sh` | R16 in three halves: (a) one static binary, doctor at landlock, R3 (kill test 1) and R4 (EACCES, `PermissionError`, a reason); (b) doctor at cgroup and R5 host-level deny; (c) the printed `lsm=` line activates bpf, then tier bpflsm and R5 with the in-kernel reason (the breadcrumb, read as in (b); PASS only when it holds) | (a) any user (as root under sudo it becomes the user); (b) root under sudo; (c) root under sudo and `bpf` in the active LSM list |
| `kt7-two-agents.sh` | (a) the Claude Agent SDK (Python) through the forwarder under `examples/agents/claude-agent-sdk.yaml`, its task done, every model request `source=forwarder`, a direct connect to the model host refused; part `a-cli`, `claude -p` under `examples/agents/claude-code.yaml` (§12.3), its task done and a write outside the contract refused; part `a-gap`, FEATURES' gap line, a named skip until tego prints it; (b) a system-Python agent on the Anthropic SDK through uprobes under `examples/agents/anthropic-sdk-python.yaml`, completing a task with one refusal | (a) tier landlock, any user (as root under sudo it becomes the user), and `test/e2e/pydeps.sh --claude-sdk`'s cache, whose wheel bundles Claude Code; no API key; (b) root under sudo and `test/e2e/pydeps.sh`'s cache |
| `smoke-exec-rules.sh` | not a kill test: the kernel matrix's exec command-rule cell (ADR 0048 C6). Under `exec.deny: [rm -r, git push]` the denied commands are refused at execve in three spellings and `rm -f` runs; under `exec.allow: [/bin/sh, rm -f, git status]` the unlisted `rm -r` and `git push` are refused | `$KT_TIER` (default landlock); root under sudo for cgroup; the git half runs only where git is installed |
| `kt-pause-orphan.sh` | launcher-death check: ADR 0124's second 2026-11-11 amendment (GAPS C42). A run is paused and resumed with its launcher alive, paused again, and its launcher SIGKILLed: its sampled beat files and surviving child CPU time stay unchanged across launcher death, `tego status` and `tego resume` say it is lost while paused (landlock) or reaped orphaned (root tiers), `tego stop` ends the frozen tree at landlock, and the record ends `launcher-lost`, `run_end orphaned` and verifies | `$KT_TIER` (default landlock); root under sudo for cgroup or bpflsm |
| `reason-claude/` | not a kill test: `fakeclaude`, a stand-in Claude Code (Go, standard library only) for tests of anything beside the harness. It reads `--settings` as Claude Code 2.1.310 does, performs a script's tool calls as real syscalls, calls the configured hooks in exec form with the documented payloads, and posts each next request, with the tool results and the hooks' text, to the model stub (`--log-content`); `report.py` asserts on the stub's log. It models no model, permission prompt or MCP; `README.md` there says what is and is not modeled, and that the end-to-end run holds the real binary to the same `golden/shape*.json` | go and python3; any user |

Every script sources `lib.sh` and returns one of three exit codes: `0` pass, `1` fail, `77` skip (a
named reason on stderr — never a silent pass when the guarantee could not be exercised here). A script
with halves prints one `KT-HALF <test> <half> <PASS|FAIL|SKIP> <reason>` line per half; its exit is 0
only when every half that ran passed, and a half that could not run is a named skip, never a pass. A jq
that cannot answer a trivial query skips every script that reads the ledger, before any check, since each
check counts ledger lines with it. Every `tego run` a script starts is bounded by `KT_RUN_TIMEOUT` seconds
(default 300; kill test 4 uses ten times its baseline plus a minute, and kill test 5 ten times the first run of a
cell plus a minute), so a launcher that hangs is a failure
with its own line, not a wait. At the bound `timeout(1)` sends `SIGTERM`, and ten seconds later `kt_run`
sends `SIGKILL` to the bound's process group itself, since uutils' `timeout` never sends the one its `-k`
asks for and would wait on a launcher that ignores `SIGTERM`; `lib_test.sh` checks both, with whichever
`timeout` is on `PATH`. uutils' `timeout` also notices its command's exit only on a 100 ms poll, so where the
host's `timeout` is uutils' (Ubuntu 25.10's), and so in that host's kernel-matrix guests, a run timed around
the bound is up to 100 ms longer than it was. Kill tests 4 and 5 therefore time each run from a shell inside the
bound that waits for the command itself, and kill test 4's baseline runs with the same shell; `kt4_test.sh` and
`kt5_test.sh` check that a bound's late return is not in the times R18 and R7 judge, run as a user or as root under
sudo.

The model traffic comes from `test/workloads/model-stub`, a local HTTPS stand-in for the Messages API
that the run trusts through `SSL_CERT_FILE`: no key, no spend, no dependency on the vendor's uptime. Claude
Code answers from it as it would from the vendor, given a dummy `ANTHROPIC_API_KEY`.

`test/vm/matrix.sh` (`make vm-matrix`) runs kill tests 1, 2, 4, 5, 6 and 7 on every kernel-matrix row, as
root in a KVM guest booted from the row's own kernel, with the user and root halves each run as the
identity they need (`test/vm/README.md`). On a host, run a script as yourself for the user
halves and with `sudo` for the root ones. `KT_FIXTURE_DIR=<dir>` makes each script save the ledger of
every run it judges under `<dir>/<test>-<half>-<tier>/`; `test/fixtures/ledger` holds one such set. A ledger
that names the invoking account anywhere is not saved, so record with `TMPDIR=/tmp` when your usual `TMPDIR`
is derived from your home.

Results are not recorded in this folder: an acceptance run is recorded as one
entry per P0 acceptance item (§12), each marked pass, fail, or not-runnable-here with the reason
actually observed.
