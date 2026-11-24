# Run teardown status version 1

`pkg/spec/runstatus` owns the strict codec for `tego.run-status/1`. All six keys
are required. The codec refuses duplicate or unknown keys, nulls, wrong types,
trailing values, invalid UTF-8 and inputs above 4 KiB. `schema.json` describes
the shape; the codec also requires a clean absolute scope path and uint64 IDs.

An empty `scope` or `cgroup_id` explicitly means unknown. `removed:true` requires
both identities to be known and `deferred:false`. It means the runtime's removal
attempt succeeded and the exact known scope was subsequently confirmed absent.
It covers no process that moved out of that scope and does not describe work
performed through an allowed daemon or other external service (GAPS A8).

The launcher writes an initial `removed:false,deferred:false` after acquiring the
scope and before exec. A refusal before scope creation writes no status. Normal
return writes the final status after the record closes and runtime release has
been attempted. Deferred cleanup writes `removed:false,deferred:true` before
return and never rewrites it after a background success. Launcher loss leaves
the initial status, or no status if the launcher died before the first write.

`tego run --status-file` requires an absolute path with no symlink components,
an absent destination in a private 0700 directory owned by the launcher, and no
overlapping agent write grants. It writes a new 0600 regular file and atomically
renames it using the held parent directory. Existing destinations are refused
before launch. `--observe` with `--status-file` is a usage error (exit 2): record-only
mode cannot protect the output from the agent. A service using `--service` and the
same status path refuses every restart because that destination already exists;
choose a fresh path for each run. Write failure before exec refuses the start; a final write failure
returns exit 125. Missing, stale, partial, unknown and deferred statuses cannot
establish completed teardown.

The independent expectation/checksum inputs to `tego receipt --verify-ci` also
refuse any symlinked parent, including a symlinked `/home`, with exit 125. Supply
their real paths. This input rule does not authenticate the checksums file.

## Guest lifecycle checks owed

All checks below are **owed in a guest**. None was run in this fix round. Use one
guest with a delegated cgroup v2 subtree and a kernel supporting Landlock and the
cgroup backend. Follow test/vm/README.md and use the required VM slot wrapper;
retain the guest console and qemu exit status. Execute the five endings at
`--tier landlock` as the guest user, then `--tier cgroup` with a root launcher and
an unprivileged agent. Ten cells are required; a skipped tier is owed, not a pass.

Use the same exact release/build identity to produce and check receipts. Give each
cell a fresh config/ledger root, chain anchor, own log directory, contract and
0700 status parent outside every agent write/ask grant. Use `record: full`,
`reason: {reads: on}`, `capture: off`, and no models or budgets. Capture off
adds `capture-off` and `model-time-unseen` coverage gaps, so the first three
endings are deliberately incomplete even when their teardown checks pass. Allow
`/bin/true` and `/bin/sleep` explicitly. Retain the effective tier/capability/read notes from `run_start`;
require that the tier equals the selected tier. Root-tier setup must not silently
substitute Landlock. Never apply these recipes on the host.

For the ordinary CLI cases, launch a background process and save its PID:

```sh
"$tego" run "$contract" --tier "$tier" --status-file "$status" -- /bin/sleep 120 &
launcher=$!
```

Wait with a bounded deadline for both initial status and `run_start`, then take
`run_id` and `scope` from that status. For clean exit use `/bin/true` in place of
sleep and wait for the launcher. For stop call `"$tego" stop "$run_id"`. For agent
SIGKILL, read the single sleep PID from the known scope's `cgroup.procs`, verify
its `/proc/<pid>/exe` and cgroup membership, and send `kill -KILL "$agent_pid"`.
For launcher SIGKILL send `kill -KILL "$launcher"`, wait for its exit, then call
`"$tego" gc --keep 876000h --json` under the same config to sweep the orphan
without expiring this fresh record. Preserve status bytes before the kill and
after the sweep. Never select a process by a command-line pattern.

| Ending, at each selected tier | Status at launcher return | Scope path check | `--check --require-ended` exit |
|---|---|---|---|
| Clean `/bin/true` exit | `removed:true,deferred:false` | Absent before return. | 1, `incomplete`; ended/teardown pass, `coverage_complete:false`, `complete:false`. |
| `tego stop` of `/bin/sleep 120` | `removed:true,deferred:false` | Absent before return. | 1, `incomplete`, with ended/teardown passing and both completeness flags false. The agent's stop exit is separate. |
| SIGKILL of the agent only | `removed:true,deferred:false` | Absent before return. | 1, `incomplete`, with ended/teardown passing and both completeness flags false. The launcher preserves agent exit 137. |
| SIGKILL of the launcher after initial status | Initial `removed:false,deferred:false`, unchanged after sweep. | Require absent after the sweep; never infer absence from the status. | 1, `mismatch`, even once the sweep writes `run_end`; initial status cannot establish teardown. |
| Source `Stop` held past the shutdown deadline | `removed:false,deferred:true`, unchanged after releasing Stop. | Present while Stop is held; absent after releasing it and waiting for background cleanup. | 1, `mismatch`, both before and after background cleanup; the status remains deferred and the stop-timeout gap remains. |

A separate complete-match extension may use a valid forwarder capture setup
with no recorded gaps. First require `coverage.complete:true` in the produced
receipt, then require exit 0, `match` and `complete:true` for the first three
endings. This extension is also owed in a guest; capture off cannot establish it.

The held-Stop cell needs a guest integration adapter; there is no CLI flag that
creates it. Adapt `TestRunStatusDeferredHasNoBackgroundSuccessRewrite` and
`TestShutdownClearsTheLiveEntryOnlyOnceTheScopeIsReleased` using a real tier
backend and real cgroup manager, rather than their fake cgroup. Add a
`source.Source` through `runtime.Deps.Extra`: `Start` returns immediately, `Stop`
blocks on a test-owned channel, and `Gaps` returns no synthetic gaps. Run
`/bin/true`, hold that channel until `Run` returns after its normal stop deadline,
check the deferred status and present scope, then release the channel and wait
with a bounded deadline for absence. Capture status through the same atomic
writer or retain `RunStatus` output as the copied status; check that its exact
bytes never change after return. The real kernel matrix adapter and its runs
remain owed; the existing fake fixtures do not establish this result.

For every cell, require nonempty `scope` and `cgroup_id`, status `run` equal to
`run_start.run`, and the status decimal `cgroup_id` equal to the `run_start` line's
common `cgroup` field, preserving the full uint64 integer. Check the known scope
path itself with `lstat`; only ENOENT establishes absence. Preserve evidence
before any unrelated run can reuse a name. Once the relevant end/sweep/cleanup
point has arrived, generate and check the retained receipt:

```sh
"$tego" receipt "$run_id" --json > "$receipt"
"$tego" receipt --check "$receipt" "$run_dir" --require-ended \
  --status-file "$status" --json > "$comparison"
check_exit=$?
```

Compare `check_exit` and every JSON check with the table; do not treat any
nonzero exit as the expected result. Also remove the copied record directory and
repeat `--check --require-ended`: require `cannot-check` and exit 125, with ended
and teardown not checked, then restore the copy. Missing/malformed status also
requires 125. Repeat the writer refusal cases with an existing destination, a
symlinked parent, and direct or symlink-aliased overlapping write and ask grants;
require pre-launch refusal with no agent execution or new status. These alias
checks are separate from the ten lifecycle cells.
