# Check that Tego works on this machine: `tego test`

`tego test` shows, in about a second, that Tego refuses what it should on this machine. It needs no root and no
setup, and it touches nothing of yours.

```
$ tego test
Tego self-check: 4 actions, 4 refused at tier landlock

  ACTION                                               WITHOUT TEGO  UNDER TEGO  REFUSAL
  read a fake SSH key in a fake home                   succeeded     refused     read-denied: fs.deny_read[<tmp>/work/home/.ssh/]
  write a file outside the project's writable folder   succeeded     refused     write-outside-contract: no entry of the contract allows it
  run a program the contract does not list             succeeded     refused     exec-not-allowed: no entry of the contract allows it
  connect to a local port the contract does not allow  succeeded     refused     net-not-allowed: no entry of the contract allows it

Each action works on this machine without Tego, and Tego refused and recorded every one.
The actions ran on decoys in a temporary folder, removed now, and the four runs' records went there too.
```

## What it does

It makes a temporary folder with decoys: a fake home holding a fake SSH key and a fake `.env`, a small project whose
`out/` folder is the only writable one, a copy of `/bin/true` (or of the `true` on your `PATH` when there is no
`/bin/true`), and a local network listener of its own on a free
port. Then it runs four harmless actions twice each:

1. read the fake key;
2. write a file beside the project, outside its writable folder;
3. run the copy of `/bin/true`, which the contract does not list;
4. connect to its own listener, on a port the contract does not allow.

The first time each action runs directly, without Tego: it must work, or a refusal later would prove nothing. The
second time it runs as the agent of `tego run` under a built-in contract: it must be refused, and the run's record
must hold the refusal. The REFUSAL column is that record's reason and rule. `<tmp>` stands for the temporary folder.

The folder is removed when `tego test` ends, and the four runs are recorded inside it, so they never appear in
`tego events`, the dashboard or your ledger.

The folder is made in `$TMPDIR` (or `/tmp`). No contract may let a run write over the tego binary, and `tego test`
keeps its folder away from it: when `$TMPDIR` lies inside the folder holding the binary (a binary downloaded to `/tmp`
and run from there), `tego test` makes its folder in `$XDG_RUNTIME_DIR` or your cache folder instead, and with neither
usable it stops and asks you to set `TMPDIR` elsewhere.

The four runs read your own `$TEGO_CONFIG` layer, with its `ledger_root` replaced by the temporary folder's. A layer
`tego run` would refuse (writable by others, a relative path, missing) makes `tego test` refuse it too, with exit 125
and the same `[config-untrusted]` message, before any action runs.

## Exit codes

| Code | Means |
| ---- | ----- |
| 0 | every action worked without Tego and was refused, and recorded, under Tego |
| 1 | an action took effect under Tego (`allowed`), or was stopped without a record (`unrecorded`) |
| 2 | a usage error |
| 125 | an action could not be judged (it failed without Tego too, or a run did not start), `tego test` could not run, or your `$TEGO_CONFIG` layer is one `tego run` refuses (`[config-untrusted]`) |

## Options

- `--json` prints one JSON object instead of the screen.
- `--tier <tier>` pins each run's tier, as `tego run --tier` does.

## The JSON object

```json
{
  "schema": "tego.selftest/v1",
  "tier": "landlock",
  "actions": 4,
  "refused": 4,
  "verdict": "pass",
  "dir": "/tmp/tego-selftest-123",
  "checks": [
    {
      "name": "read-secret",
      "action": "read a fake SSH key in a fake home",
      "baseline": { "result": "succeeded", "detail": "read 115 bytes" },
      "under_tego": {
        "result": "refused",
        "run": "r-...",
        "rule": "fs.deny_read[/tmp/tego-selftest-123/work/home/.ssh/]",
        "reason": "read-denied",
        "target": "/tmp/tego-selftest-123/work/home/.ssh/id_ed25519",
        "match": "target",
        "detail": "open ...: permission denied"
      }
    }
  ]
}
```

`verdict` is `pass`, `fail` or `inconclusive` (exit 0, 1, 125). `checks` holds the four actions in order, named
`read-secret`, `write-outside`, `run-unlisted` and `connect-unlisted`. A baseline `result` is `succeeded`, `failed`
or `error`; an under-Tego `result` is `refused`, `allowed`, `unrecorded` or `error`. `run`, `rule`, `reason` and
`target` come from the run's record. `match` (on a refused row) is `target` when the refusal names the action's own
target, or `reason` when none did and a refusal with the action's reason stands in for it; the screen then adds
`(by reason: the record names ...)` to the row. `dir` is the temporary folder, already removed. A later version only adds
fields.

## What it does not show

These four actions are ones Tego refuses at every tier. It does not yet show what a tier lets through (for example
a library preloaded into an allowed program, or a lookup through the allowed DNS resolver); see the honest limits in
[GAPS](../GAPS.md).
