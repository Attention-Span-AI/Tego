# examples/tests

A contract and the verdict table that tests it, the shipped example of
`tego compile --test` (docs/p0/limits-check-doctor-cli.md §5 R28).

```sh
cd examples/tests
tego compile agent.yaml --test verdicts.yaml    # 21 rows: 21 passed, 0 failed
```

Run it from this directory: the contract's `fs` and `exec` entries are
relative and resolve against the working directory, like every other relative
entry (docs/p0/agent-contract.md §6 E28).

| File | What |
|---|---|
| `agent.yaml` | a self-contained contract: one write directory, two `deny_read` entries (one of them inside the write directory), a watched directory, two literal network entries, one exec entry |
| `verdicts.yaml` | one row per hypothetical action: `action`, its target, the `expect`ed verdict and, optionally, the `rule` that must decide and the `tier` to simulate |

A row without `tier:` runs in every tier a run of the contract can get (the
first output line names them: the pin, or for a contract left at `auto` every
tier this tego builds that a run of yours can get here, naming those it leaves
out and why, as a normal user's tegobpf build prints
`tiers landlock (tier auto: every tier this tego builds but cgroup and bpflsm, which need root)`)
and passes only if it holds in each (ADR 0019);
`--tier cgroup` answers for one machine's tier alone. A row that names a tier
shows what that backend decides, never what this machine can reach (R33). That is how the table pins the two filesystem models side by side: the
root tiers' nearest-ancestor walk refuses a read under `out/keys/`, and
Landlock — which cannot deny beneath an allow — reports the same entry as
`unenforced: parent writable` (spec/policy/SEMANTICS.md §2).

Exit codes: 0 when every row passes, 1 when any row fails, 2 when the table
itself is malformed (no row runs).
