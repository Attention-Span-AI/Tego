# ADR 0161: the open deputy lives in a cgroup the pause does not freeze

Status: **proposed 2026-11-24**, a design record, not built. It needs kernel
proof on every tier that holds opens and a guest run on both kernel generations the plane supports; none of that can be
made without a guest. Amends ADR 0041 D2 (where the deputy runs) and ADR 0128's 2026-11-21 amendment (how
the plane names it) when built.

## The defect (found 2026-10-27, `internal/runtime/livepause.go`)

`tego pause` and the dashboard's Pause freeze the run's cgroup (`cgroup.freeze` of `run-<id>.scope`, which freezes every
task in it and below). A held open (`fs.reads: held`, `gate.completion: held`) makes the agent's thread wait for the
supervisor's answer, and the supervisor completes the open through the run's open deputy, a process of the same cgroup
(`tego __open-deputy`, ADR 0041 D2, placed by the stage; named to the plane by thread-group id and start time, ADR 0128).
A freeze that lands while the deputy is half way through a request freezes the deputy too. The agent's thread then waits
in the kernel for a notification the supervisor has received (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`), which the
freezer cannot enter, so `cgroup.events` never says `frozen`. Measured before the retries: 13 to 35 percent of pauses of a
busy held-read agent missed. Today's mitigation is up to nine 100 ms freeze attempts thawed in between, a back-off, and
no attempt while an ask waits: a miss is rare, not impossible, and a freeze attempt holds the live-block poll for up to a
second.

## What was checked in the code

- Everything that tells a run's tasks by cgroup uses the run's scope **and anything below it**: the governed-agent
  refusal (`runscope.GovernedBy`, "any cgroup below one"), `cgroup.kill`, the decision plane's slot (hooks attach to the
  scope and apply to its descendants), memory, pids and cpu limits (hierarchical), `cgroup.events populated`.
- `cgroup.freeze` is hierarchical downward too: freezing the scope freezes the children. So the deputy cannot be made
  exempt by moving it *below* the scope; it has to be in a cgroup the freeze does not reach.
- `awaitOnlyDeputy`/`onlyProcess` (`run_shutdown.go`) already read the scope's processes and its children's `cgroup.events`
  to know when "only the deputy is left", and `loopEndSettle` waits on it.
- The deputy's right to complete a held open comes from its **Landlock domain and seccomp filter**, which it carries
  with it, and from the plane's decision on its opens, which the plane makes by the cgroup the task is in.

## Design

Two child cgroups under the run's scope instead of one flat scope:

```
run-<id>.scope            hooks and limits attach here; cgroup.kill; never holds a process
  agent/                  the agent, its children, everything it runs: THE FREEZE TARGET
  deputy/                 the open deputy: never frozen
```

1. **Freeze `agent/` only.** `cgroup.Freeze` and `Frozen` take the child; `cgroup.events` of `agent/` says when its tasks
   are all frozen. The deputy keeps running, so an open in flight finishes, the agent's thread is answered, and the freezer
   can enter it. This removes the miss and the retries; a pause is one freeze and one wait.
2. **Placement.** The launcher makes both children (mkdir under the delegated scope) before the stage starts. It starts
   the stage with `clone3(CLONE_INTO_CGROUP)` as today (`internal/runtime/launch`), into `agent/` instead of the scope.
   The deputy is started by the stage as a `CLONE_PARENT` child and so is born in `agent/`; it must be moved to
   `deputy/` before the run is armed, by the launcher writing its pid to `deputy/cgroup.procs` after the deputy's hello
   (`keepDeputy`/`exemptDeputy` already run at that point, and the deputy has nothing to race yet). Whether that, or a
   launcher-started deputy placed with `CLONE_INTO_CGROUP`, keeps the identity `keepDeputy` pins (thread-group id,
   start time, unreaped zombie) is the first thing to measure. The scope has no `subtree_control`, so a non-leaf may
   keep tasks and no controller needs delegating.
3. **The plane.** Hooks attached to the scope still see both children. The deputy's slot exemption (`ExemptDeputy`: thread
   group id, start time, pid namespace) is unchanged and is checked by identity, not by cgroup, so the plane's decisions
   about the deputy's opens stay what they are: its opens meet the same plane and the same Landlock domain as the agent's
   (ADR 0128 amendment; GAPS C38).
4. **Naming.** `runscope.GovernedBy` already counts every cgroup below a run scope, so `tego block`, the dashboard and
   the governed-agent refusal need no change. The adoption scopes (`adopt-<id>.scope`) move an *existing* process tree
   and have no deputy; they keep a flat scope and freeze it as now (ADR 0055).
5. **Teardown.** `awaitOnlyDeputy` reads `agent/` for "empty" instead of "only the deputy", and `loopEndSettle` shortens to
   the agent child's `populated 0`. `cgroup.kill` on the scope ends both children.

## What is not decided here and must be measured first

- **A paused run's deputy runs.** A frozen agent sends the deputy nothing, but a request that arrives from the supervisor
  while the agent is frozen is impossible (the agent is the source). A request the supervisor is *itself* making (it
  completes only what the agent asked) cannot start, so the deputy idles. To be proved, not assumed: a stress of held
  opens against pause and resume, 10,000 pauses, zero misses.
- **Who may signal the deputy.** Today the agent shares the deputy's cgroup and non-dumpability protects it
  (the 2026-11-21 review of the deputy's exemption). In a sibling cgroup the agent still cannot trace or reach it; signals from the same uid remain the
  existing residual and the launcher's `KeepUnreaped` still holds its pid. A root-tier guest test must show the agent's
  `kill` of the deputy ends the run closed (the held opens then fail), as it does today.
- **`CLONE_INTO_CGROUP` through the user manager** and the "scope has children and tasks" rule on both cgroup v2
  mounts the supported distributions use (a delegated user scope on Fedora, Debian, Ubuntu; cgroup2 with `nsdelegate`).
- **Tier 1 and the `tegod` per-run broker** (ADR 0042) place the run's tasks themselves; the layout has to be made in the
  same place for the root tiers and for the user tier.

## Proof owed (a guest; not run here)

`test/vm` rows for the user scope and for root tiers 2 and 3: layout present (`agent/`, `deputy/` under the scope); 10,000
pause/resume cycles against a held-read agent with no `pause-failed` line; the plane still refuses the deputy's opens it
refused before (`denywrite-held/write-hard-link-alias`, GAPS C38) and the agent's `recvmsg` of a control message; a kill of
the deputy by the agent; `tego stop` ends both; the dashboard and `tego status` show the run in both children; adoption
unchanged. Unit tests to add with the build: the freeze targets the child (fake tree), the teardown wait, the layout
creation and its failure (a run is refused before `run_start`, fail closed, as an unplaceable deputy is today).
