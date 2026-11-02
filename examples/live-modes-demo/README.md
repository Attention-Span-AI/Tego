<!-- SPDX-License-Identifier: Apache-2.0 -->
# Adjustable mode demo: loosen a running agent's rules for two minutes, and it ends by itself

A short demo of Tego's Adjustable mode (docs/user/live-modes.md, ADR 0125): an agent is refused a folder,
you lift that refusal for two minutes while it runs, its next read works, and when the two minutes are up (or you
Restore) it is refused again. The ledger records every change. It needs root (below).

Nothing real is read. The "customer report" is a fake CSV that `setup` writes under `vault-data/`, and the agent is
`agent.sh`, a shell loop with no model that tries to read it every 2 seconds and prints `read ok` or `read REFUSED`.

## Needs root

Adjustable runs only at tier cgroup or bpflsm, so the run is started with `sudo`. What root does here: Tego places
the run in a cgroup of its own and adds that tier's kernel checks; the agent itself still runs as you, never as root.
Because the run is root's:

- `lift`, `restore` and `proof` use `sudo` as well. While a root run is live, its folder in the ledger is root's
  (mode 0700) and so is its live key, which a lift must be signed with.
- The dashboard runs as you and never as root (`tego-control` refuses sudo). It cannot open a root run's folder while
  the run is live, so the Rules page's **Lift…** button and its preview are not available on this run: the lift, its
  preview and its confirmation happen at the terminal. When the run ends, Tego hands its folder to you (the ledger
  root is yours) and the dashboard shows the whole run: the mode, the fence and every change. No config setting
  changes this; it is how a root run keeps its live folder out of reach until it is done.

The demo uses its own machine config, `~/tego-live-demo.yaml`, which names its own ledger, `~/tego-live-demo-ledger`.
`sudo` drops `TEGO_CONFIG` from the environment, so `demo.sh` passes it inside `sudo env ...`; every command shows it.

## Commands

From this folder, after `make build` at the top of the checkout:

```sh
./demo.sh setup        # the fake data, contract.filled.yaml, the demo's config; checks tego compile accepts it
./demo.sh run          # terminal 1: sudo tego run contract.filled.yaml -- ./agent.sh   (Ctrl-C ends it)
./demo.sh lift         # terminal 2: sudo tego lift <run> read <vault-data> --for 2m   (type "lift" to confirm)
./demo.sh restore      # terminal 2: sudo tego restore <run> read <vault-data>          (optional: refuse it now)
./demo.sh proof        # terminal 2: the ledger's lines for the lift, the expiry or restore, and every read
./demo.sh dashboard    # after the run ends: tego-control serve for the demo's ledger, as you
./demo.sh reset        # retake: removes the filled contract, the fake data and the demo's ledger
```

`lift`, `restore` and `proof` act on the newest run in the demo's ledger (`DEMO_RUN=<run id>` picks another).
`DEMO_LIFT_FOR=1m` shortens the lift for a tighter take (1 minute is the shortest limit). `./demo.sh lift --yes`
skips the typed confirmation.

## What was verified, and how

- `tego compile contract.filled.yaml` accepts the contract: Adjustable, one read fence entry refused at start, tier
  cgroup (a build without the tier-2 objects warns `tier-unavailable`; `make build` includes them).
- The whole loop (refused, lifted with `--for`, `read ok`, restored, refused, every read under
  `live.fence[read:...]`) was rehearsed as a user with a test build that lets Adjustable run at tier landlock, which
  the product refuses. As root at tier cgroup the same flow is `TestIntegrationAdjustableFenceLiftAndRestore`
  (internal/runtime/livefence_integration_test.go), which passed as root at tiers cgroup and bpflsm in a KVM guest.
  That test writes its lifts to the run's overlay itself; the commands, `tego lift --for`, `tego grant` and
  `tego restore` each answered from the launcher's own line, are `TestIntegrationLiftGrantRestoreOnALiveLauncher`
  (internal/cli/lift_integration_test.go), which CI's unprivileged integration step runs with that test build.
- The two-minute expiry itself was not run to its end in rehearsal; `live-lift-expired` is covered by the live-layer tests.
