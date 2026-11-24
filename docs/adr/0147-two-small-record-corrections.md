# ADR 0147: Two small record corrections: the signal of an escalated stop, and the rule of an observed AF_UNSPEC send

Status: **accepted 2026-11-11**; built. The number is the next free one under `docs/adr`.

## Context

Two lines of the record said something other than what happened.

1. A run that was asked to stop (SIGINT, SIGTERM or SIGHUP to `tego run`, or `tego stop`) and that Tego then killed with
   `cgroup.kill` (because `stop_grace` ran out, or a second SIGINT came within two seconds) had `run_end.signal` 9.
   `spec/identity/RUN-IDENTITY.md` ("Signals") said `run_end reason=signal signal=<n> escalated=<bool>` without
   defining which signal `<n>` selects. The code (`ending()` in `internal/runtime/run_shutdown.go`) took
   the wait status first, which is 9 after the kill, so an escalated stop lost the signal that started it.
2. In an observe run (R30) the supervisor continues a send (`sendto`, `sendmsg`, `sendmmsg`) whose address has the
   family `AF_UNSPEC`: an attempted send whose destination and result were not established. On an unconnected
   IPv4 UDP or raw socket the kernel can use the `sockaddr_in` behind the family word; on a connected
   IPv6 UDP socket it can use the existing peer; TCP can ignore the address or refuse it. The line was `observed`, rule
   `unmatched`, dst `unspec`. A `connect(2)` with `AF_UNSPEC` (a disassociation, rule `net.unspec`) has the same dst.
   The receipt counted the send among the routine socket calls that name no place ("disconnects"), and the
   dashboard's verdict left it out (GAPS C61).

## Decision

1. `run_end.signal` is the signal that started `stop_grace` for a run whose reason is `signal` or `stopped` and whose
   `escalated` is true. In every other case it is what it was: the signal the kernel reported for the agent (an
   agent that died of another signal than the one that started the stop records that one), else the one that started
   the stop when the agent left by its own exit code. A run a limit, the memory cap or the process cap ended keeps the
   kernel's: the kill that ended it. The record spec and RUN-IDENTITY.md say it. The record does not tell the two
   triggers of an escalation apart (grace ran out, second interrupt), and no key is added for it; telling them apart
   would be a new optional field and a record minor, which this ADR does not take. The receipt says "ended by signal 15,
   then killed by Tego" for an escalated `signal` run, which is true for either trigger (a new optional receipt key,
   `escalated`; `receipt_v` stays 1).
2. The supervisor writes rule `net.unspec-send` on the line of such a send in an observe run (`emitNet`, when the
   address is `AF_UNSPEC`, the run observes and the rule would have been `unmatched`). The dst stays `unspec` and the
   verdict `observed`. The enforcing tiers' refusal is not touched: `refused`, rule `unmatched`, EACCES. A new reader
   classifier, `syslookup.PlaceOf`, names the line's place "unread address, AF_UNSPEC send"; `syslookup.NoPlace` is
   false for the rule. The receipt lists the send as a connection, observed, and counts no routine socket call for
   it; the dashboard's verdict, comparison and Logs name the same destination. The name says the address was not
   read, not where the bytes went.

## Why no record version moves

`docs/VERSIONING.md` §2: within v1 only optional fields are added, and removing or re-meaning a field bumps `v`.
Decision 1 clarifies the signal selection of the existing signal/escalated pair; no key is added, removed or retyped.
This ADR treats that clarification as a correction within v1. Records from binaries through v0.1.2 keep 9 on an
escalated stop; `escalated: true` alone does not distinguish them from newer records. The `tego_version` of the run's
`run_start` identifies the writer. Decision 2 adds a value to the open set of rule names, which readers already treat
as text (the rule is "never free text", not a closed set, `docs/p0/supervisor.md` R29, which lists it). An older tego
accepts the rule as text but keeps its old classification of `dst: unspec` as a routine socket call.

## Consequences

- To find disassociations, match the rule `net.unspec` exactly; a substring search for `net.unspec` also finds
  `net.unspec-send`. To find attempted sends to an unread address, match the rule `net.unspec-send` exactly.
- `tego learn` still proposes no entry for a `udp` `unspec` line, as before.
- Proof: the supervisor's unit tests drive the three send syscalls on a fake kernel; the escalation tests drive a real
  signal handler (a real timer, a real double interrupt) with a stand-in killer. Still owed in a guest:
  `TestIntegrationObserveNamesAnUnspecSend`, checking delivery, the ledger's observed `net.unspec-send` line and the
  receipt's unread-send entry; and `TestIntegrationRunEndSignalOfAnEscalatedStop`, checking the ledger and receipt for
  grace expiry, `tego stop` grace expiry and immediate double-interrupt escalation under a long grace. These guest
  checks have not been run in this fix round.
