# Bounded contract helper cost

Fix round 3, 2026-11-12. The filesystem was healthy; the shared host was loaded by
other release jobs. These are component command measurements, not isolated-machine
benchmarks or actual CLI executable timings. No product binary ran on the host.
Actual stopped-mount and credential acceptance remains a **MERGE BLOCKER**, **owed
in a guest**: [runnable recipe](contracts-stuck-mount.md).

The before source is round 2, `065d458d9`. The historical round-3 reuse source is `60d056094`. Fix round 4 changes caller-context transport and page scopes; this table has not been rerun on round 4.
Normal, non-race test binaries call production `Discover` and `PrintList`, with a
fresh caller process per command and real own-image launcher/worker execs. Every
entry has a distinct valid source. Fixture creation and snapshots precede a shared
barrier. Wall time includes checks, discarded table formatting and caller reaping;
it excludes fixture setup, CLI startup and initial config/ledger discovery. Process
counts include successful launchers and workers, excluding caller test processes.
A scratch-only `proc.Start` overlay appends successful child PIDs, one append per
start, without ptrace or shipped instrumentation. The finite driver samples child
RSS and saves each completed matrix cell. Exit columns are catalogue `ExitCode()`
results; the measurement test process itself exits zero after reporting them.

| Entries | Concurrent commands | Before seconds | Before processes | Before exits 0/125 | Reuse seconds | Reuse processes | Reuse exits 0/125 |
| ---: | ---: | ---: | ---: | --- | ---: | ---: | --- |
| 1 | 1 | 0.095 | 4 | 1/0 | 0.095 | 2 | 1/0 |
| 1 | 4 | 0.123 | 16 | 4/0 | 0.147 | 8 | 4/0 |
| 1 | 16 | 0.145 | 16 | 4/12 | 0.217 | 32 | 16/0 |
| 20 | 1 | 1.091 | 42 | 1/0 | 0.501 | 2 | 1/0 |
| 20 | 4 | 1.400 | 168 | 4/0 | 0.597 | 8 | 4/0 |
| 20 | 16 | 1.555 | 168 | 4/12 | 1.240 | 32 | 16/0 |
| 200 | 1 | 10.803 | 402 | 1/0 | 4.182 | 2 | 1/0 |
| 200 | 4 | 15.683 | 1608 | 4/0 | 4.573 | 8 | 4/0 |
| 200 | 16 | 4.999 | 448 | 0/16 | 11.673 | 32 | 16/0 |
| 2000 | 1 | 60.100 | 1680 | 0/1 | 43.707 | 2 | 1/0 |
| 2000 | 4 | 60.258 | 4748 | 0/4 | 60.200 | 8 | 0/4 |
| 2000 | 16 | 27.392 | 1482 | 0/16 | 60.280 | 32 | 0/16 |

Reuse removes the pair per source. All sixteen-command before cases encounter the
four-slot refusal; the smaller cases let four commands finish while twelve refuse.
Some larger cases lose slots between successive checks and none finish. After
reuse, sixteen healthy commands use sixteen workers and start 32 helper processes
in total. No head matrix cell encounters shared-budget exhaustion. The 2,000-entry,
four- and sixteen-command cases still reach the unchanged sixty-second command deadline on
this loaded host. Their person-facing results include `context deadline exceeded [interrupted]` and incomplete entries with `cannot tell: this location does not answer
(a disconnected or stuck mount?): context deadline exceeded`. This is a measured
throughput limit, not proof of a stuck mount. It is not reported as success.

A separate ordinary 2,000-entry profile attributes 80.78% of helper CPU to
`agent.Compile` and 45.01% to syscall work (overlapping cumulative costs). Built-in
filesystem checks, enumeration and resolution dominate. Parent CPU was 1.16 seconds
versus helper 35.75 seconds. Those checks remain fresh; no speculative filesystem
cache or longer deadline masks the cost.

The shared limit is now 32 live workers per effective uid/network namespace,
including abandoned workers. One sequential worker per command permits sixteen
ordinary concurrent commands plus sixteen slots of headroom. Each worker retains
its kernel socket reservation until actual exit; closing caller pipes cannot free
a blocked worker's slot. At most 32 short launchers can briefly coexist. Each caller process
also has 32 local worker slots, released on pipe close. This is a finite process
ceiling, not an arbitrary-load availability or memory guarantee. The largest
sampled ordinary aggregate worker RSS was 338,644 KiB for sixteen workers. Linear
projection for 32 ordinary workers is about 661 MiB. It is an estimate: 128 MiB
frames and decoded policies can require more memory. No 32-worker real stuck-mount
resource claim is made before the owed guest proof.

| New refusal | Person-facing words after the cannot-tell prefix | Ordinary system behavior |
| --- | --- | --- |
| Shared capacity held by 32 active or abandoned workers | `32 filesystem helpers are still alive in this uid and network namespace; retry after the mounts recover` | No new worker starts. CLI entries are incomplete, exit 125; dashboard entries stay listed with changes disabled. Sixteen healthy commands do not exhaust this budget. Healthy active workers release slots when they finish. A stuck abandoned worker keeps its slot until recovery or abort. |
| Reservation or descriptor failure | `reserve filesystem helper: too many open files` (EMFILE example; the OS error is preserved) | No worker or request is trusted. An ordinary system with available descriptors does not take this refusal. Fix the resource failure before retrying. |
| Credentials differ after exec | `filesystem helper credentials differ after exec` | No request bytes or path are delivered. Same-credential ordinary exec proceeds; unexpected authority changes refuse. Actual root/sudo/other-uid execution is owed in a guest. |

Predictable reservation names permit denial by squatting, never reply injection.
Tests cover sixteen healthy sessions, reuse, retained reservations, reservation
failure, changed authority before request delivery, empty environment between
requests, private late replies and abandoned pipe-waiter cleanup. Host stand-ins
are not the real stopped-mount acceptance.

Fix round 4 separately measures actual process starts per page request. The test
image records each launcher and worker PID at initialization, including processes
which exit before the response. The before control restores the separate feed,
reference and bootstrap scopes with a source overlay; other context fixes remain.

| Request fixture | Before launchers/workers (total) | After launchers/workers (total) |
| --- | --- | --- |
| Rules, Change chooser, Logs, ended timeline, live row poll | 1/1 (2) | 1/1 (2) |
| Unused page | 2/2 (4) | 1/1 (2) |
| Least privilege page | 2/2 (4) | 1/1 (2) |
| Overview with real CLI guide bootstrap | 2/2 (4) | 1/1 (2) |
| Overview with preselected guide inputs | 1/1 (2) | 1/1 (2) |
| Link reference then catalogue in one request | 2/2 (4) | 1/1 (2) |
| Cancelled feed, reference or bootstrap | 1/1 (2) | 0/0 (0) |

These are ordinary non-race own-image HTTP fixtures, including the CLI callback
reached through Prewarm, not guest or product-binary timings. Empty initial setup
starts no check and is excluded from exact-one claims. `TestRecordedPageUsesOneHelper`,
`TestRecordedLinkSharesRequestHelper`, `TestOverviewBootstrapSharesRequestHelper`
and their cancellation controls assert these counts. All eleven affected regression
groups fail at runtime with their fixes removed. Targeted race checks also cover
request cancellation, memo ownership and guide compiler-context parity. A blocked
abandoned worker can remain until recovery; its shared reservation remains held.

Fix round 5 adds a copy-only exchange before the Rules source check. Both exchanges share one worker
and one overall deadline. The first exchange parses only recorded text, without compiler probes or a fresh enforcement claim; the
second compiles once on the healthy path so matching source positions remain available. The recorded
text must finish loading before a blocked source can be tolerated.
`TestInForceSourceTransportTimeoutKeepsRecordedRules` counts one launcher and one worker with an actual
blocked descriptor read; `TestRecordedPageUsesOneHelper` checks the healthy HTTP paths. This does not
rerun the historical timing matrix or prove a real stopped mount; that remains owed in a guest.
