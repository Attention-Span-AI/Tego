# ADR 0026: a ring per run from a machine-set budget, and capture probes shared per library

Status: accepted, implemented 2026-09-24 ((1)-(7), (9) as amended below; (8) implemented 2026-10-04 with measured multi-link selection and individual fallback; proposed 2026-09-23); (6)'s plane-row clause amended 2026-09-29 by ADR 0025's slot-kept row maps; (3) amended 2026-10-19: the probes stamp a stall-bounded run's activity in every record mode; (7) amended 2026-10-19: a record: off run with a stall budget holds the probes with no ring). Amends enforce-cgroup-observe §2 'Run scope', §3, R12, E32 and E33; capture-derive §3-§4 and R9; ARCHITECTURE §8, §15.1 and §15.7; spec/config/v0.

Decision: (1) tego_events and tego_capture_events become map-in-map outers with 4096 slots indexed by run_idx: BPF_MAP_TYPE_ARRAY_OF_MAPS if the matrix measurement of differently sized inner rings passes on every row, else BPF_MAP_TYPE_HASH_OF_MAPS (measured working on six kernels). Every program looks up the inner ring only after its run_set hit and emits nothing when it is absent. (2) Sizes are machine settings honoured only from /etc/tego/config.yaml:
- record.ringbuf: the size of a run's event ring. Its default is re-derived from measured sample rates (the reader drains every 50 ms and is woken at one eighth full), expected 1-2 MiB rather than today's 8 MiB.
- A small fixed ring for record: off runs, which emit only refusals, execs and exits.
- bpf.ring_budget: a host-wide cap on the memlock of all live inner rings.
Prepare creates the run's rings and fails with ErrRingBudget when the budget would be exceeded; doctor shows the budget and its use. A user layer that sets record.ringbuf gets a compile note and no effect. (3) A capture inner ring exists only for a run whose capture mechanism is uprobe. (4) Lost counters: one BPF_MAP_TYPE_ARRAY of u64[4096] per ring kind, incremented atomically and zeroed at Prepare, so a run counts its own drops from its own start. (5) Each run's recorder and capture source read only their own rings, so the one-reader rule holds by construction. The run-scope refusal, NotBefore, and the concurrency gaps kernel-record-unavailable and mechanism-unavailable are deleted. (6) Slots come only from the slot table in /run/tego (ADR 0034). A slot is reusable only when no run_set row, no plane-row inner map (ADR 0025) and no inner ring carries it; I5 is extended accordingly. The reaper and the sweep make release prompt, and the slot of an orphan that cannot be killed stays held. (7) Capture probes are shared per (build, library inode). Each is attached once, pinned under <hash>/uprobes/<dev>-<ino>/, and guarded by /run/tego/bpf-<hash>-lib-<dev>-<ino>.lock, which every run needing the library holds LOCK_SH. A probe emits into the ring of the run the current process belongs to, only if that run's capture ring exists. So N concurrent runs pay one probe per library, and no exchange is captured twice. The last run out detaches the probes in its reaper after run_end, never in the launcher. (8) Where the kernel has uprobe_multi (probed; 6.6+ or a backport, RHEL 9 included), one entry program and one return program dispatch on the attach cookie, with two links per library. Below that, today's single probes. Where a probe link cannot be pinned, probes are per run, with the run's slot as a load-time constant. (9) A probe grace for back-to-back capture runs is not adopted. Condition to revisit: a measurement showing its saving outweighs about 2.4 µs per TLS call for every host process during the grace.

Why: [documented, measured by cilium/ebpf's authors] Two userspace readers of one ring duplicate and corrupt samples (cilium/ebpf stores the consumer position without compare-and-swap), so today the second concurrent run of a build has no kernel record and no capture.
[measured] A HASH_OF_MAPS lookup by run_idx then bpf_ringbuf_reserve on the inner ring loaded, and a 1 MiB inner ring went into an outer map whose prototype was 64 KiB, on 6.17, 6.8, RHEL 9, 7.0, AL2023 6.12 and AL2023 6.1. ARRAY_OF_MAPS was not measured.
[documented] Falco's modern probe ships its rings in an ARRAY_OF_MAPS (falcosecurity/libs driver/modern_bpf/maps/maps.h 241-246).
[measured] Attached but filtered uprobes cost about 2.4 µs per hit for every host process (a memory-BIO TLS loop went from 1.8 to 9.0-9.5 µs an iteration). Detaching six probes, single vs multi: 445 vs 38 ms on 6.17, 187 vs 0.01 on 6.8, 189 vs 0.01 on RHEL 9, 281 vs 27 on 7.0, 1530 vs 170 on AL2023 6.12. AL2023 6.1 lacks uprobe_multi.
[measured] Each 8 MiB ring is 8,433,944 B of memlock, so about 16.9 MB a run with both rings and about 540 MB for 32 concurrent runs, against ARCHITECTURE §15.1.
[documented] record.ringbuf is a setting where the last layer wins, so the invoking user's config would size root's kernel allocations.
[inference] A shared probe fires for every run_set member; a capture ring for a capture: off run would receive its TLS plaintext.

Security argument: Isolation between concurrent runs' records improves: a launcher reads only its own rings. No TLS plaintext of a run without uprobe capture is written anywhere, because the probe finds no ring for it. The invoking user cannot size root's kernel memory, and the host budget bounds it. Slot reuse waits for every object keyed by the slot, closing E32's case of a new run receiving an orphan's samples or rows. The shared probes emit only for processes in the build's run_set and are detached when no run needs them.

Options considered: Chosen: map-in-map rings per slot under a machine-set size and host budget, capture rings only where capture runs, shared per-library probes, uprobe_multi.
Rejected:
- One host-wide reader that demuxes: tegod, P3, a daemon in the TCB.
- Per-run probes filtered by a load-time slot constant: per-hit cost scales with concurrent capture runs.
- Keeping probes attached while idle: 5x on a TLS loop for every host process.
- A per-CPU lost counter per slot: 4096 x CPUs x 8 bytes.
- Any legal ring size per run from the run's own config: user config layers would size root's memory with no cap.
- A capture ring for every run: plaintext of capture: off runs in kernel memory.

Consequence: Concurrent runs of one build each get a full kernel record and capture. Memory scales with concurrent runs at the configured size, bounded by bpf.ring_budget. An idle lingering build holds about 1.3 MB instead of about 20 MB. E33 disappears. On AL2023 6.1 (no uprobe_multi) the last-out capture detach costs about 1 s per library, in the reaper, off the user's wall time.

Implementation plan:

Measure first, in GUEST and on MATRIX:
- ARRAY_OF_MAPS with inner rings of 64 KiB, 1 MiB and 8 MiB in one outer, on every row.
- Sample rates of the kill test 2 and kill test 4 workloads at record: full and summary, to set the defaults.
Then:
- bpf/include/maps.h: the outer maps and the per-slot lost arrays. Lookups in trace_proc.bpf.c, uprobe_ssl.bpf.c and later decide.bpf.c. internal/bpf types and generation.
- enforce/cgroup: inner ring create, insert and delete; ring budget accounting under /run/tego; purgeSlot; slot allocation checks run_set, row maps and rings.
- observe: the reader on the run's inner ring and its lost slot. Delete the run-scope refusal and NotBefore.
- capture/uprobe: shared attach under the library lock; adoption of pinned probes; uprobe_multi with cookie dispatch; the single-probe fallback; detach by the reaper.
- spec/config/v0: record.ringbuf and bpf.ring_budget as /etc-only settings.
Tests as root in GUEST and on MATRIX:
- 2, 8 and 32 concurrent runs of one build under open-heavy load. Each ledger has every exec and open of its own processes and none of the others', there is no unavailable gap, and every TLS exchange is captured once.
- A capture: off run beside a capture run leaves no chunk of its TLS (the probe's miss counter shows the miss).
- ErrRingBudget at the cap.
- The Fedora 7.0 case of samples lost without a count (6 of 40 subtests today).
- Uprobe detach timings per row, and the memlock of an idle build.
Docs: as in Status; OPERATIONS (sizing the budget).

*Amended 2026-09-24 (kill test 4, tier cgroup):* (7) is built in `internal/runtime/capture/uprobe` (shared.go), with
the capture programs pinned in the build's `progs/` and adopted by its next run. What it measured, in the 1536M/2-vCPU
guest on 6.17 with kill test 4's contracts at tier cgroup: per run, placing the host libssl's six probes took 4-18 ms
and removing them 0.40-0.55 s (strace: `close` of each perf link 14-57 ms, one after another), and loading the
capture object about 20 ms; `npm install` took 1.02-1.07 s under tego against 0.41-0.43 s bare and 0.49-0.52 s with
`capture: off`, and `go build` 0.74-0.79 s against 0.12 s bare and 0.20-0.24 s with `capture: off`. So the capture
source's per-run placement and removal was the whole of npm's excess and most of go's, as the tier-2 README had it.
Two departures from (7) as written, each measured:
- The removal is not the reaper's (ADR 0020 is not built) and not the launcher's: `tego run`, once the run is over
  and its enforcement released, so no fanotify mark of the launcher exists (ADR 0021 (3)), starts `tego
  __uprobe-detach` for every library it was the last to hold, which unpins them off the run's path.
- (9) is amended: the probes stay `ProbeGrace` (2 s) after the last run out, not 0. Removed at once, they were still
  being detached when kill test 4's next run placed its own on the same library, and the kernel made that placement
  wait: pre-attach took 75-340 ms instead of 4-18 ms, and `npm install` 0.87-0.96 s. With the grace, back-to-back runs
  adopt the pinned probes (pre-attach 6-16 ms) and `npm install` takes 0.57-0.60 s, `go build` 0.22-0.26 s. The
  condition (9) set is met: at the 2.4 µs per filtered TLS call it names, 2 s of probes costs a host making 5,000 TLS
  calls a second 24 ms of its time, against 60-320 ms saved per back-to-back run. The grace is a constant, not a
  machine setting.
Kill test 4 at tier cgroup after the change: see test/vm/README.md. Not built: (1)-(6), so a second concurrent run of a
build still has no capture (mechanism-unavailable, `scope`); (8), uprobe_multi, which the off-path removal made
unnecessary for R18 (its gain is now the detacher's time and the grace window's contention, not a run's). What is left
of go's excess is the tier's own: an open at tier cgroup costs about 19-21 µs against 1.3-1.4 µs bare on 6.17 and 6.12
(the fanotify permission round trip, ADR 0021 (1)), about 50 ms over `go build`'s ~2,500 opens, and a run's fixed
start-up about 35-45 ms.

*Amended 2026-09-24 (per-run rings built):* (1)-(6) are built in `bpf/include/maps.h`, `internal/bpf` (ring.go),
`internal/runtime/enforce/cgroup` (rings.go, slots.go), `internal/runtime/observe` and `internal/runtime/capture/uprobe`.
Departures and what was not verified:
- The outers are `BPF_MAP_TYPE_HASH_OF_MAPS`, the fallback (1) names, measured on six kernels; ARRAY_OF_MAPS was not
  measured. Condition to revisit: the matrix measurement of differently sized inner rings in one ARRAY_OF_MAPS outer
  (`TestRingsOfAnySizeGoInTheOuter` does it for the chosen outer, 64 KiB, 1 MiB and 8 MiB, on any row it runs on).
  Both outers and the three per-run counters are declared in every object, so `Prepare` makes a run's capture ring
  before any capture object is loaded.
- `record.ringbuf`'s default is 2 MiB, the upper end of (2)'s expectation, not re-derived from measured sample rates:
  2 MiB holds about 6,500 open records, ten times what an open-heavy build writes in one 50 ms drain interval, and 2,
  8 and 32 concurrent runs each opening a file 3,000 times lost nothing at it in the 6.17 guest
  (`TestIntegrationConcurrentRunsOfOneBuild`). Condition to revisit: the sample rates of kill tests 2 and 4 at
  `record: full` and `summary`, measured on the matrix. The capture ring is sized by `record.ringbuf` too; a
  `record: off` run's record ring is a fixed 256 KiB.
- `bpf.ring_budget` defaults to 256 MiB. `Prepare` accounts under a host-wide flock, `/run/tego/rings.lock`: it
  removes the rings of its own build's slots no live launcher holds and no run-set row carries, sums the fdinfo
  `memlock` of every live inner ring of every build (no separate ledger: the outers are the account), and places the
  record ring, then the capture ring. A record ring over the budget is `ErrRingBudget`; a capture ring over it is left
  out and the run goes on without capture (`Handle.CaptureRefused`), which the runtime refuses, exit 125
  `[capture-unavailable]`, only for a run with a tokens, cost_usd or repeats budget (limits-check-doctor-cli R32).
  Rings of another build's dead launcher stay counted until that build's next `Prepare` reclaims them.
- The probe miss counter (3) is `tego_capture_miss`, a u64 per `run_idx` beside the lost counters, zeroed at `Prepare`.
- (6): a slot any run-set row carries is not handed out, read from the build's pinned run set before the load; plan-row
  inner maps do not exist yet (ADR 0025), and the reaper (ADR 0020) is not built, so the release a dead launcher owes is
  made by the next `Prepare`'s reclaim and `purgeSlot`.
- Verified as root in the 6.17 KVM guest only: the concurrency tests (2, 8, 32 runs, through the recorder and source
  and through `tego run`), a capture: off run beside a capture run (no chunk, misses counted), and `ErrRingBudget`
  at the cap (unit tests over a fake kernel; `TestPlaceRingOnARealOuter` for a ring past its room). Not run: the MATRIX
  rows, the Fedora 7.0 case of samples lost without a count, uprobe detach timings per row, and (8) uprobe_multi.
- Memlock, measured in the 6.17 guest (fdinfo, `TestRingsOfAnySizeGoInTheOuter`): a 64 KiB ring 78,360 B, 1 MiB
  1,065,240 B, 2 MiB 2,117,912 B, 8 MiB 8,433,944 B. So a capturing run at the default charges 4,235,824 B (a record:
  off run 256 KiB and change), 32 of them about 135.5 MB of the 256 MiB default budget, against about 540 MB at the old
  8 MiB. An idle build holds its two outers (328,672 B each, HASH_OF_MAPS of 4096 prealloc) and three counter arrays
  (33,032 B each), about 756 KB, and no ring.

*Amended 2026-09-24:* (7)'s detacher runs in tego's helper cgroup, not the launcher's, and the
probes of a library whose detacher died are removed by the next run's source as it starts, and by a root `tego
doctor` and `tego gc` (ADR 0022's amendment of the same date).

*Amended 2026-09-25 ((6): a slot's rings are reused, not placed and removed per run):* after (1)-(6), kill test 4's go
build at tier cgroup on 6.17 went from 3/20 runs within R18's bound (median 257 ms against a 258 ms budget) to 0/20
(286 ms). The cost is the kernel's, not ours: every update or delete of a map-in-map outer waits for an RCU grace
period (`maybe_wait_bpf_programs`, `synchronize_rcu`). Measured in the 6.17 guest, 20 times each: inserting a 2 MiB
ring into a HASH_OF_MAPS outer 11.5 ms median (3.3-15.8), deleting it 7.6 ms (7.3-15.7), against 0.46 ms to create
the ring, 0.06 ms to read its fdinfo, 0.26 ms to open a reader and 22 µs to delete a slot with none. A capturing run
inserted two rings and deleted two: about 38 ms. The 2 MiB size did not add drops: the kill tests' ledgers carry no
`ringbuf-full` gap, and the wakeup at an eighth full is 256 KiB now against 1 MiB, a few wakeups of a few µs per build.
Decided:
- A slot's rings stay in the outers when its run ends. The slot's next run that needs the same rings reuses them with
  `/run/tego/rings.lock` held shared: it drains them before its run-set row exists (`bpf.DrainRing`), and every
  record carries the generation of the row its program found (`tego_run.gen`, `tego_hdr.gen`, the slot's epoch: one
  more than the slot's previous run's, never 0, kept in the slot table across release, so it repeats only after
  2^31 - 1 runs of that one slot; *corrected 2026-09-30:* this said the low half of the run's own cgroup id, "which the
  kernel never hands out twice", which is wrong, since that low half is an ino from kernfs's cyclic idr and repeats
  once the idr wraps (ADR 0025's security argument)), so its recorder and capture source drop what the
  slot's previous run left or still writes. A ring of another size, or a capture ring a run does not want (the shared
  probes would write its plaintext there), is removed on the run's path, and so is one that cannot be drained. Rings
  stay counted in `bpf.ring_budget` while they wait.
- A build keeps rings at its lowest eight slots (`ringPoolSlots`), which the slot table hands out first; a run above
  them starts `tego __ring-trim` once its slot is free, which removes its build's rings above the pool that no run
  holds, off the run's path.
- A placement (the lock held exclusively) first removes the rings of builds none of whose launchers is running and
  the /run/tego files of builds that are gone (the build lock is removed last, by its exclusive holder, and every
  taker of a build lock checks that its name still leads to the file it holds); when a ring does not fit, every ring
  at a slot no live launcher holds and no run-set row carries, of any build, gives its room back and the use is
  counted again before `ErrRingBudget`. `tego gc --builds` removes every ring no run holds. A ring at a slot a row
  carries is never removed, so a row that outlived its run keeps its tasks recorded, and a program that finds its row
  and no record ring counts the miss in `tego_lost`.
- The walk that counts the rings reads the keys first and opens each ring by id, so a ring removed meanwhile is
  uncounted, not an error; a ring whose memlock cannot be read is an error, never free room.
Rejected: a free list of rings per build moved between slots, which saves nothing, since moving a ring is an outer
update; creating the two rings in parallel, which halves the wait at best and keeps the removals; ARRAY_OF_MAPS,
which waits the same (`maybe_wait_bpf_programs` covers both).
Kill test 4, `VM_ONLY=kt4 VM_KT4_TOOLS=1 test/vm/matrix.sh host debian-13`, go at tier cgroup, baseline / under tego
medians in ms, same host session, before  then after: host (6.17) 183 / 360, 6 of 20 (a loaded run; the
earlier 128 / 286, 0 of 20) against 129 / 256, 3 of 20; debian-13 122 / 350, 0 of 20 against 141 / 317, 0 of 20. What
tego adds per run fell by about 50 ms on both rows (177 to 127 ms, 228 to 176 ms). pip and npm at tier cgroup passed
on the host after the change (20/20 each); on debian-13 npm passed 19/20 and pip missed by one run (18/20, one 5.5 s
run) on a host whose baselines moved by 2x between runs. What is left of go's excess is the tier's own: the fanotify
round trip per open (ADR 0021 (1), ADR 0024) and a run's fixed start.
Verified as root in the 6.17 guest: `TestIntegrationAReusedRingHidesThePreviousRun` (drain, then generation, over the
real objects), `TestRingUseWhileRingsComeAndGo`, `TestReclaimTakesOnlyRingsNoRunHolds`, and the 2/8/32 concurrency
tests; the pool, trim, reuse, replacement and reclaim decisions by unit tests over the fake kernel.

*Amended 2026-09-29 ((6), ADR 0025's row maps; T1, TIER3-PLAN §11):* (6)'s "a slot is reusable only when no ...
plane-row inner map (ADR 0025) ... carries it" is replaced by: a slot is reusable only when no run_set row carries it,
and its plane rows either carry another gen or have been cleared; its rows inner map and exec-rows map stay in their
outers like its rings. The reason is the one the 2026-09-25 note gives for rings: an outer insert or delete waits an
RCU grace period, measured by T0 at 11.8-79.8 ms a run for the row map (79.8 ms on AL2023 6.1's 100 Hz kernel),
against 0.00 ms for a new gen. A row of another gen is absent to the walk, which is exact because a run's rows are
filled before its run_set row is armed (ADR 0025 (1) as amended). No plane-row map exists yet (TIER3-PLAN T6 builds
them); I5's extension no longer names row maps, because stale rows are harmless to the slot's next run.

*Amended 2026-09-29 (ADR 0020 built):* (6)'s prompt release by a reaper is built: a dead launcher's reaper, or a
sweep that removed its scope, purges the verdict rows of every dead launcher's uncarried slot and frees it, and trims
its build's rings above the pool (`cgroup.PurgeRun`); pool rings stay at their slot, as a normal run leaves them.

*Note 2026-09-30:* the reclaim "of any build" above read every build's run-set rows with
this binary's `Run` layout, against ADR 0022 (5)'s keys-only rule for another build. Only the binary's own build now
has its rows' `run_idx` read; another build's run set is read by its keys, and one with any row keeps every ring,
so a later layout can neither delete an orphaned run's ring nor fail the reclaim of its build. An idle build of
another binary, whose run set is empty, still gives all its unheld rings back.

*Amended 2026-10-04 ((8) implemented):* the bounded TLS dispatcher uses two multi links per library when the measured kernel interface is available. Shared adoption validates program IDs, library identity, system-wide scope, return flags and exact offset/cookie pairs under the existing library lock. A partial multi attachment is closed before individual fallback; unsupported kernels retain the required individual programs and existing lifetime behavior. No-read libraries keep their individual path.

Actual scoped 6.17 tests pass both multi and forced individual delivery, concurrent run attribution, exact-once capture, off-run no-ring accounting, shared link adoption, remaining-holder lifetime and last-holder cleanup. The 6.1 test passes ordinary capture after measuring the unavailable multi interface. Generated object and cache load proofs pass on both kernels. These implementation proofs do not replace the final expanded candidate's manual/review/automated acceptance, which is not yet recorded.

*Amended 2026-10-05 (capture-1):* adoption no longer requires the pair's programs to be this run's own program IDs.
Two cold runs of one build each load their own dispatchers (the loser of the program-pin race keeps its own), so
a pair one placed named programs the other's collection did not have, and the other refused the library for its
whole run: a capture gap for every process mapping it, while the shared links would have delivered to it. A pair
is now this build's when each link's program is this run's dispatcher, or has the same type and kernel tag (the
instruction hash with map references zeroed, equal across loads of one object) and reads the same pinned maps
position for position, only a load's own global section differing. A run without the dispatchers still refuses a
multi pair rather than placing individual probes beside it, which would capture every call twice ((7)). A map-pin
race (EEXIST) during the load now retries the whole object instead of dropping the dispatchers for the run's life.
TestIntegrationTLSMultiDispatchAndFallback/separate (two separately loaded collections, no program directory) and
TestMultiProgramsSurviveAMapPinRace cover both.

*Amended 2026-10-19 ((3); limits-check-doctor-cli.md R4, capture-derive R9):* a probe hit of a run
whose run-set row carries `TEGO_RUN_ACTIVITY` (the backend sets it when `stall_after` bounds the run) stamps the
run's slot of `tego_activity`, a pinned per-slot 16-byte stamp (the clock reading and the jiffy it was taken in)
every object declares, before the record mode or the run's
capture ring is looked at: an `SSL_write`/`_ex` that asks to move bytes and an `SSL_read`/`_ex` return that moved
some, in every record mode, so a response streaming for longer than `stall_after` is activity for the run's stall
check whether or not the run has a capture ring. The stamp is one register test, an inlined array lookup and a read
of the jiffies with a compare, and the first call of a new jiffy also reads `bpf_ktime_get_ns` and stores both; it
reads no user memory (trace_proc's same stamp measured +4 to +5 ns an open on 6.17 and 6.1, docs/BENCHMARKS.md). (3)'s rule is
unchanged: a run with no capture ring still gets nothing of its plaintext, and a `record: off` run's call still
returns before any scratch row, chunk number, ring reserve or miss count. The stamp is not a record (no ledger
line, no ring, no plaintext); the run's recorder reads it once a tick. Rejected: a ring sample per call (the wakeups
and ring room the record exists to save, for a reading the stall check takes once a second), a per-CPU slot (4096 ×
CPUs × 16 bytes for a value one load reads), and `cgroup_skb` or socket fentry as the signal (every packet or
every socket call on the host, keepalives included, so `off` would mask stalls `summary` catches).

*Amended 2026-10-19 ((7); capture-derive R4, limits-check-doctor-cli.md R4):* (7) assumed every run
holding a library was a capture run. A `record: off` run whose `stall_after` is bounded now holds the build's probes
too, with no capture ring: its uprobe source pre-attaches the host's libssl and attaches at an exec as a capture
source does, under the same library lock (`LOCK_SH`) and attach-cache reference, so that its TLS calls stamp its
`tego_activity` slot for its stall check ((3) as amended). Nothing in the holder's lifetime depends on a ring: the
lock and the links are the whole of a hold, and the last holder out, ring or none, hands the probes to the detacher
after `ProbeGrace` as before (`TestIntegrationRecordOffStampsWithoutCapture` places, holds and hands them off with no
ring anywhere). The probes' per-call cost for every host process (9) is now paid for an `off` run that has a stall
budget; one without a stall budget, or with `capture: off`, places none. `tego doctor` lists no holders (a library
lock carries no holder's identity), so no listing had to learn a ring-less one.
