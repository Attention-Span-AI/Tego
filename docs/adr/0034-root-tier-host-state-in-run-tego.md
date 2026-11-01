# ADR 0034: root-tier host state lives only in a verified /run/tego

Status: accepted; implemented 2026-09-24: internal/runtime/hoststate (Open verifies root 0700 or root:tego 1770, OpenFile opens relative to the descriptor, never through a link, only regular files, group-shared files in the 1770 form), the tier-2 build lock and slot table use it and runtimeDir is deleted, packaging/tmpfiles.d/tego.conf, /run/tego a contradiction for write entries and read-denied (agent-contract R10, R6a). Condition as built: the doctor host-state row is not added (doctor's report is D1-D8; a ninth row is its own spec change); until it lands, Prepare's refusal carries the tmpfiles line as its fix. Proposed 2026-09-23. Amends ARCHITECTURE §6 (Pins), enforce-cgroup-observe §3 and SEMANTICS §2's implicit entries. Prerequisite of ADRs 0020, 0022, 0025 and 0026.
Amended by ADR 0042 (accepted 2026-10-05): (2)'s root:tego 1770 form is withdrawn and /run/tego is root 0700 only; (5) is superseded (tegod, when a trigger builds it, is root and shares /run/tego).

Decision: (1) At tiers 2 and 3 every piece of host-wide state (build locks, the slot table, capture library locks, the linger timer file, the ring budget ledger of ADR 0026) lives in /run/tego and nowhere else. The per-user fallbacks ($XDG_RUNTIME_DIR/tego, /tmp/tego-<uid>) are removed for these tiers. (2) Prepare opens /run/tego with O_PATH|O_NOFOLLOW|O_DIRECTORY and fstat's the descriptor. Accepted: a directory owned by root with mode 0700 (root launchers; created so if absent), or root:tego with mode 1770, the sticky bit so no member can unlink another's file, provisioned by a shipped tmpfiles.d line for the file-capability path. Anything else (a symlink, another owner, another mode, a directory that cannot be created root 0700) fails Prepare with ErrHostState, and doctor prints the tmpfiles line. (3) Every file under it is opened relative to that verified descriptor with O_NOFOLLOW|O_CLOEXEC; lock files are never unlinked (tmpfs clears them at boot). (4) /run/tego joins the implicit entries never writable from inside a run, and compile reports a write entry that covers it as a contradiction. (5) A non-root tegod (P3) brings its own verified directory; that is its condition, not a fallback for launchers.

Why: [documented, code: internal/runtime/enforce/cgroup/pins.go:134-154] runtimeDir tries /run/tego, then $XDG_RUNTIME_DIR/tego, then /tmp/tego-<uid>, creating each with MkdirAll and accepting the first writable one with no owner or symlink check; the build lock and the slot table (backend.go:207-220, openSlotTable(runtimeDir())) live there.
[documented, ARCHITECTURE §16] The file-capability path runs as the invoking user with cap_bpf,cap_perfmon,cap_sys_admin and no DAC override, so it cannot write a root-owned /run/tego and always falls back.
[inference] Two users' launchers of one build then hold different build locks and slot tables: each can judge itself last out and unpin under the other's live run, and both can be handed the same run_idx, which ADRs 0025 and 0026 make the key of plane rows and rings. /tmp/tego-<uid> can be pre-created or symlinked by another local user.

Security argument: Fail-closed by construction: state that cannot be verified refuses the run instead of splitting the locks, so 'last out' and slot uniqueness are true host-wide. The sticky bit and O_NOFOLLOW stop tego group members replacing each other's files; a member can still hold a lock and deny service, which fails closed (ErrBuildLock) and stays within the trust the group already implies.

Options considered: Rejected:
- Keep the per-user fallback: it is the defect.
- A per-user fallback with owner checks: still two lock files and two slot tables for one build.
- CAP_DAC_OVERRIDE on the file-capability copy: widens every file access of the binary.
- root:tego 0770 without the sticky bit: members could unlink each other's lock files; refined to 1770.

Consequence: File-capability installs need the tmpfiles line and the tego group; doctor names both. Root launchers see no change. The live lock-splitting defect closes before ADRs 0020-0026 build on the lock and slot table.

Implementation plan:

- New package internal/runtime/hoststate: Open() returning a verified sys.FD (ADR 0023) with item (2)'s checks, plus OpenFile and Lock helpers relative to it. enforce/cgroup pins.go and slots.go and capture/uprobe's library locks use it; runtimeDir is deleted.
- packaging/tmpfiles.d/tego.conf: d /run/tego 1770 root tego -; OPERATIONS.md install steps for the file-capability path (the tego group and membership).
- doctor row host-state: path, owner, mode, verdict.
- pkg/spec/agent compile: /run/tego among the implicit entries.
- Tests: unit tests over a fake directory for each outcome. As root in GUEST: a symlinked /run/tego refuses Prepare; a 0755 or user-owned one refuses; a tmpfiles-provisioned 1770 root:tego directory with a file-capability copy (setcap in the guest) runs tier cgroup; two uids' concurrent runs of one build get distinct run_idx and share one lock file; SIGKILL of one user's launcher never unpins under the other's live run (bpftool link shows the links until both runs are gone).
Docs: ADR 0034; ARCHITECTURE §6 Pins; enforce-cgroup-observe §3; SEMANTICS §2 implicit entries; identity-config (the tego group); OPERATIONS.

Note 2026-09-29: (3)'s "lock files are never unlinked" no longer holds for one case, which ADR 0026 (6) as amended added. The build lock of a build whose pins are gone is unlinked, last of its files, by the process holding it LOCK_EX|LOCK_NB after it checks again that the pin directory is gone (internal/runtime/enforce/cgroup/statefiles.go removeBuildState). A launcher that opened the old file just before keeps its LOCK_SH only if the lock's name still leads to that file (hoststate.Dir.Names in pins.go acquireBuildLockIn), and otherwise opens it again, so two launchers never hold different lock files of one build (TestABuildLockWhoseNameWasRemovedIsTakenAgain). Last-out still never unlinks the lock of a build it unpins. docs/p0/runtime-launch.md §3 and R16 state this.

Note 2026-10-05: a second case, by the same protocol. doctor.ForRun's run-probe flight locks (/run/tego/doctor-probe-flights, one per full run-probe cache key, at most 128) are not host-wide state of a tier, but they are lock files under /run/tego. When a new key meets the limit, the caller holding the admission lock unlinks lock files no one holds, each while holding it LOCK_EX|LOCK_NB and after checking its name still leads to it; a caller that then takes a lock whose name is gone or leads elsewhere opens the name again (internal/doctor/runcache_flight.go reclaimFlights, acquireFlight; TestRunProbeFlightReclaimsUnheldLockFilesAtTheLimit, TestRunProbeFlightTakesAReclaimedNameAgain). docs/p0/limits-check-doctor-cli.md §3 and R27 "Concurrent misses" state this.

*Amended 2026-10-05 (ADR 0023's acceptance note, correction of fact):* `Open()` "returning a verified sys.FD" is not
yet true: `hoststate.Dir` holds a bare number, and its `Close` clears it non-atomically. It becomes true at ADR 0023
C12, when `Dir` holds a verified `*sys.FD` and `Dup` becomes the owner's `Dup()`.

*Amended 2026-10-05 (ADR 0042 (3)(b)):* (2)'s root:tego 1770 form is withdrawn. No launcher used it: a
file-capability copy is refused at start (ADR 0042 (3)(a)), and the form handed root's slot tables and locks to every
member of the group, who could rewrite or lock them, or create `slots-<hash>` or a lock before root did, since
`OpenFile` accepted a regular file of the name whoever owned it. `hoststate.Open` now accepts root 0700 only and
refuses 1770 with `ErrHostState` and the fix `chmod 0700 /run/tego && chgrp root /run/tego` (remove any tego
tmpfiles.d line); `packaging/tmpfiles.d/tego.conf` is deleted; `OpenFile` refuses a file whose owner is not the
effective uid, which closes the "create the name first" class even if the directory check regresses
(`TestVerifyHost`, `TestOpenFileRefusesAFileAnotherUIDOwns`, and in the guest
`TestRootLauncherRefusesGroupHostState`). (5) is superseded: tegod, when a trigger builds it, is root and shares
`/run/tego` with sudo launchers (ADR 0042 (7)(b)). The Consequence's "file-capability installs need the tmpfiles
line and the tego group" no longer applies.

*Amended 2026-10-19 (ADR 0023 C12 built):* the 2026-10-05 correction above is resolved: `hoststate.Dir` holds a
verified `*sys.FD`, `Dup` is the owner's `Dup()`, and `Close` closes once, so a racing Close is a no-op and a use
after it is `sys.ErrClosed` (`TestDirClosesOnceAndLendsNothingAfter`, `TestDirUnwindsLeaveNoDescriptor`).
