# Adoption admission regression recipe

These checks are owed in a guest. They are merge conditions. Use a
fresh disposable Ubuntu 6.17 guest with writable PREEMPT_DYNAMIC controls,
`preempt=voluntary`, debugfs mounted, no preemption waiver and two vCPUs. Use both
its default LSM list and its BPF-enabled LSM list. Force fmod_ret for this check,
including on the BPF-enabled boot. Do not run this procedure on the host.

Keep `TestIntegrationGuardBoundaryRechecksLiveFmodRetAdmission` as the startup
case. It switches to full preemption before starting the agent; it establishes
that a guard does not retain its startup probe answer for later backend selection.
It does not establish the two timing cases below.

Build the CLI fixture with `tegobpf,tegotesthooks` and the CLI integration test
binary with `integration,tegobpf`. Follow the resource and isolation rules in
`test/vm/README.md`: one build at a time, at most 3G guest
memory, and isolated config, own-log and chain
paths inside the guest. Record the fixture revision, source-overlay hash, guest
status, harness status and raw QEMU status. A skip, timeout or lost guest is not a
passing result. No build or guest execution of these new timing cases is claimed.

## Admission changes after selection, before Arm

Use the existing startup test's disposable-agent, contract, guard, owner and
preemption-control fixtures. Add a test-only source overlay barrier to the guard's
selected backend: pause at the beginning of cgroup `Handle.Arm`, before its live
admission read or any run-set insertion. The overlay only signals arrival and
waits for release; it must not change the selection, admission, error, cleanup or
migration code. The barrier records the actual handle's selected mode, rather
than trusting the environment's requested mode. Bound the wait by the test context
and always release it on failure. Build and retain the test-only overlay separately
from the product fixture.

1. Set voluntary preemption. Prove doctor selects fmod_ret, reports voluntary and
   has `preempt_waived=false`. Start the guard and its agent while still voluntary.
2. Wait for the Arm barrier and require `selected=fmod_ret`. This proves selection
   and preparation happened before the change. The runtime's additional
   check immediately before calling Arm has also passed by this point: the
   barrier is inside Arm, before its own check. The agent's original cgroup is
   still unchanged.
3. Set full preemption and reread the mode file to require `(full)`. Prove doctor's
   fmod_ret row is refused for preemption, with `tested=false` and `faulted=false`.
4. Release the barrier. Require watcher `adoption_failed`, no `adopted` event, and
   a note with the exact product prefix
   `runtime: arm cgroup: cgroup: selected fmod_ret mode is no longer admitted: doctor: this kernel preempts kernel code (preemption full, from `.
   The remaining source field is the guest's live-preemption source, followed by
   the product's trampoline-skip explanation; retain the complete note.
5. Require the agent alive in its exact original cgroup. Inspect the failed run's
   prepared scope, pinned run-set membership, slot rows, run lock, adoption record
   and live index; all state owned by the failed adoption must be removed. A
   shared build's harmless linger pins are not a surviving run and are recorded
   separately. Stop the guard and restore/read back the original preemption mode.

Expected test lines, printed only after the assertions above:

```text
POST-SELECTION-ADMISSION selected=fmod_ret preempt=voluntary waived=false
POST-SELECTION-ADMISSION changed=full event=adoption_failed
POST-SELECTION-ADMISSION agent-alive=true original-cgroup=true moved=0
POST-SELECTION-ADMISSION run-rows=0 slot-rows=0 scope-absent=true adoption-record-absent=true live-index-absent=true
--- PASS: TestIntegrationGuardBoundaryRejectsAdmissionLostAfterSelection
```

## Admission changes while waiting for migration

Repeat with a test-owned exclusive flock on the verified host-wide adoption move
lock (`adoptStore.lockMoves`), acquired before starting adoption. Use a test-only
barrier at the entry to `lockMoves`, before its flock call, to report that the
actual prepared handle has finished Arm in fmod_ret mode. Keep the flock held
until the test sees that barrier. This observation must come from the adoption
under test; a startup message or an arbitrary sleep is insufficient.

While the lock is held, switch voluntary to full, verify `(full)`, then release
the barrier and flock. The last admission function must reread preemption after
acquiring the lock and before the first process movement. Require a note with the exact product prefix
`runtime: no decision plane decides this contract for an adopted process: live plane admission before adoption: cgroup: selected fmod_ret mode is no longer admitted: doctor: this kernel preempts kernel code (preemption full, from `,
then the same live source and explanation. Require the same cleanup checks as above. The armed run-set row must disappear
when the failed adoption closes. Expected lines:

```text
POST-LOCK-ADMISSION armed=fmod_ret lock-held=true preempt=voluntary
POST-LOCK-ADMISSION changed=full event=adoption_failed
POST-LOCK-ADMISSION agent-alive=true original-cgroup=true moved=0
POST-LOCK-ADMISSION run-rows=0 slot-rows=0 scope-absent=true adoption-record-absent=true live-index-absent=true
--- PASS: TestIntegrationGuardBoundaryRejectsAdmissionLostDuringMigrationWait
```

For each timing case, retain an overlay negative control that removes only its
live recheck. The test must fail at that seam's expected refusal-prefix assertion.
Removing only Arm's check still leaves final admission intact: expect the later
`runtime: no decision plane decides this contract for an adopted process: live plane admission before adoption:`
refusal, cleanup and no movement. Do not require an adopted event for that negative.
Removing only the final migration check permits an `adopted` event or observed
movement; record it, then release and clean up the adopted agent before the test
ends. Do not confuse an expected assertion failure with guest loss.
The existing startup case must still pass unchanged. Real network-mounted homes,
governed layer edits and nonempty-baseline acceptance remain separate guest rows;
these timing checks do not accept nonempty-baseline launches.

## Direct kernel fixture admission model

Direct cgroup kernel tests do not select their backend through doctor. Their
`testPlaneAdmission` callback explicitly models an admitted mode so row, fill and
cleanup tests retain their existing purpose, including when the suite enables its
preemption waiver. This callback is a test fixture only and returns success; it
is not evidence of live product admission. The ordinary product selection path
always obtains its callback from doctor. `TestPreparedPlaneAdmissionReadsLivePreemption`
checks that doctor's callback rereads full and unknown preemption, while
`TestFmodRetAdmissionRequiresLiveChecker` requires refusal when a prepared fmod_ret
handle has no callback. The two guest timing cases above must exercise the
product callback, never the direct fixture's admission model.
