# ADR 0150: The capture programs keep their own stack

Status: **accepted 2026-11-12; amended 2026-11-12 after review**. The first version used a dead tail call and was
tested in KVM guests as described below. The amendment makes the call live and checks the instructions read back
from the kernel. Eight x86-64 kernel rows now pass loading, read-back and capture availability with a disclosed
dump-only test overlay. The stock check's guest rerun on RHEL 9 and Fedora 7.2 and arm64 acceptance remain **owed
in a guest**. Integration assigned ADR 0150 and GAPS C76; all references use those numbers.

## Context

The hosted kernel matrix of 2026-11-12 (run 43152191607, public main f8efe5c) failed on the Fedora 7.0 row with the
BPF LSM active: one of 32 concurrent `tego run --tier cgroup` of one build, each with a token budget and
`capture: uprobe`, ended with exit 125, reason `error`. The run's ledger, printed by the test, says
`capture: 1 model exchanges spent tokens no budget could count (a request's response was never seen before its
connection closed)`: capture lost the response, and a budget that cannot see spend ends the run (limits R1, by
design). The question was why capture lost it.

Measured in KVM guests with `TestTier2ConcurrentRunsOfOneBuild` (2560M, 4 vCPUs, the hosted settings), the same
build on several kernels:

| Kernel, preemption | Rounds of 32 | Rounds with a failed run | Runs ended exit 125 | Agents killed by a kernel fault |
|---|---|---|---|---|
| Fedora 7.0.14-201.fc44, lazy, 1 exchange per agent (the hosted test) | 69 | 1 | 1 | 0 |
| Fedora 7.0.14-201.fc44, lazy, 40 exchanges per agent | 11 | 9 | 11 | 7 |
| Fedora 7.2.9-300.fc45, lazy, 40 exchanges | 2 | 1 | 0 | 1 |
| Ubuntu 6.17.0-41-generic, voluntary, 40 exchanges | 9 | 0 | 0 | 0 |
| the same 6.17 booted `preempt=full`, 40 exchanges | 1 | 1 (17 of its 32 runs) | 11 | 6 |

The guest kernel log (`/dev/kmsg`) showed `BUG: kernel NULL pointer dereference, address: 0000000000000038` and
`general protection fault, probably for non-canonical address 0x706f7473222c5db5`, with
`RIP: __bpf_ringbuf_reserve+0x1e`, called from `bpf_prog_..._tego_ssl_multi_return` under
`uprobe_multi_link_ret_handler` and `uprobe_handle_trampoline`. The ring pointer was `0x706f7473222c5d7d`, whose bytes
spell `}],"stop` from the fake model reply; the helper faulted while reading at that pointer plus `0x38`. The capture
losses that did not crash had the same shape: a request record whose head carried cgroup id 1045328160 while its
response carried the run's own, a read whose 303 bytes were reported unreadable, a lost-chunk count with no entry
row left behind. After a fault, observed tasks blocked in SRCU grace periods (`uprobe_unregister_sync` and
`perf_event_detach_bpf_prog` in `__synchronize_srcu`), and later `tego doctor` tasks hung for the observation period.
The regression test now requires readable, complete kernel-log evidence; inability to read it is not a clean log.

The mechanism was read in `kernel/bpf/verifier.c` (7.0.14 and mainline as of 2026-11-12): `bpf_enable_priv_stack`
returns `PRIV_STACK_ADAPTIVE` for `BPF_PROG_TYPE_KPROBE` programs. With a supporting JIT, `check_max_stack_depth`
can give a program whose stack reaches `BPF_PRIV_STACK_MIN_SIZE` (64 bytes) a per-CPU private stack. Ordinary kprobes
exclude overlapping execution through preemption and recursion protection. Uprobe and uprobe_multi programs have
the same type but run in the traced task with migration off and preemption allowed (`kernel/trace/bpf_trace.c`
`uprobe_prog_run`). Two tasks interleaved in the same program on one CPU can then overwrite each other's locals.
This needs a kernel with the private-stack feature, a supporting JIT and a preemption mode that permits this
interleaving. Fedora's measured lazy default was exposed. Ubuntu 6.17's measured voluntary default did not show the
interleaving; the same kernel booted `preempt=full` did. Upstream kernels before 6.13 lack the feature; vendor
backports must be considered separately.

The inspected objects before the amendment have these deepest direct stack accesses, measured within each ELF
function's symbol span rather than across a whole section. They are BPF byte offsets, before JIT rounding:

| Program | x86 bytes | arm64 bytes |
|---|---:|---:|
| `tego_ssl_write` | 96 | 96 |
| `tego_ssl_write_ex` | 104 | 96 |
| `tego_ssl_read` | 64 | 64 |
| `tego_ssl_read_ex` | 64 | 64 |
| `tego_ssl_read_return` | 104 | 104 |
| `tego_ssl_free` | 32 | 32 |
| `tego_ssl_multi_enter` | 136 | 136 |
| `tego_ssl_multi_return` | 104 | 104 |

After regeneration with pinned clang 20.1.8, the live-call objects have the same depths except x86
`tego_ssl_multi_enter`, whose deepest direct access is 152 bytes. These remain byte offsets before JIT rounding.

The source mechanism, preemption comparison, corrupt metadata, reply bytes in a ring pointer and successful stack
workaround strongly support this diagnosis. Those observations alone are not unique proof: a Tego race can depend
on preemption, and a JIT spill bug, helper overwrite or lifetime defect could fit parts of them. A verified program
must not fault the kernel. The workaround addresses the identified private-stack collision.

## Decision

1. **Every capture program attempts a live tail call.** Each of the eight programs in `bpf/uprobe_ssl.bpf.c` starts
   with `TEGO_OWN_STACK`, an unconditional `bpf_tail_call` into an empty program array. Its empty slot makes the call
   fail and execution falls through to capture. In the inspected kernels, `check_max_stack_depth` gives no private
   stack to a program that contains a tail call. A live call cannot be removed as dead code, so this no longer
   depends on whether the kernel chooses the stack before or after dead-code removal. It costs one failed tail call
   per probe hit, including hits from processes outside a governed run. The measured increment is within noise
   in the Fedora 7.0 comparison below. This does not establish a zero runtime cost.
2. **One empty program array per attach type.** A program array accepts programs of one expected attach type
   (`kernel/bpf/core.c` `__bpf_prog_map_compatible`): the six single programs name `tego_ssl_ownstk`, the multi pair
   `tego_ssl_ownstkm`. One shared array caused the first experiment's multi programs to fail loading beside the
   single programs, so that experiment used single probes and did not prove the multi case. Both arrays are pinned
   behind the existing root-only build directories. Tego never populates them. Host root could populate a pinned
   array; governed agents gain no new write path.
3. **Each program's body is its own inline function** (`tego_ssl_write_body` and the rest). The single program and
   multi dispatcher share the body, and each entry program makes its own live call.
4. **The ELF remains the cheap first check.** `TestCaptureProgramsKeepTheirOwnStack` reads both architectures'
   objects and checks that every capture program carries a tail call naming the correct array. It does not show
   what a kernel retains after loading or which stack its JIT uses.
5. **The loader checks each loaded or adopted capture program.** It reads translated instructions through program
   info and requires the tail-call instruction to remain. If reading fails or the call is missing, uprobe capture
   is unavailable through the existing mechanism-unavailable path. An omitted `capture` or `capture: auto` keeps
   the forwarder selected beside it. Existing budget refusals still apply when direct traffic would be unmetered.
   Explicit `capture: uprobe` with recording enabled is refused at start with the reason, and `tego doctor`
   reports the same reason, including an optional dispatcher whose read-back fails. No deciding or tracking program depends on this check.
6. **Every kernel row must prove acceptance.** A root guest invariant loads all eight programs, reads the call back
   from each and requires uprobe capture to be offered. It belongs to the row suites for RHEL 9 5.14, 6.1, 6.8, 6.12,
   6.17, 7.0 and 7.2. All eight x86-64 rows passed with a dump-only test overlay, as recorded below. The stock
   exporter rejected kernel-translated helper offsets on all eight rows after loading and the invariant check.
   The overlay preserved the library's raw read-back bytes; it changed no loading, scanning or production check.
   The corrected exporter preserves numeric translated helper offsets instead of resolving them as helper names.
   Permanent host tests round-trip all 64 authentic dumps and run them through the existing scanner, alongside
   the small synthetic failure controls. This host proof does not replace the corrected stock check's guest rerun
   on RHEL 9 and Fedora 7.2, which remains **owed in a guest**. Arm64 acceptance also remains **owed in a guest**.
   Amazon Linux 6.1 lacks native multi-uprobe support: the test loads the two dispatcher bodies with expected
   attach type `NONE`, and production uses the six individual programs. That is not native multi acceptance.

## Why not

- **Refuse uprobe capture on every kernel that preempts kernel code** (as ADR 0024 (16) does for the fmod_ret
  plane mode). This would remove direct TLS capture on exposed hosts. Forwarder capture would remain a source for
  model budgets where the agent uses it. The live call keeps direct capture available when its loaded instruction
  invariant can be established, rather than excluding all such hosts.
- **Shrink each program's stack below 64 bytes.** The ring pointer, scratch row and key use stack space, as do
  compiler spills. A later edit could cross the threshold again. The ELF check and loaded call instead cover
  every capture program, including ones currently below that threshold.
- **Keep the dead call.** The first workaround relied on verifier pass ordering. Its ELF test could pass while a
  kernel removed the call before stack selection and restored the unsafe private stack. Removing the dead call
  also did not prove zero runtime cost: a guard load could still run. The live call removes that ordering dependency
  and gives the loader an instruction to require after loading.
- **Sleepable programs.** The inspected verifier's KPROBE private-stack classification does not distinguish
  sleepable uprobes, and sleepability does not exclude interleaving.

## Consequence

- The earlier dead-call workaround had no capture failures or reported kernel faults in the observed forty-exchange loops:
  6 of 6 rounds on 6.17 booted `preempt=full`, and 9 of 9 on Fedora 7.0.14. Before it, 17 of 32 runs failed in the
  first 6.17 full-preemption round and 9 of 11 Fedora rounds failed. The committed one-exchange test had 45 rounds
  with no run ended by capture and no reported kernel fault; two rounds failed on GAPS C53 (c)'s exec skip. These
  are historical results for the dead-call design. The separate amended live-call results below establish
  acceptance and observed runtime behavior; the earlier rounds do not establish those properties.
- This fix covers the private-stack collision, not every capture loss. Ring exhaustion, unreadable buffers and
  the other capture limits in `docs/GAPS.md` remain. Capture supplies token, cost and repeat budget evidence
  and activity for stall checks, even though its BPF programs do not grant or refuse calls.
- The inspected deciding and tracking programs do not expose the same unprotected private-stack collision:
  program types, load flags or runner recursion protection exclude it. That is a conclusion about this mechanism,
  not assurance of kernel integrity after an oops. A host kernel fault can affect people whose own runs use another
  capture mechanism; later doctor calls and probe removal can hang.
- The tail-call exclusion is an internal kernel rule, not an ABI promise. Reading back a live call proves its
  presence, not the JIT's private-stack state. A future kernel that changed the exclusion rule would need a fresh
  assessment. Older upstream kernels lack private stacks but still execute the failed call; their measured
  acceptance is recorded below, with the same limits on untested kernels.
- The underlying kernel defect remains for other exposed uprobe programs. Tego has no production uprobes besides
  these eight. Its guarded tracing programs can instead skip overlapping execution (ADR 0148).

## Amended live-call evidence, 2026-11-12

The source under test was `353d5ce4a172bf9e6dfbab6047443f73c55ccb6b`. Each row loaded all eight bodies,
retained the call in every read-back, passed fresh and adopted production collections, attached all six doctor
capture probes and offered uprobe capture. Every final guest status and harness exit was zero, with no nested
skip. The stock dump encoder failed on all eight rows; these passes used the disclosed dump-only test overlay.
The 64 byte-preserving fixtures and their kernel, preemption, attach-type and console digests are committed under
`internal/bpf/testdata/capture-stack/`. They do not claim the stock guest command is green.

| Row | Actual kernel | Preemption |
|---|---|---|
| RHEL 9 | 5.14.0-687.53.1.el9_8.x86_64 | voluntary |
| Amazon Linux 2023 | 6.1.188-233.386.amzn2023.x86_64 | none |
| Ubuntu 24.04 | 6.8.0-146-generic | voluntary |
| Debian 13 | 6.12.107+deb13-amd64 | voluntary |
| Amazon Linux 2023 6.12 | 6.12.110-135.202.amzn2023.x86_64 | none |
| Ubuntu 25.10 | 6.17.0-41-generic | voluntary |
| Fedora 7.0 | 7.0.14-201.fc44.x86_64 | lazy |
| Fedora 7.2 | 7.2.9-300.fc45.x86_64 | lazy |

The amended concurrent regression passed 9 of 9 full rounds on Fedora 7.0 lazy and 6 of 6 on Ubuntu 6.17
booted `preempt=full`. Each full round exercised 2, 8 and 32 agents with forty exchanges per run: 25,200 exchanges
across 630 runs, with zero kernel faults, capture losses or capture-caused run errors. All 45 per-subround kernel-log
windows and 15 whole-guest logs were readable. The two outer root-suite commands returned 1 because their plain
binaries skipped the kernel test without BPF objects. Only the tagged test passes supply this evidence; the complete
harness is not claimed green. This supports the workaround on those two exposed kernels, not all future kernels.

`TestIntegrationRecordOffTLSCallCost` compared the dead-call base `bf663b7a5` with the live-call source in separate
fresh Fedora 7.0 guests (lazy, four vCPUs, 2560M), once per build. Each passed nine rounds with three alternating arms
and 3,000 TLS round trips per arm, recording 9,001 actual probe hits per sample. Values are BPF program runtime per
actual hit, not TLS wall time or complete trap cost:

| Arm | Base median; min to max, ns/hit | Live-call median; min to max, ns/hit |
|---|---|---|
| Outside every run | 147.12; 139.06 to 160.65 | 118.31; 104.87 to 166.95 |
| Record off, no activity stamp | 164.56; 154.37 to 188.44 | 154.59; 124.85 to 182.08 |
| Record off, activity stamp | 182.97; 156.91 to 251.44 | 168.39; 132.23 to 189.80 |

The incremental live-call cost is **within noise**. Round spreads exceed median differences; the lower head samples
establish no speedup or nanosecond saving. These were within-invocation rounds, not repeated independent benchmark
invocations, and shared-host scheduling and CPU state were not tightly controlled.

In the same Fedora 7.0 guest, `net.core.bpf_jit_harden=0` and `kernel.kptr_restrict=1` permitted read-back. Setting
both to 2 still allowed all eight bodies to load but withheld their translated instructions. Uprobe capture became
unavailable. Doctor kept the bpflsm tier and 27 of 27 required hooks; its capture summary said `0 of 6 programs load`
and attachment not tested, reflecting availability after read-back rather than a verifier refusal. Explicit
`capture: uprobe` with `record: full` exited 125 before agent release. With a declared model endpoint and no model
budget, `capture: auto` started the forwarder, exited zero and recorded one count-zero capture/mechanism-unavailable
gap for uprobe. Direct traffic bypassing the forwarder is not proved visible. The remedy is forwarder capture with
a declared endpoint, or relaxing the blocking setting if the host owner accepts it. Host hardening is respected,
never bypassed. Other privilege or visibility denials remain unavailable through the same check.

Full consoles, statuses, overlays and runtime samples are retained as external evidence.
The committed fixture manifest records their source-console names and SHA256 digests.
The [VM runbook](../../test/vm/README.md#loaded-capture-stack-invariant) gives the exact corrected stock reruns still
**owed in a guest** on RHEL 9 and Fedora 7.2. Arm64 kernel acceptance and the integrated hosted matrix remain owed.
