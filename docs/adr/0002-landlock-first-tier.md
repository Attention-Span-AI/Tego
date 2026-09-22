# ADR 0002: Landlock is the first enforcement tier, BPF LSM the hardened tier

Status: accepted 2026-09-21.
Superseded in part by ADR 0011 (a `cgroup` middle tier between this tier and BPF LSM). Amended by ADR 0024 (accepted 2026-09-29; the BPF LSM tier is built as one attach mode of the kernel decision plane; step A, the tier-2 plane backend, the `bpflsm` tier wiring and step D are built; steps B, C and E are not; as of 2026-10-04 all of steps A to E are built, per ADR 0024's Status).
Amended in part by ADR 0040 (accepted 2026-10-05): a contract whose write entries contain a built-in `deny_write` target needs a kernel decision plane, so tier 1 refuses it before launch.
That amendment is superseded by ADR 0041 D1 (a) (accepted 2026-10-05): tier 1 runs such a contract by default, with the supervisor's best-effort refusal disclosed, and refuses it only under `fs.assurance: kernel`.
Decision: every run applies Landlock (unprivileged, no boot parameter). BPF LSM programs are applied in addition where `bpf` is in the active LSM list and the launcher has CAP_BPF. The backend capability matrix (`spec/backend`) records which tier ran.
Why: the developer's own machine and stock Ubuntu ship without `bpf` in the LSM list; the standard must run on day one.
Consequence: host-level network deny, exec-by-name and reason strings are hardened-tier features and are reported as absent, never silently.

Amended 2026-09-21: (a) a Landlock domain with filesystem rights refuses mount and pivot_root, so rootless container tools and bubblewrap-based sandboxes do not start inside a run in this tier; `containers: rootless` is a root-tier flag (GAPS A8). (b) Attach never fails when `bpf` is absent from the LSM list: the program attaches and never executes; the only reliable signals are `/sys/kernel/security/lsm` and dmesg, and doctor builds the boot line by appending `,bpf` to the currently active list. (c) Host-level network deny is also an unprivileged-tier property through supervisor-completed connects (ADR 0008 as amended). (d) Superseded in part by ADR 0011: a `cgroup` middle tier (root, no boot change) sits between this tier and BPF LSM.
