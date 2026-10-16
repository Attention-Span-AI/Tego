# ADR 0032: SECBIT_EXEC_RESTRICT_FILE is not set by default

Status: accepted 2026-10-19 (proposed 2026-09-23); the detector implemented 2026-10-19.

Decision: The child stage does not set SECBIT_EXEC_RESTRICT_FILE or its lock bit. Condition to revisit: a released version of a mainstream interpreter (CPython, bash or dash, Node) on a matrix row checks scripts with AT_EXECVE_CHECK, shown by an ADR 0017 cell. The bit then becomes an opt-in contract field, exec: {scripts: execute}, recorded as a cooperative narrowing and never as enforcement.

Why: [documented, from kernel source] AT_EXECVE_CHECK and SECBIT_EXEC_RESTRICT_FILE arrived in 6.14; security/commoncap.c lets an unprivileged process set them because they are 'not restrictions enforced by the kernel but by user space on itself'. [inference] Interpreter adoption was not verified. Setting the bit turns SEMANTICS §4's 'sh tool.sh needs only READ_FILE' into 'needs EXECUTE' for any interpreter that implements the check: a semantic change with no guarantee behind it. ADR 0024 closes script and loader execution race-free at tiers 2 and 3.

Security argument: Nothing is weakened: the bit is not a control today. Tier 1's script execution stays best-effort, as SEMANTICS §4 states, and the revisit condition is detected by a cell rather than remembered.

Options considered: Rejected:
- Set the bit by default at tier 1: changes semantics for cooperating interpreters and enforces nothing against the others.
- Set the bit and record the result as enforcement: false, per the kernel's own comment.

Consequence: Tier 1 keeps its stated best-effort limit for interpreted scripts. The option is re-evaluated automatically once an interpreter adopts the check.

Implementation plan:

No code now. ADR 0017's second space (exec) adds a cell that probes whether the interpreters on each matrix row honour AT_EXECVE_CHECK (run a script under a domain without EXECUTE on it, with the bit set in a test-only stage, and record whether the interpreter refuses). Docs: ADR 0032; SEMANTICS §4 references it.

## Implementation notes

- 2026-10-19 (ADR 0017 space 2): accepted as decided, and the detector built.
  `test/conformance` `TestExecveCheckDetector` runs, in one governed run per tier the machine offers (tier landlock
  always, unprivileged too; tier cgroup on the listener as root), the actor's two halves on an empty script the
  domain grants no `EXECUTE`: the kernel half, `execveat(fd, "", AT_EMPTY_PATH|AT_EXECVE_CHECK)`, must refuse with
  `EACCES` from 6.14 and never exec below, where the flag is unknown (`EINVAL`) unless the run's supervisor refused
  the unlisted script's execveat first (`EACCES`, as on AL2023's 6.1); the interpreter half runs each of bash, dash, python3
  and node present on the row on the script twice, without the bit (the control, which must run it) and after the
  actor's own stage set `SECBIT_EXEC_RESTRICT_FILE` on itself (unprivileged, as commoncap.c allows). An interpreter
  that refuses the script with the bit and runs it without fails the test with "ADR 0032 revisit condition met"
  and its version: the revisit is detected, not remembered. Below 6.14 the kernel refuses the bit and each result is
  logged `n/a`, an explicit pass, never a skip. A self-test interpreter (the actor under the name `check-interp`,
  which asks the kernel as an honouring interpreter does) must be detected wherever the kernel has the check, so
  the detector cannot go blind. `TestChildNeverSetsExecRestrictBits` reads `PR_GET_SECUREBITS` in the agent at tier
  landlock and tier cgroup and holds bits 8-11 clear. Both are in `test/vm/root-must-pass.txt`. First result, Linux
  6.17 (Ubuntu 25.10): bash 5.2.37, dash, Python 3.13.7 and Node 20.19.4 each ignore the bit; on AL2023's 6.1 (the
  al2023 row, both boots) the kernel refuses the bit and every result is n/a. Departure from the
  plan: the detector is a test of its own rather than a table cell, since its verdict is
  a fact about the row's interpreters and not an allow or a refusal any column could hold, and it adds no baseline
  entry; it runs at tiers landlock and cgroup, where the interpreter half is the same and the kernel half is
  Landlock's `EXECUTE` floor, which every tier installs.
- 2026-10-19: the kernel half above was not the kernel's. The
  script was mode 0644, so the file mode alone refused it, and it was outside exec.allow, so the supervisor's exec
  arm refused its execveat (`source=seccomp`, rule unmatched) before the kernel's check ran; the same EACCES came back
  on every kernel. Both scripts are now 0755 and the detector has two halves. The run half is the unlisted script:
  the run must refuse its execveat(AT_EXECVE_CHECK) with EACCES on every kernel (the supervisor answers first,
  Landlock's `EXECUTE` floor stands behind it), which is what a checking interpreter meets. The kernel half is a
  script exec.allow lists, which the supervisor lets through: from 6.14 the kernel's check must pass it without an
  exec, and below 6.14 the kernel must refuse the unknown flag (EINVAL, logged n/a). A refusal by Landlock itself
  cannot be reached in a governed run, since the supervisor and the Landlock plan both grant exactly exec.allow; the
  "Landlock's `EXECUTE` floor" wording above is corrected to this. First result, 6.17 tier landlock: run half EACCES,
  kernel half passes, the self-test detected, bash, dash, Python and Node ignore the bit.
