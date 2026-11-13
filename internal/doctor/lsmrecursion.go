// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"bytes"
	"os"
	"sync"
)

// LSM programs and the trampoline's recursion check (ADR 0148, GAPS C53). An LSM-mode plane program is attached
// through the BPF trampoline. Upstream from 6.2, and in the 6.1 stable series from 6.1.54, the trampoline enters an
// LSM program with no per-CPU recursion check (bpf_trampoline_enter picks __bpf_prog_enter when bpf_prog_check_recur
// is false, which it is for BPF_PROG_TYPE_LSM); __bpf_prog_enter_recur, the entry that does check, exists from the same
// change. Before it (6.1.0 to 6.1.53, 6.0, 5.19, and the 5.15 series, which never took it) every trampoline program,
// LSM included, enters through __bpf_prog_enter with the check: a program already active on a CPU is skipped there,
// its miss counted, and the hook goes on as if it had returned 0. Where such a kernel preempts kernel code, a task
// preempted inside a plane program leaves it active on its CPU, and a hook another task reaches there is not decided:
// fmod_ret mode's exposure (ADR 0024 (16)), in LSM mode. A vendor kernel can carry the change on an older version
// (RHEL 9's 5.14 does), so the version is not read: the running kernel's own symbols are.
//
// The kernel is taken to exempt LSM programs only when /proc/kallsyms names __bpf_prog_enter_recur (or a compiler's
// copy of it, name.suffix); a kernel without the symbol, or one whose kallsyms cannot be read, is taken not to, and LSM
// mode is then held to fmod_ret mode's rule: admitted only where the kernel is shown never to preempt kernel code
// (lsmRecursionRefusal). Measured 2026-11-11 on the kit's rows: the symbol is in RHEL 9's 5.14.0-687, Amazon Linux
// 2023's 6.1.188, Ubuntu 24.04's 6.8, Debian 13's 6.12, Ubuntu 25.10's 6.17 and Fedora's 7.0 and 7.2, and not in
// Ubuntu 22.04's 5.15 (which does not preempt kernel code and has no bpf in its LSM list).

// lsmRecursionSymbol is the trampoline entry that exists exactly where LSM programs are exempt from the check.
const lsmRecursionSymbol = "__bpf_prog_enter_recur"

// kallsymsPath is the kernel's symbol table; a variable for the tests.
var kallsymsPath = "/proc/kallsyms"

// readLSMRecursion reports whether the running kernel enters LSM programs with no recursion check, and what was read.
// It reads kallsyms to the symbol, about 0.1 s at most on a 370,000-symbol kernel; lsmRecursionNow keeps the answer for
// the process, since the kernel's text cannot change while it runs.
func readLSMRecursion() (bool, string) {
	f, err := os.Open(kallsymsPath)
	if err != nil {
		return false, kallsymsPath + " could not be read (" + err.Error() + ")"
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<16)
	for sc.Scan() {
		if kallsymsNames(sc.Bytes(), lsmRecursionSymbol) {
			return true, kallsymsPath + " names " + lsmRecursionSymbol
		}
	}
	if err := sc.Err(); err != nil {
		return false, kallsymsPath + " could not be read to its end (" + err.Error() + ")"
	}
	return false, kallsymsPath + " does not name " + lsmRecursionSymbol
}

// kallsymsNames reports whether a kallsyms line ("<address> <type> <name>[\t[module]]") is the symbol name, or a
// compiler's copy of it (name.isra.0, name.llvm.123).
func kallsymsNames(line []byte, name string) bool {
	f := bytes.Fields(line)
	if len(f) < 3 {
		return false
	}
	sym := f[2]
	return string(sym) == name || bytes.HasPrefix(sym, []byte(name+"."))
}

var (
	lsmRecursionMu   sync.Mutex
	lsmRecursionRead bool
	lsmRecursionOK   bool
	lsmRecursionSrc  string
)

// lsmRecursionNow is readLSMRecursion, read once per process.
func lsmRecursionNow() (bool, string) {
	lsmRecursionMu.Lock()
	defer lsmRecursionMu.Unlock()
	if !lsmRecursionRead {
		lsmRecursionOK, lsmRecursionSrc = readLSMRecursion()
		lsmRecursionRead = true
	}
	return lsmRecursionOK, lsmRecursionSrc
}

// lsmRecursionRefusal is what rules LSM mode out on a kernel whose trampoline still checks LSM programs for recursion
// and that is not shown never to preempt kernel code, and the fix: "" where the kernel exempts LSM programs or is shown
// not to preempt kernel code. The test builds' waiver of fmod_ret mode's precondition does not reach it.
func lsmRecursionRefusal(env PlaneEnv) (string, string) {
	if env.LSMRecursionExempt || !preemptsKernelCode(env.Preempt) {
		return "", ""
	}
	why := "this kernel's BPF trampoline still checks LSM programs for recursion (" + env.LSMRecursionSource +
		"; kernels from 6.2, and from 6.1.54 in the 6.1 series, do not)"
	if env.Preempt == "" {
		why += ", and its preemption model is not proven (" + env.PreemptSource + ")"
	} else {
		why += ", and it preempts kernel code (preemption " + env.Preempt + ", from " + env.PreemptSource + ")"
	}
	why += ": the trampoline skips an LSM program on a CPU where a preempted task is still inside it, and the hook " +
		"then proceeds undecided"
	return why, "run a kernel from 6.2 (or 6.1.54 or later in the 6.1 series), or boot with preempt=voluntary or " +
		"preempt=none where this kernel offers them"
}

// execPinWhereSkippable withholds a passed exec pin cell on a kernel that preempts kernel code (ADR 0148): the check
// after an exec is a tp_btf program on sched_process_exec, which from 7.0 runs preemptibly, so the kernel can skip it
// there, and an older kernel may carry that change. The pins still go on and every exec they hold or kill is recorded
// as before; only the claim that the kernel holds every exec to the decided facts is not made (exec.command_argv,
// exec.assurance: kernel). A test build's waiver keeps the claim, as it keeps fmod_ret mode, so CI's exec pin cells run
// on its 7.0 runners.
func execPinWhereSkippable(cell *PlaneExecPinCell, env PlaneEnv) *PlaneExecPinCell {
	if cell == nil || !cell.OK || !preemptsKernelCode(env.Preempt) || env.PreemptWaived {
		return cell
	}
	model := "its preemption model is not proven (" + env.PreemptSource + ")"
	if env.Preempt != "" {
		model = "it preempts kernel code (preemption " + env.Preempt + ", from " + env.PreemptSource + ")"
	}
	return &PlaneExecPinCell{OK: false, Detail: "the check after an exec is a tracepoint program this kernel can skip, " +
		"since " + model + ": an exec it skips runs unchecked, so exec rules on argv stay best effort here (boot with " +
		"preempt=voluntary where this kernel offers it)"}
}
