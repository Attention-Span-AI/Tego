// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"compress/gzip"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// The kernel's preemption model, which fmod_ret mode needs to be one shown never to preempt kernel code (ADR 0024
// (16); docs/p0/enforce-plane.md R21). In fmod_ret mode the plane's programs are BPF tracing programs, which the
// kernel's trampoline runs under a per-CPU recursion check (bpf_prog_check_recur, __bpf_prog_enter_recur): a program
// that is already active on a CPU is skipped there, its miss counted, and the hooked call goes ahead as if it had
// returned 0. Where the kernel preempts kernel code, a task preempted inside a plane program leaves it active on its
// CPU, and every other task that reaches the same hook on that CPU before it resumes is not decided at all. Measured
// 2026-11-02 with one tier-cgroup run opening a deny_read file: on 6.17 booted preempt=full, 87,075 of 320,000
// opens succeeded; under lazy preemption (Fedora's 7.0 default, and 6.17 booted preempt=lazy) eight processes
// opening it beside eight spawning /usr/bin/true opened it 2,809 and 2,313 times in 20 s; under 6.17's default
// voluntary preemption no open succeeded in either workload. LSM programs take no such check on a kernel from 6.2 (6.1.54
// in the 6.1 series), so LSM mode is not affected there; on an older one they do, and LSM mode is held to the same rule
// (lsmrecursion.go). A kernel that does not preempt kernel code (none, voluntary) never preempts a non-sleepable program,
// and no plane hook is called from interrupt context, so there the check never skips a plane program.
//
// The mode is admitted on proof alone, and any doubt refuses it (2026-11-03, after a review found a build default, a
// kernel log line and a boot line each standing in for a live mode they do not prove):
//   - a build that is not PREEMPT_DYNAMIC has its model fixed by its build: its config must set CONFIG_PREEMPT_NONE or
//     CONFIG_PREEMPT_VOLUNTARY and none of CONFIG_PREEMPT, CONFIG_PREEMPT_LAZY, CONFIG_PREEMPT_RT and
//     CONFIG_PREEMPT_DYNAMIC, and uname -v must carry no PREEMPT flag; an unreadable config is no proof;
//   - a PREEMPT_DYNAMIC build's mode can change while it runs, and only debugfs's mode file says what it is now: it
//     must be readable and select none or voluntary. The boot line, the build's default and the kernel log are not
//     read: each can name a mode the kernel does not run (a value the kernel refused, a change made after boot, a log
//     overwritten or cut short).
//
// The reading is never kept: every probe, run-probe cache hit, pinned answer and reused adoption backend reads it again
// (readPreempt), so a change made between runs is seen by the next one. A change made by root while a run lives is
// not watched (root is outside the threat model; ADR 0024 (16)).

// Preemption models of PlaneEnv.Preempt: the kernel's own names, and one for a build uname -v alone describes.
const (
	preemptNone      = "none"
	preemptVoluntary = "voluntary"
	preemptFull      = "full"
	preemptLazy      = "lazy"
	preemptRT        = "rt"
	// preemptFullOrLazy is a build uname -v flags PREEMPT, with no config to say which of the two.
	preemptFullOrLazy = "full or lazy"
)

// envTestPlanePreempt is the variable a test build's waiver of fmod_ret mode's preemption precondition is read from
// (preempt_testhook.go, and the package's own test binary); a product build reads no variable by it.
const envTestPlanePreempt = "TEGO_TEST_PLANE_PREEMPT"

// preemptsKernelCode reports whether model lets the kernel preempt kernel code, and so a running BPF program. An
// unknown model ("") is taken to: fmod_ret mode is admitted only on a kernel shown not to.
func preemptsKernelCode(model string) bool {
	switch model {
	case preemptNone, preemptVoluntary:
		return false
	}
	return true
}

// preemptFacts is what the model is read from.
type preemptFacts struct {
	// Version is uname -v, which carries the build's PREEMPT, PREEMPT_DYNAMIC or PREEMPT_RT flag.
	Version string
	// Config is which CONFIG_PREEMPT* options the kernel's build config sets to y; nil when no config was read.
	Config map[string]bool
	// ConfigSource is the config file read.
	ConfigSource string
	// Debugfs is /sys/kernel/debug/sched/preempt (a PREEMPT_DYNAMIC kernel's live mode, in parentheses), "" when
	// it cannot be read: debugfs not mounted there, or lockdown, which refuses that file (and so any change of the
	// mode). DebugfsErr says why.
	Debugfs    string
	DebugfsErr string
}

// preemptConfigKeys are the build options the model reads.
var preemptConfigKeys = []string{"CONFIG_PREEMPT_RT", "CONFIG_PREEMPT_DYNAMIC", "CONFIG_PREEMPT_NONE",
	"CONFIG_PREEMPT_VOLUNTARY", "CONFIG_PREEMPT", "CONFIG_PREEMPT_LAZY"}

// preemptModel is the kernel's preemption model and where it was read. A model that does not preempt kernel code is
// returned only on proof (the package comment); otherwise the model is the most preemptive one any source names, or
// "" with source saying why nothing proves one.
func preemptModel(f preemptFacts) (string, string) {
	const uname = "uname -v"
	flags := unamePreemptFlags(f.Version)
	cfg := f.Config
	switch {
	case flags["PREEMPT_RT"]:
		return preemptRT, uname
	case cfg["CONFIG_PREEMPT_RT"]:
		return preemptRT, f.ConfigSource
	case flags["PREEMPT_DYNAMIC"] || cfg["CONFIG_PREEMPT_DYNAMIC"]:
		if m := debugfsPreemptMode(f.Debugfs); m != "" {
			return m, debugfsPreemptPath
		}
		why := "a PREEMPT_DYNAMIC build, whose live mode only " + debugfsPreemptPath + " says, and it "
		if f.DebugfsErr != "" {
			return "", why + "cannot be read (" + f.DebugfsErr + ")"
		}
		return "", why + "names no mode"
	case cfg["CONFIG_PREEMPT_LAZY"]:
		return preemptLazy, f.ConfigSource
	case cfg["CONFIG_PREEMPT"]:
		return preemptFull, f.ConfigSource
	case len(flags) > 0:
		return preemptFullOrLazy, uname
	case cfg == nil:
		return "", "a build that is not PREEMPT_DYNAMIC by uname -v, with no build config to prove its model (" +
			"/proc/config.gz, /boot/config-<release>, /lib/modules/<release>/config)"
	case cfg["CONFIG_PREEMPT_VOLUNTARY"]:
		return preemptVoluntary, f.ConfigSource
	case cfg["CONFIG_PREEMPT_NONE"]:
		return preemptNone, f.ConfigSource
	}
	return "", "a build config (" + f.ConfigSource + ") that sets none of CONFIG_PREEMPT_NONE, CONFIG_PREEMPT_VOLUNTARY, " +
		"CONFIG_PREEMPT, CONFIG_PREEMPT_LAZY and CONFIG_PREEMPT_RT"
}

// unamePreemptFlags is the set of uname -v's words that begin with PREEMPT (PREEMPT, PREEMPT_DYNAMIC, PREEMPT_RT,
// PREEMPT_LAZY).
func unamePreemptFlags(version string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(version) {
		if strings.HasPrefix(w, "PREEMPT") {
			out[w] = true
		}
	}
	return out
}

// debugfsPreemptPath is a PREEMPT_DYNAMIC kernel's live mode.
const debugfsPreemptPath = "/sys/kernel/debug/sched/preempt"

// debugfsPreemptMode reads the parenthesised mode of debugfsPreemptPath ("none (voluntary) full lazy"), "" when
// there is not exactly one, or it is not a mode this file knows.
func debugfsPreemptMode(s string) string {
	if strings.Count(s, "(") != 1 || strings.Count(s, ")") != 1 {
		return ""
	}
	i := strings.IndexByte(s, '(')
	j := strings.IndexByte(s, ')')
	if j <= i {
		return ""
	}
	switch m := s[i+1 : j]; m {
	case preemptNone, preemptVoluntary, preemptFull, preemptLazy:
		return m
	}
	return ""
}

// readPreempt reads the running kernel's preemption model (preemptModel) and where it was read from, afresh; a
// variable so that a test can change the kernel's mode between two runs.
var readPreempt = readPreemptLive

// unameVersion is uname -v, and preemptConfigPaths the build configs readPreemptLive reads: variables so a test can
// take the live reading through a failed uname or a config of its own.
var (
	unameVersion = func() (string, error) {
		var u unix.Utsname
		if err := unix.Uname(&u); err != nil {
			return "", err
		}
		return unix.ByteSliceToString(u.Version[:]), nil
	}
	preemptConfigPaths = kernelConfigPaths
)

// readPreemptLive is readPreempt on this kernel. uname -v is half of every proof (a fixed build's flags must agree
// with its config, and a dynamic build may be one by its flag alone), so a uname that fails proves nothing.
func readPreemptLive(release string) (string, string) {
	var f preemptFacts
	v, err := unameVersion()
	if err != nil {
		return "", "uname -v could not be read (" + err.Error() + "), so no build config can be checked against it"
	}
	f.Version = v
	for _, p := range preemptConfigPaths(release) {
		if cfg, ok := configPreempt(p); ok {
			f.Config, f.ConfigSource = cfg, p
			break
		}
	}
	if flags := unamePreemptFlags(f.Version); flags["PREEMPT_DYNAMIC"] || f.Config["CONFIG_PREEMPT_DYNAMIC"] {
		if b, err := os.ReadFile(debugfsPreemptPath); err != nil {
			f.DebugfsErr = err.Error()
		} else {
			f.Debugfs = string(b)
		}
	}
	return preemptModel(f)
}

// configPreempt reads which of preemptConfigKeys one kernel config file, gzip or plain, sets to y. A file with no
// CONFIG_ line at all, or one that cannot be read to its end, is no answer, as for scanConfigLTO.
func configPreempt(path string) (map[string]bool, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return nil, false
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	return scanConfigPreempt(r)
}

// scanConfigPreempt is configPreempt over a config's text.
func scanConfigPreempt(r io.Reader) (map[string]bool, bool) {
	out := map[string]bool{}
	configs := 0
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "CONFIG_") || strings.HasPrefix(line, "# CONFIG_") {
			configs++
		}
		if k, ok := strings.CutSuffix(line, "=y"); ok {
			for _, want := range preemptConfigKeys {
				if k == want {
					out[k] = true
				}
			}
		}
	}
	if sc.Err() != nil || configs == 0 {
		return nil, false
	}
	return out, true
}

// fmodRetPreemptRefusal is what rules fmod_ret mode out on a kernel not shown to never preempt kernel code, and the
// fix: "" when the model is shown not to, or when a test build waives the check (planePreemptWaived).
func fmodRetPreemptRefusal(env PlaneEnv, lsm LSMState) (string, string) {
	if !preemptsKernelCode(env.Preempt) || env.PreemptWaived {
		return "", ""
	}
	var why string
	if env.Preempt == "" {
		why = "this kernel's preemption model is not proven (" + env.PreemptSource + "), and fmod_ret mode needs one " +
			"shown never to preempt kernel code"
	} else {
		why = "this kernel preempts kernel code (preemption " + env.Preempt + ", from " + env.PreemptSource + ")"
	}
	why += ": the BPF trampoline skips an fmod_ret program on a CPU where a preempted task is still inside it, and " +
		"the hook then proceeds undecided"
	fix := "boot with preempt=voluntary where this kernel offers it (x86_64 and arm64 kernels from 7.0 offer only " +
		"full and lazy)"
	if env.Preempt == "" && strings.Contains(env.PreemptSource, debugfsPreemptPath) {
		fix = "mount debugfs (mount -t debugfs none /sys/kernel/debug), which lockdown may refuse, so that its live " +
			"mode can be read; or " + fix
	}
	switch {
	case !env.LSMRecursionExempt:
		// This kernel's trampoline checks LSM programs too: LSM mode is no way out of the skip (lsmRecursionRefusal).
	case lsm.BPFActive:
		fix = "use LSM mode (bpf.plane: auto or lsm), whose programs this kernel's trampoline does not skip; or " + fix
	case lsm.Source != LSMSourceNone:
		fix = lsm.GRUBFix() + ", for LSM mode, whose programs this kernel's trampoline does not skip; or " + fix
	}
	return why, fix
}

// fmodRetAdmittedNow reports whether this kernel admits fmod_ret mode now, read afresh, and why not: "" when it does.
// It is the check a reused answer (a pinned build's, the run-probe cache's, a guard's prepared backend) is held to
// before a run or an adoption takes fmod_ret mode from it.
func fmodRetAdmittedNow(release string, lsm LSMState) (PlaneEnv, string) {
	var env PlaneEnv
	env.Preempt, env.PreemptSource = readPreempt(release)
	env.PreemptWaived = planePreemptWaived && preemptsKernelCode(env.Preempt)
	if preemptsKernelCode(env.Preempt) {
		// Only a kernel that preempts kernel code needs the LSM answer (lsmRecursionRefusal, execPinWhereSkippable),
		// and only it pays for reading kallsyms, once per process.
		env.LSMRecursionExempt, env.LSMRecursionSource = lsmRecursionNow()
	}
	why, _ := fmodRetPreemptRefusal(env, lsm)
	return env, why
}

// FmodRetRefusedNow is fmodRetAdmittedNow for a caller outside doctor that holds a backend selected in fmod_ret mode
// (internal/cli's guard, which reuses one prepared backend for many adoptions): "" when this kernel still admits the
// mode, else why it does not, so the caller selects again.
func FmodRetRefusedNow() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "uname: " + err.Error()
	}
	_, why := fmodRetAdmittedNow(unix.ByteSliceToString(u.Release[:]), LSMState{Source: LSMSourceNone})
	return why
}
