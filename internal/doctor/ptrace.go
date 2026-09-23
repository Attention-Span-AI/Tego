// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// yamaScopePath is Yama's sysctl. An absent file means the kernel was built without
// CONFIG_SECURITY_YAMA, which is the same answer as scope 0: no extra ptrace restriction.
const yamaScopePath = "/proc/sys/kernel/yama/ptrace_scope"

// The four values Yama defines for ptrace_scope (ptrace(2), "/proc/sys/kernel/yama/ptrace_scope";
// security/yama/yama_lsm.c). Only scope 1 carries the descendant exemption the supervisor relies on.
const (
	// yamaAbsent is "no Yama on this kernel", not a scope the sysctl can hold.
	yamaAbsent = -1
	// yamaClassic (0) imposes nothing beyond commoncap and the other LSMs.
	yamaClassic = 0
	// yamaRelational (1, the Debian/Ubuntu default) allows an ancestor to attach to its own
	// descendant. Tego's supervisor is the agent's parent, so this is the case that works.
	yamaRelational = 1
	// yamaAdminOnly (2) drops the descendant exemption: only CAP_SYS_PTRACE in the target's user
	// namespace passes.
	yamaAdminOnly = 2
	// yamaNoAttach (3) refuses every PTRACE_MODE_ATTACH check, CAP_SYS_PTRACE included, and cannot
	// be lowered again without a reboot.
	yamaNoAttach = 3
)

// capSysPtraceBit is CAP_SYS_PTRACE (19), the capability Yama checks at scope 2.
const capSysPtraceBit = unix.CAP_SYS_PTRACE

// PtraceState is what D5 learned about the ptrace access mode the tier-1 supervisor needs.
//
// The supervisor reaches into the agent for every decision it makes: process_vm_readv(2) for each
// sockaddr, path and argv ("permission ... is governed by a ptrace access mode
// PTRACE_MODE_ATTACH_REALCREDS check"), the /proc/<pid>/mem fallback behind the same check, and
// pidfd_getfd(2) for the listener itself and for every connect it completes ("EPERM: the calling
// process did not have PTRACE_MODE_ATTACH_REALCREDS permissions"). Yama gates exactly that access
// mode, so its scope decides whether tier 1 can work at all — and it is a global sysctl no identity
// check would surface (docs/p0/supervisor.md E18 attributes the same EPERM to an identity mismatch
// alone, which is only one of the two causes).
type PtraceState struct {
	// Scope is the sysctl's value, or -1 when Yama is not built into this kernel.
	Scope int `json:"scope"`
	// CapSysPtrace says whether *this* process holds CAP_SYS_PTRACE in its effective set.
	CapSysPtrace bool `json:"cap_sys_ptrace"`
	// Blocked names the consequence when the supervisor cannot make an attach-mode access, "" when
	// it can. A non-empty value blocks every enforcement tier: all of them install the tier-1
	// seccomp filter and hand its listener over with pidfd_getfd.
	Blocked string `json:"blocked,omitempty"`
	// Detail is the one clause D5 adds to its own line, whether or not Blocked is set.
	Detail string `json:"detail"`
	// Fix is the operator action, "" when nothing is wrong.
	Fix string `json:"fix,omitempty"`
}

// probePtrace reads Yama's scope and decides what it means for the supervisor. It never fails: an
// unreadable sysctl is reported as unknown and, because the consequence of guessing wrong is a run
// that reports a working sandbox while refusing everything, unknown is treated as blocking.
func probePtrace(path string) PtraceState {
	st := PtraceState{Scope: yamaAbsent}
	if have, err := capSysPtrace(); err == nil {
		st.CapSysPtrace = have
	}
	scope, err := readYamaScope(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		st.Detail = "no Yama (CONFIG_SECURITY_YAMA off): ptrace is unrestricted"
		return st
	case err != nil:
		st.Detail = fmt.Sprintf("%s: %v", path, err)
		st.Blocked = fmt.Sprintf("yama: %s could not be read (%v), so it is not known whether the supervisor "+
			"may read the agent's memory", path, err)
		// Two separate actions, because either can be the one missing: the file is masked or denied
		// (a reboot changes neither), and what it holds may be a scope that blocks. The second is the
		// persistent setting, since the fix line can put a reboot after it (probeState.fix).
		st.Fix = fmt.Sprintf("make %s readable to tego and re-run; if it holds 2, %s, and if 3, %s", path,
			yamaPersistentFix, yamaBootFix)
		return st
	}
	st.Scope = scope
	st.Detail, st.Blocked, st.Fix = yamaConsequence(scope, st.CapSysPtrace)
	return st
}

// yamaConsequence is the pure half of probePtrace: what one scope, with or without CAP_SYS_PTRACE,
// means for the supervisor. It is the whole rule, so it is the whole test.
//
// Scope 1 is safe only because the supervisor is the agent's own parent — Yama's "predefined
// relationship is that the target process must be a descendant of the caller" — and Tego never
// puts the agent in a separate user namespace, which per ptrace(2) would remove the protection and
// the restriction with it. Scope 2 keeps no such exemption: yama_ptrace_access_check's
// YAMA_SCOPE_CAPABILITY arm is the capability test alone, with none of YAMA_SCOPE_RELATIONAL's
// task_is_descendant(). Scope 3 refuses everyone.
func yamaConsequence(scope int, capPtrace bool) (detail, blocked, fix string) {
	const consequence = "every connect the supervisor is asked to complete fails closed with EACCES " +
		"and every exec and fs event records rule=args-unreadable"
	switch {
	case scope <= yamaClassic:
		return fmt.Sprintf("yama ptrace_scope=%d (unrestricted)", scope), "", ""
	case scope == yamaRelational:
		return "yama ptrace_scope=1 (the supervisor is the agent's parent, which Yama exempts)", "", ""
	case scope == yamaAdminOnly && capPtrace:
		// True for this process, which is usually root. An ordinary `tego run` on the same box has
		// no such capability, so say so rather than report a clean bill of health for everyone.
		return "yama ptrace_scope=2, allowed here only by CAP_SYS_PTRACE (an unprivileged tego run on " +
			"this machine would be refused)", "", ""
	case scope == yamaAdminOnly:
		return "yama ptrace_scope=2 without CAP_SYS_PTRACE",
			"yama: ptrace_scope=2 admits only CAP_SYS_PTRACE, and pidfd_getfd(2) and process_vm_readv(2) " +
				"are both PTRACE_MODE_ATTACH_REALCREDS operations, so " + consequence,
			yamaPersistentFix + " (1 is the default; the supervisor is the agent's own parent), or grant tego " +
				"CAP_SYS_PTRACE"
	case scope == yamaNoAttach:
		return "yama ptrace_scope=3 (no attach, not lowerable without a reboot)",
			"yama: ptrace_scope=3 refuses every PTRACE_MODE_ATTACH check, CAP_SYS_PTRACE included, so " + consequence,
			yamaBootFix
	default:
		// Yama defines 0..3. A larger value is a kernel this build does not understand, and the
		// safe reading of an unknown restriction is that it restricts.
		return fmt.Sprintf("yama ptrace_scope=%d, a value this build does not know", scope),
			fmt.Sprintf("yama: ptrace_scope=%d is outside the 0..3 Yama defines, so it is not known whether "+
				"the supervisor may read the agent's memory", scope),
			yamaPersistentFix
	}
}

// yamaPersistentFix is every lowerable scope's remedy. It is the persistent setting, not a bare
// `sysctl -w`: a write to /proc/sys lasts only until the next boot, which applies the sysctl.d files
// again, including whichever chose the blocking value. The fix line can ask for a reboot beside this
// one (D4's lsm= line, probeState.fix), and a bare write would be undone by it before the first run.
const yamaPersistentFix = "set kernel.yama.ptrace_scope=1 in /etc/sysctl.d, in place of the setting that " +
	"chose the current value, and apply it with sysctl --system"

// yamaBootFix is scope 3's remedy: Yama refuses to lower 3 on a running kernel, so it is a boot
// setting, which a reboot keeps by construction.
const yamaBootFix = "boot with kernel.yama.ptrace_scope=1; the value cannot be lowered on a running kernel"

// readYamaScope reads the sysctl. A missing file is returned as os.ErrNotExist for the caller to
// read as "Yama is not built in"; anything else the file could hold is an error, never a guess.
func readYamaScope(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return yamaAbsent, err
	}
	scope, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return yamaAbsent, fmt.Errorf("%q is not a ptrace_scope value", strings.TrimSpace(string(b)))
	}
	return scope, nil
}

// capSysPtrace reports whether this process's effective set holds CAP_SYS_PTRACE, the capability
// Yama's scope-2 arm tests (ns_capable(..., CAP_SYS_PTRACE)). capget(2) with pid 0 asks about the
// caller; CAP_SYS_PTRACE is 19, so it lives in the first 32-bit word of the version-3 layout.
func capSysPtrace() (bool, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false, fmt.Errorf("capget: %w", err)
	}
	return data[capSysPtraceBit>>5].Effective&(1<<(uint(capSysPtraceBit)&31)) != 0, nil
}
