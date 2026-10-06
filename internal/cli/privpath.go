// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"math/bits"
	"os"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// ADR 0042 (3)(a): the root tiers are reached only by a root launcher (sudo, or a root unit). A launcher that
// gained privilege without being root of the initial user namespace — a file-capability or setuid copy of the
// binary, or one that inherited a privileged capability set — is refused before any code path can use what it
// holds; one that inherited only incidental capabilities (a unit's AmbientCapabilities=CAP_NET_BIND_SERVICE) has
// them cleared and runs unprivileged, at tier landlock, as it did before.

// privAction is what GuardPrivilege does with this process's credentials.
type privAction int

const (
	privNone   privAction = iota // nothing held, or root of the initial user namespace
	privClear                    // only incidental capabilities: clear every set on every thread and continue
	privRefuse                   // privilege gained without root: exit 125 [privileged-path-unsupported]
)

// privFacts are the credentials privilegeAction reads: the process's user namespace as its uid map shows it
// (initial, child or unknown), its real and effective ids, AT_SECURE, and its four capability sets as 64-bit masks.
type privFacts struct {
	userNS                 config.UserNamespace
	ruid, euid, rgid, egid int
	secure                 bool
	prm, eff, inh, amb     uint64
}

// incidentalCaps is (3)(a)'s allowlist: capabilities an ordinary unit may hand a service, none of which reaches
// BPF, cgroups, other users' files or the kernel's own state. Anything else, an unknown number included, refuses.
var incidentalCaps = map[int]string{
	10: "cap_net_bind_service",
	11: "cap_net_broadcast",
	13: "cap_net_raw",
	14: "cap_ipc_lock",
	23: "cap_sys_nice",
	28: "cap_lease",
	29: "cap_audit_write",
	35: "cap_wake_alarm",
	36: "cap_block_suspend",
}

// privilegedCapNames names the capabilities a refusal most often meets: the withdrawn copy's three and the rest
// the root tiers use. Others print as cap_<n>.
var privilegedCapNames = map[int]string{1: "cap_dac_override", 6: "cap_setgid", 7: "cap_setuid",
	12: "cap_net_admin", 19: "cap_sys_ptrace", 21: "cap_sys_admin", 38: "cap_perfmon", 39: "cap_bpf"}

// incidentalMask is incidentalCaps as a mask.
var incidentalMask = func() uint64 {
	var m uint64
	for c := range incidentalCaps {
		m |= 1 << c
	}
	return m
}()

// privilegeAction is ADR 0042 (3)(a)'s table, a pure function of the credentials and the command (os.Args[1]).
// why names the refusal's cause and is "" otherwise.
//
//   - Root of the initial user namespace (real uid 0 there): none. That is a root launcher, and the child stage,
//     helpers and probe children it starts, all with real uid 0.
//   - version: none, whatever is held; it reads and acts on nothing.
//   - Refused: AT_SECURE (the kernel's "privilege gained by exec" bit, set by file capabilities and setuid or
//     setgid, not by an inherited ambient set); a real and effective uid or gid that differ; and, unless the uid
//     map was read and shows a child namespace, a permitted, effective or ambient set holding anything outside
//     incidentalCaps.
//   - Cleared: unless the uid map shows a child namespace, an incidental capability in the permitted, effective or
//     ambient set. All four sets are then emptied, the inheritable one with them.
//
// An inheritable set alone is neither: it grants nothing unless an exec meets file capabilities that name the same
// ones, and a desktop session hands every process one (Ubuntu's user sessions carry cap_wake_alarm there), so
// clearing it would note and pay for a clear on every command for nothing. The child stage empties it before the
// agent's exec anyway (sys.ClearCapabilities).
//
// A child user namespace (`unshare -r`, a rootless container) holds every capability of its own namespace and none
// over the host's BPF, cgroup2 root or /run/tego, so its sets are not read; it is refused only for a gain by
// exec or an id mismatch. Refusing on its capabilities would refuse every command there, doctor and tier landlock
// included, for nothing that reaches the root tiers (the root-tier gates already ask config.InitNSRoot).
//
// An unknown namespace (a uid map that could not be read: a chroot or minimal container with no /proc, where
// AT_SECURE still comes from unix.Auxv) may be the initial one, so its sets are read as there; and since only the
// initial namespace's uid 0 is root, its real uid 0 is not let through on the ids alone. Both fail closed.
func privilegeAction(f privFacts, cmd string) (privAction, string) {
	if (f.userNS == config.UserNamespaceInitial && f.ruid == 0) || cmd == "version" {
		return privNone, ""
	}
	switch {
	case f.secure:
		return privRefuse, "it was executed with AT_SECURE set (a file-capability, setuid or setgid copy)"
	case f.ruid != f.euid:
		return privRefuse, fmt.Sprintf("its effective uid %d is not its real uid %d (a setuid copy)", f.euid, f.ruid)
	case f.rgid != f.egid:
		return privRefuse, fmt.Sprintf("its effective gid %d is not its real gid %d (a setgid copy)", f.egid, f.rgid)
	case f.userNS == config.UserNamespaceChild:
		return privNone, ""
	}
	if held := (f.prm | f.eff | f.amb) &^ incidentalMask; held != 0 {
		why := "it holds " + capNames(held) + " without being root"
		if f.userNS != config.UserNamespaceInitial {
			why += " of the initial user namespace (its uid map could not be read)"
		}
		return privRefuse, why
	}
	if f.prm|f.eff|f.amb != 0 {
		return privClear, ""
	}
	return privNone, ""
}

// capNames names the capabilities of mask as capabilities(7) does, lowest number first; a number this table does
// not name is cap_<n>.
func capNames(mask uint64) string {
	var out []string
	for mask != 0 {
		c := bits.TrailingZeros64(mask)
		mask &^= 1 << c
		name, ok := incidentalCaps[c]
		if !ok {
			name, ok = privilegedCapNames[c]
		}
		if !ok {
			name = "cap_" + strconv.Itoa(c)
		}
		out = append(out, name)
	}
	return strings.Join(out, ",")
}

// GuardPrivilege is cmd/tego's first call, before the child stage and the helper dispatch: it applies
// privilegeAction to this process. It returns ok to go on, or the code to exit with after the refusal it printed.
func GuardPrivilege(args []string, stderr io.Writer) (code int, ok bool) {
	// Every tego process passes here, the child stage of each run included, so root's answer is reached from the
	// ids and the uid map alone (both cached for the process): the sets cannot change it.
	if (os.Getuid() == 0 && config.InitialUserNamespace()) || (len(args) > 1 && args[1] == "version") {
		return 0, true
	}
	f, err := readPrivFacts()
	if err != nil {
		message(stderr, "", 0, 0, "tego: cannot read this process's credentials: "+err.Error(), identity.CodePrivilegedPathUnsupported)
		return identity.ExitLauncher, false
	}
	return guardPrivilege(args, stderr, f, sys.ClearProcessCapabilities)
}

// guardPrivilege is GuardPrivilege over given credentials and a given clearing.
func guardPrivilege(args []string, stderr io.Writer, f privFacts, clear func() error) (int, bool) {
	cmd := ""
	if len(args) > 1 {
		cmd = args[1]
	}
	action, why := privilegeAction(f, cmd)
	switch action {
	case privNone:
		return 0, true
	case privClear:
		held := f.prm | f.eff | f.amb
		if err := clear(); err != nil {
			why = "its inherited capabilities " + capNames(held) + " could not be cleared: " + err.Error()
			break
		}
		if cmd == "run" {
			fmt.Fprintln(stderr, "tego run: note: cleared the inherited capabilities "+capNames(held)+
				"; this run is unprivileged (ADR 0042 (3)(a))")
		}
		return 0, true
	case privRefuse:
	}
	message(stderr, "", 0, 0, "tego: refused: "+why+"; the root tiers are reached only by a root launcher "+
		"(`sudo tego run`), and a capability or setuid copy of tego is not supported (ADR 0042 (3)); "+
		"run tego unprivileged for tier landlock", identity.CodePrivilegedPathUnsupported)
	return identity.ExitLauncher, false
}

// readPrivFacts reads this process's credentials: the ids, AT_SECURE, the user namespace (unknown when the uid map
// cannot be read) and the capability sets.
func readPrivFacts() (privFacts, error) {
	f := privFacts{userNS: config.CurrentUserNamespace(), ruid: os.Getuid(), euid: os.Geteuid(),
		rgid: os.Getgid(), egid: os.Getegid()}
	var err error
	if f.secure, err = config.DetectSecureExec(); err != nil {
		return f, err
	}
	if f.eff, f.prm, f.inh, err = sys.Capabilities(); err != nil {
		return f, err
	}
	// The kernel keeps ambient within permitted ∩ inheritable (capabilities(7)), so with no capability in both the
	// ambient set is empty and its per-capability prctl reads are skipped.
	if f.prm&f.inh != 0 {
		if f.amb, err = sys.AmbientCapabilities(); err != nil {
			return f, err
		}
	}
	return f, nil
}
