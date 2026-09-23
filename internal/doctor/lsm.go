// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The LSM id numbers of include/uapi/linux/lsm.h, the answer lsm_list_modules(2) gives. They are a
// stable uapi contract, so they are spelled out rather than probed.
const (
	lsmIDCapability = 100
	lsmIDSELinux    = 101
	lsmIDSmack      = 102
	lsmIDTomoyo     = 103
	lsmIDAppArmor   = 104
	lsmIDYama       = 105
	lsmIDLoadPin    = 106
	lsmIDSafeSetID  = 107
	lsmIDLockdown   = 108
	lsmIDBPF        = 109
	lsmIDLandlock   = 110
	lsmIDIMA        = 111
	lsmIDEVM        = 112
	lsmIDIPE        = 113
)

// lsmNames maps an LSM id to the name the kernel's own lsm= command line uses.
var lsmNames = map[uint64]string{
	lsmIDCapability: "capability", lsmIDSELinux: "selinux", lsmIDSmack: "smack",
	lsmIDTomoyo: "tomoyo", lsmIDAppArmor: "apparmor", lsmIDYama: "yama",
	lsmIDLoadPin: "loadpin", lsmIDSafeSetID: "safesetid", lsmIDLockdown: "lockdown",
	lsmIDBPF: "bpf", lsmIDLandlock: "landlock", lsmIDIMA: "ima", lsmIDEVM: "evm", lsmIDIPE: "ipe",
}

// LSMNameBPF is the name of the LSM tier 3 needs on the kernel's lsm= line.
const LSMNameBPF = "bpf"

// securityFSLSM is the securityfs file listing the active LSMs as CSV, the fallback below 6.8.
const securityFSLSM = "/sys/kernel/security/lsm"

// kernelLogDevice is the last resort: the kernel's own boot line naming the LSMs it initialized.
const kernelLogDevice = "/dev/kmsg"

// maxLSMModules bounds the lsm_list_modules(2) answer. The kernel has well under a hundred LSMs;
// the cap keeps a wrong size answer from turning into an unbounded allocation.
const maxLSMModules = 64

// lsmSources names where an LSM list came from, in the order R27's D6 tries them.
const (
	LSMSourceSyscall    = "lsm_list_modules(2)"
	LSMSourceSecurityFS = securityFSLSM
	LSMSourceKernelLog  = kernelLogDevice
	LSMSourceNone       = "none"
)

// LSMState is what D6 learned about this kernel's active LSMs.
type LSMState struct {
	// Modules is the active list in the kernel's own order; empty when nothing could be read.
	Modules []string `json:"modules"`
	// Source names which of R27 D6's three mechanisms answered.
	Source string `json:"source"`
	// BPFActive reports whether "bpf" is in Modules. Activation is silent: a BPF LSM program
	// attaches whether or not bpf is active and then never runs (docs/ARCHITECTURE.md §10), so this
	// list — not a successful program load — is what decides tier 3.
	BPFActive bool `json:"bpf_active"`
	// Functional carries the root-only counting probe's answer: "" when it did not run.
	Functional string `json:"functional,omitempty"`
}

// ErrLSMList is a failure to read the active LSM list by any of the three mechanisms.
var ErrLSMList = errors.New("doctor: cannot read the active LSM list")

// lsmUnreadFix is the fix when no mechanism could read the active LSM list.
const lsmUnreadFix = "mount securityfs (mount -t securityfs none /sys/kernel/security) or boot a kernel >= 6.8"

// bpfInactive is why tier 3's LSM mode cannot run on this list, with the fix, or "" when bpf is active. A list no
// mechanism could read (ReadLSMState's error, Source none) is unknown, not empty: it is not said to lack bpf, and no
// GRUB line is built from it, since a bare lsm=bpf would switch off every LSM the machine runs.
func (s LSMState) bpfInactive() (string, string) {
	switch {
	case s.Source == LSMSourceNone:
		return fmt.Sprintf("%v, so whether bpf is an active LSM is unknown", ErrLSMList), lsmUnreadFix
	case !s.BPFActive:
		return fmt.Sprintf("bpf is not in the active LSM list (%s)", strings.Join(s.Modules, ",")), s.GRUBFix()
	}
	return "", ""
}

// ReadLSMState reads the active LSM list in R27 D6's exact order: lsm_list_modules(2) first (6.8+,
// unprivileged), then securityfs, then the kernel log. The first that answers wins; the source is
// reported so an operator can tell a definitive answer from a parsed boot line.
func ReadLSMState() (LSMState, error) {
	if mods, err := listModulesSyscall(); err == nil && len(mods) > 0 {
		return lsmState(mods, LSMSourceSyscall), nil
	}
	if b, err := os.ReadFile(securityFSLSM); err == nil {
		if mods := ParseLSMList(b); len(mods) > 0 {
			return lsmState(mods, LSMSourceSecurityFS), nil
		}
	}
	if b, err := readKernelLog(); err == nil {
		if mods, ok := ParseLSMLog(b); ok {
			return lsmState(mods, LSMSourceKernelLog), nil
		}
	}
	return LSMState{Source: LSMSourceNone}, ErrLSMList
}

// lsmState fills the derived fields of a state.
func lsmState(mods []string, source string) LSMState {
	s := LSMState{Modules: mods, Source: source}
	for _, m := range mods {
		if m == LSMNameBPF {
			s.BPFActive = true
		}
	}
	return s
}

// Boot-loader families of the GRUB fix: the tool an operator runs to make a kernel command line change stick
// differs by distribution, so the fix names the one this machine's /etc/os-release says it has.
const (
	bootDebian  = "debian" // Debian, Ubuntu and derivatives: /etc/default/grub, then update-grub
	bootRHEL    = "rhel"   // RHEL, Fedora, CentOS, Rocky, Alma, Amazon Linux 2023: grubby
	bootUnknown = ""
)

// osReleasePath is where bootFamily reads the distribution from; a test points it at a fixture.
var osReleasePath = "/etc/os-release"

// bootFamilyOf classifies an os-release file's text by its ID and ID_LIKE.
func bootFamilyOf(osRelease string) string {
	var ids []string
	for _, line := range strings.Split(osRelease, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (k != "ID" && k != "ID_LIKE") {
			continue
		}
		ids = append(ids, strings.Fields(strings.ToLower(strings.Trim(v, `"'`)))...)
	}
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu":
			return bootDebian
		case "rhel", "fedora", "centos", "rocky", "almalinux", "amzn":
			return bootRHEL
		}
	}
	return bootUnknown
}

// bootFamily is this machine's boot-loader family, bootUnknown when os-release is unreadable or names none.
func bootFamily() string {
	b, err := os.ReadFile(osReleasePath)
	if err != nil {
		return bootUnknown
	}
	return bootFamilyOf(string(b))
}

// GRUBFix is the one-line fix R27 asks for, built from the machine's own active list: the same list
// with bpf appended, in the form this distribution's operator edits it. Building it from the live list
// matters — a bare "lsm=bpf" would disable every LSM the machine currently runs.
func (s LSMState) GRUBFix() string { return s.GRUBFixFor(bootFamily()) }

// GRUBFixFor is GRUBFix for a boot-loader family: update-grub for Debian and Ubuntu, grubby for the RHEL family,
// and for a machine that names neither the file to edit and the step to regenerate its config.
func (s LSMState) GRUBFixFor(family string) string {
	list := strings.Join(append(append([]string(nil), s.Modules...), LSMNameBPF), ",")
	switch family {
	case bootRHEL:
		return fmt.Sprintf(`add lsm=%s to the kernel command line `+
			`(grubby --update-kernel=ALL --args="lsm=%s") and reboot`, list, list)
	case bootDebian:
		return fmt.Sprintf(`add lsm=%s to the kernel command line `+
			`(GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then update-grub) and reboot`, list)
	}
	return fmt.Sprintf(`add lsm=%s to the kernel command line `+
		`(GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub, then regenerate the GRUB config) and reboot`, list)
}

// listModulesSyscall calls lsm_list_modules(2) (Linux 6.8, unprivileged) and maps the ids to names.
// ENOSYS means an older kernel, which is the caller's cue to fall back.
func listModulesSyscall() ([]string, error) {
	ids := make([]uint64, maxLSMModules)
	size := uint32(len(ids) * 8)
	n, _, errno := unix.Syscall(unix.SYS_LSM_LIST_MODULES,
		uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("lsm_list_modules(2): %w", errno)
	}
	count := int(n)
	if count < 0 || count > len(ids) {
		return nil, fmt.Errorf("lsm_list_modules(2): %w: returned %d of at most %d modules",
			ErrLSMList, count, len(ids))
	}
	out := make([]string, 0, count)
	for _, id := range ids[:count] {
		if name, ok := lsmNames[id]; ok {
			out = append(out, name)
			continue
		}
		out = append(out, fmt.Sprintf("lsm%d", id))
	}
	return out, nil
}

// ParseLSMList decodes /sys/kernel/security/lsm's comma-separated list. Pure and total: every shape
// yields a (possibly empty) slice and never a panic (FuzzParseLSMList).
func ParseLSMList(b []byte) []string {
	var out []string
	for _, f := range strings.Split(string(b), ",") {
		if name := strings.TrimSpace(f); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// ParseLSMLog finds the kernel's own "LSM: initializing lsm=<list>" boot line in a log blob and
// returns the list. ok is false when no such line is present — which is not the same as an empty
// list. Pure and total (FuzzParseLSMLog).
func ParseLSMLog(b []byte) ([]string, bool) {
	const marker = "LSM: initializing lsm="
	var found []string
	var ok bool
	for _, line := range strings.Split(string(b), "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		rest := line[i+len(marker):]
		if j := strings.IndexAny(rest, " \t"); j >= 0 {
			rest = rest[:j]
		}
		// The last such line wins: a kexec'd kernel appends its own.
		found, ok = ParseLSMList([]byte(rest)), true
	}
	return found, ok
}

// readKernelLog reads the head of /dev/kmsg without blocking. The boot lines are at the front of the
// buffer, so a bounded read is enough; a kernel with dmesg_restrict=1 returns EACCES to a normal
// user, which is a fallback failure, not an error to report to the operator.
func readKernelLog() ([]byte, error) {
	const maxLogBytes = 1 << 20
	fd, err := unix.Open(kernelLogDevice, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", kernelLogDevice, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var out []byte
	buf := make([]byte, 8192)
	for len(out) < maxLogBytes {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EPIPE) {
				break // EAGAIN: the ring is drained. EPIPE: records were overwritten while reading.
			}
			return out, fmt.Errorf("read %s: %w", kernelLogDevice, err)
		}
		if n == 0 {
			break
		}
		out = append(out, buf[:n]...)
	}
	return out, nil
}

// probeLSM is D6: the active LSM list, with the root-only functional check behind it. It never
// fails the probe for a missing bpf — a machine without it simply cannot reach tier 3 — but it does
// fail when no mechanism could answer at all, because then nothing can decide tier 3 safely.
func probeLSM(root bool) (Result, LSMState) {
	state, err := ReadLSMState()
	if err != nil {
		return Result{ID: CheckLSM,
			Detail: fmt.Sprintf("%v (tier bpflsm cannot be decided safely)", err),
			Fix:    lsmUnreadFix}, state
	}
	detail := fmt.Sprintf("%s via %s", strings.Join(state.Modules, ","), state.Source)
	if !state.BPFActive {
		return Result{ID: CheckLSM, Detail: detail + "; bpf is not active: tier 3 (bpflsm) is unavailable, tiers 1 and 2 are not affected",
			Fix: state.GRUBFix()}, state
	}
	if root {
		ran, err := bpfLSMRuns()
		switch {
		case err != nil:
			state.Functional = "not confirmed: " + err.Error()
			return Result{ID: CheckLSM, Detail: detail + "; bpf is listed but the functional probe could not run: " + err.Error(),
				Fix: state.GRUBFix()}, state
		case !ran:
			// Silent attach: the program loaded and attached and never ran (ARCHITECTURE §10).
			state.Functional = "attached but never ran"
			return Result{ID: CheckLSM, Detail: detail + "; a BPF LSM program attached but never ran",
				Fix: state.GRUBFix()}, state
		default:
			state.Functional = "confirmed by a counting program on file_open"
		}
	}
	return Result{ID: CheckLSM, OK: true, Detail: detail + "; bpf is active"}, state
}
