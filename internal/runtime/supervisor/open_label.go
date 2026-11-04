// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	ruleHeldLabelDiffers     = "held-label-differs"
	ruleHeldLabelUnavailable = "held-label-unavailable"
)

var errOpenLabelDiffers = errors.New("open completer's LSM label differs from the task's")

// CheckOpenLabel implements ADR 0041 D2's conservative completion: differing
// labels refuse, even if their policies might admit this particular file. Read
// the trapping TID afresh, never a TGID or an exec-invalidated cache. The task
// cannot change its own credentials while trapped; openLabel brackets these
// reads with ID_VALID so de_thread or TID reuse cannot substitute another task.
func (k sysKernel) CheckOpenLabel(tid, opener, flags int) error {
	return checkOpenLabelAuthority(tid, opener, flags, readOpenLabelFile, sys.LSMListModules, k.assumeAppArmorRoot)
}

// readOpenLabelFile bounds labels and other LSM facts without truncation. The
// comparator distinguishes a successfully read empty creation default from a
// missing fact or an invalid empty current label.
func readOpenLabelFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	const limit = 64 * 1024
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && len(b) > limit {
		err = errors.New("LSM fact exceeds 64 KiB")
	}
	return b, err
}

// openLSMNames follows include/uapi/linux/lsm.h. Unknown IDs retain their
// identity and refuse; a new module cannot silently become label-free.
var openLSMNames = map[uint64]string{
	100: "capability", 101: "selinux", 102: "smack", 103: "tomoyo",
	104: "apparmor", 105: "yama", 106: "loadpin", 107: "safesetid",
	108: "lockdown", 109: "bpf", 110: "landlock", 111: "ima",
	112: "evm", 113: "ipe",
}

func checkOpenLabelAuthority(tid, opener, flags int, read func(string) ([]byte, error), modules func() ([]uint64, error), assumeAppArmorRoot bool) error {
	// The unprivileged syscall is authoritative even when securityfs is masked
	// in a container. Older kernels or container seccomp can deny it; only then
	// use securityfs. Neither proc directory names (built at CONFIG time) nor
	// one readable label establishes the complete active module set.
	var b []byte
	var listErr error
	if modules != nil {
		ids, e := modules()
		listErr = e
		if e == nil {
			var names []string
			for _, id := range ids {
				name, ok := openLSMNames[id]
				if !ok {
					return fmt.Errorf("unsupported active LSM ID %d", id)
				}
				names = append(names, name)
			}
			b = []byte(strings.Join(names, ","))
		}
	}
	if b == nil {
		var err error
		b, err = read("/sys/kernel/security/lsm")
		if err != nil {
			return fmt.Errorf("active LSM list: syscall: %v; securityfs: %w; permit lsm_list_modules in the outer seccomp filter or expose readable /sys/kernel/security/lsm; the AppArmor namespace assertion does not waive module discovery", listErr, err)
		}
	}
	var labels []string
	seen := make(map[string]bool)
	for _, name := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if seen[name] {
			return fmt.Errorf("duplicate active LSM %q", name)
		}
		seen[name] = true
		switch name {
		case "apparmor", "selinux", "smack":
			labels = append(labels, name)
		case "lockdown", "capability", "landlock", "yama", "bpf", "ima", "evm", "integrity", "loadpin", "safesetid", "ipe":
			// No independently changing task label for these modules.
		default:
			return fmt.Errorf("unsupported active LSM %q", name)
		}
	}
	if seen["smack"] {
		// smackfs load-self2 reads current_cred()->smk_rules, not the target's.
		// There is no cross-task process-rule query. Even equal labels cannot prove
		// equivalence, so never open on another task's behalf under Smack.
		return errors.New("smack task-specific rules cannot be established")
	}
	if seen["selinux"] && len(labels) != 1 {
		return errors.New("SELinux attr/current is ambiguous with another task-label LSM")
	}
	if seen["apparmor"] {
		// attr/current omits EVERY invisible stack component, without a marker
		// when another component is visible. Only the root policy namespace sees
		// all namespaces. This fact is about the READER, not either compared PID.
		level, e := read("/sys/kernel/security/apparmor/.ns_level")
		if e != nil && !assumeAppArmorRoot {
			return fmt.Errorf("AppArmor viewer namespace depth is unreadable: %w; held opens return EACCES (held-label-unavailable); expose readable securityfs from the root AppArmor policy namespace, or have the container administrator accept hidden-ancestor risk with fs.apparmor_assume_root_namespace: true", e)
		}
		// An explicit assertion substitutes only for an unreadable fact. A known
		// nonzero or malformed depth contradicts it and still refuses. No other
		// fact (module list, current labels, SELinux fscreate) is waived.
		if e == nil && string(level) != "0\n" {
			return errors.New("AppArmor complete stack visibility is not established")
		}
	}
	for _, name := range labels {
		if tid <= 0 || opener <= 0 {
			return errors.New("missing task or open completer identity")
		}
		attr := "/attr/" + name + "/current"
		if name == "selinux" {
			attr = "/attr/current"
		}
		if err := compareOpenAttr(tid, opener, name, attr, false, read); err != nil {
			return err
		}
		if name == "selinux" && (flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE) {
			// fscreate supplies create_sid independently of current. Empty means the
			// policy default, and is a fact only after a successful read. keycreate
			// and sockcreate govern key/socket creation, neither performed here.
			if err := compareOpenAttr(tid, opener, name, "/attr/fscreate", true, read); err != nil {
				return err
			}
		}
	}
	return nil
}

func compareOpenAttr(tid, opener int, name, attr string, empty bool, read func(string) ([]byte, error)) error {
	label := func(pid int) (string, error) {
		procReads.Add(1)
		b, err := read("/proc/" + strconv.Itoa(pid) + attr)
		if err != nil {
			return "", err
		}
		s := strings.TrimSuffix(strings.TrimSuffix(string(b), "\x00"), "\n")
		if s == "" && !empty || strings.ContainsAny(s, "\x00\n") || name == "apparmor" && strings.Contains(s, "---") {
			return "", errors.New("empty, malformed or hidden LSM attribute")
		}
		return s, nil
	}
	task, err := label(tid)
	if err != nil {
		return fmt.Errorf("%s task %s: %w", name, attr, err)
	}
	completer, err := label(opener)
	if err != nil {
		return fmt.Errorf("%s completer %s: %w", name, attr, err)
	}
	if task != completer {
		return fmt.Errorf("%s %s: %w", name, attr, errOpenLabelDiffers)
	}
	return nil
}

// openLabel returns a refusal marker, or nothing when the required authority
// facts match (or the notification is gone). No check can authorize a later syscall: it authorizes
// only this still-trapped task, whose label is stable until the answer.
func (l *Loop) openLabel(n *notif, opener, flags int) string {
	if !l.valid(n) {
		return ""
	}
	err := l.k.CheckOpenLabel(n.pid, opener, flags)
	if !l.valid(n) || err == nil {
		return ""
	}
	if errors.Is(err, errOpenLabelDiffers) {
		return ruleHeldLabelDiffers
	}
	l.log.Warn("supervisor: held open refused, LSM labels could not be established", "tid", n.pid, "err", err)
	return ruleHeldLabelUnavailable
}

func (l *Loop) heldLabel(h *heldPlan) bool {
	if rule := l.openLabel(h.n, l.deputy.PID(), h.flags); rule != "" {
		l.heldRefuse(h, rule, record.ReasonFSGate, h.d.gate)
		return false
	}
	return !h.n.gone
}

// alternateProbeLabel is also used by an answer callback that can outlive the
// worker's hold. It captures the ID and TID by value, never the worker's mutable
// notification, and never answers a notification from that callback.
func (l *Loop) alternateProbeLabel(id uint64, tid, flags int) error {
	if ok, err := l.k.IDValid(id); err != nil || !ok {
		return errors.New("alternate probe: notification is not held")
	}
	err := l.k.CheckOpenLabel(tid, os.Getpid(), flags)
	if ok, validErr := l.k.IDValid(id); validErr != nil || !ok {
		return errors.New("alternate probe: notification is no longer held")
	}
	return err
}
