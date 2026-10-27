// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// ScopePrefix and ScopeSuffix name an adoption's cgroup: adopt-<run id>.scope, beside tego run's run-<run id>.scope
// under tego.slice/tego-<agent>.slice. It is not run-<id>.scope on purpose: the sweep and `tego stop` kill a run's
// scope whose launcher is gone (ADR 0020), and an adopted agent is the operator's own process, started outside Tego,
// which an adoption never kills (ADR 0055). internal/runscope reads the name (GovernedBy, AdoptionScopeRun,
// TestScopeNameIsWhatRunscopeReads).
const (
	ScopePrefix = "adopt-"
	ScopeSuffix = ".scope"
)

// ScopeName is the cgroup name of run id's adoption.
func ScopeName(runID string) string { return ScopePrefix + runID + ScopeSuffix }

// The rules a Refusal names. Each is a reason a process is never adopted, whoever asks.
const (
	RefuseInit      = "init"            // pid 1
	RefuseKernel    = "kernel-thread"   // a kernel thread: no program, nothing of the operator's
	RefuseThread    = "thread"          // a thread id: adoption moves a process, named by its process id
	RefuseTego      = "tego"            // tego itself: this process, or any process running tego's binary
	RefuseAncestor  = "ancestor"        // an ancestor of the caller: its shell, sshd, a multiplexer, the user manager
	RefuseManager   = "service-manager" // a systemd manager (its cgroup is an init.scope)
	RefuseNamespace = "namespace"       // in another cgroup or pid namespace: a container's process
	RefuseGoverned  = "governed"        // already inside a tego run or another adoption
	RefuseNoCgroup  = "no-cgroup"       // in no cgroup v2 hierarchy: there is no cgroup to move it from
	RefuseRoot      = "root-cgroup"     // in the cgroup2 root, which a release never writes: it could not go back
	RefuseUID       = "uid"             // the guard's owner filter: its uids are not one of the listed uids
)

// Refusal is why a process is not adopted. It is an error.
type Refusal struct {
	Rule   string
	PID    int
	Detail string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("pid %d is not adopted (%s): %s", r.PID, r.Rule, r.Detail)
}

// IsRefusal reports whether err is a Refusal, and under which rule.
func IsRefusal(err error) (string, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Rule, true
	}
	return "", false
}

// Self is what Check compares a candidate with: the process that would adopt it.
type Self struct {
	PID int
	// Ancestors are the caller's parent, its parent, and so on up to pid 1 (included).
	Ancestors []int
	// ExeFile is the identity of the caller's own binary; Exe its path.
	ExeFile FileID
	Exe     string
	// CgroupNS and PidNS are the caller's namespaces.
	CgroupNS, PidNS uint64
}

// maxAncestry bounds the walk up the caller's parents: a pid chain is never this long, and a /proc that loops is not
// followed for ever.
const maxAncestry = 4096

// SelfOf reads pid (the caller's own) as a Self: its ancestry from /proc, its binary's identity, its namespaces.
func SelfOf(p Proc, pid int) (Self, error) {
	me, err := Identify(p, pid)
	if err != nil {
		return Self{}, fmt.Errorf("adopt: read this process: %w", err)
	}
	s := Self{PID: pid, ExeFile: me.ExeFile, Exe: me.Exe, CgroupNS: me.CgroupNS, PidNS: me.PidNS}
	seen := map[int]bool{pid: true}
	for ppid := me.PPID; ppid > 0 && len(s.Ancestors) < maxAncestry && !seen[ppid]; {
		seen[ppid] = true
		s.Ancestors = append(s.Ancestors, ppid)
		st, err := p.Stat(ppid)
		if err != nil {
			break // a parent that exited meanwhile: the caller was reparented, and its new parent is next time's
		}
		ppid = st.PPID
	}
	return s, nil
}

// Check refuses a process no adoption may move, whoever asked for it: pid 1, a kernel thread, a thread id, tego
// itself, an ancestor of the caller (adopting it would move the caller's own shell, terminal or login), a systemd
// manager, a process in another cgroup or pid namespace than the caller's (a container's, whose cgroup belongs to its
// runtime), one already inside a tego run or adoption, one in no cgroup v2 hierarchy, and one in the cgroup2 root
// (a release never moves a process into the root cgroup, so such a process could not be given back). It reads
// nothing: t and self are what Identify and SelfOf read.
func Check(t Process, self Self) error {
	refuse := func(rule, format string, args ...any) error {
		return &Refusal{Rule: rule, PID: t.PID, Detail: fmt.Sprintf(format, args...)}
	}
	switch {
	case t.PID == 1:
		return refuse(RefuseInit, "pid 1 is the system's init")
	case t.Exe == "":
		return refuse(RefuseKernel, "%s is a kernel thread", t.Comm)
	case t.Tgid != 0 && t.Tgid != t.PID:
		return refuse(RefuseThread, "it is a thread of process %d; name the process", t.Tgid)
	case t.PID == self.PID:
		return refuse(RefuseTego, "it is this tego")
	case t.ExeFile != (FileID{}) && t.ExeFile == self.ExeFile, filepath.Base(t.Exe) == "tego":
		return refuse(RefuseTego, "it runs tego (%s)", t.Exe)
	case slices.Contains(self.Ancestors, t.PID):
		return refuse(RefuseAncestor, "it is an ancestor of this tego (%s): its shell, terminal, login or user manager", t.Comm)
	case t.Cgroup == "":
		return refuse(RefuseNoCgroup, "/proc/%d/cgroup names no cgroup v2 path", t.PID)
	case path.Clean("/"+t.Cgroup) == "/":
		return refuse(RefuseRoot, "it is in the root cgroup, where a release could not put it back")
	case path.Base(t.Cgroup) == "init.scope":
		return refuse(RefuseManager, "it is a service manager (%s)", t.Cgroup)
	case t.CgroupNS == 0 || t.PidNS == 0:
		return refuse(RefuseNamespace, "its cgroup and pid namespaces could not be read")
	case t.CgroupNS != self.CgroupNS || t.PidNS != self.PidNS:
		return refuse(RefuseNamespace, "it runs in another cgroup or pid namespace (a container), whose cgroup is its runtime's")
	}
	if run := runscope.GovernedBy(t.Cgroup); run != "" {
		return refuse(RefuseGoverned, "it is already inside tego run %s (%s)", run, t.Cgroup)
	}
	return nil
}

// UIDs is the guard's owner filter (`tego agents --follow --adopt --uid <uid>...`): any local user can name a
// program claude, so a signature alone never adopts. A process is admitted only when its real, effective and saved
// user ids are one and the same listed uid; root's processes only when 0 is listed.
type UIDs []int

// Admits reports whether u admits t, and why not.
func (u UIDs) Admits(t Process) (bool, string) {
	owner := t.Owner()
	switch {
	case owner < 0:
		return false, fmt.Sprintf("its real, effective and saved uids differ (%d, %d, %d)", t.UID[0], t.UID[1], t.UID[2])
	case slices.Contains(u, owner):
		return true, ""
	case owner == 0:
		return false, "it runs as root (uid 0), which no --uid names; list --uid 0 to adopt root's processes"
	}
	return false, fmt.Sprintf("it runs as uid %d, which no --uid names", owner)
}

// Admit is Admits as an error, a Refusal under RefuseUID.
func (u UIDs) Admit(t Process) error {
	if ok, why := u.Admits(t); !ok {
		return &Refusal{Rule: RefuseUID, PID: t.PID, Detail: why}
	}
	return nil
}
