// SPDX-License-Identifier: Apache-2.0

// Package answertest is the one table of run-membership answers (internal/runscope.Answer) that every caller's test
// walks: the zero value, every way of being inside, every cause of unknown, and outside. A caller permits on the
// last row alone. internal/runscope's TestAnswerTableNamesEveryCause holds the table to the causes the rule declares.
//
// An answer's fields belong to internal/runscope, so no other package can make an Outside answer. This package makes
// its inside and outside answers the one way there is, by runscope.Decide over a process's facts (here a table's: a
// clean or a governed path in the kernel's first cgroup namespace), and its unknown answers with runscope.Unproven.
// TestCallersReadTheAnswerThroughOutside lets it, internal/platform/peer and tests call Decide, and no other file.
package answertest

import (
	"errors"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// Row is one answer, the cause it carries ("" for the zero value and for outside), and whether a caller may permit
// on it.
type Row struct {
	Name    string
	Answer  runscope.Answer
	Cause   runscope.Cause
	Permits bool
}

// insidePaths are cgroup files that make Decide answer Inside, one per cause. A nil file is one that cannot be read.
var insidePaths = []struct {
	cause runscope.Cause
	file  []byte
}{
	{runscope.CausePathUnreadable, nil},
	{runscope.CausePathMalformed, []byte("12:pids:/user.slice\n")},
	{runscope.CausePathAboveRoot, []byte("0::/../../user.slice/user-1000.slice/session-2.scope\n")},
	{runscope.CauseGoverned, []byte("0::/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-r.scope\n")},
}

var unknownCauses = []runscope.Cause{runscope.CauseNSUnreadable, runscope.CauseMixedIDs, runscope.CauseRootCaller,
	runscope.CauseCapabilities, runscope.CauseProcUnanchored, runscope.CauseUserNamespace,
	runscope.CauseInitUnreadable, runscope.CauseInitNotAtRoot, runscope.CauseNoUserManager, runscope.CauseManagerNotListening,
	runscope.CauseManagerBusy, runscope.CauseSocketRefused, runscope.CauseProbeError, runscope.CausePeerUID,
	runscope.CausePeerUnidentified, runscope.CauseNoPeerPidfd, runscope.CausePeerElsewhere, runscope.CauseProbeTimeout,
	runscope.CauseWSLLauncherUnproven, runscope.CauseSystemUnproven}

// Outside is the answer for a process whose path shows no run in the kernel's first cgroup namespace.
func Outside() runscope.Answer {
	return runscope.Decide(&firstNamespace{cgroup: []byte("0::/user.slice/user-1000.slice/session-2.scope\n")})
}

// Inside is the inside answer for cause c, one of the four Decide gives with that verdict; the governed one for
// any other cause.
func Inside(c runscope.Cause) runscope.Answer {
	for _, p := range insidePaths {
		if p.cause == c {
			return runscope.Decide(&firstNamespace{cgroup: p.file})
		}
	}
	return Inside(runscope.CauseGoverned)
}

// Recorded is the unknown answer for cause c of a process outside the kernel's first cgroup namespace whose own facts
// held and whose seccomp mode the rule read as mode: what an ordinary WSL shell gets when its proof fails for c. The
// answer carries the mode for a diagnostic line (runscope.Describe).
func Recorded(c runscope.Cause, mode int) runscope.Answer {
	return runscope.Decide(&otherNamespace{mode: mode, proof: runscope.Unproven(c, nil)})
}

// Rows is the table. Only its last row permits.
func Rows() []Row {
	rows := []Row{{Name: "the zero value", Answer: runscope.Answer{}}}
	for _, p := range insidePaths {
		rows = append(rows, Row{Name: "inside, " + string(p.cause), Answer: Inside(p.cause), Cause: p.cause})
	}
	for _, c := range unknownCauses {
		rows = append(rows, Row{Name: "unknown, " + string(c), Answer: runscope.Unproven(c, nil), Cause: c})
	}
	return append(rows, Row{Name: "outside", Answer: Outside(), Permits: true})
}

// Self is a caller's seam for a row: a function that answers it.
func (r Row) Self() runscope.Answer { return r.Answer }

// errUnreadable is the error of a cgroup file that cannot be read.
var errUnreadable = errors.New("answertest: the cgroup file cannot be read")

// firstNamespace is runscope.Facts for a process in the kernel's first cgroup namespace whose own cgroup file is
// cgroup (nil: unreadable). Decide reads nothing else there; the other reads answer what would refuse.
type firstNamespace struct{ cgroup []byte }

func (f *firstNamespace) OwnCgroup() ([]byte, error) {
	if f.cgroup == nil {
		return nil, errUnreadable
	}
	return f.cgroup, nil
}

func (f *firstNamespace) CgroupNS() (runscope.Namespace, error) {
	return runscope.Namespace{Ino: runscope.InitCgroupNS}, nil
}

func (f *firstNamespace) UIDs() (int, int, int)      { return 0, 0, 0 }
func (f *firstNamespace) Permitted() (uint64, error) { return ^uint64(0), nil }
func (f *firstNamespace) Seccomp() (int, error)      { return 2, nil }

func (f *firstNamespace) AnchoredCgroup() ([]byte, error) { return nil, runscope.ErrUnanchored }

func (f *firstNamespace) Proof(runscope.Namespace, int) runscope.Answer {
	return runscope.Unproven(runscope.CauseProbeError, nil)
}

func (f *firstNamespace) Withheld(bool) (runscope.Cause, bool) { return "", false }

// otherNamespace is runscope.Facts for an unprivileged process outside the kernel's first cgroup namespace whose
// path shows no run, whose seccomp mode is mode, and whose proof answers proof.
type otherNamespace struct {
	mode  int
	proof runscope.Answer
}

var shellPath = []byte("0::/non-systemd\n")

func (f *otherNamespace) OwnCgroup() ([]byte, error) { return shellPath, nil }
func (f *otherNamespace) CgroupNS() (runscope.Namespace, error) {
	return runscope.Namespace{Dev: 4, Ino: runscope.InitCgroupNS + 0x10000001}, nil
}
func (f *otherNamespace) UIDs() (int, int, int)                         { return 1000, 1000, 1000 }
func (f *otherNamespace) Permitted() (uint64, error)                    { return 0, nil }
func (f *otherNamespace) Seccomp() (int, error)                         { return f.mode, nil }
func (f *otherNamespace) AnchoredCgroup() ([]byte, error)               { return shellPath, nil }
func (f *otherNamespace) Proof(runscope.Namespace, int) runscope.Answer { return f.proof }
func (f *otherNamespace) Withheld(bool) (runscope.Cause, bool)          { return "", false }
