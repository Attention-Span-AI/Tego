// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// procs is what the hook asks of the machine's processes, so a test can stand in for it: who this hook is, which
// harness started it, and whether a process that once claimed a note is still there.
type procs struct {
	// self is this hook process's identity ("pid:start-ticks", as the supervisor writes the owners of a refusal), ""
	// when it cannot be read.
	self func() string
	// harness is the identity of the harness this hook belongs to: its nearest ancestor that is not a shell, "" when
	// there is none to find (the hook then claims only the refusals nobody owns).
	harness func() string
	// alive reports whether the process id names is still the one that had that start time.
	alive func(id string) bool
	// now is the clock the claims are dated by.
	now func() time.Time
}

// systemProcs is procs over /proc.
func systemProcs() procs {
	return procs{
		self:    func() string { return identityOf(readProcStat, os.Getpid()) },
		harness: func() string { return harnessOf(readProcStat, os.Getpid()) },
		alive:   func(id string) bool { return aliveID(readProcStat, id) },
		now:     time.Now,
	}
}

// procStat is the part of /proc/<pid>/stat the hook reads.
type procStat struct {
	comm  string
	ppid  int
	start uint64
}

// readProcStat reads /proc/<pid>/stat; ok is false for a process that is gone or a line this cannot parse.
func readProcStat(pid int) (procStat, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procStat{}, false
	}
	return parseProcStat(string(b))
}

// parseProcStat reads the comm (between the first "(" and the last ")", which may hold both), the parent pid
// (field 4) and the start time (field 22) of a stat line.
func parseProcStat(s string) (procStat, bool) {
	open, closing := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closing < open {
		return procStat{}, false
	}
	f := strings.Fields(s[closing+1:]) // state ppid ... starttime is the 20th after the comm
	if len(f) < 20 {
		return procStat{}, false
	}
	ppid, err := strconv.Atoi(f[1])
	if err != nil {
		return procStat{}, false
	}
	start, err := strconv.ParseUint(f[19], 10, 64)
	if err != nil {
		return procStat{}, false
	}
	return procStat{comm: s[open+1 : closing], ppid: ppid, start: start}, true
}

func identityString(pid int, start uint64) string {
	return strconv.Itoa(pid) + ":" + strconv.FormatUint(start, 10)
}

// identityOf is pid's "pid:start" identity, "" when it cannot be read.
func identityOf(read func(int) (procStat, bool), pid int) string {
	st, ok := read(pid)
	if !ok {
		return ""
	}
	return identityString(pid, st.start)
}

// aliveID reports whether id ("pid:start") names a process that is there now with that start time.
func aliveID(read func(int) (procStat, bool), id string) bool {
	p, s, ok := strings.Cut(id, ":")
	if !ok {
		return false
	}
	pid, err := strconv.Atoi(p)
	if err != nil || pid <= 0 {
		return false
	}
	st, ok := read(pid)
	return ok && strconv.FormatUint(st.start, 10) == s
}

// maxHarnessDepth bounds how far up the hook looks for its harness.
const maxHarnessDepth = 32

// shells are the process names the hook passes over on its way up: a harness may start its hook through a shell
// (Claude Code does not for the exec form the provisioner writes, and a hand-written hook command may), and that
// shell is no harness. comm is the 15 characters /proc keeps of the name.
var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ash": true, "fish": true, "ksh": true, "csh": true, "tcsh": true}

// harnessOf is the identity of the nearest ancestor of pid that is not a shell, "" when a process 1, an unreadable
// process or maxHarnessDepth ancestors come first. The supervisor writes the same identities into a refusal's owners
// (ADR 0063), so the harness's identity is in the owners of every refusal its tools' processes drew.
func harnessOf(read func(int) (procStat, bool), pid int) string {
	for range maxHarnessDepth {
		st, ok := read(pid)
		if !ok || st.ppid <= 1 {
			return ""
		}
		parent, ok := read(st.ppid)
		if !ok {
			return ""
		}
		if !shells[parent.comm] {
			return identityString(st.ppid, parent.start)
		}
		pid = st.ppid
	}
	return ""
}
