// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The program each line's process was running, for Logs' Process column, its prog: key and its Program facet. It
// follows the line page's rule (proc.go) in one forward pass over the run's lines: a process is an exec_id; a forked
// process runs its parent's program (parent_exec_id) until an exec the kernel let through starts its own; a refused
// exec changes nothing. A line of a pid that made no exec at or before it has no program: a parent is never guessed.
//
// Two cases read better than the record's own words. An exec of /proc/self/exe (Codex starts its sandbox helper that
// way) runs the program the process already ran, so it keeps that name instead of "exe". And the pass is
// incremental: a live run that gained lines continues from where the last pass stopped, so a live Logs page does not
// walk the whole run again on every line.

// progIndex is one run's programs: names, and for each line (by index in the run's lines) its name's index, -1 when
// not known. Its slices only grow; a reader holds them cut to the run version it reads.
type progIndex struct {
	names []string
	// paths is each name's program as the record gave it, the pathname the name was cut from (a name is its last
	// element): two programs of one name in different folders are two entries, so prog:/opt/py/bin can tell them apart.
	paths []string
	of    []int32
	// The pass's state, to continue it: the processes by exec_id and the process each pid is now, the names'
	// indexes, and the last line taken (to see that a longer run is the same run grown).
	byID     map[string]*progProc
	byPid    map[int]*progProc
	ids      map[string]int32
	lastSeq  uint64
	lastOff  int64
	firstOff int64
}

// progProc is one process: its exec_id and the program it runs now.
type progProc struct {
	id   string
	prog int32
}

// progEntry guards one run's index while a pass extends it. The index lives in its run's runState (runState.prog), so
// it is dropped with the state, and with the run's lines when the Store evicts them (Store.evict): it needs no
// count of its own, and no table of its own that keeps a state the Store has dropped reachable.
type progEntry struct {
	mu sync.Mutex
	x  *progIndex
}

// progs is the program index of r's lines: the cached one, extended to r's lines, when r is a run the store
// publishes; built afresh otherwise. The slices it returns are cut to r's lines.
func (r *Run) progs() (names []string, of []int32) {
	names, _, of = r.progsFull()
	return names, of
}

// progsFull is progs with each name's pathname (progIndex.paths).
func (r *Run) progsFull() (names, paths []string, of []int32) {
	evs := r.AllEvents()
	if r.st == nil {
		x := newProgIndex()
		x.extend(evs)
		return x.names, x.paths, x.of
	}
	ent := r.st.prog.Load()
	if ent == nil {
		r.st.prog.CompareAndSwap(nil, &progEntry{})
		ent = r.st.prog.Load()
	}
	ent.mu.Lock()
	defer ent.mu.Unlock()
	if ent.x == nil || !ent.x.continues(evs) {
		ent.x = newProgIndex()
	}
	if len(ent.x.of) < len(evs) {
		ent.x.extend(evs)
	}
	n := len(evs)
	k := len(ent.x.names)
	return ent.x.names[:k:k], ent.x.paths[:k:k], ent.x.of[:n:n]
}

func newProgIndex() *progIndex {
	return &progIndex{byID: map[string]*progProc{}, byPid: map[int]*progProc{}, ids: map[string]int32{}}
}

// continues reports whether evs is the run x was built from, the same or grown: its first line and the last line
// x took are where they were. A run cut shorter or read anew from a replaced file starts over.
func (x *progIndex) continues(evs []Event) bool {
	n := len(x.of)
	if n == 0 {
		return true
	}
	if len(evs) < n {
		return false
	}
	return evs[0].off == x.firstOff && evs[n-1].Seq == x.lastSeq && evs[n-1].off == x.lastOff
}

// extend takes evs' lines after the ones x holds.
func (x *progIndex) extend(evs []Event) {
	if len(x.of) == 0 && len(evs) > 0 {
		x.firstOff = evs[0].off
	}
	for i := len(x.of); i < len(evs); i++ {
		e := &evs[i]
		prog := int32(-1)
		if e.Kind == string(record.KindExec) && !e.Mirror {
			prog = x.exec(e)
		} else if p := x.byPid[e.pid]; p != nil {
			prog = p.prog
		}
		x.of = append(x.of, prog)
	}
	if n := len(evs); n > 0 {
		x.lastSeq, x.lastOff = evs[n-1].Seq, evs[n-1].off
	}
}

// exec takes an exec line: the process it names (new when the pid's exec_id changed, running its parent's program)
// and, when the kernel let it through, its new program. It answers the program the process runs after the line.
func (x *progIndex) exec(e *Event) int32 {
	var p struct {
		ID     string `json:"exec_id"`
		Parent string `json:"parent_exec_id"`
	}
	if json.Unmarshal([]byte(e.Raw), &p) != nil || p.ID == "" {
		if cur := x.byPid[e.pid]; cur != nil {
			return cur.prog
		}
		return -1
	}
	pr := x.byID[p.ID]
	if pr == nil {
		pr = &progProc{id: p.ID, prog: -1}
		if parent := x.byID[p.Parent]; parent != nil {
			pr.prog = parent.prog // forked: it runs its parent's program until its own exec
		}
		x.byID[p.ID] = pr
	}
	x.byPid[e.pid] = pr
	if e.Verdict == string(record.VerdictRefused) {
		return pr.prog
	}
	name := programName(e)
	if selfExe(e.path) && pr.prog >= 0 {
		return pr.prog // it starts again the program it runs
	}
	if name == "" {
		return pr.prog
	}
	full := e.Program()
	k, ok := x.ids[full]
	if !ok {
		k = int32(len(x.names)) //nolint:gosec // a run names far fewer than 2^31 programs
		x.names = append(x.names, name)
		x.paths = append(x.paths, full)
		x.ids[full] = k
	}
	pr.prog = k
	return k
}

// selfExe reports whether path is a process's own program by its /proc link (/proc/self/exe, /proc/<pid>/exe).
func selfExe(p string) bool {
	rest, ok := strings.CutPrefix(p, "/proc/")
	if !ok {
		return false
	}
	_, exe, ok := strings.Cut(rest, "/")
	return ok && exe == "exe"
}

// programAt is the name of the program line i of a run ran, "" when not known.
func programAt(names []string, of []int32, i int32) string {
	if int(i) >= len(of) || of[i] < 0 {
		return ""
	}
	return names[of[i]]
}

// ProgramOf is the program the process of r's line seq was running at that line ("" when the record does not say).
func ProgramOf(r *Run, seq uint64) string {
	evs := r.AllEvents()
	i := findSeq(evs, seq)
	if i < 0 {
		return ""
	}
	names, of := r.progs()
	return programAt(names, of, int32(i)) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
}
