// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The line page's process facts. A ledger line names its process only by pid, tid and cgroup; no line records a
// process's program, parent or working folder. But every exec line carries exec_id (<run>/<pid>/<start>, one per
// process) and parent_exec_id (the process that forked it), and run_start names the launcher (launcher_pid,
// launcher_start_ns). So the program a pid was running at a line is the latest exec of that process at or before the
// line that the kernel let through, and its parents follow parent_exec_id up to the launcher. A refused exec does not
// change what a process runs.
//
// The chain is partial by design: a process that forked and never started a program (a subshell running awk in a
// pipeline) writes no exec line, so a child whose parent_exec_id names it ends the chain there, shown as "forked, no
// exec recorded". A parent is never guessed: a line of a pid with no exec at or before it has no program and no
// chain. The working folder is run_start's cwd for every line; a process's own cwd is not recorded.

// ProcRef is one process as the line page shows it: the program it was running at the line, or why that is not
// known.
type ProcRef struct {
	PID int
	// ExecID is the process's exec_id ("" for the launcher when run_start did not give its start time).
	ExecID string
	// ExecSeq is the seq of the exec line that started the program (HasExec).
	ExecSeq uint64
	HasExec bool
	// Path is the program's path as the exec line wrote it; Name the name a person knows it by (bash, curl, codex).
	Path, Name string
	// Argv is the command line as recorded (read back from its blob when the writer moved it there, at most
	// MaxTargetBytes); ArgvMasked is it with credential-looking values hidden.
	Argv, ArgvMasked string
	// Refused marks a process whose every exec up to the line was refused: Path is what it tried to start, and it
	// still ran its parent's program.
	Refused bool
	// Unrecorded marks a process that forked without starting a program, so no line names its program or parent.
	Unrecorded bool
	// Launcher marks tego's own launcher, the root of every run's tree.
	Launcher bool
	// Words is the process in a few words: "bash (pid 4037090)", "pid 4036305, forked, no exec recorded".
	Words string
}

// procInfo is one process of the run: its exec_id, its parent's, and its exec lines in file order.
type procInfo struct {
	id, parent string
	pid        int
	execs      []int32
}

// execFact is what an exec line says about its process, decoded once per version of the run.
type execFact struct {
	id, parent, path string
	refused          bool
}

// lineIndex is the per-version index Explain reads: the processes by exec_id and by pid, the launcher, the asks
// by id with the lines that belong to each, and the mirror pairs.
type lineIndex struct {
	procs       map[string]*procInfo
	byPid       map[int][]*procInfo // in the order of their first exec line
	execs       map[int32]execFact
	launcherPID int
	launcherID  string
	// users maps a uid to the user name run_start recorded for the launcher, the only name the record holds.
	users map[string]string

	asks  map[string]*askEntry
	askOf map[int32]string // a line's index → the ask it belongs to (the ask, its answer, its consequences)

	mirrorOf   map[int32]int32 // a mirror's index → its action's
	mirroredBy map[int32]int32 // an action's index → its mirror's

	// treeOnce builds tree, the Processes tab's process tree (proctree.go), from this index.
	treeOnce sync.Once
	tree     *ProcTree
}

// askEntry is one ask_id of the run: its ask and answer lines and the lines that followed from the answer.
type askEntry struct {
	id                    string
	askIdx, answerIdx     int32
	hasAsk, hasAnswer     bool
	op, target, rule      string
	hold                  string
	pid                   int
	approved              *bool
	by, reason, alternate string
	afterS                float64
	consequences          []int32
}

// consequenceWindow is how many lines after an answer the line it let through or refused may be: the supervisor
// writes it as it releases the held call, so it is a line or two later, past lines other processes slipped in.
const consequenceWindow = 64

// lineIndexOf is r's lineIndex, built once per published version (runMemo).
func (r *Run) lineIndexOf() *lineIndex {
	m := r.memoOf()
	m.factsOnce.Do(func() { m.facts = buildLineIndex(r.ID, r.AllEvents()) })
	return m.facts
}

func buildLineIndex(run string, evs []Event) *lineIndex {
	x := &lineIndex{procs: map[string]*procInfo{}, byPid: map[int][]*procInfo{}, execs: map[int32]execFact{},
		users: map[string]string{}, asks: map[string]*askEntry{}, askOf: map[int32]string{},
		mirrorOf: map[int32]int32{}, mirroredBy: map[int32]int32{}}
	// The mirrors are marked as the store takes each line (pair.go); which action each one took is the builder's
	// state, so it is replayed here with the same rule over the same lines.
	pair := &runState{}
	for i := range evs {
		e := &evs[i]
		idx := int32(i) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
		if e.Mirror {
			cp := *e
			pair.b.Events = evs[:i]
			pair.markMirror(&cp)
			if cp.Mirror && len(pair.paired) > 0 {
				a := int32(pair.paired[len(pair.paired)-1]) //nolint:gosec // as idx
				x.mirrorOf[idx], x.mirroredBy[a] = a, idx
			}
		}
		switch e.Kind {
		case string(record.KindRunStart):
			var p struct {
				PID   int    `json:"launcher_pid"`
				Start uint64 `json:"launcher_start_ns"`
				UID   *int   `json:"launcher_uid"`
				User  string `json:"launcher_user"`
			}
			if json.Unmarshal([]byte(e.Raw), &p) == nil {
				x.launcherPID = p.PID
				if p.PID > 0 && p.Start > 0 {
					x.launcherID = run + "/" + strconv.Itoa(p.PID) + "/" + strconv.FormatUint(p.Start, 10)
				}
				if p.UID != nil && p.User != "" {
					x.users[strconv.Itoa(*p.UID)] = p.User
				}
			}
		case string(record.KindExec):
			id, parent, ok := execIDs(e.Raw)
			if !ok {
				var p struct {
					ID     string `json:"exec_id"`
					Parent string `json:"parent_exec_id"`
				}
				if json.Unmarshal([]byte(e.Raw), &p) != nil {
					continue
				}
				id, parent = p.ID, p.Parent
			}
			// e.path is the payload's path, decoded as the store took the line.
			x.execs[idx] = execFact{id: id, parent: parent, path: e.path, refused: e.Verdict == string(record.VerdictRefused)}
			if id == "" {
				continue
			}
			pi := x.procs[id]
			if pi == nil {
				pi = &procInfo{id: id, parent: parent, pid: e.pid}
				x.procs[id] = pi
				x.byPid[e.pid] = append(x.byPid[e.pid], pi)
			}
			pi.execs = append(pi.execs, idx)
		case string(record.KindAsk):
			a := x.ask(e.AskID)
			a.askIdx, a.hasAsk, a.hold, a.pid = idx, true, e.Op, e.pid
			a.op, a.target, a.rule = e.askOp, e.askTarget, e.Rule
			x.askOf[idx] = e.AskID
		case string(record.KindAnswer):
			var p struct {
				Approved  *bool   `json:"approved"`
				By        string  `json:"by"`
				AfterS    float64 `json:"after_s"`
				Reason    string  `json:"answer_reason"`
				Alternate string  `json:"alternate"`
				Rule      string  `json:"ask_rule"`
			}
			_ = json.Unmarshal([]byte(e.Raw), &p) // an answer that does not decode still answers its ask_id
			a := x.ask(e.AskID)
			a.answerIdx, a.hasAnswer = idx, true
			a.approved, a.by, a.afterS, a.reason, a.alternate = p.Approved, p.By, p.AfterS, p.Reason, p.Alternate
			if !a.hasAsk {
				a.op, a.target, a.rule, a.pid = e.askOp, e.askTarget, p.Rule, e.pid
			}
			x.askOf[idx] = e.AskID
		}
	}
	for _, a := range x.asks {
		if a.hasAnswer && a.id != "" {
			x.consequences(evs, a)
		}
	}
	return x
}

// execIDs is an exec line's exec_id and parent_exec_id read straight from the line as the ledger writes it, without
// decoding the line, whose argv can be kilobytes (decoding was most of the index's cost on a run of 25,000
// processes). exec_id must be there and parent_exec_id may be left out; a key that is there must be there once, at
// a key's place (after "{" or ","; inside a string value its quotes would be escaped), with a plain string value:
// no escape in it. ok is false for anything else, and the caller decodes the line.
func execIDs(raw string) (id, parent string, ok bool) {
	id, ok = plainField(raw, `"exec_id":"`)
	if !ok {
		return "", "", false
	}
	const parentKey = `"parent_exec_id":"`
	if !strings.Contains(raw, parentKey) {
		return id, "", true // a process whose parent the writer did not name
	}
	parent, ok = plainField(raw, parentKey)
	return id, parent, ok
}

// plainField is the value of the one key in raw (key is `"<name>":"`), when it is there once, at a key's place,
// and its value has no escape.
func plainField(raw, key string) (string, bool) {
	i := strings.Index(raw, key)
	if i <= 0 || (raw[i-1] != ',' && raw[i-1] != '{') {
		return "", false
	}
	v := raw[i+len(key):]
	if strings.Contains(v, key) {
		return "", false
	}
	j := strings.IndexByte(v, '"')
	if j < 0 || strings.IndexByte(v[:j], '\\') >= 0 {
		return "", false
	}
	return v[:j], true
}

func (x *lineIndex) ask(id string) *askEntry {
	a := x.asks[id]
	if a == nil {
		a = &askEntry{id: id}
		x.asks[id] = a
	}
	return a
}

// consequences finds the line the answer to a let through or refused: the first action line of the asking process
// after the answer that a person decided (authority human) or that a question refused (reason ask-*), with the same
// rule when both name one, and its mirror. Nothing is linked when no such line is in the window.
func (x *lineIndex) consequences(evs []Event, a *askEntry) {
	end := min(len(evs), int(a.answerIdx)+1+consequenceWindow)
	for j := int(a.answerIdx) + 1; j < end; j++ {
		e := &evs[j]
		if e.Kind == string(record.KindAsk) || e.Kind == string(record.KindAnswer) || e.Mirror || e.pid != a.pid {
			continue
		}
		if e.Authority != string(record.AuthorityHuman) && !strings.HasPrefix(e.Reason, "ask-") {
			continue
		}
		if a.rule != "" && e.Rule != "" && e.Rule != a.rule {
			continue
		}
		idx := int32(j) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
		a.consequences = append(a.consequences, idx)
		if _, taken := x.askOf[idx]; !taken {
			x.askOf[idx] = a.id
		}
		if m, ok := x.mirroredBy[idx]; ok {
			a.consequences = append(a.consequences, m)
			if _, taken := x.askOf[m]; !taken {
				x.askOf[m] = a.id
			}
		}
		return
	}
}

// procAt is the process pid was at line index at, and the index of the exec line in force for it (-1 when every
// exec of it up to at was refused; then refused names the newest refused one, else it is -1 too). ok is false when
// pid made no exec at or before at.
func (x *lineIndex) procAt(pid int, at int32) (pi *procInfo, exec, refused int32, ok bool) {
	ps := x.byPid[pid]
	// The newest process of the pid whose first exec is at or before the line: a pid the kernel reused in the run
	// is a new process with a new exec_id.
	k := sort.Search(len(ps), func(i int) bool { return ps[i].execs[0] > at }) - 1
	if k < 0 {
		return nil, -1, -1, false
	}
	pi = ps[k]
	exec, refused = -1, -1
	for _, i := range pi.execs {
		if i > at {
			break
		}
		if x.execs[i].refused {
			refused = i
		} else {
			exec = i
		}
	}
	return pi, exec, refused, true
}

// inForce is the process exec_id at line index at as a ProcRef, and its parent's exec_id; the ProcRef is Unrecorded
// when the run holds no exec of that process, and has no program (HasExec false, Refused false) when its first exec
// is after the line.
func (x *lineIndex) inForce(evs []Event, id string, at int32) (ProcRef, string) {
	pi := x.procs[id]
	if pi == nil {
		ref := ProcRef{PID: pidOfExecID(id), ExecID: id, Unrecorded: true}
		ref.Words = "pid " + strconv.Itoa(ref.PID) + ", forked, no exec recorded"
		return ref, ""
	}
	exec, refused := int32(-1), int32(-1)
	for _, i := range pi.execs {
		if i > at {
			break
		}
		if x.execs[i].refused {
			refused = i
		} else {
			exec = i
		}
	}
	return x.ref(evs, pi, exec, refused), pi.parent
}

// ref is process pi running the program of exec line exec (or, with exec -1, having tried refused).
func (x *lineIndex) ref(evs []Event, pi *procInfo, exec, refused int32) ProcRef {
	ref := ProcRef{PID: pi.pid, ExecID: pi.id}
	i := exec
	if i < 0 {
		i, ref.Refused = refused, true
	}
	if i < 0 {
		// The process is recorded (a later line starts a program in it), but not what it ran at this line: it had
		// forked and not yet started a program of its own. Its parent is still known.
		ref.Words = "pid " + strconv.Itoa(pi.pid) + ", no program recorded yet at this line"
		return ref
	}
	e := &evs[i]
	f := x.execs[i]
	ref.HasExec, ref.ExecSeq, ref.Path = true, e.Seq, f.path
	ref.Argv = e.Target
	ref.Name = programName(f.path, e.Target)
	return ref
}

// programName is the name a person knows a program by: its path's last element, or the first word of its command
// line when the line wrote no path.
func programName(p, argv string) string {
	if p == "" {
		p, _, _ = strings.Cut(argv, " ")
	}
	if p == "" {
		return ""
	}
	return path.Base(p)
}

// pidOfExecID is the pid an exec_id (<run>/<pid>/<start>) names, 0 when it names none.
func pidOfExecID(id string) int {
	parts := strings.Split(id, "/")
	if len(parts) < 3 {
		return 0
	}
	n, _ := strconv.Atoi(parts[len(parts)-2])
	return n
}

// maxChain bounds a process chain: no real tree is this deep, and a malformed ledger whose exec ids loop ends here.
const maxChain = 64

// chain is the parents of the process whose parent exec_id is parent, nearest first, as they were at line index at,
// up to the launcher or the first parent the run did not record.
func (x *lineIndex) chain(evs []Event, parent string, at int32) []ProcRef {
	var out []ProcRef
	seen := map[string]bool{}
	for parent != "" && len(out) < maxChain && !seen[parent] {
		seen[parent] = true
		if x.isLauncher(parent) {
			out = append(out, ProcRef{PID: pidOfExecID(parent), ExecID: parent, Launcher: true, Name: "tego launcher"})
			break
		}
		ref, next := x.inForce(evs, parent, at)
		out = append(out, ref)
		if ref.Unrecorded {
			break
		}
		parent = next
	}
	return out
}

// isLauncher reports whether exec_id id is the run's launcher: its exec_id when run_start gave the launcher's start
// time, else its pid.
func (x *lineIndex) isLauncher(id string) bool {
	if x.launcherID != "" {
		return id == x.launcherID
	}
	return x.launcherPID > 0 && pidOfExecID(id) == x.launcherPID
}
