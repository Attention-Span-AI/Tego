// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"cmp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/linewords"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The run page's Processes tab: the run's processes as a tree, rebuilt from the same index the line page reads
// (proc.go). Every exec line carries exec_id (one per process) and parent_exec_id (the process that forked it), and
// run_start names tego's launcher, the root. Each process says what it ran (every exec of it in file order, the
// refused ones that only differ by the path a PATH search tried folded into one attempt), what it did (its lines,
// reads, writes, connects and the hosts it reached) and what was refused.
//
// The tree is honest but partial. A process that forked and never started a program (a subshell running one stage of
// a pipeline) writes no exec line, so the record does not say who its parent was: its children still hang from it,
// shown as "forked, no exec recorded", and it hangs from the root marked ParentUnknown. A pid that wrote lines but no
// exec line, and that no exec names as a parent, is shown the same way. A parent is never guessed. Per-process
// working folders are not recorded.
//
// A line belongs to the process its envelope's pid names at that line: the newest process of that pid whose first
// exec is at or before the line, else the pid's first process (a forked child's lines before its own exec, which ran
// its parent's program), else the launcher for the launcher's pid, else the pid's unrecorded node. An exec line
// belongs to the process its exec_id names. A refused action's mirror (pair.go) is not counted, so the lines of all
// processes add up to the run's lines in Logs, and each process's lines are those Logs shows for `run:<id> pid:<pid>`
// (a pid the kernel reused inside one run is two processes here and one pid there).

// ProcTree is one run's process tree, built once per published version of the run (ProcessTree).
type ProcTree struct {
	Run  string
	Root *ProcNode
	// Procs is the number of processes in the tree, the root included; Unrecorded is how many of them forked
	// without starting a program (or wrote lines with no exec line), so their parent is not recorded.
	Procs, Unrecorded int
	// Lines is the lines counted on the tree's processes: every line of the run but the mirrors and NoPID.
	Lines int
	// Refused is the refusals among them (Event.Refusal), the run's Refusals when every line names a pid.
	Refused int
	// NoPID is the lines whose envelope names no process (pid 0), on no process.
	NoPID int
}

// ProcNode is one process of the tree.
type ProcNode struct {
	// Run is the run's id, so a node links to its lines on its own.
	Run string
	PID int
	// ExecID is the process's exec_id ("" for a pid with lines and no exec line, and for a launcher run_start gave
	// no start time for).
	ExecID string
	// Launcher marks tego's launcher, the root.
	Launcher bool
	// Unrecorded marks a process that started no program the record shows: it forked and never ran exec, or only
	// its children's exec lines and its own other lines name it.
	Unrecorded bool
	// ParentUnknown marks a process the record names no recorded parent for, hung from the root.
	ParentUnknown bool
	// Name and Path are the latest program the process ran that the kernel let through (or, when every exec of it
	// was refused, the latest it tried: Refused): the name a person knows it by and its path; Command gives its
	// command line. ExecSeq is that exec line's seq.
	Name, Path string
	cmd        string
	ExecSeq    uint64
	HasExec    bool
	// Refused marks a process whose every exec was refused: it never ran a program of its own.
	Refused bool
	// FirstSeq and Start are the seq and time of the process's first line, or, for an unrecorded process with no
	// line of its own, of its first child's.
	FirstSeq uint64
	Start    time.Time
	// Execs is every exec of the process in file order; refused execs in a row with the same command (a PATH search
	// trying /usr/bin/x, then /bin/x) are one entry with Count and every Path.
	Execs []ProcExec
	// Counts is what the process itself did; Below is the same summed over every process under it.
	Counts, Below ProcCounts
	// Hosts is the hosts the process connected to or tried to, most lines first, at most MaxTreeHosts; Counts.Hosts
	// is how many distinct ones.
	Hosts []HostCount
	// Children are the processes it forked, by their first line.
	Children []*ProcNode
	// Depth is the node's depth, the root's 0.
	Depth int

	// parent is the node it hangs from (nil for the root); state and hosts are the build's own.
	parent *ProcNode
	state  uint8
	hosts  map[string]int
}

// ProcExec is one exec of a process, or several refused ones in a row with the same command.
type ProcExec struct {
	Seq uint64
	// Name is the program; Command gives its command line; Paths is every path the folded execs named.
	Name    string
	cmd     string
	Paths   []string
	Refused bool
	// Count is the execs folded into this one (1 for an allowed exec).
	Count int
	// Seqs is every folded exec's seq, in file order.
	Seqs []uint64
}

// ProcCounts is what one process did, or the processes under one.
type ProcCounts struct {
	// Procs is the number of processes (0 on a node's own Counts, the processes under it on Below).
	Procs int
	// Lines is every line of the process; Refused its refusals (Event.Refusal); Execs its exec lines.
	Lines, Refused, Execs int
	// Reads and Writes are its file lines: an open for reading, and every other file operation (an open for
	// writing, mkdir, unlink, rename, chmod, symlink), allowed or refused.
	Reads, Writes int
	// Connects is its network lines and its refused connections; Hosts the distinct hosts they name.
	Connects, Hosts int
}

// HostCount is a host and the lines that name it.
type HostCount struct {
	Host string
	N    int
}

// MaxTreeCommand bounds a node's command line: the tree shows a command at a glance, the line page shows it whole.
const MaxTreeCommand = 1 << 10

// MaxTreeHosts is how many hosts a node names.
const MaxTreeHosts = 3

// ProcessTree is r's process tree, built once per published version of the run and shared: do not modify it.
func ProcessTree(r *Run) *ProcTree {
	x := r.lineIndexOf()
	x.treeOnce.Do(func() { x.tree = buildProcTree(r.ID, r.AllEvents(), x) })
	return x.tree
}

// treeBuilder holds the build's state. A run can hold tens of thousands of processes, and a live run's tree is
// built again for each new version of it, so the nodes and their execs are carved from a few slabs, and the parent
// links and walk states are fields of the nodes, not maps.
type treeBuilder struct {
	t     *ProcTree
	x     *lineIndex
	evs   []Event
	byID  map[string]*ProcNode
	byPid map[int]*ProcNode // the unrecorded node a pid's lines without an exec go to
	order []*ProcNode       // every node but the root, in the order made

	owners  map[int]*pidOwners // ownerOf's per pid
	last    *pidOwners
	lastPid int
}

func buildProcTree(run string, evs []Event, x *lineIndex) *ProcTree {
	b := &treeBuilder{t: &ProcTree{Run: run}, x: x, evs: evs, byID: make(map[string]*ProcNode, len(x.procs)), byPid: map[int]*ProcNode{},
		owners: make(map[int]*pidOwners, len(x.byPid))}
	root := &ProcNode{Run: run, PID: x.launcherPID, ExecID: x.launcherID, Launcher: true, Name: "tego launcher"}
	b.t.Root = root

	// The recorded processes, in the order of their first exec line, so the build is the same every time: each is
	// put at its first exec line's index, and the slots read in order (a sort costs more at 25,000 processes).
	at := make([]*procInfo, len(evs))
	for _, pi := range x.procs {
		at[pi.execs[0]] = pi
	}
	procs := make([]*procInfo, 0, len(x.procs))
	for _, pi := range at {
		if pi != nil {
			procs = append(procs, pi)
		}
	}
	nodes := make([]ProcNode, len(procs))
	execs := make([]ProcExec, len(x.execs))
	seqs := make([]uint64, len(x.execs))
	paths := make([]string, len(x.execs))
	b.order = make([]*ProcNode, 0, len(procs)+8)
	// owner is the process of each exec line, by index: an exec line belongs to the process its exec_id names.
	owner := make([]*ProcNode, len(evs))
	off := 0
	for k, pi := range procs {
		n := &nodes[k]
		n.Run, n.PID, n.ExecID = run, pi.pid, pi.id
		end := off + len(pi.execs)
		b.execsOf(n, pi, execs[off:off:end], seqs[off:end:end], paths[off:end:end])
		off = end
		b.byID[pi.id] = n
		b.order = append(b.order, n)
		for _, i := range pi.execs {
			owner[i] = n
		}
	}
	for k, pi := range procs {
		n := &nodes[k]
		switch p := pi.parent; {
		case p == "":
			n.parent, n.ParentUnknown = root, true
		case x.isLauncher(p):
			n.parent = root
		case b.byID[p] != nil:
			n.parent = b.byID[p]
		default:
			n.parent = b.unrecorded(p, pidOfExecID(p))
		}
	}

	for i := range evs {
		e := &evs[i]
		if e.Mirror {
			continue
		}
		n := owner[i]
		if n == nil {
			n = b.ownerOf(int32(i), e) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
		}
		if n == nil {
			b.t.NoPID++
			continue
		}
		b.count(n, e)
	}

	b.breakLoops(root)
	for _, n := range b.order {
		n.parent.Children = append(n.parent.Children, n)
	}
	b.finish(root)
	return b.t
}

// keyOf is an exec_id's key: "<pid>-<start>", or, for an exec_id not of that shape, "x-" and the id with every
// character but a letter, digit or dash made "_".
func keyOf(id string) string {
	i := strings.LastIndexByte(id, '/')
	j := -1
	if i > 0 {
		j = strings.LastIndexByte(id[:i], '/')
	}
	if j >= 0 {
		return id[j+1:i] + "-" + id[i+1:]
	}
	return "x-" + strings.Map(func(r rune) rune {
		if r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, id)
}

// unrecorded is the node of a process the record names (by exec_id id, or "" for a pid with lines only) but holds
// no exec of: made once, hung from the root.
func (b *treeBuilder) unrecorded(id string, pid int) *ProcNode {
	if n := b.byID[id]; id != "" && n != nil {
		return n
	}
	if id == "" {
		if n := b.byPid[pid]; n != nil {
			return n
		}
	}
	n := &ProcNode{Run: b.t.Run, PID: pid, ExecID: id, Unrecorded: true, ParentUnknown: true, Name: "pid " + strconv.Itoa(pid)}
	if id != "" {
		b.byID[id] = n
	}
	// A pid's lines with no exec go to the first unrecorded process the record names for it.
	if b.byPid[pid] == nil {
		b.byPid[pid] = n
	}
	n.parent = b.t.Root
	b.order = append(b.order, n)
	return n
}

// execsOf fills n's program and execs from pi's exec lines, in the slabs given: execs with room for one entry per
// exec, seqs and paths one slot per exec (a folded entry's seqs and paths are slots in a row, as its execs are).
func (b *treeBuilder) execsOf(n *ProcNode, pi *procInfo, execs []ProcExec, seqs []uint64, paths []string) {
	n.Execs = execs
	last, lastRefused := -1, -1 // the entries of n.Execs holding the newest allowed and the newest refused exec
	prev := ""                  // the command of the exec before, which a refused one folds into when both were refused
	for j, i := range pi.execs {
		e := &b.evs[i]
		f := execFact{path: e.path, refused: e.Verdict == string(record.VerdictRefused)} // as the index read it (proc.go)
		same := prev == e.Target
		prev = e.Target
		if k := len(n.Execs) - 1; f.refused && same && k >= 0 && n.Execs[k].Refused {
			ex := &n.Execs[k]
			ex.Count++
			ex.Seqs = append(ex.Seqs, e.Seq)
			if !slices.Contains(ex.Paths, f.path) {
				ex.Paths = append(ex.Paths, f.path)
			}
			lastRefused = k
			continue
		}
		n.Execs = append(n.Execs, ProcExec{Seq: e.Seq, Name: programName(f.path, e.Target), cmd: e.Target,
			Paths: append(paths[j:j:len(paths)], f.path), Refused: f.refused, Count: 1, Seqs: append(seqs[j:j:len(seqs)], e.Seq)})
		if f.refused {
			lastRefused = len(n.Execs) - 1
		} else {
			last = len(n.Execs) - 1
		}
	}
	for k := range n.Execs { // a caller's append never reaches the next entry's slots
		n.Execs[k].Paths, n.Execs[k].Seqs = slices.Clip(n.Execs[k].Paths), slices.Clip(n.Execs[k].Seqs)
	}
	k := last
	if k < 0 {
		k, n.Refused = lastRefused, true
	}
	if k < 0 {
		return
	}
	ex := &n.Execs[k]
	n.HasExec, n.ExecSeq, n.Name, n.cmd = true, ex.Seq, ex.Name, ex.cmd
	n.Path = ex.Paths[len(ex.Paths)-1]
}

// Command is the process's command line as the tree shows it: credential-looking values hidden, at most
// MaxTreeCommand bytes (the line page has it whole); "" for a process that started no program.
func (n *ProcNode) Command() string { return treeCommand(n.cmd) }

// Command is the exec's command line as the tree shows it, as ProcNode.Command.
func (x *ProcExec) Command() string { return treeCommand(x.cmd) }

// treeCommand is a command line as the tree shows it: credential-looking values hidden, at most MaxTreeCommand
// bytes. Masking is a few regular expressions per command (about 15 µs), so it is done for the commands a page
// shows, when it shows them, not for every process of the run as the tree is built; and the masked commands are
// remembered (treeMasks), so the next version of a live run's tree, which names the same commands, pays nothing.
func treeCommand(s string) string {
	if s == "" {
		return ""
	}
	if len(s) > MaxTreeCommand {
		cut := MaxTreeCommand
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	treeMaskMu.Lock()
	m, ok := treeMasks[s]
	treeMaskMu.Unlock()
	if ok {
		return m
	}
	m = linewords.Mask(s)
	treeMaskMu.Lock()
	if len(treeMasks) >= maxTreeMasks {
		clear(treeMasks) // dropped wholesale: the next builds fill it again with the commands still in use
	}
	treeMasks[s] = m
	treeMaskMu.Unlock()
	return m
}

// treeMasks remembers treeCommand's masked commands, at most maxTreeMasks of them (each at most MaxTreeCommand
// bytes, so a few tens of MB at worst).
var (
	treeMaskMu sync.Mutex
	treeMasks  = map[string]string{}
)

const maxTreeMasks = 1 << 14

// ownerOf is the process line i belongs to by its pid (see the file comment; an exec line with an exec_id belongs to
// that process instead), nil when its envelope names no pid.
func (b *treeBuilder) ownerOf(i int32, e *Event) *ProcNode {
	if e.pid == 0 {
		return nil
	}
	// Lines of one pid come in runs, so the pid's owners are looked up once per run of lines.
	if b.last == nil || b.lastPid != e.pid {
		b.last, b.lastPid = b.owners[e.pid], e.pid
		if b.last == nil {
			b.last = b.ownersOf(e.pid)
			b.owners[e.pid] = b.last
		}
	}
	o := b.last
	switch len(o.nodes) {
	case 0:
		return o.other
	case 1:
		return o.nodes[0]
	}
	k := max(sort.Search(len(o.first), func(j int) bool { return o.first[j] > i })-1, 0)
	return o.nodes[k]
}

// pidOwners is the processes a pid's lines can belong to: its recorded processes (nodes, by the index of their first
// exec line, first), else other, the launcher or the pid's unrecorded node.
type pidOwners struct {
	first []int32
	nodes []*ProcNode
	other *ProcNode
}

func (b *treeBuilder) ownersOf(pid int) *pidOwners {
	o := &pidOwners{}
	for _, pi := range b.x.byPid[pid] {
		o.first = append(o.first, pi.execs[0])
		o.nodes = append(o.nodes, b.byID[pi.id])
	}
	switch {
	case len(o.nodes) > 0:
	case pid == b.x.launcherPID:
		o.other = b.t.Root
	default:
		o.other = b.unrecorded("", pid)
	}
	return o
}

// count adds line e to n.
func (b *treeBuilder) count(n *ProcNode, e *Event) {
	c := &n.Counts
	if c.Lines == 0 || e.Seq < n.FirstSeq {
		n.FirstSeq, n.Start = e.Seq, e.TS
	}
	c.Lines++
	b.t.Lines++
	if e.Refusal() {
		c.Refused++
		b.t.Refused++
	}
	host := ""
	switch {
	case e.Kind == string(record.KindExec):
		c.Execs++
	case e.Kind == string(record.KindFS):
		if e.Op == "read" {
			c.Reads++
		} else {
			c.Writes++
		}
	case e.Kind == string(record.KindNet), e.Kind == string(record.KindRefused) && e.Op == "net":
		c.Connects++
		host = e.Host
	}
	if host != "" {
		if n.hosts == nil {
			n.hosts = map[string]int{}
		}
		n.hosts[host]++
	}
}

// breakLoops hangs from the root every process whose parents loop back to it without reaching the root (a malformed
// ledger whose exec ids name each other), so every process is in the tree once.
func (b *treeBuilder) breakLoops(root *ProcNode) {
	const (
		unseen = iota
		walking
		done
	)
	root.state = done
	var path []*ProcNode
	for _, n := range b.order {
		path = path[:0]
		cur := n
		for cur.state == unseen {
			cur.state = walking
			path = append(path, cur)
			cur = cur.parent
		}
		if cur.state == walking {
			// cur's parents lead back to cur: cut the loop at cur.
			cur.parent, cur.ParentUnknown = root, true
		}
		for _, p := range path {
			p.state = done
		}
	}
}

// finish orders every node's children by their first line, sets depths, the hosts and the Below totals, and the
// tree's process counts. It walks the tree without recursion: a malformed ledger can chain thousands of processes.
func (b *treeBuilder) finish(root *ProcNode) {
	// Pre-order with depths, then totals in reverse (children before parents).
	var pre []*ProcNode
	stack := []*ProcNode{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		pre = append(pre, n)
		for _, c := range n.Children {
			c.Depth = n.Depth + 1
			stack = append(stack, c)
		}
	}
	for k := len(pre) - 1; k >= 0; k-- {
		n := pre[k]
		if n.Counts.Lines == 0 {
			// An unrecorded process with no line of its own starts with its first child.
			for _, c := range n.Children {
				if n.Start.IsZero() || c.FirstSeq < n.FirstSeq {
					n.FirstSeq, n.Start = c.FirstSeq, c.Start
				}
			}
		}
		bySeq := func(a, b *ProcNode) int { return cmp.Compare(a.FirstSeq, b.FirstSeq) }
		if !slices.IsSortedFunc(n.Children, bySeq) { // made in first-exec order, they mostly are
			slices.SortStableFunc(n.Children, bySeq)
		}
		for _, c := range n.Children {
			n.Below.add(c.Counts)
			n.Below.add(c.Below)
			n.Below.Procs++
		}
		if m := n.hosts; m != nil {
			n.hosts = nil
			n.Counts.Hosts = len(m)
			for h, c := range m {
				n.Hosts = append(n.Hosts, HostCount{h, c})
			}
			sort.Slice(n.Hosts, func(i, j int) bool {
				if n.Hosts[i].N != n.Hosts[j].N {
					return n.Hosts[i].N > n.Hosts[j].N
				}
				return n.Hosts[i].Host < n.Hosts[j].Host
			})
			n.Hosts = n.Hosts[:min(len(n.Hosts), MaxTreeHosts)]
		}
		b.t.Procs++
		if n.Unrecorded {
			b.t.Unrecorded++
		}
	}
}

// add adds o's counts to c, but Hosts, which do not add up across processes.
func (c *ProcCounts) add(o ProcCounts) {
	c.Procs += o.Procs
	c.Lines += o.Lines
	c.Refused += o.Refused
	c.Execs += o.Execs
	c.Reads += o.Reads
	c.Writes += o.Writes
	c.Connects += o.Connects
}

// Key is the process's key on the page, unique in the tree: "<pid>-<start>" from its exec_id, "<pid>-u" for a pid
// with lines and no exec line, "launcher" for a launcher whose start time run_start did not give.
func (n *ProcNode) Key() string {
	switch {
	case n.ExecID != "":
		return keyOf(n.ExecID)
	case n.Launcher:
		return "launcher"
	}
	return strconv.Itoa(n.PID) + "-u"
}

// HasRefusal reports whether the process or one under it had a refusal.
func (n *ProcNode) HasRefusal() bool { return n.Counts.Refused+n.Below.Refused > 0 }

// Words is the process in a few words: "bash (pid 4037090)", "pid 4036305, forked, no exec recorded".
func (n *ProcNode) Words() string {
	switch {
	case n.Launcher:
		return "tego launcher (pid " + strconv.Itoa(n.PID) + ")"
	case n.Unrecorded:
		return "pid " + strconv.Itoa(n.PID) + ", forked, no exec recorded"
	}
	return n.Name + " (pid " + strconv.Itoa(n.PID) + ")"
}
