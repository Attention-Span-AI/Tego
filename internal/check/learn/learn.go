// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/internal/mirror"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Bounds on what one run can make the learner hold. A run can open any number of distinct paths, and the record
// is the agent's own doing: past maxDistinct a map stops taking new keys (the ones it has keep counting) and the
// proposal says it was cut, rather than a hostile run growing this process without limit.
const (
	maxDistinct = 100_000
	// maxWriteDirs is the most fs.write entries one proposal holds. Past it the directories are collapsed to their
	// first level under the workspace, then to the workspace itself: never to anything broader.
	maxWriteDirs = 32
	// maxOutside is how many directories outside the workspace the proposal names one by one; the rest are one line.
	maxOutside = 20
)

// ErrNoRunStart is Proposal's error for a record with no run_start line: there is no run to learn from.
var ErrNoRunStart = errors.New("the record holds no run_start")

// Options is what the proposal depends on besides the record.
type Options struct {
	// Workspace is the directory the proposal may allow writes under: absolute. Empty is the run's working
	// directory from run_start. "/" is refused: it is every directory.
	Workspace string
	// StateDirs are tego's own directories (the run's record, the ledger root, the chain anchor's directory, the host
	// state directory): an fs.write entry that is one, is inside one or holds one is never proposed, because tego
	// refuses a contract that lets the agent write them.
	StateDirs []string
	// Executable reports whether path is, on this machine, a program an exec could have started: a regular file
	// with an execute bit, reached by following its links. Nil is the real file system (executable). An exec.allow
	// entry is proposed only when it holds: tego compile refuses a path that does not exist (path-missing), and a
	// PATH search's misses are paths that do not (agent-contract.md R8, docs/OPERATIONS.md "tego learn").
	Executable func(path string) bool
	// LeaveLeaksToCaller turns the leak rule (leak.go) off: every address the run reached is proposed, and the caller
	// judges them. The dashboard does, with its own verdict, which knows the run's pair and its contract
	// (rulesview.Withhold). Anything else leaves it false, so a proposal leaves out every address the rule names.
	LeaveLeaksToCaller bool
}

// executable is Options.Executable's default: a regular file with an execute bit, by os.Stat, which follows links
// as compile's own check of a path entry does.
func executable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// Item is one entry of a list the proposal writes, with how many times the run did it.
type Item struct {
	Value string // the entry as the contract spells it
	Count int
	Note  string // a short remark ("created by the run"), or empty
}

// Excluded is something the run did that the proposal does not allow, and why. Section is the contract section it
// would have gone in: "fs", "exec" or "net".
type Excluded struct {
	Section string
	What    string
	Why     string
	Count   int
}

// Limits is the suggestion the resource peaks give. A field is empty when the record held no peak for it.
type Limits struct {
	Memory, MemoryPeak string
	Pids, PidsPeak     string
	Wall, Ran          string
}

// Proposal is what learn found in one run, ready to be written (Contract).
type Proposal struct {
	Run, Agent string
	Started    time.Time
	// Ended is false when the record has no run_end: the run was still going or was cut off, and no limits are
	// suggested.
	Ended     bool
	EndReason string
	ExitCode  int
	Ran       time.Duration

	Name        string
	Command     []string
	CommandNote string
	Workspace   string
	// NoWorkspace is why there is no workspace to allow writes under, when Workspace is empty.
	NoWorkspace string

	Write []Item
	Exec  []Item
	Net   []Item
	// Left lists what was seen and not allowed, in the order the contract's sections print them.
	Left []Excluded

	Limits *Limits

	// Leaks are the destinations the leak rule says the run's secrets may have gone to, in the order it reached them,
	// and LeakSecrets the secrets that went with them. LeakChecked is false when Options.LeaveLeaksToCaller turned the
	// rule off.
	Leaks       []*Leak
	LeakSecrets []string
	LeakChecked bool

	// Reads is how many file opens for reading the run made; none of them is in the proposal.
	Reads int
	// Refused counts the actions the record shows refused or held for approval (an enforced run's): none is
	// proposed, since a refused action did not happen.
	Refused int
	// Failed counts the exec and fs actions that did not succeed (a nonzero errno): none is proposed.
	Failed int
	// SearchMisses counts exec attempts that were not a program starting: a PATH search tries each directory in turn,
	// and the record of a run with no kernel outcome shows every try.
	SearchMisses int
	// Unresolved counts fs actions whose path was not absolute, which no entry can name.
	Unresolved int
	// Alternates counts the opens a person answered with another file (tego alternate, ADR 0057 D1): the agent did
	// not get the file it asked for, and the file it got was the person's choice, not its own reach, so none is
	// proposed.
	Alternates int
	// RuntimeGranted counts fs actions the run's grant of its own CODEX_HOME allowed (fs.codex_home[...], a grant the
	// run made on its own authority, agent.IsRuntimeRule): every run makes that grant again, and no entry can name its
	// path.
	RuntimeGranted int
	// HarnessStateGranted counts fs actions the run's grant of its harness's hook-state directory allowed
	// (fs.harness-state[...], agent-contract.md R10a (4)), the same kind of grant, made for a provisioned harness.
	HarnessStateGranted int
	// HarnessHookGranted counts the execs the run's grant of its harness hook's exact argv allowed
	// (exec.harness-hook[...], ADR 0064): an entry naming the tego binary would admit every argv of it, and every
	// run of an allow-list contract makes the grant again, so none is proposed.
	HarnessHookGranted int
	// Collapsed is non-empty when the write directories were merged to stay under maxWriteDirs: the level they
	// were merged to.
	Collapsed string
	// Truncated is true when a bound (maxDistinct) cut what the learner kept.
	Truncated bool
}

// WriteDirs are the fs.write entries of the proposal, without the devices.
func (p *Proposal) WriteDirs() []string {
	var out []string
	for _, it := range p.Write {
		if !strings.HasPrefix(it.Value, "/dev/") {
			out = append(out, it.Value)
		}
	}
	return out
}

type netKey struct{ proto, dst string }

// Learner accumulates one run's record. The zero value is not usable: use New.
type Learner struct {
	opts Options

	start *record.RunStartPayload
	run   struct {
		id, agent string
		ts        time.Time
		mono      uint64
	}
	end     *record.RunEndPayload
	endTS   time.Time
	endMono uint64

	execs      map[string]*execStat
	pending    map[string]pendingExec
	devs       map[string]int
	writeDirs  map[string]int
	touched    map[string]bool
	nets       map[netKey]int
	reads      int
	refused    int
	alternates int
	failed     int
	misses     int
	unresolved int
	runtime    int
	hookState  int
	hookExecs  int
	truncated  bool
	leak       *leakRule

	// pairs holds the lines before the one being added: a refused line that mirrors a refused action line is that
	// action again, and counts once, as drift and measure count it.
	pairs mirror.Pairs
}

// New is a Learner for one run.
func New(o Options) *Learner {
	return &Learner{
		opts:      o,
		execs:     map[string]*execStat{},
		pending:   map[string]pendingExec{},
		devs:      map[string]int{},
		writeDirs: map[string]int{},
		touched:   map[string]bool{},
		nets:      map[netKey]int{},
		leak:      newLeakRule(),
	}
}

// Add takes the run's next event. Events that say nothing about what the run did (gaps, model traffic, decisions)
// are ignored; one whose payload does not decode is an error, since a record this reader cannot read must not
// become a proposal that looks complete.
func (l *Learner) Add(e *record.Event) error {
	mirrored := l.pairs.Take(e)
	switch e.Kind {
	case record.KindRunStart:
		if l.start != nil {
			return nil
		}
		var p record.RunStartPayload
		if err := e.DecodePayload(&p); err != nil {
			return fmt.Errorf("learn: run_start: %w", err)
		}
		l.start = &p
		l.run.id, l.run.agent, l.run.ts, l.run.mono = e.Run, e.Agent, e.TS, e.MonoNS
	case record.KindRunEnd:
		if l.end != nil {
			return nil
		}
		var p record.RunEndPayload
		if err := e.DecodePayload(&p); err != nil {
			return fmt.Errorf("learn: run_end: %w", err)
		}
		l.end, l.endTS, l.endMono = &p, e.TS, e.MonoNS
	case record.KindRefused:
		if !mirrored {
			l.refused++
		}
		return l.leakAddRefused(e)
	case record.KindAsk:
		return l.leakAddAsk(e)
	case record.KindExec:
		return l.addExec(e)
	case record.KindFS:
		return l.addFS(e)
	case record.KindNet:
		return l.addNet(e)
	}
	return nil
}

// notDone is whether the event says the action did not happen: refused, or held and not yet allowed.
func notDone(e *record.Event) bool {
	return e.Verdict == record.VerdictRefused || e.Verdict == record.VerdictAsk
}

func (l *Learner) addExec(e *record.Event) error {
	var p record.ExecPayload
	if err := e.DecodePayload(&p); err != nil {
		return fmt.Errorf("learn: exec at seq %d: %w", e.Seq, err)
	}
	switch {
	case notDone(e):
		l.refused++
		return nil
	case p.Errno != 0 || p.SyscallRet < 0:
		l.failed++
		return nil
	case p.Path == "":
		l.unresolved++
		return nil
	case agent.IsRuntimeRule(e.Rule) && strings.HasPrefix(e.Rule, "exec."+agent.HarnessHookGrant+"["):
		l.hookExecs++
		return nil
	}
	argv := strings.Join(p.Argv, "\x00")
	key := p.ExecID
	if key == "" {
		key = fmt.Sprint("pid:", e.PID)
	}
	if prev, ok := l.pending[key]; ok {
		if argv != "" && prev.argv == argv {
			// The same process asked for the same command line again: execvp walking PATH, one directory after
			// another (a directory listed twice is tried twice), where every attempt but one failed. The record of
			// a run with no kernel outcome (tier 1, record-only) shows each attempt as an exec, so only one of them
			// is a program that started: the chain is settled when it ends (commitChain). A program that
			// re-executes itself with its own command line is the one case this reads wrongly, and it loses a
			// count, never a path that exists.
			l.misses++
			if len(prev.paths) < maxChain {
				prev.paths = append(prev.paths, p.Path)
			} else {
				prev.paths[len(prev.paths)-1] = p.Path
			}
			l.pending[key] = prev
			return nil
		}
		l.commitChain(prev)
	}
	if len(l.pending) >= maxDistinct {
		l.flushExecs()
	}
	l.pending[key] = pendingExec{paths: []string{p.Path}, argv: argv, seq: e.Seq}
	return nil
}

// maxChain bounds the attempts of one PATH search the learner keeps: a PATH of more directories than this keeps its
// first maxChain-1 and its last.
const maxChain = 64

// commitChain settles one process's run of identical command lines: the attempt that started a program is the one
// whose path is a program on this machine (Options.Executable), not under /proc. execvp stops at the first attempt
// that succeeds, so a search has one; the record's order alone cannot say which, because a record taken before
// supervisor.md R23a could hold a later attempt before an earlier one, and the last attempt was then a miss
// (/usr/sbin/bash after the /usr/bin/bash that ran). Where several qualify (an attempt refused for another reason,
// a noexec mount) the last of them is taken, and where none does, the last attempt, which proposeExecs then leaves
// out as a path that does not exist.
func (l *Learner) commitChain(pe pendingExec) {
	pick := pe.paths[len(pe.paths)-1]
	if len(pe.paths) > 1 {
		for i := len(pe.paths) - 1; i >= 0; i-- {
			if c := pe.paths[i]; !isProc(c) && l.executable(c) {
				pick = c
				break
			}
		}
	}
	l.commitExec(pick, pe.seq)
}

// executable is Options.Executable, or the real file system's answer.
func (l *Learner) executable(p string) bool {
	if l.opts.Executable != nil {
		return l.opts.Executable(p)
	}
	return executable(p)
}

// isProc is whether an exec path is a /proc path, or reaches one through its links: compile refuses such an entry
// (agent-contract.md R8a, exec-proc), since /proc/self/exe names the executable of whichever process opens it.
func isProc(p string) bool {
	if !path.IsAbs(p) {
		return false
	}
	_, ok := config.ThroughProc(p)
	return ok
}

// execStat is one program the run started: how many times, and the line of its first start.
type execStat struct {
	n   int
	seq uint64
}

// pendingExec is the last run of identical command lines a process made: every attempt's path in record order, of
// which a PATH search started one program (commitChain), and the line of the first.
type pendingExec struct {
	paths []string
	argv  string
	seq   uint64
}

func (l *Learner) commitExec(path string, seq uint64) {
	st := l.execs[path]
	if st == nil {
		if len(l.execs) >= maxDistinct {
			l.truncated = true
			return
		}
		st = &execStat{seq: seq}
		l.execs[path] = st
	}
	st.n++
	st.seq = min(st.seq, seq)
}

// flushExecs commits every exec still pending: the process made no later exec that could say it failed.
func (l *Learner) flushExecs() {
	for k, pe := range l.pending {
		l.commitChain(pe)
		delete(l.pending, k)
	}
}

func (l *Learner) addNet(e *record.Event) error {
	var p record.NetPayload
	if err := e.DecodePayload(&p); err != nil {
		return fmt.Errorf("learn: net at seq %d: %w", e.Seq, err)
	}
	l.leakAddNet(e, &p)
	switch {
	case p.Op == "http_request":
		return nil // the forwarder's request policy, not a connection of the run's own
	case notDone(e):
		l.refused++
		return nil
	}
	l.bumpNet(netKey{p.Proto, p.Dst})
	return nil
}

// Open flags (Linux, asm-generic and x86-64): the access mode, and the two bits that make a read-only open
// change a file.
const (
	oAccMode = 0o3
	oCreat   = 0o100
	oTrunc   = 0o1000
)

func (l *Learner) addFS(e *record.Event) error {
	var p record.FSPayload
	if err := e.DecodePayload(&p); err != nil {
		return fmt.Errorf("learn: fs at seq %d: %w", e.Seq, err)
	}
	l.leakAddFS(e, &p)
	n := max(1, p.Count)
	switch {
	case notDone(e):
		l.refused++
		return nil
	case p.AlternateFor != "":
		l.alternates++
		return nil
	case p.Errno != 0:
		l.failed++
		return nil
	case !path.IsAbs(p.Path):
		l.unresolved++
		return nil
	case agent.IsRuntimeRule(e.Rule) && strings.HasPrefix(e.Rule, "fs."+agent.HarnessStateGrant+"["):
		l.hookState += n
		return nil
	case agent.IsRuntimeRule(e.Rule):
		l.runtime += n
		return nil
	}
	file := path.Clean(p.Path)
	if p.Op == record.FSOpen && (file == "/dev/null" || file == "/dev/tty") {
		l.devs[file] += n // a device opened for any access: tego needs the grant to open it for writing
		return nil
	}
	if p.Op == record.FSOpen && p.Flags&(oAccMode|oCreat|oTrunc) == 0 {
		l.reads += n
		return nil
	}
	// Every other operation changes the file system, and each names the directory it needs to write in.
	switch p.Op {
	case record.FSMkdir:
		// The directory made: tego creates a missing fs.write directory itself, so granting it is enough,
		// where granting its parent would widen the entry to everything beside it.
		l.dir(file, 1)
		l.touch(file)
	case record.FSRename, record.FSLink:
		l.dir(path.Dir(file), 1)
		l.touch(file)
		if path.IsAbs(p.Path2) {
			to := path.Clean(p.Path2)
			l.dir(path.Dir(to), 1)
			l.touch(to)
		}
	default:
		// open for writing, unlink, symlink (its path is the link made; path2 is only what it points at), chmod,
		// chown, truncate, xattr.
		l.dir(path.Dir(file), 1)
		l.touch(file)
	}
	return nil
}

func (l *Learner) dir(d string, n int) {
	l.bump(l.writeDirs, d, n)
}

func (l *Learner) touch(p string) {
	if len(l.touched) < maxDistinct {
		l.touched[p] = true
	} else {
		l.truncated = true
	}
}

func (l *Learner) bump(m map[string]int, k string, n int) {
	if _, ok := m[k]; !ok && len(m) >= maxDistinct {
		l.truncated = true
		return
	}
	m[k] += n
}

func (l *Learner) bumpNet(k netKey) {
	if _, ok := l.nets[k]; !ok && len(l.nets) >= maxDistinct {
		l.truncated = true
		return
	}
	l.nets[k]++
}

// within is whether p is root or inside it. Both are clean absolute paths.
func within(p, root string) bool {
	if root == "/" {
		return true
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

// stateConflict is why d may not be an fs.write entry, or "": it is, is inside or holds one of tego's own
// directories.
func (l *Learner) stateConflict(d string) string {
	for _, s := range l.opts.StateDirs {
		s = path.Clean(s)
		switch {
		case !path.IsAbs(s):
		case within(d, s):
			return "inside tego's own state directory " + s
		case within(s, d):
			return "it holds tego's own state directory " + s
		}
	}
	return ""
}

// plain is whether s can be written into the contract as it is: valid UTF-8 with nothing a terminal or a person
// reading the file could be misled by (record.Printable would escape it), and no pattern character, since a
// contract path is matched as a name and an entry with one would not mean the file seen. U+FFFD is refused too: the
// record is JSON, which cannot hold a byte that is not UTF-8, so the replacement character stands for a name that
// was not valid and is gone, and an entry made of it would name nothing.
func plain(s string) bool {
	return s != "" && record.Printable(s) == s && !strings.ContainsAny(s, "*?[\uFFFD")
}

// Proposal is what the events added so far say. Call it once the record is read: it settles the execs still pending,
// so an exec added after it is not compared with one added before.
func (l *Learner) Proposal() (*Proposal, error) {
	if l.start == nil {
		return nil, ErrNoRunStart
	}
	l.flushExecs()
	first := l.firstExec()
	ws, noWorkspace := l.opts.Workspace, ""
	if ws != "" && (!path.IsAbs(ws) || path.Clean(ws) == "/") {
		if path.IsAbs(ws) {
			return nil, errors.New("a workspace of / is every directory: name the directory the agent works in")
		}
		return nil, fmt.Errorf("the workspace %q is not an absolute path", ws)
	}
	if ws == "" {
		switch cwd := l.start.Cwd; {
		case cwd == "" || !path.IsAbs(cwd):
			noWorkspace = "the record names no working directory"
		case path.Clean(cwd) == "/":
			noWorkspace = "the run's working directory was /, which is every directory"
		default:
			ws = cwd
		}
	}
	if ws != "" {
		ws = path.Clean(ws)
	}
	p := &Proposal{
		NoWorkspace: noWorkspace,
		Run:         l.run.id, Agent: l.run.agent, Started: l.run.ts,
		Workspace: ws, Reads: l.reads, Refused: l.refused, Failed: l.failed, SearchMisses: l.misses, Unresolved: l.unresolved,
		Alternates: l.alternates, RuntimeGranted: l.runtime, HarnessStateGranted: l.hookState, HarnessHookGranted: l.hookExecs, Truncated: l.truncated,
	}
	p.Name = contractName(l.run.agent)
	p.Command = append([]string(nil), l.start.Command...)
	if len(p.Command) == 0 {
		if first == "" {
			return nil, errors.New("the record holds neither the run's command nor a program it started")
		}
		p.Command = []string{first}
		p.CommandNote = "the run's whole command line was too long for the record; this is only the program it started"
	}
	if l.end != nil {
		p.Ended, p.EndReason, p.ExitCode = true, l.end.Reason, l.end.ExitCode
		p.Ran = roundRan(l.ran())
		p.Limits = suggestLimits(l.end, l.ran())
	}
	l.proposeWrites(p, ws)
	l.proposeExecs(p, first)
	l.proposeNet(p)
	sortLeft(p.Left)
	p.Truncated = p.Truncated || l.leak.truncated
	return p, nil
}

// ran is how long the run lasted: on the monotonic clock, as tego measure says, since the wall clock can step during a
// run (NTP, a suspended laptop's correction) and the proposal then said "lasted -59m" or suggested a wall limit a day
// long. A ledger with no monotonic reading (E20) falls back on the wall clock.
func (l *Learner) ran() time.Duration {
	if l.run.mono > 0 && l.endMono > l.run.mono {
		return time.Duration(l.endMono - l.run.mono)
	}
	return l.endTS.Sub(l.run.ts)
}

// roundRan is how long the run lasted, for a person: to a tenth of a second, or to the hundredth under one second.
func roundRan(d time.Duration) time.Duration {
	if d < time.Second {
		return d.Round(10 * time.Millisecond)
	}
	return d.Round(100 * time.Millisecond)
}

// contractName is the contract name for the agent's: "learned-" and the agent name without a "watch-" prefix,
// within the schema's [a-z0-9-]{1,40}.
func contractName(agentName string) string {
	n := "learned-" + strings.TrimPrefix(agentName, "watch-")
	if len(n) > 40 {
		n = n[:40]
	}
	n = strings.TrimRight(n, "-")
	if _, err := identity.ParseAgentID(n); err != nil {
		return "learned"
	}
	return n
}

// proposeWrites decides fs.write: the directories under the workspace the run wrote in, collapsed to the
// outermost, and the devices it opened.
func (l *Learner) proposeWrites(p *Proposal, ws string) {
	var inside []string
	outside := map[string]int{}
	state := map[string]*Excluded{}
	for d, n := range l.writeDirs {
		switch why := l.stateConflict(d); {
		case why != "":
			ex := state[why]
			if ex == nil {
				ex = &Excluded{Section: "fs", What: "writes under " + dirName(d), Why: why}
				state[why] = ex
			}
			ex.Count += n
		case ws != "" && within(d, ws):
			inside = append(inside, d)
		default:
			outside[d] = n
		}
	}
	keep := collapse(inside)
	if len(keep) > maxWriteDirs {
		keep, p.Collapsed = collapse(firstLevel(inside, ws)), "the first level under the workspace"
		if len(keep) > maxWriteDirs {
			keep, p.Collapsed = []string{ws}, "the workspace itself"
		}
	}
	counts := map[string]int{}
	for _, d := range inside {
		if k := owner(d, keep); k != "" {
			counts[k] += l.writeDirs[d]
		}
	}
	for _, k := range keep {
		if why := l.stateConflict(k); why != "" {
			// Merging made an entry that holds a state directory: dropped, not narrowed again.
			p.Left = append(p.Left, Excluded{Section: "fs", What: "writes under " + dirName(k), Why: why, Count: counts[k]})
			continue
		}
		if !plain(k) {
			p.Left = append(p.Left, Excluded{Section: "fs", What: "writes under " + record.Printable(dirName(k)),
				Why: "the name is not a plain path (a control or pattern character in it)", Count: counts[k]})
			continue
		}
		p.Write = append(p.Write, Item{Value: dirName(k), Count: counts[k]})
	}
	for _, dev := range []string{"/dev/null", "/dev/tty"} {
		if n := l.devs[dev]; n > 0 {
			p.Write = append(p.Write, Item{Value: dev, Count: n})
		}
	}
	for _, ex := range state {
		p.Left = append(p.Left, *ex)
	}
	p.Left = append(p.Left, outsideLeft(outside, ws, p.NoWorkspace)...)
}

// dirName is d as an fs.write entry: a directory, so with a trailing slash.
func dirName(d string) string {
	if d == "/" {
		return d
	}
	return d + "/"
}

// collapse drops every directory that has an ancestor in the set, and returns the rest sorted.
func collapse(dirs []string) []string {
	sorted := append([]string(nil), dirs...)
	sort.Strings(sorted)
	var out []string
	for _, d := range sorted {
		if owner(d, out) == "" { // out is sorted, as owner needs
			out = append(out, d)
		}
	}
	return out
}

// owner is the entry of set that is d or holds d, "" if none does.
func owner(d string, set []string) string {
	for a := d; ; a = path.Dir(a) {
		if i := sort.SearchStrings(set, a); i < len(set) && set[i] == a {
			return a
		}
		if a == "/" || a == "." {
			return ""
		}
	}
}

// firstLevel is each directory of dirs reduced to its first component under ws.
func firstLevel(dirs []string, ws string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		r := d
		if d != ws {
			rest := strings.TrimPrefix(d, strings.TrimSuffix(ws, "/")+"/")
			first, _, _ := strings.Cut(rest, "/")
			r = path.Join(ws, first)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// outsideLeft reports the writes outside the workspace: the outermost directories by how often they were written,
// the first maxOutside by name and the rest as one line.
func outsideLeft(outside map[string]int, ws, noWorkspace string) []Excluded {
	if len(outside) == 0 {
		return nil
	}
	dirs := make([]string, 0, len(outside))
	for d := range outside {
		dirs = append(dirs, d)
	}
	keep := collapse(dirs)
	counts := map[string]int{}
	for _, d := range dirs {
		counts[owner(d, keep)] += outside[d]
	}
	sort.Slice(keep, func(i, j int) bool {
		if counts[keep[i]] != counts[keep[j]] {
			return counts[keep[i]] > counts[keep[j]]
		}
		return keep[i] < keep[j]
	})
	why := "outside the workspace " + record.Printable(ws)
	if ws == "" {
		why = "no workspace to allow writes under: " + noWorkspace + "; give --workspace"
	}
	var out []Excluded
	for i, d := range keep {
		if i == maxOutside {
			rest, n := 0, 0
			for _, r := range keep[i:] {
				rest++
				n += counts[r]
			}
			out = append(out, Excluded{Section: "fs", What: fmt.Sprintf("writes under %d more directories", rest), Why: why, Count: n})
			break
		}
		out = append(out, Excluded{Section: "fs", What: "writes under " + record.Printable(dirName(d)), Why: why, Count: counts[d]})
	}
	return out
}

// firstExec is the program the run started first: the agent itself, which the contract's command already admits.
func (l *Learner) firstExec() string {
	first, at := "", uint64(0)
	for p, st := range l.execs {
		if first == "" || st.seq < at {
			first, at = p, st.seq
		}
	}
	return first
}

// topologyTools are the programs that set up a mount or user namespace, which tiers 1 and 2 refuse (the list compile
// warns by, pkg/spec/agent's, kept in step by hand). Proposing one would propose a program that fails in the run.
var topologyTools = map[string]bool{"bwrap": true, "podman": true, "buildah": true, "unshare": true, "runc": true, "crun": true}

// proposeExecs decides exec.allow: every distinct program the run started, except the agent's own first one, which
// the contract's command already admits.
func (l *Learner) proposeExecs(p *Proposal, first string) {
	own := map[string]bool{first: true}
	if l.start.RunCommandGrant != "" {
		own[l.start.RunCommandGrant] = true
	}
	paths := make([]string, 0, len(l.execs))
	for e := range l.execs {
		paths = append(paths, e)
	}
	sort.Strings(paths)
	for _, e := range paths {
		switch {
		case own[e]:
		case topologyTools[path.Base(e)]:
			p.Left = append(p.Left, Excluded{Section: "exec", What: record.Printable(e), Count: l.execs[e].n,
				Why: "it sets up a mount namespace, which a Landlock domain refuses, so it would fail inside the run: an agent's own sandbox (bubblewrap) probes it at start-up, and is better turned off in the agent when tego is the cage"})
		case !path.IsAbs(e) || !plain(e):
			p.Left = append(p.Left, Excluded{Section: "exec", What: record.Printable(e),
				Why: "not an absolute plain path (a relative name, or a control or pattern character in it)", Count: l.execs[e].n})
		case isProc(e):
			p.Left = append(p.Left, Excluded{Section: "exec", What: record.Printable(e), Count: l.execs[e].n,
				Why: "a /proc path names the executable of whichever process opens it (tego compile refuses it, exec-proc): a program that re-executes itself this way is already admitted by its own entry"})
		case !l.executable(e):
			p.Left = append(p.Left, Excluded{Section: "exec", What: record.Printable(e), Count: l.execs[e].n,
				Why: "not a program on this machine now (tego compile would refuse it, path-missing): a PATH search's miss, or a file the run removed"})
		default:
			p.Exec = append(p.Exec, Item{Value: path.Clean(e), Count: l.execs[e].n})
		}
	}
}

// proposeNet decides net.allow from the connections the run made.
func (l *Learner) proposeNet(p *Proposal) {
	var held map[netKey]*Leak
	if !l.opts.LeaveLeaksToCaller {
		p.LeakChecked = true
		p.Leaks, p.LeakSecrets = l.leak.judge()
		held = l.leak.held(p.Leaks)
	}
	keys := make([]netKey, 0, len(l.nets))
	for k := range l.nets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if a, b := protoRank(keys[i].proto), protoRank(keys[j].proto); a != b {
			return a < b
		}
		return keys[i].dst < keys[j].dst
	})
	probes, probed := 0, 0
	for _, k := range keys {
		n := l.nets[k]
		entry, note, left := l.classify(k)
		switch {
		case left != nil && left.Why == routeProbeWhy:
			// One line for all of them: a musl program makes one per address of every lookup, eight in one Codex start.
			probes, probed = probes+n, probed+1
		case left != nil:
			left.Section, left.Count = "net", n
			p.Left = append(p.Left, *left)
		case entry != "":
			if _, err := agent.ParseEndpoint(entry); err != nil {
				p.Left = append(p.Left, Excluded{Section: "net", What: record.Printable(entry), Why: "tego would not accept it: " + record.Printable(err.Error()), Count: n})
				continue
			}
			if p.withhold(held, k, entry, n) {
				continue
			}
			p.Net = append(p.Net, Item{Value: entry, Count: n, Note: note})
		}
	}
	if probed > 0 {
		p.Left = append(p.Left, Excluded{Section: "net", What: fmt.Sprintf("udp port %d of %d addresses", routeProbePort, probed),
			Why: routeProbeWhy, Count: probes})
	}
}

func protoRank(proto string) int {
	switch proto {
	case "tcp":
		return 0
	case "udp":
		return 1
	case "unix":
		return 2
	}
	return 3
}

// classify decides one observed destination: an entry to allow (with a remark), or something left out and why. It
// returns neither when the destination needs no entry.
func (l *Learner) classify(k netKey) (entry, note string, left *Excluded) {
	switch k.proto {
	case "tcp", "udp":
		ap, err := netip.ParseAddrPort(k.dst)
		if err != nil {
			if k.proto == "udp" && k.dst == "unspec" {
				return "", "", nil // a datagram socket disconnecting: no destination, so nothing to allow
			}
			return "", "", &Excluded{What: k.proto + " " + record.Printable(k.dst), Why: "not an address and port"}
		}
		addr := ap.Addr().Unmap().WithZone("")
		ap = netip.AddrPortFrom(addr, ap.Port())
		if ap.Port() == 53 && addr.IsLoopback() {
			// SEMANTICS §2 (UDP): the resolver in /etc/resolv.conf is allowed on port 53 in every tier.
			return "", "", nil
		}
		if ap.Port() == 0 {
			return "", "", &Excluded{What: k.proto + " " + ap.String(), Why: "port 0 names no service"}
		}
		if k.proto == "udp" && ap.Port() == routeProbePort {
			return "", "", &Excluded{What: k.proto + " " + ap.String(), Why: routeProbeWhy}
		}
		if k.proto == "udp" && l.nets[netKey{"tcp", k.dst}] > 0 {
			note = "possibly the C library's address-sorting probe, a UDP connect that sends nothing (glibc makes one to each address a lookup returns, on the service's port), which the record cannot tell from traffic: remove it unless the agent speaks UDP (QUIC) here"
		}
		return k.proto + "://" + ap.String(), note, nil
	case "unix":
		return l.classifyUnix(k.dst)
	case "raw":
		return "", "", &Excluded{What: "raw socket " + record.Printable(k.dst), Why: rawWhy(k.dst)}
	}
	return "", "", &Excluded{What: record.Printable(k.proto + " " + k.dst), Why: "not a TCP, UDP or unix connection"}
}

// routeProbePort is the port musl's getaddrinfo connects a UDP socket to, for each address a lookup returns, to
// learn the route and source address it would use (RFC 6724 destination address selection): a connect that sends
// nothing. Codex is a static musl binary, and its record held eight such destinations in one start-up. No service
// listens there (65535 is IANA-reserved), so learn leaves these out rather than propose a grant the agent never used;
// the record does not show sends on a connected socket, so a program that really sends to UDP port 65535 is added
// by hand.
const routeProbePort = 65535

// routeProbeWhy is why a UDP connect to routeProbePort is left out.
const routeProbeWhy = "a route probe: musl's getaddrinfo connects a UDP socket to port 65535 of each address it returns to choose among them, and sends nothing; no service listens there (add it by hand if a program really sends to it)"

// rawWhy names what a raw socket's family is: "family(16)" is the netlink family.
func rawWhy(dst string) string {
	switch dst {
	case "family(16)":
		return "a netlink socket (the kernel's routing and device interface): no net.allow entry names one, and a read-only route query needs none"
	case "family(17)":
		return "a packet socket (raw frames on an interface): no net.allow entry names one"
	}
	return "a raw socket: no net.allow entry names one"
}
