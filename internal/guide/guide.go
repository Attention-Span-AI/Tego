// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Schema is the object's schema line. New fields may be added within it; removing one or changing what one means
// makes tego.setup/2.
const Schema = "tego.setup/1"

// The steps, in order, by id (Step.ID).
const (
	StepInstall  = "install"
	StepCheck    = "check"
	StepFind     = "find"
	StepRecord   = "record"
	StepContract = "contract"
	StepEnforce  = "enforce"
)

// The states a step is in (Step.State).
const (
	// Done is a step whose fact holds now.
	Done = "done"
	// Todo is a step nothing has done yet.
	Todo = "todo"
	// Waiting is a step a run that is still going will decide when it ends.
	Waiting = "waiting"
	// Blocked is a step that was tried and failed: the check found no tier, no contract compiles, a record does not
	// check out.
	Blocked = "blocked"
	// Skipped is a step a person went past: a contract written by hand skips recording a run.
	Skipped = "skipped"
	// NotKnown is a step whose source could not be read; NotKnown lines say which.
	NotKnown = "not-known"
)

// titles are the steps' names, the same words on both surfaces (ADR 0142 (1)).
var titles = map[string]string{
	StepInstall:  "Install",
	StepCheck:    "Check this machine",
	StepFind:     "Find your agents",
	StepRecord:   "Record one run",
	StepContract: "Make its contract",
	StepEnforce:  "Enforce it",
}

// Inputs is what Compute reads. Both callers fill it for the invoking user: internal/cli from the process it runs
// in, the dashboard from the machine config it serves.
type Inputs struct {
	// Machine is the machine config (pkg/spec/config): its registry, profiles and ledger root.
	Machine *config.Machine
	// Home is the invoking user's home, absolute (check.json lives under it).
	Home string
	// UID is the invoking user, whose registry files (and root's) are trusted.
	UID int
	// LedgerRoot is the resolved ledger root.
	LedgerRoot string
	// Anchor is the chain anchor runs are checked against, "" when it cannot be named (the enforce step is then not
	// known).
	Anchor string
	// Dir is the project registry's folder (the working directory), "" for none.
	Dir string
	// Version and Commit are the build's, as tego version prints them; Build is BuildID's identity of it.
	Version, Commit, Build string
	// Host is the machine's kernel and this boot (ThisHost).
	Host Host
	// As is who asks and from where (Invoker), nil when no shell asks (the dashboard).
	As *As
	// Fresh is a check the caller has just made (tego setup), which stands for its place in place of the stored one;
	// nil for none.
	Fresh *Check
	// PATH, Exe and RuntimeDirs are the compile's (nextrun.Context): the PATH exec basenames are found on, the
	// running tego binary ("" when it cannot be named) and config.RuntimeDirBases.
	PATH        string
	Exe         string
	RuntimeDirs []string
	// Linger is the command that starts the invoking user's user manager so that it runs without a login
	// (cgroup.LingerCommand: sudo loginctl enable-linger and the name from the passwd entry), which the next step names
	// when the check found no user manager running (CauseNoUserManager); "" where the caller cannot build it (the
	// dashboard, which links no engine package), and the step then names tego doctor, which prints it.
	Linger string
	// ManagerRefused is why systemd starts no user manager for the invoking user at all, whose name in the passwd entry
	// it refuses (cgroup.ManagerRefused: digits only, among others), so linger changes nothing; "" when it accepts the
	// name or the caller cannot tell (the dashboard). With it the check step says so, and the next step names no
	// command (RuleCheckNoManagerName).
	ManagerRefused string
}

// State is the object: `tego setup --json` prints it, and the dashboard's guide renders it.
type State struct {
	Schema string `json:"schema"`
	Tego   Tego   `json:"tego"`
	As     *As    `json:"as"`
	Host   Host   `json:"host"`
	Steps  []Step `json:"steps"`
	Next   Next   `json:"next"`
	// NotKnown is what the guide could not know, one sentence each; never empty, since it never knows of an agent
	// Tego did not record.
	NotKnown []string `json:"not_known"`
}

// Tego is the build that made the object.
type Tego struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
}

// Step is one step: its state, the fact that decided it and where that fact was read.
type Step struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	State string `json:"state"`
	// Fact is the sentence that decided State, null when its source could not be read.
	Fact *string `json:"fact"`
	// Source is where Fact was read: a file, a folder or a run's record.
	Source string `json:"source"`
	// Run is the run the fact is about, "" for none.
	Run string `json:"run,omitempty"`
	// Link is why that run or contract, and not another, was taken (-v prints it), "" for none.
	Link string `json:"link,omitempty"`
}

// Next is the one next step.
type Next struct {
	// Step is the step it moves on, "" when every step is done.
	Step string `json:"step"`
	// Rule names the rule of next.go that chose it.
	Rule string `json:"rule"`
	Text string `json:"text"`
	// Command is the one command to type, "" for none. Words in angle brackets are what Tego cannot know.
	Command string `json:"command"`
	// NeedsRoot is a command written to run as root.
	NeedsRoot bool `json:"needs_root"`
	// Placeholder is a command with a part in angle brackets the person fills in.
	Placeholder bool `json:"placeholder"`
	// built marks a Command this package built (Compute, next.go), which Built reports; it is not in the JSON, so a
	// Next decoded from text is never one.
	built bool
}

// Built reports whether Command was built by this package (next.go: fixed words and values it checked, never a
// file's text) for the object Compute returned: the only command a surface may offer to copy and run. A Next that did
// not come from Compute (decoded from JSON, or made by hand) is not, and its Command is shown as text if at all.
func (n Next) Built() bool { return n.built && n.Command != "" }

// Unreadable reports whether the record or a registry could not be read, or a run's record could not be checked
// against the chain anchor: `tego setup` exits 125 then.
func (s *State) Unreadable() bool {
	for _, st := range s.Steps {
		if st.State == NotKnown && st.ID != StepCheck {
			return true
		}
	}
	return false
}

// facts is what Compute read, for the steps and the rules of next.go.
type facts struct {
	in        *Inputs
	runs      *runs
	runsErr   error
	contracts *contracts
	checks    []Check
	steps     map[string]*Step
	notKnown  []string
	ctx       context.Context
	// verdicts are the runs checked against the chain anchor, by id (verify).
	verdicts map[string]verdict
	// ready is the stored or fresh check that says a tier runs, nil for none; hereCannot is true when the invoker's own
	// place (As.Where) has a check that says no tier runs from it.
	ready      *Check
	hereCannot bool
	// here is the invoker's own place's check, nil for none (the dashboard); blocked is the check that decided a
	// Blocked check step, nil otherwise.
	here, blocked *Check
}

// verdict is one run's check against the chain anchor.
type verdict struct {
	v   ledger.Verdict
	err error
}

// Compute reads the sources and returns the object. It writes nothing and starts no program.
func Compute(ctx context.Context, in Inputs) *State {
	f := &facts{in: &in, steps: map[string]*Step{}, ctx: ctx, verdicts: map[string]verdict{}}
	s := &State{Schema: Schema, Tego: Tego{Version: in.Version, Commit: in.Commit}, As: in.As, Host: in.Host}
	f.install()
	f.check()
	f.runs, f.runsErr = readRuns(in.LedgerRoot)
	if f.runsErr != nil {
		f.notKnown = append(f.notKnown, "the record under "+in.LedgerRoot+": "+errText(f.runsErr))
	}
	f.find()
	f.record()
	if in.Machine != nil {
		rs := f.runs
		if rs == nil {
			rs = &runs{}
		}
		f.contracts = readContracts(ctx, &in, rs)
	}
	f.contract()
	f.enforce()
	f.recordSkipped()
	if rs := f.runs; rs != nil {
		if rs.unreadable > 0 {
			f.notKnown = append(f.notKnown, fmt.Sprintf("%d run records under %s could not be read", rs.unreadable, in.LedgerRoot))
		}
		if rs.more > 0 {
			f.notKnown = append(f.notKnown, fmt.Sprintf("%d older runs under %s were not read (the guide reads the newest %d)",
				rs.more, in.LedgerRoot, maxRuns))
		}
	}
	f.notKnown = append(f.notKnown,
		"agents Tego never recorded: nothing here looks for them yet",
		"a contract in no registry (a file given by its path) that no run used")
	s.Next = f.next() // before the steps are copied: runUnder adds to the contract step's link
	s.Next.built = true
	for _, id := range []string{StepInstall, StepCheck, StepFind, StepRecord, StepContract, StepEnforce} {
		s.Steps = append(s.Steps, *f.steps[id])
	}
	s.NotKnown = f.notKnown
	return s
}

// set records step id's state, fact and source.
func (f *facts) set(id, state, fact, source string) *Step {
	st := &Step{ID: id, Title: titles[id], State: state, Source: source}
	if state != NotKnown {
		st.Fact = &fact
	}
	f.steps[id] = st
	return st
}

// install: always done, since it is running.
func (f *facts) install() {
	f.set(StepInstall, Done, fmt.Sprintf("tego %s (commit %s)", f.in.Version, f.in.Commit), "the binary's build info")
}

// check: a stored check of this boot and build that says a tier runs from its place (Fresh standing for its own).
func (f *facts) check() {
	in := f.in
	source := CheckPath(in.Home)
	stored, err := ReadChecks(in.Home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		f.notKnown = append(f.notKnown, "the stored machine check: "+errText(err))
	}
	var left []string
	var before []Check // checks of places other than the fresh one's, from before this boot
	switch {
	case in.Host.BootID == "" || in.Build == "":
		if len(stored) > 0 {
			f.notKnown = append(f.notKnown, "whether the stored machine check is of this boot and this build: "+
				"the boot id or the build could not be read")
		}
		stored = nil
	default:
		for _, c := range stored {
			if c.BootID != in.Host.BootID && (in.Fresh == nil || c.Where != in.Fresh.Where) {
				before = append(before, c)
			}
		}
		stored, left = usable(stored, in.Host.BootID, in.Build)
	}
	if in.Fresh != nil {
		stored = slices.DeleteFunc(stored, func(c Check) bool { return c.Where == in.Fresh.Where })
		stored = append(stored, *in.Fresh)
	}
	f.checks = stored
	if len(stored) == 0 {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			f.set(StepCheck, NotKnown, "", source)
			return
		}
		fact := NotCheckedSinceStart
		if len(left) > 0 {
			fact += "; left out: " + joinAnd(left)
		}
		f.set(StepCheck, Todo, fact, source)
		return
	}
	// After a reboot, tego setup checks its own place only; a place checked before it started is said, not dropped
	// in silence (acceptance B, 2026-11-11).
	var stale string
	for _, w := range places {
		if slices.ContainsFunc(before, func(c Check) bool { return c.Where == w }) &&
			!slices.ContainsFunc(stored, func(c Check) bool { return c.Where == w }) {
			stale += "; " + whereWords(w) + ": " + NotCheckedSinceStart
		}
	}
	var here *Check
	if in.As != nil {
		for i := range stored {
			if stored[i].Where == in.As.Where {
				here = &stored[i]
			}
		}
	}
	var ready *Check
	for _, w := range places {
		for i := range stored {
			if stored[i].Where == w && stored[i].Tier != "" && ready == nil {
				ready = &stored[i]
			}
		}
	}
	if here != nil && here.Tier != "" {
		ready = here
	}
	f.here = here
	if ready == nil {
		c := stored[0]
		if here != nil {
			c = *here
		}
		f.blocked = &c
		fact := fmt.Sprintf("no tier enforces from %s, checked %s", whereWords(c.Where), when(c.Time))
		switch {
		case c.Cause == CauseOutsideUserManager:
			fact = fmt.Sprintf("tego starts no run from %s, not even tego watch, checked %s; a shell inside it can start one",
				whereWords(c.Where), when(c.Time))
		case c.Cause == CauseNoUserManager && f.in.ManagerRefused != "":
			fact = fmt.Sprintf("no user manager runs for you, so tego starts no run from %s, not even tego watch, checked %s; %s",
				whereWords(c.Where), when(c.Time), f.in.ManagerRefused)
		case c.Cause == CauseNoUserManager:
			fact = fmt.Sprintf("no user manager runs for you, so tego starts no run from %s, not even tego watch, checked %s",
				whereWords(c.Where), when(c.Time))
			if c.FirstFix != "" {
				fact += "; the check's fix: " + c.FirstFix
			}
		case c.FirstFix != "":
			fact += "; the check's fix: " + c.FirstFix
		}
		f.set(StepCheck, Blocked, fact+f.scopeMissing(&c)+f.scopeAs(&c)+stale, source)
		return
	}
	fact := fmt.Sprintf("ready: %s from %s, checked %s", tierWords(ready.Tier), whereWords(ready.Where), when(ready.Time))
	if here != nil && here.Tier == "" {
		fact += fmt.Sprintf("; not from %s, where you are now", whereWords(here.Where))
		switch here.Cause {
		case CauseOutsideUserManager:
			fact += ", which starts no run, not even tego watch"
		case CauseNoUserManager:
			fact += ", where no user manager runs for you"
		}
		fact += f.scopeMissing(here) + f.scopeAs(here)
		f.hereCannot = true
	}
	if ready.Where == WhereRoot {
		// A root check holds a run started as root (sudo), never one started as you (acceptance B, 2026-11-11).
		fact += "; root's check holds only a run started as root, with sudo"
	}
	f.ready = ready
	f.set(StepCheck, Done, fact+stale, source)
}

// NotCheckedSinceStart is what both surfaces say of a place no check of this boot and build covers (ADR 0142).
const NotCheckedSinceStart = "not checked since this machine started"

// scopeMissing is, for the invoker's own check c when it starts no run only because it is outside the user manager's
// cgroup, why no command opens a shell in it from here (As.ScopeMissing), as the end of a fact; "" otherwise.
func (f *facts) scopeMissing(c *Check) string {
	if as := f.in.As; as != nil && c.Cause == CauseOutsideUserManager && c.Where == as.Where && as.Scope == "" &&
		as.ScopeMissing != "" {
		return "; no command opens one from here: " + as.ScopeMissing
	}
	return ""
}

// scopeAs is, for the invoker's own check c when it starts no run only because it is outside the user manager's
// cgroup and the shell is opened as this user from another's (As.ScopeAs), whose shell the next command opens and where
// to type it, as the end of a fact; "" otherwise. The name is the passwd entry's, as the command writes it.
func (f *facts) scopeAs(c *Check) string {
	if as := f.in.As; as != nil && c.Cause == CauseOutsideUserManager && c.Where == as.Where && as.Scope != "" &&
		as.ScopeAs != "" {
		return "; tego ran as " + as.ScopeAs + ", started from another user's shell through sudo or su: type the next " +
			"command in your own login shell, not in one sudo or su opened; it opens a shell as " + as.ScopeAs + " in " + as.ScopeAs + "'s user manager's cgroup, not in yours"
	}
	return ""
}

// find: a run is recorded. Nothing looks for agents yet, so Todo never says there are none.
func (f *facts) find() {
	source := f.in.LedgerRoot
	switch {
	case f.runsErr != nil:
		f.set(StepFind, NotKnown, "", source)
	case len(f.runs.all) == 0:
		f.set(StepFind, Todo, "Tego has recorded no run here yet", source)
	default:
		r := f.runs.all[0]
		st := f.set(StepFind, Done, "you recorded "+commandWords(r.start.Command), filepath.Join(source, r.id))
		st.Run, st.Link = r.id, "the newest run under the ledger root"
	}
}

// record: a run that enforced nothing has ended, and its record checks out now against the chain anchor (verify): the
// run tego learn is pointed at. One that does not check out is Blocked; one still going is Waiting. Skipped is decided
// after the contract and enforce steps (recordSkipped).
func (f *facts) record() {
	source := f.in.LedgerRoot
	if f.runsErr != nil {
		f.set(StepRecord, NotKnown, "", source)
		return
	}
	if r := f.runs.newest(func(r *run) bool { return r.observe() && r.state == ledger.StateEnded }); r != nil {
		dir := filepath.Join(source, r.id)
		link := "the newest ended run whose tier is observe (tego watch, --observe)"
		if f.in.Anchor != "" {
			link += ", checked against " + f.in.Anchor
		}
		var st *Step
		switch v := f.verify(r); v.v {
		case ledger.Verified:
			st = f.set(StepRecord, Done, fmt.Sprintf("run %s recorded %s and ended", f.runs.short(r.id), commandWords(r.start.Command)), dir)
		case ledger.Unverified:
			st = f.set(StepRecord, Blocked, fmt.Sprintf("run %s ended, and its record does not check out: %s",
				f.runs.short(r.id), firstLine(v.err)), dir)
		default:
			f.notKnown = append(f.notKnown, "whether run "+r.id+"'s record checks out: "+errText(v.err))
			st = f.set(StepRecord, NotKnown, "", dir)
		}
		st.Run, st.Link = r.id, link
		return
	}
	if r := f.runs.newest(func(r *run) bool { return r.observe() && r.state == ledger.StateRunning }); r != nil {
		st := f.set(StepRecord, Waiting, fmt.Sprintf("run %s is recording %s now", f.runs.short(r.id), commandWords(r.start.Command)),
			filepath.Join(source, r.id))
		st.Run, st.Link = r.id, "the newest running run whose tier is observe"
		return
	}
	f.set(StepRecord, Todo, "no run has been recorded with tego watch yet", source)
}

// recordSkipped makes a Todo record step Skipped when a contract compiles or a run was enforced without one.
func (f *facts) recordSkipped() {
	st := f.steps[StepRecord]
	if st.State != Todo {
		return
	}
	if c, e := f.steps[StepContract], f.steps[StepEnforce]; c.State == Done || e.State == Done || e.State == Waiting || e.State == Blocked {
		fact := "no run was recorded first; the contract was not made from one"
		st.Fact, st.State = &fact, Skipped
	}
}

// contract: a contract in the registries compiles now.
func (f *facts) contract() {
	cs := f.contracts
	source := "the registries"
	if cs != nil {
		source = registrySource(cs.places)
	}
	switch {
	case cs == nil:
		f.notKnown = append(f.notKnown, "the registries: no machine config to read them with")
		f.set(StepContract, NotKnown, "", source)
		return
	case cs.err != nil:
		f.notKnown = append(f.notKnown, cs.unreadable+": "+errText(cs.err))
		f.set(StepContract, NotKnown, "", source)
		return
	}
	if cs.more {
		f.notKnown = append(f.notKnown, fmt.Sprintf("agents past the first %d in name order were not compiled: "+
			"the guide compiles at most %[1]d", maxContracts))
	}
	if c, why := f.preferred(); c != nil {
		st := f.set(StepContract, Done, fmt.Sprintf("%s compiles now", c.name), c.path)
		st.Link = why
		if c.linked != nil {
			st.Link += fmt.Sprintf("; compiled as run %s ran it, from its folder at its tier", f.runs.short(c.linked.id))
		}
		return
	}
	if len(cs.all) > 0 {
		c := cs.all[0]
		st := f.set(StepContract, Blocked, fmt.Sprintf("%s does not compile: %s", c.name, firstLine(c.err)), c.path)
		st.Link = "no contract in the registries compiles; this is the first in name order"
		if cs.more {
			st.Link = fmt.Sprintf("no contract of the first %d in the registries, in name order, compiles; this is the first",
				maxContracts)
		}
		return
	}
	if f.runs != nil {
		if r := f.runs.newest(enforced); r != nil && r.start.ContractSource != nil {
			st := f.set(StepContract, Skipped, fmt.Sprintf("no contract in the registries; run %s ran under %s",
				f.runs.short(r.id), pathWords(r.start.ContractSource.Path)), filepath.Join(f.in.LedgerRoot, r.id))
			st.Run = r.id
			return
		}
	}
	f.set(StepContract, Todo, "no contract in the registries", source)
}

// preferred is the contract the contract step names, and why, among those that compile now: the one whose file the
// newest ended run under a contract ran (run_start.contract_source.path), taken only when that run's record checks out
// against the chain anchor; else the one named after the folder of the run the record step took, whose record checks
// out too (the name learn --save proposes); else the first in name order. With several contracts the step used to name
// the first in name order while the run used another (acceptance B, 2026-11-11). nil when none compiles.
func (f *facts) preferred() (*contract, string) {
	cs := f.contracts
	if cs == nil {
		return nil, ""
	}
	if f.runs != nil {
		if r := f.runs.newest(func(r *run) bool { return enforced(r) && r.state == ledger.StateEnded }); r != nil &&
			r.start.ContractSource != nil {
			for _, c := range cs.all {
				if c.err == nil && c.path == r.start.ContractSource.Path && f.verify(r).v == ledger.Verified {
					return c, fmt.Sprintf("the contract the newest ended run under a contract, %s, ran; its record checks out",
						f.runs.short(r.id))
				}
			}
		}
		if st := f.steps[StepRecord]; st != nil && st.State == Done {
			if r := f.runs.newest(func(r *run) bool { return r.id == st.Run }); r != nil && r.start.Cwd != "" {
				for _, c := range cs.all {
					if c.err == nil && c.name == filepath.Base(r.start.Cwd) {
						return c, fmt.Sprintf("named after the folder of run %s, whose record checks out", f.runs.short(r.id))
					}
				}
			}
		}
	}
	if c := cs.compiling(); c != nil {
		return c, "the first agent, in name order, whose contract compiles"
	}
	return nil, ""
}

// enforced is a run under a contract: any tier but observe.
func enforced(r *run) bool { return !r.observe() }

// verify checks run r's record against the chain anchor, as tego receipt --verify does (ledger.VerifyRunDir), once
// per run. With no anchor named it is NoVerdict.
func (f *facts) verify(r *run) verdict {
	if v, ok := f.verdicts[r.id]; ok {
		return v
	}
	v := verdict{err: errors.New("the chain anchor could not be named")}
	if f.in.Anchor != "" {
		rep, err := ledger.VerifyRunDir(f.ctx, r.dir, ledger.NewFileChainAnchor(f.in.Anchor))
		v = verdict{ledger.VerdictOf(rep, err), err}
		if v.v == ledger.NoVerdict && v.err == nil {
			v.err = errors.New("the record holds no run_start")
		}
	}
	f.verdicts[r.id] = v
	return v
}

// enforce: a run under a contract has ended and its record checks out now; one still going is Waiting.
func (f *facts) enforce() {
	source := f.in.LedgerRoot
	if f.runsErr != nil {
		f.set(StepEnforce, NotKnown, "", source)
		return
	}
	r := f.runs.newest(func(r *run) bool { return enforced(r) && r.state == ledger.StateEnded })
	if r == nil {
		if w := f.runs.newest(func(r *run) bool { return enforced(r) && r.state == ledger.StateRunning }); w != nil {
			st := f.set(StepEnforce, Waiting, fmt.Sprintf("run %s is running under a contract; its record is checked when it ends",
				f.runs.short(w.id)), filepath.Join(source, w.id))
			st.Run, st.Link = w.id, "the newest running run under a contract"
			return
		}
		f.set(StepEnforce, Todo, "no run under a contract has ended", source)
		return
	}
	dir := filepath.Join(source, r.id)
	link := "the newest ended run under a contract, checked against " + f.in.Anchor
	if f.in.Anchor == "" {
		f.notKnown = append(f.notKnown, "whether run "+r.id+"'s record checks out: the chain anchor could not be named")
		st := f.set(StepEnforce, NotKnown, "", dir)
		st.Run = r.id
		return
	}
	v := f.verify(r)
	err := v.err
	switch v.v {
	case ledger.Verified:
		fact := fmt.Sprintf("run %s ran at tier %s and ended; its record checks out now", f.runs.short(r.id), tierKey(r.start.Tier))
		if w := f.runs.newest(func(w *run) bool { return enforced(w) && w.state == ledger.StateRunning }); w != nil &&
			ledger.CompareRunIDs(w.id, r.id) > 0 {
			fact += fmt.Sprintf("; run %s is running now and is checked when it ends", f.runs.short(w.id))
		}
		st := f.set(StepEnforce, Done, fact, dir)
		st.Run, st.Link = r.id, link
	case ledger.Unverified:
		st := f.set(StepEnforce, Blocked, fmt.Sprintf("run %s ended, and its record does not check out: %s",
			f.runs.short(r.id), firstLine(err)), dir)
		st.Run, st.Link = r.id, link
	case ledger.NoVerdict:
		f.notKnown = append(f.notKnown, "whether run "+r.id+"'s record checks out: "+errText(err))
		st := f.set(StepEnforce, NotKnown, "", dir)
		st.Run, st.Link = r.id, link
	}
}

// when is a time as a fact says it: UTC to the minute.
func when(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
