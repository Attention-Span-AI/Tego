// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Where a view's contract positions point (InForceView.Positions).
const (
	// PositionsSource: file and line name the rules file the run named (and the profiles it extends), which still
	// loads to the run's contract_hash, so each line is where a person would edit that rule.
	PositionsSource = "source"
	// PositionsCopy: file and line name the run's own copy (<run>/contract.yaml), because the rules file no longer
	// loads to the run's contract_hash, is gone, or could not be checked; PositionsWhy says which. The page reads such a
	// position as "run copy line N".
	PositionsCopy = "copy"
)

// InForceView is the Rules in force page of one run: what its contract lets the agent do at the run's tier, as
// inforce sentences in fixed groups, with each rule's hits in the run, the run's live blocks, and whether its rules
// file changed for the next run. The dashboard's Rules page and `tego rules` show it.
type InForceView struct {
	Run string `json:"run"`
	// View is the groups and their rules; its live group holds the run's live blocks while the run has not ended.
	View inforce.View `json:"view"`
	// Contract is the run's copy, its compile table and diagnostics: the page's raw YAML and compile details.
	Contract Contract `json:"-"`
	// Source is the rules file the run named (run_start's contract_source), "" when it named none; SourceName is
	// the agent name it was resolved from, "" when it was named by its path.
	Source     string `json:"source,omitempty"`
	SourceName string `json:"source_name,omitempty"`
	// CopyPath is the run's own copy, <run>/contract.yaml.
	CopyPath string `json:"copy_path"`
	// Positions is PositionsSource or PositionsCopy; PositionsWhy is why the copy, "" for the source.
	Positions    string `json:"positions"`
	PositionsWhy string `json:"positions_why,omitempty"`
	// Started is the time of the run's first line; Ended is a run_end read; Lines the lines read.
	Started time.Time `json:"started"`
	Ended   bool      `json:"ended"`
	Lines   int       `json:"lines"`
	// LiveBlocks is how many live blocks the run's overlay holds. LiveErr is why the overlay could not be read, in plain
	// words that follow "The run's live blocks could not be read:" (the file and what is wrong with it, never Go's
	// error), "" when it was or there is none.
	LiveBlocks int    `json:"live_blocks"`
	LiveErr    string `json:"live_err,omitempty"`
	// EndedLive is an ended run's live blocks, each said by what it did while the run ran (inforce.EndedLiveRule: "Was
	// blocked: cannot run curl" for a block the run put in force, "Never put in force: …" for one it did not, "Was
	// marked (recorded, not refused): …" on a watched run), with who added it and the hits of the lines under its rule
	// key in the run. They refuse nothing now, so they are not in View's live group, and a note in View.Notes counts
	// them. Nil while the run has not ended.
	EndedLive []inforce.Rule `json:"ended_live,omitempty"`
	// Pending says the rules file changed after the run started, so the next run gets other rules, or that it loads
	// to other rules with nothing to date the change (Pending.Differs). Nil when it still loads to the run's rules
	// (changed and changed back too), or could not be compared and nothing dates a change.
	Pending *Pending `json:"pending,omitempty"`
	// Err is why the run could not be read at all, "" when it was.
	Err string `json:"err,omitempty"`
}

// InForce is the Rules in force view of run under the ledger root root. It reads the run's ledger once (run_start,
// each line's rule for the hits and an unmatched line's kind for the default that decided it, run_end, the exec lines'
// programs), or takes all but run_start from the read model's run (Options.Run), compiles the contract as Load does,
// reads the run's live blocks read-only, and reads the rule-change journal and the rules file for Pending. It writes
// nothing.
//
// The contract compiled is the run's rules file when that file still loads to the run's contract_hash (the same
// merged contract, so the same table), which makes every position a line of the real file; otherwise it is the
// run's copy, and the positions are the copy's lines. A contract that does not compile today is shown from its text
// (inforce.Declared), with no enforcement claim.
func InForce(ctx context.Context, root, run string, o Options) *InForceView {
	v := &InForceView{Run: run, Positions: PositionsCopy}
	if !ledger.IsRunID(run) {
		v.Err = "not a run id"
		v.View = emptyView("Not a run id.")
		return v
	}
	dir := filepath.Join(root, run)
	v.CopyPath = filepath.Join(dir, ledger.ContractFile)
	var sc *runScan
	var err error
	if o.Run != nil && o.Run.ID == run {
		sc, err = memoScan(dir, o.Run) // kept per run version (inforce_cache.go)
	} else {
		sc, err = scanRun(ctx, dir)
	}
	if err != nil {
		v.Err = err.Error()
		v.View = emptyView("The run's record could not be read.")
		return v
	}
	v.Started, v.Ended, v.Lines = sc.started, sc.ended, sc.lines
	if s := sc.start.ContractSource; s != nil {
		v.Source, v.SourceName = s.Path, s.Name
	}
	src := checkSource(v.Source, sc.start.ContractHash, o.Profiles)
	var alt *agent.Contract
	if src.matches {
		alt = src.contract
	}
	loadCopy(ctx, &v.Contract, dir, sc.start, o, alt, sc.moreDirs)
	v.Contract.Run = run
	c := &v.Contract
	tier, _ := backend.ParseTier(sc.start.Tier)
	switch {
	case c.Compiled != nil:
		v.View = inforce.Of(c.Compiled, tier, sc.start.DecisionPlane)
		if src.matches {
			v.Positions = PositionsSource
		} else {
			relocate(&v.View, placeOf(c.Path, sc.start), c.Path)
		}
	case src.matches:
		v.View, _ = inforce.Declared(src.text, v.Source)
		v.Positions = PositionsSource
	case c.Text != "":
		v.View, _ = inforce.Declared([]byte(c.Text), c.Path)
	default:
		v.View = emptyView("The run left no copy of its rules.")
	}
	if v.Positions == PositionsCopy {
		v.PositionsWhy = src.why
	}
	v.addLive(dir, run, func() ledgerview.LiveFacts { return liveFacts(root, run, o, &sc.start, v.Ended) })
	v.View.Count(func(yield func(string) bool) {
		for rule, n := range sc.rules {
			for range n {
				if !yield(rule) {
					return
				}
			}
		}
	})
	for kind, n := range sc.unmatched {
		v.View.CountDefault(kind, n)
	}
	for i := range v.EndedLive { // in no group, so Count passed them by: each counts the refusals under its key
		v.EndedLive[i].Hits = sc.rules[v.EndedLive[i].RuleKey]
	}
	v.Pending = pendingOf(root, v.Source, v.Started, src)
	return v
}

// terminalDevices are the device files a contract grants so a shell and its programs can talk to a terminal and
// throw output away: a person reads four rows of them as noise, so a rules table folds them into one (FoldDevices).
var terminalDevices = map[string]bool{"/dev/null": true, "/dev/tty": true, "/dev/ptmx": true, "/dev/pts": true}

// TerminalDevice reports whether rule r is about a terminal device file (/dev/null, /dev/tty, /dev/ptmx, or
// /dev/pts/ and what is under it), by its entry as written.
func TerminalDevice(r inforce.Rule) bool {
	e := filepath.Clean(r.Entry)
	return r.Entry != "" && (terminalDevices[e] || strings.HasPrefix(e, "/dev/pts/"))
}

// Rule is one rule in force (inforce.Rule), named here so the dashboard, which does not import the check cores
// (ADR 0100 (1d)), can shape a view's rows.
type Rule = inforce.Rule

// RuleWords is a ledger rule key in words (inforce.Words, the one vocabulary for rule keys), named here for the same
// reason: the dashboard names every line's rule by it.
func RuleWords(ruleKey string) string { return inforce.Words(ruleKey) }

// Fold is one row of a rules table: a rule alone (Devices nil), or, at the first terminal device rule's place, the
// group's terminal device rules folded under one row, each kept whole (its key, its line, its hits) for the
// expander. Rule is then the first of them.
type Fold struct {
	Rule    inforce.Rule
	Devices []inforce.Rule
}

// FoldDevices is a group's rules as table rows: two or more terminal device rules with the same effect fold into
// one row where the first of them stood; every other rule, and a lone device rule, stays its own row, in order.
func FoldDevices(rules []inforce.Rule) []Fold {
	byEffect := map[inforce.Effect]int{}
	for _, r := range rules {
		if TerminalDevice(r) {
			byEffect[r.Effect]++
		}
	}
	out := make([]Fold, 0, len(rules))
	at := map[inforce.Effect]int{} // effect -> index in out of its fold row
	for _, r := range rules {
		if !TerminalDevice(r) || byEffect[r.Effect] < 2 {
			out = append(out, Fold{Rule: r})
			continue
		}
		i, ok := at[r.Effect]
		if !ok {
			i = len(out)
			at[r.Effect] = i
			out = append(out, Fold{Rule: r})
		}
		out[i].Devices = append(out[i].Devices, r)
	}
	return out
}

// emptyView is a view with every group empty and one note.
func emptyView(note string) inforce.View {
	v, _ := inforce.Declared([]byte("{}\n"), "")
	v.Notes = []string{note}
	return v
}

// relocate points every position the copy's compile placed at place (the rules file's path, where the copy is
// compiled) at the copy itself: the lines are the copy's, and the rules file no longer holds them there.
func relocate(v *inforce.View, place, copyPath string) {
	if place == copyPath {
		return
	}
	v.ContractPath = copyPath
	for gi := range v.Groups {
		for ri := range v.Groups[gi].Rules {
			if s := &v.Groups[gi].Rules[ri].Source; s.File == place {
				s.File = copyPath
			}
		}
	}
}

// addLive lists the run's live blocks in the view's live group while the run has not ended, each with its state now
// (internal/check/livestatus): facts gives the run's live facts, called only when there is a block to say. Once the
// run has ended they refuse nothing: addEnded lists them in EndedLive instead. An overlay that cannot be read lists
// nothing and says why in LiveErr.
func (v *InForceView) addLive(dir, run string, facts func() ledgerview.LiveFacts) {
	ov, err := liveblock.Read(dir, run)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		v.LiveErr = LiveErrWords(err)
		return
	}
	v.LiveBlocks = len(ov.Blocks)
	if len(ov.Blocks) == 0 {
		return
	}
	f := facts()
	if v.Ended {
		v.addEnded(ov, f)
		return
	}
	// Each block's serial is its latest add's, or the overlay's when that add is no longer listed (runact.Live).
	serial := make(map[string]uint64, len(ov.Blocks))
	for _, c := range ov.Changes {
		if c.Op == liveblock.OpAdd {
			serial[liveblock.Key(c.Kind, c.Value)] = c.Serial
		}
	}
	for _, e := range ov.Blocks {
		s, ok := serial[e.Key()]
		if !ok {
			s = ov.Serial
		}
		// A block with a time limit is judged now (livestatus.StatusAt): an unblock for a while or a passed limit
		// refuses nothing, and the live group must not say it does.
		st := livestatus.StatusAt(string(e.Kind), f.Facts, s, f.Confirmed, time.Now(), e.From, e.Until)
		v.View.AddLiveStatus(string(e.Kind), e.Value, e.By, st.State, st.Sentence)
	}
}

// addEnded lists an ended run's live blocks (ov holds at least one) in EndedLive, apart from the live group, each
// said by what it did while the run ran (inforce.EndedLiveRule): its state as livestatus.Status gives it on the run's
// facts f with the run not ended, against the serial of the add that made it (madeAt). So a block the launcher put in
// force reads "Was blocked", one it never did "Never put in force", and a watched run's mark "Was marked", whatever
// any of them does now. The note counts them and says only what holds of every one now: blocks refuse nothing, marks
// record nothing.
func (v *InForceView) addEnded(ov *liveblock.Overlay, f ledgerview.LiveFacts) {
	running := f.Facts
	running.Ended = false
	made := madeAt(ov)
	for _, e := range ov.Blocks {
		was := livestatus.Status(string(e.Kind), running, made[e.Key()], f.Confirmed)
		v.EndedLive = append(v.EndedLive, inforce.EndedLiveRule(string(e.Kind), e.Value, e.By, was.State))
	}
	n := len(ov.Blocks)
	var note string
	switch {
	case running.Observe && n == 1:
		note = "The run has ended, so its live mark records nothing now."
	case running.Observe:
		note = fmt.Sprintf("The run has ended, so its %d live marks record nothing now.", n)
	case n == 1:
		note = "The run has ended, so its live block refuses nothing now."
	default:
		note = fmt.Sprintf("The run has ended, so its %d live blocks refuse nothing now.", n)
	}
	v.View.Notes = append(v.View.Notes, note)
}

// madeAt is the overlay serial of the add that made each block ov holds (by Entry.Key): the oldest add of it the
// overlay lists since it was last removed for good (a remove with no time limit). The launcher stores every block of
// the overlay it reads and then confirms each change it read, so a confirmed serial at or past this one means the run
// put the block in force. A later add of a block it holds (a longer time limit, a block again after an unblock for a
// while) does not undo that, though it gives the block a new serial (runact.Live's): a run that ended before
// confirming that add still had the block in force. A block made before the oldest change the overlay lists (it keeps
// the newest liveblock.MaxChanges) is judged by the first add it lists of it, or, with none, by the overlay's serial as
// runact.Live judges it: a serial later than the one that made it can only say "never put in force" of a block that
// was, never the reverse.
func madeAt(ov *liveblock.Overlay) map[string]uint64 {
	made := make(map[string]uint64, len(ov.Blocks))
	for _, c := range ov.Changes { // oldest first
		k := liveblock.Key(c.Kind, c.Value)
		switch {
		case c.Op == liveblock.OpAdd:
			if _, ok := made[k]; !ok {
				made[k] = c.Serial
			}
		case c.Op == liveblock.OpRemove && c.Until.IsZero():
			delete(made, k) // removed for good: a later add makes another block
		}
	}
	for _, e := range ov.Blocks {
		if _, ok := made[e.Key()]; !ok {
			made[e.Key()] = ov.Serial
		}
	}
	return made
}

// LiveErrWords is why liveblock.Read (or runact.Live, which hands its error on) could not read a run's overlay, in
// plain words that follow "The run's live blocks could not be read:": a file Tego does not trust says what is wrong
// with it ("live-block.json is a symlink"), one that does not decode is damaged or a newer Tego's, one this user may
// not read says so, and any other error is the system's own words without Go's prefixes or the run's folder. It is
// the dashboard's one wording of an overlay it cannot read: the Rules page's LiveErr, the run page's Block now panel
// and the fence's lift preview.
func LiveErrWords(err error) string {
	switch {
	case errors.Is(err, liveblock.ErrUntrusted):
		// liveblock names the file and what is wrong with it after its sentinel's words.
		if why, ok := strings.CutPrefix(err.Error(), liveblock.ErrUntrusted.Error()+": "); ok && why != "" {
			return why + ", so it is not trusted"
		}
		return liveblock.FileName + " is not trusted"
	case errors.Is(err, liveblock.ErrInvalid):
		return liveblock.FileName + " is damaged, or a newer Tego wrote it"
	case errors.Is(err, fs.ErrPermission):
		return "this user may not read " + liveblock.FileName
	}
	for u := errors.Unwrap(err); u != nil; u = errors.Unwrap(err) {
		err = u // a path error's own words ("input/output error"), without the operation and the path
	}
	return err.Error()
}

// liveFacts is run's live facts from the read model's run when the caller handed it, else from a read of the run;
// a run that cannot be read gives run_start's facts with nothing confirmed.
func liveFacts(root, run string, o Options, start *record.RunStartPayload, ended bool) ledgerview.LiveFacts {
	r := o.Run
	if r == nil || r.ID != run {
		var err error
		if r, err = ledgerview.LoadRun(root, run); err != nil {
			f := livestatus.FromStart(start)
			f.Ended = ended
			return ledgerview.LiveFacts{Facts: f}
		}
	}
	f := ledgerview.LiveFactsOf(r)
	f.Ended = ended
	return f
}

// source is what checkSource found of a run's rules file.
type source struct {
	// read: the file was read; text is its bytes, mtime its modification time.
	read  bool
	text  []byte
	mtime time.Time
	// checked: the file loaded and the run recorded a contract_hash, so matches says whether the file loads to it;
	// contract is it loaded.
	checked, matches bool
	contract         *agent.Contract
	// why is why the run's copy gives the positions, "" when the file matches.
	why string
}

// checkSource reads the rules file at path (no link followed at its last name, under the size cap) and loads it with
// profiles resolving its extends, to see whether it still is the contract the run ran: its canonical form hashes to
// hash. A file that extends a profile when no profiles source is given is read and not checked, and so is any file
// of a run that recorded no hash: there is nothing to compare it with.
func checkSource(path, hash string, profiles agent.ProfileSource) source {
	var s source
	if path == "" || !filepath.IsAbs(path) {
		s.why = "the run named no rules file"
		return s
	}
	text, st, err := readNoFollow(path)
	if errors.Is(err, os.ErrNotExist) {
		s.why = "the rules file is gone"
		return s
	}
	if err != nil {
		s.why = "the rules file could not be read"
		return s
	}
	s.read, s.text, s.mtime = true, text, st.ModTime()
	if profiles == nil {
		profiles = &agent.ProfileChain{}
	}
	c, _, err := agent.LoadBytes(path, text, profiles)
	var sum [32]byte
	if err == nil {
		sum, err = c.Hash()
	}
	if err != nil {
		s.why = "the rules file does not load here as the run loaded it"
		return s
	}
	if hash == "" {
		s.why = "the run recorded no contract hash to compare the rules file with"
		return s
	}
	s.checked = true
	if s.matches = hex.EncodeToString(sum[:]) == hash; s.matches {
		s.contract = c
	} else {
		// Not "changed since the run started": when a profile it extends changed, or the run started from other
		// bytes, nothing changed the file after the start (Pending.Differs).
		s.why = "the rules file no longer loads to the rules this run ran"
	}
	return s
}
