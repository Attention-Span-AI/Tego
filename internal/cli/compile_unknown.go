// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// rootPrediction is what compile, run by this user, could not finish that root finishes (ADR 0043, amendment
// 2026-11-18): a prediction for a root tier says what the same contract decides when root compiles and launches it,
// so a step a permission failure cut short leaves the answers that depend on it unknown, never allowed. compile --test
// and compile --exec share it, and unknown is the one decision both print.
//
// A place the compile could not read makes unknown only the rows whose own answer depends on what lies behind it
// (ADR 0043, amendment 2026-11-19): by the step that met it (agent.CutReach), a row about a path at, beneath or above
// the place, every exec row, or every file-backed row. The rows left unknown are named once per place (explain).
type rootPrediction struct {
	// cuts holds each place a step of the compile was cut short at (agent.WithNamePrediction's callback), by the
	// folder this user could not read, so the table is not the one a root tier is given for the rows the reach names.
	cuts []rootCut
	// walks holds each row path, as the row's action carries it, whose own walk a permission failure stopped: root's
	// walk goes on to a place this process cannot name, and that row alone is unknown. The value is the folder the
	// walk stopped in.
	walks map[string]string
	// notes is what made a column unknown, in the order it was found, one per folder and kind of reach.
	notes []rootNote
	// rerun is the arguments of this compile, for the root command explain prints.
	rerun string
}

// rootCut is a place a permission failure kept from this user.
type rootCut struct {
	folder string
	reach  agent.CutReach
}

// rootNote is one reason a column was unknown: the folder, and which rows it leaves unknown.
type rootNote struct {
	folder string
	scope  string
}

// The rows a folder this user could not read leaves unknown, as explain says them.
const (
	leavesHere = "a row about a path at, beneath or above it"
	leavesExec = "every exec row (what root finds there changes how a program is read)"
	leavesWide = "every file-backed row, an fs, exec or executable-map one (what root finds there can name any path)"
	leavesWalk = "a row whose path leads through it (root's walk goes on to a place this user cannot name)"
)

// cutTable is agent.WithNamePrediction's callback.
func (p *rootPrediction) cutTable(c agent.NameCut) {
	cut := rootCut{folder: blockingFolder(c.Path), reach: c.Reach}
	if !slices.Contains(p.cuts, cut) {
		p.cuts = append(p.cuts, cut)
	}
}

// cutWalk records a row path whose walk stopped at a permission failure.
func (p *rootPrediction) cutWalk(path string) {
	if p.walks == nil {
		p.walks = map[string]string{}
	}
	p.walks[path] = blockingFolder(path)
}

// note records that a column is unknown for folder, once per folder and scope.
func (p *rootPrediction) note(folder, scope string) {
	n := rootNote{folder, scope}
	if !slices.Contains(p.notes, n) {
		p.notes = append(p.notes, n)
	}
}

// blockingFolder is the folder this user cannot read on the way to path: the deepest folder it can reach whose next
// component the kernel refuses it (EACCES), or path itself when every component stats (a listing or a read of path
// was what failed).
func blockingFolder(path string) string {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return path
	}
	cur := "/"
	for part := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		next := filepath.Join(cur, part)
		var st unix.Stat_t
		if err := unix.Lstat(next, &st); err != nil {
			if errors.Is(err, unix.EACCES) {
				return cur
			}
			return path
		}
		cur = next
	}
	return path
}

// reaches reports whether a place cut at c leaves the answer for a unknown at a root tier.
func (c rootCut) reaches(a agent.Action) bool {
	fileBacked := strings.HasPrefix(string(a.Kind), "fs_") || a.Kind == agent.ActionExec || a.Kind == agent.ActionMapExec
	switch c.reach {
	case agent.CutHere:
		for _, path := range []string{a.Path, a.DestPath, a.Script, strings.TrimPrefix(a.Path, "unix:")} {
			if path != "" && filepath.IsAbs(path) && (agent.Covers(c.folder, path) || agent.Covers(path, c.folder)) {
				return true
			}
		}
		return false
	case agent.CutExec:
		return a.Kind == agent.ActionExec || a.Kind == agent.ActionMapExec
	case agent.CutWide:
		return fileBacked
	}
	return fileBacked // a reach this build does not know is the widest
}

// scope is the text of what the cut leaves unknown.
func (c rootCut) scope() string {
	switch c.reach {
	case agent.CutHere:
		return leavesHere
	case agent.CutExec:
		return leavesExec
	case agent.CutWide:
		return leavesWide
	}
	return leavesWide
}

// explain says, once per folder, which folder this user could not read and which rows that left unknown at a root
// tier, then the one command that gives root's answer (ADR 0043, amendment 2026-11-19). It says nothing when no
// column was unknown: a place nothing depends on changes no answer.
func (p *rootPrediction) explain(stderr io.Writer) {
	if p == nil || len(p.notes) == 0 {
		return
	}
	// One line per folder, the rows it leaves unknown joined: a row whose walk led through the folder is one of those a
	// row about a path beneath it names, and is said alone only when nothing wider is.
	var folders []string
	scopes := map[string][]string{}
	for _, n := range p.notes {
		if _, ok := scopes[n.folder]; !ok {
			folders = append(folders, n.folder)
		}
		scopes[n.folder] = append(scopes[n.folder], n.scope)
	}
	for _, folder := range folders {
		what := scopes[folder]
		if len(what) > 1 {
			what = slices.DeleteFunc(slices.Clone(what), func(s string) bool { return s == leavesWalk })
		}
		message(stderr, "", 0, 0, fmt.Sprintf("tego compile: could not read %s (permission denied); root can, so at tiers cgroup and bpflsm the answer for %s is %q, and every other row keeps its answer",
			record.Printable(folder), strings.Join(what, " and "), agent.VerdictRootRequired), agent.RootRequiredRule)
	}
	command, why := sudoSelf(p.rerun)
	if why != "" {
		message(stderr, "", 0, 0, "tego compile: to get root's answer, run this compile as root ("+strings.TrimSuffix(why, ".")+")", agent.RootRequiredRule)
		return
	}
	message(stderr, "", 0, 0, "tego compile: root's answer: "+command, agent.RootRequiredRule)
}

// rerunArgs is the arguments that run this compile again as root: the contract, the one way it was asked (--test with
// its table, or --exec with its line), the tiers and --json as given.
func rerunArgs(path string, req compileRequest) string {
	args := "compile " + shellword.Quote(path)
	switch {
	case req.testTable != "":
		args += " --test " + shellword.Quote(req.testTable)
	case req.execLine != "":
		args += " --exec " + shellword.Quote(req.execLine)
	}
	if len(req.tiers) > 0 {
		names := make([]string, len(req.tiers))
		for i, t := range req.tiers {
			names[i] = t.String()
		}
		args += " --tier " + strings.Join(names, ",")
	}
	if req.asJSON {
		args += " --json"
	}
	return args
}

// landers is l with each walk a permission failure stops recorded: a filesystem path under its cleaned spelling,
// which is what the action then carries (agent's landed), and a unix name as the row spells it. The unix walk
// answers a class, not an errno, so the name is asked once more with one O_PATH open.
func (p *rootPrediction) landers(l agent.Landers) agent.Landers {
	path, unixName := l.Path, l.Unix
	if path != nil {
		l.Path = func(name string, how agent.Lookup) (string, error) {
			at, err := path(name, how)
			if errors.Is(err, unix.EACCES) {
				p.cutWalk(filepath.Clean(name))
			}
			return at, err
		}
	}
	if unixName != nil {
		l.Unix = func(name string) (agent.UnixLanding, error) {
			if walkDenied(name) {
				p.cutWalk(name)
			}
			return unixName(name)
		}
	}
	return l
}

// walkDenied reports whether the kernel's walk of path, every link followed, stops for this process at a directory it
// may not search. A name that is not there fails the same way for root and is no such stop.
func walkDenied(path string) bool {
	f, err := os.OpenFile(path, unix.O_PATH, 0)
	if err == nil {
		_ = f.Close()
		return false
	}
	return errors.Is(err, unix.EACCES)
}

// unknown reports whether the answer for a in tier is one this user cannot be given: tier is a root tier, and either
// a place the compile could not read is one a's answer depends on (rootCut.reaches), or one of a's own paths was not
// walked to where root's walk leads. A landlock column is this user's own run and stays concrete, and a network row
// with no pathname is decided by no file.
func (p *rootPrediction) unknown(a agent.Action, tier backend.Tier) bool {
	if p == nil || tier != backend.TierCgroup && tier != backend.TierBPFLSM {
		return false
	}
	hit := false
	for _, c := range p.cuts {
		if c.reaches(a) {
			p.note(c.folder, c.scope())
			hit = true
		}
	}
	for _, path := range []string{a.Path, a.DestPath, a.Script, strings.TrimPrefix(a.Path, "unix:")} {
		if folder, ok := p.walks[path]; ok && path != "" {
			p.note(folder, leavesWalk)
			hit = true
		}
	}
	// Whether the object is a directory is a fact of the row (a name entry never decides one): where this process may
	// not look the name up in its directory, root may, and answers on what it finds.
	switch a.Kind {
	case agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSRename:
		var st unix.Stat_t
		if !a.Dir && filepath.IsAbs(a.Path) && errors.Is(unix.Lstat(a.Path, &st), unix.EACCES) {
			p.note(blockingFolder(a.Path), leavesWalk)
			hit = true
		}
	}
	return hit
}

// unknownResult is the answer of a column unknown reports.
func unknownResult() agent.EvalResult {
	return agent.EvalResult{Verdict: agent.VerdictRootRequired, Rule: agent.RootRequiredRule}
}
