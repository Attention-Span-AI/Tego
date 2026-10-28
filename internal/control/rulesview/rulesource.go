// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The line page's "rule it matched" names the contract line the rule came from: "Never read ~/.ssh/ · agent.yaml
// line 14 (enforced)". The rule is looked up in the run's Rules in force view (InForce), whose compile is the costly
// part, so the view's rules are kept per run and built again only when a file the view reads changed: the run's copy
// (contract.yaml), its live blocks (live-block.json) or the rules file the positions name. A page view of a line
// then costs a few stats and a map lookup.

// RuleOrigin is where a rule a ledger line names came from, and how the run enforces it.
type RuleOrigin struct {
	// RuleKey is the rule field the line carries; Group the Rules page group the rule is listed in.
	RuleKey, Group string
	// Sentence says the rule in plain words ("Cannot read ~/.ssh/").
	Sentence string
	// File and Line are where the rule is written (the rules file, or the run's copy when Positions is
	// PositionsCopy); File is "" for a built-in rule. Origin is one of inforce's Origin values.
	File   string
	Line   int
	Origin string
	// Positions is PositionsSource or PositionsCopy: whether File is the rules file a person edits or the run's own
	// copy, because the rules file changed since the run.
	Positions string
	// State is the enforcement claim; StateWords it in words ("enforced", "best effort", "watched only"), ""
	// when the view makes no claim; EnforcedText says how, or why not in full.
	State        inforce.State
	StateWords   string
	EnforcedText string
}

// RuleSource is the origin of rule key ruleKey in run's Rules in force view (a rule whose RuleKey is it, or that
// Covers it, the first in the view's order); ok is false when no rule of the view names it (an unmatched line, a
// rule of a later contract, a run that cannot be read). The view is built at most once per version of the files it
// reads (see the file comment); o is passed to InForce as is.
func RuleSource(ctx context.Context, root, run, ruleKey string, o Options) (RuleOrigin, bool) {
	if ruleKey == "" || !ledger.IsRunID(run) {
		return RuleOrigin{}, false
	}
	e := ruleEntryOf(root, run)
	e.mu.Lock()
	defer e.mu.Unlock()
	dir := filepath.Join(root, run)
	stamp := ruleStamp{copy: stampOf(filepath.Join(dir, ledger.ContractFile)), live: stampOf(filepath.Join(dir, liveblock.FileName))}
	if e.source != "" {
		stamp.source = stampOf(e.source)
	}
	if e.byKey == nil || stamp != e.stamp {
		complete := e.build(ctx, root, run, o)
		e.stamp = stamp
		if e.source != "" {
			e.stamp.source = stampOf(e.source)
		}
		ruleBuilds.Add(1)
		if !complete {
			// A view that could not be read (a cancelled request, a run being written) answers this call only:
			// keeping it would hide the rules until a file changed.
			r, ok := e.byKey[ruleKey]
			e.byKey = nil
			return r, ok
		}
	}
	r, ok := e.byKey[ruleKey]
	return r, ok
}

// ruleStamp is the identity, size and mtime of each file a run's view reads.
type ruleStamp struct{ copy, live, source fileStamp }

type fileStamp struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

// stampOf is path's stamp, zero when it cannot be looked at (a missing file is a state too).
func stampOf(path string) fileStamp {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	s := fileStamp{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		s.dev, s.ino = uint64(st.Dev), st.Ino //nolint:unconvert // Dev's type differs between platforms
	}
	return s
}

// ruleEntry is one run's cached rule origins.
type ruleEntry struct {
	mu     sync.Mutex
	stamp  ruleStamp
	source string // the rules file the view's positions name, "" for none
	byKey  map[string]RuleOrigin
}

// build reads the run's view and indexes its rules by every rule key they name. It reports whether the view was read
// whole: no error, and the request not cancelled while it was built.
func (e *ruleEntry) build(ctx context.Context, root, run string, o Options) bool {
	v := InForce(ctx, root, run, o)
	e.byKey = map[string]RuleOrigin{}
	e.source = ""
	if v.Positions == PositionsSource {
		e.source = v.Source
	}
	for _, r := range v.View.Rules() {
		ro := RuleOrigin{RuleKey: r.RuleKey, Group: r.Group, Sentence: r.Sentence, File: r.Source.File, Line: r.Source.Line,
			Origin: r.Source.Origin, Positions: v.Positions, State: r.State, StateWords: stateWords(r.State), EnforcedText: r.EnforcedText}
		for _, k := range append([]string{r.RuleKey}, r.Covers...) {
			if _, seen := e.byKey[k]; k != "" && !seen {
				ro.RuleKey = k
				e.byKey[k] = ro
			}
		}
	}
	return v.Err == "" && ctx.Err() == nil
}

// stateWords is a rule's enforcement claim in words.
func stateWords(s inforce.State) string {
	switch s {
	case inforce.StateEnforced:
		return "enforced"
	case inforce.StateBestEffort:
		return "best effort"
	case inforce.StateNotEnforced:
		return "watched only"
	case inforce.StateNone:
	}
	return ""
}

// maxRuleEntries bounds the cache: past it, it starts again, which costs one compile per run looked at next.
const maxRuleEntries = 128

var (
	ruleMu      sync.Mutex
	ruleEntries = map[string]*ruleEntry{}
	// ruleBuilds counts the views built, for the test that a page view does not compile.
	ruleBuilds atomic.Int64
)

func ruleEntryOf(root, run string) *ruleEntry {
	k := filepath.Clean(root) + "\x00" + run
	ruleMu.Lock()
	defer ruleMu.Unlock()
	e := ruleEntries[k]
	if e == nil {
		if len(ruleEntries) >= maxRuleEntries {
			ruleEntries = map[string]*ruleEntry{}
		}
		e = &ruleEntry{}
		ruleEntries[k] = e
	}
	return e
}
