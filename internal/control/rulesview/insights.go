// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/learn"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Learned is the run page's Least privilege tab: the contract `tego learn <run>` proposes, but for the leak rule, which
// the page leaves to the run's verdict (Withhold).
type Learned struct {
	Text string
	// Ended is false for a run with no run_end: the proposal is the run so far and suggests no limits.
	Ended bool
	Left  int
	Err   string
}

// proposal is what `tego learn <run>` proposes for the run under root, with its leak rule off, with the workspace from run_start and tego's
// own directories (the run's record, /run/tego, the ledger root, the chain anchor's directory) kept out of it.
func proposal(ctx context.Context, root, anchor, id string) (*learn.Proposal, error) {
	if !ledger.IsRunID(id) {
		return nil, errors.New("not a run id")
	}
	dir := filepath.Join(root, id)
	r, err := ledger.OpenReader(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	dirs := []string{dir, "/run/tego", root}
	if anchor != "" {
		dirs = append(dirs, filepath.Dir(anchor))
	}
	for _, d := range slices.Clone(dirs) {
		if real, err := filepath.EvalSymlinks(d); err == nil && real != d {
			dirs = append(dirs, real)
		}
	}
	// The page and the plan judge a leak with the run's verdict (Withhold), which knows its pair and its contract.
	l := learn.New(learn.Options{StateDirs: dirs, LeaveLeaksToCaller: true})
	first := true
	for e, err := range r.Iter() {
		if err == nil {
			err = ctx.Err()
		}
		if err == nil && first && e.Kind != record.KindRunStart {
			err = fmt.Errorf("its first line is %s, not run_start", e.Kind)
		}
		first = false
		if err == nil {
			err = l.Add(e)
		}
		if err != nil {
			return nil, err
		}
	}
	if first {
		return nil, errors.New("the run holds no run_start yet")
	}
	return l.Proposal()
}

// Learn is the Least privilege tab of run id under the ledger root root, the chain anchor at anchor. It is kept per
// run while the run and the anchor are the same (cache.go) and is shared: a caller must not modify it.
func Learn(ctx context.Context, root, anchor, id string) *Learned {
	if !ledger.IsRunID(id) {
		return &Learned{Err: "not a run id"}
	}
	return cachedLearn(ctx, root, anchor, id)
}

// learnRun is Learn uncached.
func learnRun(ctx context.Context, root, anchor, id string) *Learned {
	p, err := proposal(ctx, root, anchor, id)
	if err != nil {
		return &Learned{Err: err.Error()}
	}
	return &Learned{Text: p.Contract(), Ended: p.Ended, Left: len(p.Left)}
}

// DriftRow is one contract entry, or one rule the run named that no entry declares.
type DriftRow struct {
	Section string
	drift.RuleCount
	// Unused is a declared grant no action used: granted but never used.
	Unused bool
	// Guard is an exec.deny or exec.ask entry no line named: a guard, never a grant to cut.
	Guard bool
	// Unobservable is an entry the record could not have shown used.
	Unobservable bool
}

// Drifted is the run page's Unused permissions tab: `tego drift <run>`'s report, entry by entry.
type Drifted struct {
	Rows        []DriftRow
	Unused      int
	Declared    int
	HashChanged bool
	Unknown     bool
	// FromText: the contract did not compile here, so Rows count the entries its text declares (a plain reading
	// of the copy, as RunLists does); a rule the run named that the text does not declare is still Unknown (the
	// command, the run's own home folder and the resolver are granted without an entry).
	FromText      bool
	NoContract    bool
	Contract, Err string
}

// Drift is the Unused permissions tab of run id under the ledger root root: its contract recompiled as Load does,
// and drift.ComputeCtx over its ledger, as `tego drift <run>` reports it. It is kept per run while the run, its
// contract copy, the anchor, the machine config and PATH are the same (cache.go) and is shared: a caller must not
// modify it.
func Drift(ctx context.Context, root, id string, o Options) *Drifted {
	if !ledger.IsRunID(id) {
		return driftRun(ctx, root, id, o)
	}
	return cachedDrift(ctx, root, id, o)
}

// driftRun is Drift uncached.
func driftRun(ctx context.Context, root, id string, o Options) *Drifted {
	c := Load(ctx, root, id, o)
	v := &Drifted{NoContract: c.Missing}
	if c.Compiled == nil && !c.Missing {
		v.Unknown, v.Contract = true, c.Err
	}
	rt := c.Compiled
	if rt == nil && c.Text != "" {
		if l := RunLists(root, id); l.OK {
			rt, v.FromText = textTable(l), true
		}
	}
	r, err := ledger.OpenReader(filepath.Join(root, id))
	if err != nil {
		v.Err = err.Error()
		return v
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	rep, err := drift.ComputeCtx(ctx, r, rt)
	if err != nil {
		v.Err = err.Error()
		return v
	}
	rep.DeclaredUnknown = v.Unknown
	v.HashChanged = rep.HashChanged
	set := func(xs []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	undone, unusedMCP := set(rep.Undone), set(rep.UnusedMCP)
	guards := set(rep.GuardsNotExercised)
	blind := set(slices.Concat(rep.UnobservableFS, rep.UnobservableMCP, rep.UnobservableRecord))
	for _, sec := range rep.Sections() {
		for _, rc := range sec.Counts {
			row := DriftRow{Section: string(sec.Section), RuleCount: rc, Guard: guards[rc.Rule], Unobservable: blind[rc.Rule]}
			row.Unused = undone[rc.Rule] || unusedMCP[rc.Rule]
			if rc.Declared {
				v.Declared++
			}
			if row.Unused {
				v.Unused++
			}
			v.Rows = append(v.Rows, row)
		}
	}
	// Never-used grants first: they are what a least-privilege contract would drop.
	slices.SortStableFunc(v.Rows, func(a, b DriftRow) int {
		if a.Unused != b.Unused {
			if a.Unused {
				return -1
			}
			return 1
		}
		return 0
	})
	return v
}

// textTable is a rule table holding only the entries the contract text declares, named as the ledger names them
// (the entry as written): enough for drift to count each one, though it carries no resolved path or verdict. It is
// what the Unused permissions tab falls back on when the copy cannot be compiled here.
func textTable(l Lists) *agent.RuleTable {
	rt := &agent.RuleTable{}
	fs := func(kind agent.FSKind, askRead bool, xs []string) {
		for _, x := range xs {
			rt.FS = append(rt.FS, agent.FSRule{Kind: kind, Raw: x, Path: x, AskRead: askRead})
		}
	}
	fs(agent.FSWrite, false, l.Write)
	fs(agent.FSDenyRead, false, l.DenyRead)
	fs(agent.FSDenyRead, true, l.AskRead)
	for _, x := range l.Ask {
		rt.FSAsk = append(rt.FSAsk, agent.FSRule{Kind: agent.FSAsk, Raw: x, Path: x})
	}
	for _, x := range l.Net {
		rt.Net = append(rt.Net, agent.NetRule{Raw: x})
	}
	for _, x := range l.Exec {
		if execmatch.IsPattern(x) {
			continue // a command pattern names its rule by its parse; not counted from text
		}
		w := execmatch.Word(x)
		rt.Exec = append(rt.Exec, agent.ExecRule{Raw: w, Path: w, Source: agent.ExecSourceAllow})
	}
	return rt
}
