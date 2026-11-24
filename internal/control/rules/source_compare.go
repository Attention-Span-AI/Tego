// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
)

// SourceComparison is what the rules file says now, compared with the rules a run ran: each compiled family the two
// differ in, in words. It answers the Rules page's "the file differs from this run" (an edit made outside Tego, or
// one nothing dates), so a person sees what the next run would do differently and not only that the file changed.
type SourceComparison struct {
	// Families are the compiled families that differ, with the direction the comparison ordered each in; none with Err
	// empty says the two compile to the same rules.
	Families []FamilyChange
	// Direction is the one direction the comparison gives the whole difference: narrows, widens or mixed; "same" when
	// no compiled family differs (the text differs in comments, spelling or an entry another one still covers).
	Direction string
	// Err is why the two could not be compared ("" when they were): the file does not compile, the run's copy is
	// gone, or the check did not finish.
	Err string
	// NoCompiler marks a service with only a test compiler, which returns no table to compare: it says nothing, and a
	// page shows no comparison. A production service never sets it.
	NoCompiler bool
}

// CompareSource compares the contract run ran (its recorded copy) with the rules file the run named as it is now,
// through the same compiled-family comparison a change is previewed with. It reads and writes nothing else. A run
// that named no file, a file that no longer compiles or a copy that is gone is the comparison's Err, never a guess.
func (s *Service) CompareSource(ctx context.Context, run string) SourceComparison {
	if s.remote() {
		out, err := remoteService[SourceComparison](s, ctx, "CompareSource", struct{ Run string }{run})
		if err != nil {
			return SourceComparison{Err: "Tego could not compare the file with this run: " + err.Error()}
		}
		return out
	}
	if !runID(run) {
		return SourceComparison{Err: "no such run"}
	}
	if s.Compile != nil || s.Check != nil {
		return SourceComparison{NoCompiler: true}
	}
	runDir := filepath.Join(s.Ledger, run)
	st, err := readStart(runDir)
	if err != nil || st.Contract == "" {
		return SourceComparison{Err: "the run named no rules file to compare"}
	}
	cur, err := s.writer().Read(st.Contract)
	if err != nil {
		return SourceComparison{Err: fmt.Sprintf("the rules file could not be read: %v", err)}
	}
	if cur.Path != st.Resolved {
		return SourceComparison{Err: "the rules file's folder now points elsewhere than the run's did"}
	}
	before, err := rulesview.RecordedCopy(s.Ledger, run)
	if err != nil {
		return SourceComparison{Err: "the run's own copy of its rules could not be read"}
	}
	cwd := st.Cwd
	if cwd == "" {
		cwd = filepath.Dir(st.Contract)
	}
	cc := CheckContext{Contract: st.Contract, Cwd: cwd, Tier: st.Tier, RunCommandGrant: st.Grant, runDir: runDir}
	ctx = draftcompile.WithBudget(ctx)
	// The comparison goes through the one site that compares compiled tables (compareSnapshots): no process start of its own.
	plan := &ChangePlan{}
	if _, err = s.compareSnapshots(ctx, cc, before, cur.Text, plan); err != nil {
		// An error here may quote contract text: say only what happened.
		if words, ok := rule.NotFinishedWords(err); ok {
			return SourceComparison{Err: words + "; the file was not compared"}
		}
		return SourceComparison{Err: "the rules file does not compile now, so it cannot be compared"}
	}
	if plan.repair {
		return SourceComparison{Err: "the run's own copy of its rules does not compile here, so there is nothing to compare the file with"}
	}
	fams := familyChanges(plan.rows)
	if len(fams) == 0 {
		return SourceComparison{Direction: "same"}
	}
	d, _ := agentdiff.Fold(plan.rows)
	return SourceComparison{Families: fams, Direction: string(d)}
}
