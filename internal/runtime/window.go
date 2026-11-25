// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/budgetwindow"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrBudgetWindow is a run whose contract sets limits.window and whose window cannot be established, refused before
// run_start (ADR 0165): the contract names no agent across restarts, the retention would remove runs the window needs,
// an earlier run of the agent does not verify against chain.log, or another run of it is live. The CLI exits 125
// [budget-window] with the cause and the fix.
var ErrBudgetWindow = errors.New("runtime: budget window")

// GapWindowCarried is the gap, what=limits, that says this run began with spend of earlier runs counted against its
// tokens or cost_usd budget; its count is the number of earlier runs read. The amounts are not in it: they are the
// ledgers' (ADR 0165), and each is recomputed from them.
const GapWindowCarried = "window-carried"

// GapWindowUnanchored is the gap, what=limits, that says earlier runs of this agent were counted although chain.log has
// no line for them (their anchor write failed); its count is the number of such runs. Their chain verified on its own.
const GapWindowUnanchored = "window-unanchored"

// GapWindowUnattributed is the gap, what=limits, that says run directories were left out because their first line could
// not say whose they were; its count is the number of them.
const GapWindowUnattributed = "window-unattributed"

// openWindow reads what the agent's earlier runs spent inside limits.window and holds the agent's window for this run.
// It runs after the run's ledger is open and before anything the run starts, so a refusal leaves no process behind.
func (r *runner) openWindow(ctx context.Context) error {
	span := r.rt.Limits.Window
	if span <= 0 {
		return nil
	}
	// The count is read from the agent's own earlier records, so it is only as good as the agent's inability to reach
	// them. A held run cannot write the ledger root (the tiers deny it, and tego's own directory is refused to read as
	// well); a record-only run holds nothing back, so its agent can edit or delete its earlier ledgers and zero its own
	// count. The window is refused there, rather than offered as a cap it cannot be.
	if r.deps.Enforce != nil && r.deps.Enforce.Tier() == backend.TierObserve {
		return fmt.Errorf("%w: limits.window cannot protect its count in a record-only run (tego run --observe, or a tier that "+
			"holds nothing back): the agent could reach its own earlier records and lower the count. Fix: run it held, which "+
			"is the default, or remove limits.window", ErrBudgetWindow)
	}
	id, ok := budgetwindow.IdentityOf(r.deps.ContractSource)
	if !ok {
		return fmt.Errorf("%w: limits.window counts across restarts of one agent, and this run's contract names none: it was "+
			"not started from a registry name or a contract file. Fix: start it with tego run --agent NAME, or from a contract file, "+
			"or remove limits.window", ErrBudgetWindow)
	}
	if m := r.deps.Config; m != nil && m.Retention.Value < span && m.Retention.Value != KeepForever {
		return fmt.Errorf("%w: limits.window is %s and the machine's retention is %s, so tego gc removes runs the window still "+
			"counts and the count would fall. Fix: set retention to at least %s, or shorten limits.window",
			ErrBudgetWindow, config.FormatDuration(span), config.FormatDuration(m.Retention.Value), config.FormatDuration(span))
	}
	root, err := LedgerRoot(r.deps.Config)
	if err != nil {
		return err
	}
	lock, err := budgetwindow.Acquire(root, id)
	if err != nil {
		return windowErr(err)
	}
	anchor := ledger.NewFileChainAnchor(r.deps.AnchorPath)
	if r.deps.AnchorPath == "" {
		anchor = ledger.NewFileChainAnchor(ledger.DefaultAnchorPath(r.dir))
	}
	res, err := budgetwindow.Read(ctx, budgetwindow.Request{Root: root, Anchor: anchor, Self: string(r.id), Identity: id,
		Now: r.deps.Clock.Now(), Window: span, Foreign: foreignRun})
	if err != nil {
		_ = lock.Close()
		return windowErr(err)
	}
	r.windowLock, r.windowRuns, r.windowUnanchored, r.windowUnattributed = lock, res.Runs, len(res.Unanchored), len(res.Unattributed)
	r.window = &limits.Window{Span: span, Carry: res.Carry}
	if len(res.Unanchored) > 0 {
		r.log.Warn("run: earlier runs of this agent ended with no line in chain.log; their spend is counted from the record as it stands, "+
			"which nothing checks against an anchor", "runs", res.Unanchored)
	}
	if len(res.Unattributed) > 0 {
		r.log.Warn("run: run directories whose first line cannot say whose they are were left out of the window", "runs", res.Unattributed)
	}
	if len(res.Lost) > 0 {
		r.log.Warn("run: earlier runs of this agent were lost with their launcher; their spend is counted to the last line they wrote",
			"runs", res.Lost)
	}
	return nil
}

// windowErr turns the loader's refusals into ErrBudgetWindow, keeping the loader's own text, which names the run.
func windowErr(err error) error {
	switch {
	case errors.Is(err, budgetwindow.ErrLive):
		return fmt.Errorf("%w: %w. Fix: wait for it to end, or stop it with tego session stop; two runs of one agent would each "+
			"count the other's spend as zero", ErrBudgetWindow, err)
	case errors.Is(err, budgetwindow.ErrTooLarge):
		return fmt.Errorf("%w: %w. Fix: run this agent under record: summary (the default), or shorten limits.window; reading "+
			"more than that before every start is not a start", ErrBudgetWindow, err)
	case errors.Is(err, budgetwindow.ErrLockFile):
		return fmt.Errorf("%w: %w. No run's ledger is at fault: the agent's lock file in the ledger root, which holds nothing, "+
			"cannot be opened, usually because its mode was taken (tego restores it when a run starts, so this is a mode taken "+
			"again just after, or a file of another account's). Fix: chmod u+rw that file, or remove it", ErrBudgetWindow, err)
	case errors.Is(err, budgetwindow.ErrUnprovable):
		return fmt.Errorf("%w: %w. The window counts only what a verified ledger proves, so the run is refused rather than started with a "+
			"count that could be low, and waiting does not change it. Fix: restore that run's ledger or its chain.log line from a copy; "+
			"if the damage is known not to be the agent's work, move that run's directory out of the ledger root, which keeps the "+
			"record and stops counting its spend", ErrBudgetWindow, err)
	}
	return err
}

// closeWindow releases the agent's window. It is the run's last step: the ledger is closed and anchored by then, so
// the next run of the agent reads it ended.
func (r *runner) closeWindow() {
	_ = r.windowLock.Close()
	r.windowLock = nil
}

// emitWindowGap says, right after run_start, that this run's budget counted earlier runs.
func (r *runner) emitWindowGap() {
	if r.window == nil {
		return
	}
	if r.windowRuns > 0 {
		r.emitGap(source.Gap{What: record.GapLimits, Why: GapWindowCarried, Count: int64(r.windowRuns)})
	}
	if r.windowUnanchored > 0 {
		r.emitGap(source.Gap{What: record.GapLimits, Why: GapWindowUnanchored, Count: int64(r.windowUnanchored)})
	}
	if r.windowUnattributed > 0 {
		r.emitGap(source.Gap{What: record.GapLimits, Why: GapWindowUnattributed, Count: int64(r.windowUnattributed)})
	}
}
