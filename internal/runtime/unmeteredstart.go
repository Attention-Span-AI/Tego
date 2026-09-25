// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrCaptureUnavailable is a run with a tokens, cost_usd or repeats budget whose capture mechanism could not
// start, refused before run_start: nothing would meter its model spend, and a budget that is silently not
// enforced is the failure it exists to prevent (limits-check-doctor-cli.md R32). The CLI exits 125
// [capture-unavailable] with the cause and the fix.
var ErrCaptureUnavailable = errors.New("runtime: capture unavailable")

// ErrBudgetUnmetered is a run with a tokens, cost_usd or repeats budget its contract declares and nothing to count
// it with: no capture runs for it (the contract's capture: off, a machine capture ceiling of off, a forwarder with
// no models: endpoint, record: off under uprobe capture), or, for cost_usd, no price table that lists a model, or
// one that prices no model (every entry lacks an input or an output price).
// Such a limit never trips, and an unattended run under it has no limit at all, so the run is refused before run_start
// (limits-check-doctor-cli.md R32). The CLI exits 125 [budget-unmetered] with the cause and the fix.
var ErrBudgetUnmetered = errors.New("runtime: budget unmetered")

// meteredBudgets are the run's bounded budgets that only capture can meter, by their contract names.
func meteredBudgets(rt *agent.RuleTable) []string {
	if rt == nil {
		return nil
	}
	var out []string
	for _, b := range []struct {
		set  agent.BudgetSet
		name string
	}{{agent.BudgetTokens, "tokens"}, {agent.BudgetCostUSD, "cost_usd"}, {agent.BudgetRepeats, "repeats"}} {
		if rt.Limits.Bounded(b.set) {
			out = append(out, b.name)
		}
	}
	return out
}

// declaredBudgets are the meteredBudgets the run's contract (or a profile it extends) sets itself. A budget a
// machine ceiling alone imposes is not among them: that ceiling bounds every contract on the machine, most of
// which talk to no model, so where nothing counts it the run keeps its gap why=budget-unmetered and is not refused.
func declaredBudgets(rt *agent.RuleTable) []string {
	if rt == nil || rt.Contract == nil {
		return nil
	}
	l := rt.Contract.Limits
	var out []string
	for _, b := range []struct {
		set      agent.BudgetSet
		name     string
		declared bool
	}{{agent.BudgetTokens, "tokens", l.Tokens != nil}, {agent.BudgetCostUSD, "cost_usd", l.CostUSD != nil}, {agent.BudgetRepeats, "repeats", l.Repeats != nil}} {
		if b.declared && rt.Limits.Bounded(b.set) {
			out = append(out, b.name)
		}
	}
	return out
}

// refuseUncountedBudget fails the run's start when a tokens, cost_usd or repeats budget its contract declares has
// nothing to count it with: run_start.capture would be off, or the budget is cost_usd and no price table that
// lists a model loaded (limits.FromMachine reads one that lists none as no table), or the table that loaded prices
// no model (every entry lacks an input or an output price: limits.PriceTable.PricesAnyModel). That table loads, so
// its run went ahead and ended at its first response, while one that lists no model was refused;
// it is kept loaded rather than read as no table, so a cost ceiling a machine alone imposes still ends its run at
// the first response (the watcher), where no table would let that run go on uncounted.
// It runs right after refuseUnmeteredBudget, which names a mechanism the run was given and that failed; this is
// the budget nothing was ever going to meter, which ran with only compile's warning and a gap
// why=budget-unmetered and exited as the agent did (the custom-agent POC's item 1: for an unattended night, a
// limit that silently does nothing). Like that refusal it comes before run_start and the agent's release, so the
// run leaves no record. compile reports the same contracts [budget-unmetered] (agent budgetsUnmetered).
func (r *runner) refuseUncountedBudget() error {
	declared := declaredBudgets(r.rt)
	if len(declared) == 0 {
		return nil
	}
	if r.captureMode() == string(agent.CaptureOff) {
		cause, fix := r.uncountedCause()
		return fmt.Errorf("%w: the %s budget cannot be counted, so the run is refused rather than run with a limit "+
			"that never trips: %s. Fix: %s, or remove the budget", ErrBudgetUnmetered, strings.Join(declared, ", "), cause, fix)
	}
	if r.deps.PriceGap != "" && slices.Contains(declared, "cost_usd") {
		return fmt.Errorf("%w: the cost_usd budget cannot be counted, so the run is refused rather than run with a "+
			"limit that never trips: no price table that lists a model loaded (%s). Fix: install a price table "+
			"pricing the run's models at the machine config's prices: path, or bound the run with tokens instead",
			ErrBudgetUnmetered, r.deps.PriceGap)
	}
	if r.deps.Prices != nil && !r.deps.Prices.PricesAnyModel() && slices.Contains(declared, "cost_usd") {
		return fmt.Errorf("%w: the cost_usd budget cannot be counted, so the run is refused rather than run with a "+
			"limit no response can be priced against: the price table %s prices no model (every entry lacks an "+
			"input_per_mtok or an output_per_mtok). Fix: give a model entry both input_per_mtok and output_per_mtok, "+
			"or bound the run with tokens instead", ErrBudgetUnmetered, r.deps.Prices.Path)
	}
	return nil
}

// uncountedCause says why no capture runs for this run, and the fix for it.
//
// A forwarder with no models: endpoint comes before record: off: the forwarder records under record: off, so
// declaring the endpoint is the whole fix, while "set record: summary" only fixes the uprobe source, which a run
// that captures with the forwarder (every unprivileged run, tier landlock) does not have, and led to a second
// refusal. record: off is named only where the uprobe source is the run's capture: the run's capture mode is
// uprobe, or a uprobe source was handed to it.
func (r *runner) uncountedCause() (cause, fix string) {
	switch {
	case r.rt.Contract != nil && r.rt.Contract.Capture == agent.CaptureOff:
		return "the contract sets capture: off, so no model traffic is metered", "set capture: auto"
	case r.rt.Capture == agent.CaptureOff:
		return "capture is off for this run (the machine config's capture: ceiling lowers it there), so no model " +
			"traffic is metered", "raise the machine config's capture: ceiling"
	}
	for _, g := range r.deps.CaptureGaps {
		if g.Why == derive.GapNoModels {
			return "no models: endpoint is declared, so the forwarder capture does not run and no model traffic is metered",
				"declare the model endpoint under models: (provider, host, port)"
		}
	}
	if r.rt.Record == agent.RecordOff && r.uprobeCapture() {
		return "record: off, under which the uprobe capture captures nothing, so no model traffic is metered",
			"set record: summary, or capture: forwarder with a models: endpoint"
	}
	return "no capture source runs for this run, so no model traffic is metered",
		"declare the model endpoint under models: (provider, host, port)"
}

// uprobeCapture reports whether the uprobe source is this run's capture: its capture mode names it, or a source
// of that name was handed to the run.
func (r *runner) uprobeCapture() bool {
	if r.rt.Capture == agent.CaptureUprobe {
		return true
	}
	for _, s := range r.captureSources() {
		if agent.CaptureMode(s.Name()) == agent.CaptureUprobe {
			return true
		}
	}
	return false
}

// refuseUnmeteredBudget fails the run's start when it has a tokens, cost_usd or repeats budget and the capture
// mechanism that would meter it could not start: a selection gap why=mechanism-unavailable, or a capture
// source that started inert (its own mechanism-unavailable gap, or a follower no kernel record drives), and
// either nothing else captures (captureMode is off), or the table's capture is uprobe and only the forwarder
// beside the probes runs. A table whose capture is uprobe guards no models[] endpoint (agent.RuleTable.GuardedModels:
// the probes read a direct connection's TLS themselves), so with the probes not running a direct connection to the
// model is neither captured nor refused, and the forwarder meters only what the agent chooses to send it: a budget
// the agent can go around, refused as a capture that could not start (the run started with the forwarder alone,
// though GuardedModels said such a run is refused). It runs once every source has started, before
// run_start, so the run ends as a launcher failure with no agent process ever released.
//
// A budget nothing was ever going to meter is refuseUncountedBudget's when the contract declares it, and keeps its
// gap (emitBudgetUnmeteredGaps) when a machine ceiling alone imposes it: the contract's own capture: off or a
// machine ceiling of off, a forwarder with no models: endpoint, and the uprobe source under record: off, which
// captures nothing by design (it places the probes only for a stall budget's activity stamp). This refusal is for a
// mechanism the run was given and that failed at run time, and under record: off that includes a forwarder that
// could not start (every record: off run was passed over, and a failed forwarder was refused [budget-unmetered],
// told to declare the models: it declared).
func (r *runner) refuseUnmeteredBudget() error {
	budgets := meteredBudgets(r.rt)
	if len(budgets) == 0 {
		return nil
	}
	var causes []string
	so := ", so the run is refused rather than run unmetered"
	switch mode := r.captureMode(); {
	case mode == string(agent.CaptureOff):
		causes = r.unavailableCaptureCauses(r.rt.Record == agent.RecordOff)
	case mode == string(agent.CaptureForwarder) && r.rt.Capture == agent.CaptureUprobe && r.enforcesWithProbes():
		so = " on a direct connection to the model, which under uprobe capture is not refused and with no probe " +
			"running is not captured either, so the run is refused rather than run with a budget the agent can go around"
		causes = r.unavailableCaptureCauses(false)
		if len(causes) == 0 {
			causes = []string{"the uprobe capture is not running for this run"}
		}
	}
	if len(causes) == 0 {
		return nil
	}
	return fmt.Errorf("%w: the %s budget cannot be metered%s: %s. Fix: %s", ErrCaptureUnavailable,
		strings.Join(budgets, ", "), so, strings.Join(causes, "; "), captureUnavailableFix(causes))
}

// captureUnavailableFix is the fix for the mechanisms causes name: a forwarder that could not start gets its own
// (another process holding the machine config's forwarder.listen address is one cause), and a probe capture the
// ring-budget advice and the forwarder as the alternative. When the forwarder is the only cause, the probe fix is
// left out: a tier landlock run has no rings, and the contract already captures with the forwarder and declares
// models:.
func captureUnavailableFix(causes []string) string {
	isForwarder := func(c string) bool { return strings.HasPrefix(c, "the forwarder ") }
	var fixes []string
	if slices.ContainsFunc(causes, func(c string) bool { return !isForwarder(c) }) {
		fixes = append(fixes, "when the host's ring budget is spent, wait for other runs to end or raise "+
			"bpf.ring_budget in /etc/tego/config.yaml (`tego doctor` shows the rings in use); or run with "+
			"capture: forwarder and a models: endpoint")
	}
	if slices.ContainsFunc(causes, isForwarder) {
		fixes = append(fixes, "for the forwarder, free the machine config's forwarder.listen address (another "+
			"process holding it is one cause) or set forwarder.listen to a free one")
	}
	return strings.Join(append(fixes, "tego.log has the capture source's own account"), "; ")
}

// enforcesWithProbes reports whether the run's tier is one whose table relies on the uprobes for a direct connection
// to the model: an enforcing tier that runs them (cgroup, bpflsm). At tier landlock the table's capture is the
// forwarder already (agent.RuleTable.AtTier), and an --observe run refuses nothing, a direct connection to the model
// included, whatever its capture. A runner with no backend (a unit test's) is judged by its table's tier, and one
// that names none counts as such a tier.
func (r *runner) enforcesWithProbes() bool {
	tier := r.rt.Tier
	if r.deps.Enforce != nil {
		tier = r.deps.Enforce.Tier()
	}
	return tier == "" || backend.TierCgroup.AtOrBelow(tier)
}

// unavailableCaptureCauses lists why each capture mechanism this run wanted is not running: the selection's
// mechanism-unavailable gaps, and each started source that captures nothing. recordOff leaves out the uprobe
// source, which captures nothing under record: off by design: not a mechanism that failed.
func (r *runner) unavailableCaptureCauses(recordOff bool) []string {
	var out []string
	for _, g := range r.deps.CaptureGaps {
		if recordOff && agent.CaptureMode(g.Binary) == agent.CaptureUprobe {
			continue
		}
		if (g.What == "" || g.What == record.GapCapture) && g.Why == derive.GapMechanismUnavailable {
			out = append(out, fmt.Sprintf("the %s capture is not available to this run", g.Binary))
		}
	}
	driven := r.kernelRecord != nil && !kernelRecordInert(r.kernelRecord)
	for _, s := range r.captureSources() {
		if recordOff && agent.CaptureMode(s.Name()) == agent.CaptureUprobe {
			continue
		}
		_, follows := s.(source.KernelFollower)
		inert := mechanismUnavailable(s)
		if !inert && (!follows || driven) {
			continue
		}
		cause := fmt.Sprintf("the %s capture did not start", s.Name())
		if c, ok := s.(source.UnavailableCause); ok && c.UnavailableCause() != "" {
			cause += " (" + c.UnavailableCause() + ")"
		} else if !inert {
			cause += " (no kernel record reads this run)"
		}
		out = append(out, cause)
	}
	return out
}
