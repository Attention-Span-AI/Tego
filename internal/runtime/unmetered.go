// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// meteredLane is the capture lane as a MeteredSink: what a source reports goes to the runner.
type meteredLane struct {
	source.Sink
	r *runner
}

// Unmetered hands the report to the runner.
func (m meteredLane) Unmetered(n int64, why string) { m.r.captureUnmetered(n, why) }

// Abandoned hands the step tracker the request a source gave up on.
func (m meteredLane) Abandoned(pair uint64) {
	if m.r.steps != nil {
		m.r.steps.Abandon(pair)
	}
}

// captureUnmetered ends a run with a token or cost budget at the first model exchange whose spend capture could
// not count, as captureLost does for one the queue dropped: the budget can no longer see what the run spends,
// and a budget that is silently not enforced is the failure it exists to prevent (R1).
// The run ends with reason error, the cause in run_end's detail, and the tree killed. A run with no such budget
// keeps running: its record already says what could not be read (an unparsed decision, a capture gap).
//
// A report that arrives once no process of the run can spend any more — the run's cgroup is empty, or tego's
// own teardown (the kill after a cancel, shutdown) has begun, so the report is a request that teardown aborted
// or one lost with a process that has exited — records gap what=capture why=unmetered-after-exit with its
// count, and changes neither the end reason nor the exit code: a budget can no longer be enforced on a run that
// has ended. The main process's exit alone is not that point: while a descendant that outlived it keeps the
// cgroup populated, it can still spend, and a report then fails closed as before (ADR 0037).
func (r *runner) captureUnmetered(n int64, why string) {
	lim := r.rt.Limits
	if !lim.Bounded(agent.BudgetTokens) && !lim.Bounded(agent.BudgetCostUSD) {
		return
	}
	why = strings.TrimSpace(why)
	if why == "" {
		why = "usage unreadable"
	}
	if r.quiesced.Load() {
		r.log.Warn("run: model spend uncounted after the run quiesced", "exchanges", n, "why", why)
		r.emitGap(source.Gap{What: record.GapCapture, Why: GapUnmeteredAfterExit, Count: n})
		return
	}
	detail := fmt.Sprintf("capture: %d model exchanges spent tokens no budget could count (%s); a token or cost "+
		"budget cannot be enforced", n, why)
	r.endRun(identity.ReasonError, detail, "run: model spend uncounted under a budget; ending the run",
		"run: kill after uncounted model spend", "exchanges", n, "why", why)
}
