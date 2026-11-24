// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// GapLedgerCeilingOvershoot is the why of the gap what=limits a run that hit record.max_run_bytes writes just
// before run_end: the ledger holds Count bytes more than the ceiling.
//
// The overshoot is recorded, not bounded. The ceiling is read before the pipeline writes a line, so every line already
// queued or in flight is written after the trip, and a bound would have to drop or hold back lines to keep it: a
// refusal or a verdict line is never dropped (the record would then show a run that did less than it did), and
// holding back the producers stalls the kernel's own waits. So the limit line says what the ledger held when it
// tripped and this gap says what it held when the pipeline drained. A reader sees the exact size the run's rule
// allowed and the exact size it reached.
const GapLedgerCeilingOvershoot = "ledger-ceiling-overshoot"

// emitLedgerOvershootGap writes the gap when the run ended on its ledger ceiling and the ledger holds more than it.
// It counts the bytes before its own line, and it is called after the pipeline's last drain: the lines it counts
// are every one written through run_start's pipeline; the gap itself, a later gap and run_end are not in the count.
func (r *runner) emitLedgerOvershootGap() {
	if r.budget == nil || r.writer == nil {
		return
	}
	b, tripped := r.budget.Tripped()
	if !tripped || b.Which != record.LimitLedgerBytes {
		return
	}
	if over := r.writer.LedgerBytes() - int64(b.Ceiling); over > 0 {
		r.emitGapNow(source.Gap{What: record.GapLimits, Why: GapLedgerCeilingOvershoot, Count: over})
	}
}
