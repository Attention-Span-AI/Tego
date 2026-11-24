// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"fmt"
	"slices"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// learnWithheld joins history only to an exact refused connect, or a refused UDP send (GAPS C172: it names the same
// endpoint a connect would). A sparse refused line has no protocol, so cannot establish this match (ADR 0016).
func (b *builder) learnWithheld(e *record.Event, p *payload) string {
	if op := opOf(e, p); e.Kind != record.KindNet || (op != "connect" && op != record.NetOpSend) || e.Rule != "unmatched" || e.Reason != "net-not-allowed" {
		return ""
	}
	if b.learned == nil {
		return ""
	}
	endpoint, ok := record.LearnEndpoint(p.Proto + "://" + p.Dst)
	if !ok {
		return ""
	}
	if _, found := slices.BinarySearch(b.learned.Withheld, endpoint); !found {
		return ""
	}
	return b.learned.Run
}

// LearnWords is the sentence beside a refused destination on the terminal and
// Receipt tab. History is an editable contract claim, never proof of a leak or
// of why this run's mechanism refused the destination.
func (rc *Receipt) LearnWords(r Refusal) string {
	if r.LearnWithheldRun == "" {
		return ""
	}
	return fmt.Sprintf("This run's contract says tego learn withheld this destination after a secret read next to a send in run %s; only if you know it is the agent's own service, allow it for the next run with `tego rule %s %d --allow`.", r.LearnWithheldRun, rc.Run, r.Seq)
}
