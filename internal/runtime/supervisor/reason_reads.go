// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// This file is ADR 0077 on this loop's side: the line of a read open the Landlock ruleset refuses.
//
// Under record: summary or off tier 1's filter tells this loop of no read open unless something in the table asks for
// it (record: full, a read gate, an fs.ask_read entry, held reads, and reason reads: agent.RuleTable.ReasonReadsAt). A
// read open it is told of at tier landlock and does not hold is answered CONTINUE (quietRead for an allowed one), and
// one beneath a deny_read the ruleset enforces is then refused EACCES by Landlock's file_open hook, which this loop's
// answer cannot change. Its line is refused read-denied under that entry (decide.AdvisoryFS, the ruleset's own model)
// with mechanism landlock, the mechanism that refuses it: written under every record mode, as every refusal is
// (emitFS), so the reason file holds it and the agent's harness learns why its read failed. The line is written before
// the kernel answers, from the path this loop read and walked; a sibling that rewrites the path between that read and
// the kernel's leaves a line naming the path this loop read (supervisor R15's caveat, which every continued fs line
// shares).

// readMechanism is the mechanism of the fs line emitFS writes: MechanismLandlock for a read open the run's Landlock
// ruleset refuses after this loop continued it (verdict refused, reason read-denied, a read open this loop did not
// refuse itself and that reaches file_open, at tier landlock), else none. An O_PATH open reaches no hook and is
// allowed (decide.AdvisoryFS); at tier cgroup the kernel recorder or the fanotify listener writes such a line (R7a);
// an --observe run refuses nothing.
func (c *compiled) readMechanism(op string, flags int, verdict record.Verdict, reason record.Reason, d fsDecided) string {
	if op != record.FSOpen || d.mknod || d.enforce || verdict != record.VerdictRefused || reason != record.ReasonReadDenied ||
		!isRead(op, flags) || flags&unix.O_PATH != 0 || c.tier() != backend.TierLandlock {
		return ""
	}
	return record.MechanismLandlock
}
