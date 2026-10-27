// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ruleDenyReadSnapshot names a read the run's Landlock ruleset refuses because the deny_read enumeration froze at
// launch (Options.DenyReadSnapshot): the path lies beneath an ancestor of a deny_read target through a name made
// after the ruleset's one listing of that ancestor, so no rule grants it READ_FILE. The reason stays read-denied, the
// closed set's code for a read the run may not make; this rule names why.
const ruleDenyReadSnapshot = "deny-read-snapshot"

// snapshotRead is the refusal of a read-capable open the decision core allows and the run's Landlock ruleset
// refuses: this loop refuses it itself, with the EACCES the kernel would answer, so its line says refused under
// ruleDenyReadSnapshot instead of the allow the contract's paths alone give. Continued, the kernel refused it all
// the same and the line said allow (the 2026-10-25 always-on audit's 8 lines). The snapshot answers true only where
// it knows the kernel refuses (landlock.Snapshot.Refuses), so this refuses nothing the kernel would allow, and it
// never widens a deny_read: it adds a refusal and changes no allow of a path the ruleset grants. at is where the open
// lands (landed): the ruleset decides on that object's chain, not on the copied spelling.
func (l *Loop) snapshotRead(n *notif, flags int, d fsDecided, e fsEnd) fsDecided {
	if l.snapshotRefuses == nil || d.enforce || d.verdict != record.VerdictAllow || !readCapable(flags) || e.p == "" {
		return d
	}
	at := l.landed(n, e)
	if n.gone || at == "" || !l.snapshotRefuses(at) {
		return d
	}
	return fsDecided{rule: ruleDenyReadSnapshot, verdict: record.VerdictRefused, reason: record.ReasonReadDenied, enforce: true}
}

// snapshotExplains reports whether the EACCES a held read met in the kernel is the deny_read snapshot's (snapshotRead's
// question asked after the fact): the open deputy opens in the run's own domain, so its open of a name made after
// launch beside a deny_read ancestor is refused by the same ruleset, and the line names that refusal.
func (l *Loop) snapshotExplains(kind agent.ActionKind, resolved string) bool {
	return l.snapshotRefuses != nil && kind == agent.ActionFSRead && resolved != "" && l.snapshotRefuses(resolved)
}
