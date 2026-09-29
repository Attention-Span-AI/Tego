// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ruleKeyring names a refused kernel-keyring syscall (SEMANTICS §1). It is a rule name, not a reason: the reason
// is read-denied — the keyring is a credential store the run is denied — and the specifics (which of the
// three syscalls) live in the rule and the refused op (§9, REASON-CHANNEL "the rule name carries the
// specifics").
const ruleKeyring = "keyring"

// gapWhyKeyring prefixes the why of the gap line a continued keyring syscall leaves: "keyring-" and the
// syscall's name. Record v1 has no keyring action kind (a new kind is a v: 2 bump, VERSIONING §2), so a
// gap — "the record cannot describe this as an action" — is the existing kind that makes the use visible.
const gapWhyKeyring = "keyring-"

// handleAddKey, handleRequestKey and handleKeyctl answer the three kernel-keyring syscalls (SEMANTICS §1). The
// kernel keyring is a non-namespaced, same-uid credential store — on a RHEL/IPA host its default
// KEYRING:persistent ccache holds live Kerberos tickets — that no fs or net rule can see and no P0 tier's
// hooks reach: Landlock has no keyring right, and the planned BPF-LSM hook set has no security_key_*
// hook. Left to run unseen, add_key/request_key/keyctl are a credential-exfil channel the ledger never
// records. This loop is the only place in tiers 1 and 2 that sees them (SEMANTICS §1).
func handleAddKey(l *Loop, n *notif)     { l.answerKeyring(n, "add_key") }
func handleRequestKey(l *Loop, n *notif) { l.answerKeyring(n, "request_key") }
func handleKeyctl(l *Loop, n *notif)     { l.answerKeyring(n, "keyctl") }

// answerKeyring answers one keyring syscall. By default it is refused with EPERM — Docker's and
// firejail's default seccomp profiles refuse the same three — and the refusal recorded. A contract that
// declares `keyring: true` has the syscall continued, and so does an observe run, which enforces nothing
// (R30); either way the use is recorded as gap what=record why=keyring-<syscall>, once per binary (per
// process when the binary cannot be read: gapOwner) and syscall, so a learn pass over an observe run and the record of an opted-in run both show the agent
// reached the keyring. There is no argument to read: the syscalls take scalars and key ids, not a path or
// an address this loop matches, so the answer depends on the contract alone.
func (l *Loop) answerKeyring(n *notif, op string) {
	l.answerOptIn(n, op, l.table.Load().keyringAllowed, &l.keyringSeen, gapWhyKeyring, ruleKeyring)
}

// answerOptIn is the answer the keyring and System V IPC families share: refused EPERM with a refused line
// under rule, unless the contract opted in (allowed) or the run observes, when the syscall is continued and each
// binary's (or, its binary unreadable, each process's: gapOwner) first use of each syscall leaves a gap
// what=record why=<why><op> line, remembered in seen.
func (l *Loop) answerOptIn(n *notif, op string, allowed bool, seen *topologySeen, why, rule string) {
	if allowed || l.observing() {
		binary, key := l.gapOwner(n)
		if n.gone {
			return
		}
		l.respond(n, respContinue())
		if seen.first(key + "\x00" + op) {
			gap := l.event(n, record.KindGap, record.SourceSupervisor)
			l.emitFor(n, gap, record.GapPayload{What: record.GapRecord, Why: why + op, Binary: binary, Count: 1})
		}
		return
	}
	l.respond(n, respErrno(unix.EPERM))
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = rule, record.ReasonReadDenied
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Reason: record.ReasonReadDenied, Rule: rule})
}
