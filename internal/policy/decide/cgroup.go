// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unlinkedSuffix is what the kernel's d_path appends to the path of a file unlinked since it was opened, so what a
// readlink of a fanotify event's descriptor reads for a file removed or renamed over while its open waited.
const unlinkedSuffix = " (deleted)"

// unlinkedSpelling is path without unlinkedSuffix, and whether path carried it (an absolute path remains). The
// listener decides such a path under both spellings and refuses when either refuses (ADR 0043 C0): the suffix kept a
// deny_read file renamed over or unlinked during the wait from matching its entry, and a name entry from matching
// its final name. A file whose real name ends in the suffix is decided under the shorter spelling as well, the
// stricter side.
func unlinkedSpelling(path string) (string, bool) {
	s, ok := strings.CutSuffix(path, unlinkedSuffix)
	return s, ok && strings.HasPrefix(s, "/")
}

// listenerOpenRefused is tier 2's fanotify open decision (internal/runtime/enforce/cgroup decideOpen): the
// nearest deny_read entry covering path refuses an open of it, whatever the open's mode, unless a write entry
// with a longer path covers it too. Watch and implicit entries grant nothing and reopen nothing. Like the
// listener it bounds no depth.
func listenerOpenRefused(rt *agent.RuleTable, path string) (int, bool) {
	deny, write := -1, -1
	var denySteps, writeSteps int
	for i := range rt.FS {
		k := rt.FS[i].Kind
		if k != agent.FSDenyRead && k != agent.FSWrite {
			continue
		}
		n, covered := ruleSteps(rt.FS[i], path)
		if !covered {
			continue
		}
		if k == agent.FSDenyRead && (deny < 0 || n < denySteps) {
			deny, denySteps = i, n
		}
		if k == agent.FSWrite && (write < 0 || n < writeSteps) {
			write, writeSteps = i, n
		}
	}
	if deny < 0 || (write >= 0 && writeSteps < denySteps) {
		return -1, false
	}
	return deny, true
}

// ListenerOpenRefused is tier 2's fanotify open decision on path (listenerOpenRefused): the deny_read entry
// that refuses an open of it whatever the open's access mode, read-denied, and whether one does. Evaluate's
// tier-2 write column and internal/runtime/supervisor's advisory write-open verdict both ask it, so neither
// says allow for a write-open the listener refuses (R15). A path with the unlinked suffix is decided as the
// listener decides it, under both spellings (unlinkedSpelling).
func ListenerOpenRefused(rt *agent.RuleTable, path string) (agent.FSRule, bool) {
	if rt == nil || path == "" {
		return agent.FSRule{}, false
	}
	if i, ok := listenerOpenRefused(rt, Canonical(rt, cleanPath(path))); ok {
		return rt.FS[i], true
	}
	if s, ok := unlinkedSpelling(path); ok {
		if i, ok := listenerOpenRefused(rt, Canonical(rt, cleanPath(s))); ok {
			return rt.FS[i], true
		}
	}
	return agent.FSRule{}, false
}

// ListenerOpen is tier 2's fanotify open decision (internal/runtime/enforce/cgroup decideOpen) over the
// listener's own indexes: denyRead holds the deny_read entries and readable the write entries, each under
// every spelling (agent.FSRule.Spellings) as a directory entry. A path under a deny_read entry is refused
// unless a more specific write entry names it, which is how a contract that denies a directory but names one
// file inside it keeps working. Everything else is allowed: fanotify cannot see the access mode, so it never
// guesses (enforce-cgroup-observe §5 R8). deny is the refusing entry's position in denyRead. A path read back
// with the unlinked suffix is decided under both spellings, refused when either is (unlinkedSpelling).
//
// It is listenerOpenRefused's rule, which Evaluate's tier-2 column and the supervisor's advisory write-open
// verdict ask, on an index instead of a walk of the table: the listener asks it for every open its marks
// report, and it allocates nothing. TestListenerOpenMatchesTheTableWalk holds the two to one answer.
func ListenerOpen(denyRead, readable *PathIndex, path string) (deny int, refused bool) {
	if deny, refused = listenerOpen(denyRead, readable, path); refused {
		return deny, true
	}
	if s, ok := unlinkedSpelling(path); ok {
		return listenerOpen(denyRead, readable, s)
	}
	return -1, false
}

// listenerOpen is ListenerOpen of one spelling.
func listenerOpen(denyRead, readable *PathIndex, path string) (deny int, refused bool) {
	deny, ok := denyRead.Match(path)
	if !ok {
		return -1, false
	}
	if allow, ok := readable.Match(path); ok && len(readable.Path(allow)) > len(denyRead.Path(deny)) {
		return -1, false
	}
	return deny, true
}

// ListenerOpenName is the name half of tier 2's fanotify open decision (ADR 0043 D7, the fallback): an open the
// path half (ListenerOpen) allows is refused when a name entry covers the opened file (NameIndex.Match on the
// canonical path the event's descriptor reads back, under both spellings of an unlinked file), read-denied, since
// the listener sees no access mode, named per D8. No deny_read entry is at such a path, since the path half would
// have refused it, so the entry's own rule names it. A climb that cannot decide within the walk's bound refuses
// path-unresolved, as the root model at tier cgroup refuses it (Evaluator.root). Directory opens never reach the
// listener (no FAN_ONDIR), so the object is a file. It allocates nothing.
func ListenerOpenName(n *NameIndex, path string) (rule string, reason record.Reason, refused bool) {
	if n == nil {
		return "", "", false
	}
	m, ok := n.Match(path, false)
	if !ok {
		s, unlinked := unlinkedSpelling(path)
		if !unlinked {
			return "", "", false
		}
		if m, ok = n.Match(s, false); !ok {
			return "", "", false
		}
	}
	if m.Unresolved {
		return agent.UnmatchedRule, record.ReasonPathUnresolved, true
	}
	return n.Rule(m, -1), record.ReasonReadDenied, true
}

// ListenerExec is tier 2's fanotify exec decision (internal/runtime/enforce/cgroup decideExec): a binary no
// entry of execAllow covers is refused, unless the contract has no exec: section (unrestricted,
// agent.RuleTable.ExecUnrestricted), under which it refuses none, as neither the inherited seccomp filter nor
// the Landlock ruleset does. execAllow holds each allowed exec entry under the path it was compiled to and
// that path with its symlinks followed, a directory entry as a directory. A path read back with the unlinked
// suffix is allowed only when both its spellings are (unlinkedSpelling).
func ListenerExec(unrestricted bool, execAllow *PathIndex, path string) bool {
	if unrestricted {
		return true
	}
	if _, ok := execAllow.Match(path); !ok {
		return false
	}
	if s, ok := unlinkedSpelling(path); ok {
		_, ok = execAllow.Match(s)
		return ok
	}
	return true
}
