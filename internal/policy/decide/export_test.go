// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// NewFSMatch is FSIndex.NewFSMatch's answer asked of rt by scan (FSDecider), the tests' oracle for the index; rt nil
// leaves Read and Write unset.
func NewFSMatch(rt *agent.RuleTable, path, name string, entry *agent.FSRule) FSMatch {
	m := FSMatch{Rule: name, Entry: entry, Watched: entry.Kind == agent.FSWatch, Path: path}
	if rt != nil {
		if r, ok := FSDecider(rt, path, true); ok {
			m.Read = r
			m.DenyRead = r.Kind == agent.FSDenyRead
		}
		if w, ok := FSDecider(rt, path, false); ok {
			m.Write = w
		}
	}
	return m
}

// Unenforced is R4 on the strings compile used: the deny_read target lies at or below one of writes, the
// write and ask entries and the exec.allow directories, each at its resolved path (an ancestor of the target
// lies below a write entry iff the target does, so checking the target covers every enumerated level, and
// E26's degenerate equal-path case).
func Unenforced(target string, writes []string) bool {
	return fsplan.FirstCover(target, writes) >= 0
}

// RenameGains is REFER's no-gain rule on a rename by scan with the table's exec grants (RenameGainedBy's doc is the
// contract, ReferRefuses its verdict), the tests' oracle for the index.
func RenameGains(rt *agent.RuleTable, src, dst string, dir bool) bool {
	return ReferRefuses(RenameGained(rt, src, dst), dir)
}

// RenameGained is RenameGainedBy (whose doc is the contract) with the table's exec grants.
func RenameGained(rt *agent.RuleTable, src, dst string) agent.AccessSet {
	return RenameGainedBy(rt, src, dst, nil)
}

// LinkGains is LinkGainsBy (whose doc is the contract) with the table's exec grants.
func LinkGains(rt *agent.RuleTable, src, dst string) bool {
	return LinkGainsBy(rt, src, dst, nil)
}
