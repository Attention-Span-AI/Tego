// SPDX-License-Identifier: Apache-2.0

package observe

import "github.com/attention-span-ai/tego/pkg/spec/agent"

// Helpers only the tests call, kept out of the package's own files so the production binary carries nothing it
// never runs.

// newRuleIndex builds the index over this process's mounts.
func newRuleIndex(rt *agent.RuleTable) *ruleIndex { return newRuleIndexAt(rt, selfMountinfo) }

// statDevIno is statEntry without the mount id.
func statDevIno(path string) (devIno, bool) {
	di, _, ok := statEntry(path)
	return di, ok
}
