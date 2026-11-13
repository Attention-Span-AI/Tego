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

// newRuleIndexAt builds the index. Building the (dev, ino) half opens every declared path O_PATH and
// fstats it; a path that cannot be opened (missing write directory, a deny_read entry naming a file
// that was deleted) is simply absent from dirs, which costs attribution and never correctness.
func newRuleIndexAt(rt *agent.RuleTable, mountinfo string) *ruleIndex {
	mt, _, _ := agent.ReadMountSnapshot(mountinfo)
	return newRuleIndexFrom(rt, rowsFrom(mt))
}

// markedDevices is the set of super block devices the tier-2 fanotify listener marks for the deny_read entries
// the Landlock ruleset leaves unenforced (those nested in a write entry, which the listener alone refuses) and for
// the name entries' scopes: the mount each such entry or scope is on and every mount point beneath it, as
// enforce/cgroup's policy marks them at
// Prepare, which is before the recorder is built. nil when there is no such entry or no table to read, and
// then every read under one is stamped as before.
func markedDevices(rt *agent.RuleTable, mountinfo string) map[uint64]struct{} {
	return markedDevicesFrom(rt, readMounts(mountinfo))
}
