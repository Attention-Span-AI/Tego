// SPDX-License-Identifier: Apache-2.0

package identity

import "path/filepath"

// Path conventions (spec/identity/RUN-IDENTITY.md). These functions only format strings; creating
// the directory or cgroup is the caller's job.
const (
	// SystemCgroupRoot is the cgroup v2 mount point used by a privileged launcher or tegod.
	SystemCgroupRoot = "/sys/fs/cgroup"
	// TopSlice is the slice under which every agent slice lives.
	TopSlice = "tego.slice"
	// SystemLedgerRoot is the run directory root under tegod.
	SystemLedgerRoot = "/var/lib/tego/runs"
)

// RunDir is the run directory: <ledgerRoot>/<run id>. It must never be under a declared write directory
// (agent.Compile refuses that as a contradiction).
func RunDir(ledgerRoot string, run RunID) string {
	return filepath.Join(ledgerRoot, string(run))
}

// AgentSlice is the per-agent slice name: tego-<agent>.slice.
func AgentSlice(agent AgentID) string { return "tego-" + string(agent) + ".slice" }

// RunScope is the per-run scope name: run-<run id>.scope.
func RunScope(run RunID) string { return "run-" + string(run) + ".scope" }

// UserCgroupPath is the run cgroup of an unprivileged launcher:
// <delegated user subtree>/tego.slice/tego-<agent>.slice/run-<id>.scope.
func UserCgroupPath(delegatedSubtree string, agent AgentID, run RunID) string {
	return filepath.Join(delegatedSubtree, TopSlice, AgentSlice(agent), RunScope(run))
}

// SystemCgroupPath is the run cgroup of a privileged launcher or tegod:
// /sys/fs/cgroup/tego.slice/tego-<agent>.slice/run-<id>.scope.
func SystemCgroupPath(agent AgentID, run RunID) string {
	return UserCgroupPath(SystemCgroupRoot, agent, run)
}

// DockerParentSlice is the container parent pre-created in the daemon's manager (systemd driver):
// tego-<agent>-<slug>.slice, where slug is the run id without dashes.
func DockerParentSlice(agent AgentID, slug string) string {
	return "tego-" + string(agent) + "-" + slug + ".slice"
}

// DockerParentCgroupfs is the container parent under the cgroupfs driver: /sys/fs/cgroup/tego/<agent>/<run>.
func DockerParentCgroupfs(agent AgentID, run RunID) string {
	return filepath.Join(SystemCgroupRoot, "tego", string(agent), string(run))
}
