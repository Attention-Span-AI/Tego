// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"path"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The names a run's cgroup is made with: run-<run id>.scope (tego run's, identity.RunScope), adopt-<run id>.scope (an
// adoption's, internal/watch/adopt.ScopeName) and the Docker cgroupfs parent tego/<agent>/<run id>
// (identity.DockerParentCgroupfs). The makers keep their own spelling; the tests hold each to these.
const (
	runPrefix    = "run-"
	adoptPrefix  = "adopt-"
	scopeSuffix  = ".scope"
	agentPrefix  = "tego-"
	sliceSuffix  = ".slice"
	cgroupfsRoot = "tego"
)

// GovernedBy is the run a cgroup path belongs to, read from the places tego makes a run's cgroup and nowhere else: a
// run-<id>.scope (tego run's) as the child of tego-<agent>.slice under tego.slice, at the cgroup2 root or in a
// user's delegated subtree (an unprivileged run's); an adopt-<id>.scope (an adoption's, which root alone makes) there
// at the cgroup2 root only; and the Docker cgroupfs parent tego/<agent>/<id> at the root; each with anything below
// it. "" when the path is in no run's cgroup. A run's name anywhere else is anyone's to make (a user can mkdir
// app.slice/run-<id>.scope or adopt-<victim's id>.scope in their own delegated subtree, and every run id is readable
// in /proc/<pid>/cgroup), so it names no run. What stays: a user can build the whole unprivileged shape in their own
// subtree, where tego's own unprivileged runs live, and so keep their own process out of the guard; the guard is no
// boundary against the user who owns the agent (ADR 0055, "The scope guard"). A refusal asks LooksGoverned instead.
func GovernedBy(cgroup string) string {
	c := strings.Split(path.Clean("/"+cgroup), "/") // c[0] is the root's empty name
	for i := 3; i < len(c); i++ {
		if c[i-2] != identity.TopSlice || !isAgentSlice(c[i-1]) {
			continue
		}
		if id, ok := scopeRunID(c[i], runPrefix); ok {
			return id
		}
		if id, ok := scopeRunID(c[i], adoptPrefix); ok && i == 3 {
			return id
		}
	}
	if len(c) >= 4 && c[1] == cgroupfsRoot && identity.RunID(c[3]).Valid() {
		return c[3]
	}
	return ""
}

// AdoptionScopeRun is the run whose adoption scope cgroup is, exactly: /tego.slice/tego-<agent>.slice/adopt-<id>.scope
// at the cgroup2 root, where root alone makes one. "" for any other path, one below the scope included.
func AdoptionScopeRun(cgroup string) string {
	c := strings.Split(path.Clean("/"+cgroup), "/")
	if len(c) != 4 || c[1] != identity.TopSlice || !isAgentSlice(c[2]) {
		return ""
	}
	id, _ := scopeRunID(c[3], adoptPrefix)
	return id
}

// isAgentSlice reports whether name is an agent's slice, tego-<agent>.slice.
func isAgentSlice(name string) bool {
	a, ok := strings.CutPrefix(name, agentPrefix)
	if !ok {
		return false
	}
	a, ok = strings.CutSuffix(a, sliceSuffix)
	return ok && a != ""
}

// scopeRunID is the run id of a scope named <prefix><id>.scope.
func scopeRunID(name, prefix string) (string, bool) {
	id, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return "", false
	}
	id, ok = strings.CutSuffix(id, scopeSuffix)
	return id, ok && identity.RunID(id).Valid()
}
