// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// testRun is a well-formed run id.
const testRun = "r-0a1b2c3d-0123456789abc-xyz123"

// governedByTable is GovernedBy's table as it stood in internal/watch/adopt before the move: each
// path and the run it names, "" for none.
var governedByTable = map[string]string{
	"/tego.slice/tego-a.slice/run-" + testRun + ".scope":       testRun,
	"/tego.slice/tego-a.slice/run-" + testRun + ".scope/sub":   testRun,
	"/tego.slice/tego-a.slice/adopt-" + testRun + ".scope":     testRun,
	"/tego.slice/tego-a.slice/adopt-" + testRun + ".scope/sub": testRun,
	"/tego/a/" + testRun + "/c1":                               testRun, // a Docker run's cgroupfs parent
	// An unprivileged run, in its user's delegated subtree.
	"/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/run-" + testRun + ".scope": testRun,
	"/user.slice/user-1000.slice/session-2.scope":                                                     "",
	"/tego.slice/tego-a.slice/adopt-notarunid.scope":                                                  "",
	"/tego.slice/tego-a.slice/run-" + testRun:                                                         "",
	"": "",
	// A run's name anywhere tego does not make one is anyone's: a user's own cgroups name no run.
	"/user.slice/user-1001.slice/user@1001.service/app.slice/adopt-" + testRun + ".scope": "",
	"/user.slice/user-1000.slice/user@1000.service/app.slice/run-" + testRun + ".scope":   "",
	"/system.slice/docker.service/" + testRun + "/c1":                                     "",
	"/tego.slice/run-" + testRun + ".scope":                                               "",
	"/tego.slice/tego-.slice/run-" + testRun + ".scope":                                   "",
	"/x.slice/tego-a.slice/run-" + testRun + ".scope":                                     "",
	// An adoption is root's, at the cgroup2 root only.
	"/user.slice/user-1000.slice/user@1000.service/tego.slice/tego-a.slice/adopt-" + testRun + ".scope": "",
}

// adoptionScopeTable is AdoptionScopeRun's table as it stood in internal/watch/adopt before the move.
var adoptionScopeTable = map[string]string{
	"/tego.slice/tego-a.slice/adopt-" + testRun + ".scope":                                              testRun,
	"/tego.slice/tego-a.slice/adopt-" + testRun + ".scope/sub":                                          "",
	"/tego.slice/tego-a.slice/run-" + testRun + ".scope":                                                "",
	"/user.slice/user-1001.slice/user@1001.service/app.slice/adopt-" + testRun + ".scope":               "",
	"/user.slice/user-1001.slice/user@1001.service/tego.slice/tego-a.slice/adopt-" + testRun + ".scope": "",
}

// TestGovernedByUnchanged holds the moved GovernedBy and AdoptionScopeRun to the tables they had in
// internal/watch/adopt: the move to runscope changed no answer (ADR 0100 (7), a behaviour-identical move).
func TestGovernedByUnchanged(t *testing.T) {
	for cg, want := range governedByTable {
		if got := GovernedBy(cg); got != want {
			t.Errorf("GovernedBy(%q) = %q, want %q", cg, got, want)
		}
	}
	for cg, want := range adoptionScopeTable {
		if got := AdoptionScopeRun(cg); got != want {
			t.Errorf("AdoptionScopeRun(%q) = %q, want %q", cg, got, want)
		}
	}
}

// TestGovernedByReadsWhatTheMakersMake: the names identity makes a run's cgroup and Docker parent with are the ones
// GovernedBy reads (adopt's own ScopeName is held in internal/watch/adopt's tests).
func TestGovernedByReadsWhatTheMakersMake(t *testing.T) {
	run := identity.RunID(testRun)
	rel := func(p string) string { return strings.TrimPrefix(p, identity.SystemCgroupRoot) }
	for _, cg := range []string{
		rel(identity.SystemCgroupPath("a", run)),
		identity.UserCgroupPath("/user.slice/user-1000.slice/user@1000.service", "a", run),
		rel(identity.DockerParentCgroupfs("a", run)) + "/c1",
	} {
		if got := GovernedBy(cg); got != testRun {
			t.Errorf("GovernedBy(%q) = %q, want %q", cg, got, testRun)
		}
	}
}
