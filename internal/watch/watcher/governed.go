// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// governance reads what a process's environment and cgroup say about whether a tego run holds it. It is governed
// when its cgroup is a run's (runscope.GovernedBy: read only where tego makes a run's cgroup, since a name of that kind
// anywhere else is anyone's to make). A cgroup path is the kernel's account of where a process is; unlike an
// environment variable it is not inherited by accident, and a process cannot move itself out of a cgroup it cannot
// write. The environment alone is a claim any child of a governed process inherits, so it is reported (RunID) and
// never believed: an agent whose environment names a run but whose cgroup does not is outside, and the note says why.
//
// envRun was read from another process's environment, so it is reported only when it is a run id: a Tego identifier
// that passed validation is printed, and any other value is never echoed, in the note or in a field (envRunID;
// pkg/spec/identity envtext.go, rules (a) to (c)).
func governance(envRun, cgroup string) (outside bool, cgRun, note string) {
	cgRun = runscope.GovernedBy(cgroup)
	switch {
	case cgRun != "":
		return false, cgRun, ""
	case envRunID(envRun) != "":
		return true, "", "TEGO_RUN_ID names " + envRun + ", but the process is in no run's cgroup: it was moved out, or its run has ended"
	case envRun != "":
		return true, "", "TEGO_RUN_ID is set to a value that is not a run id (not shown), and the process is in no run's cgroup"
	}
	return true, "", ""
}

// envRunID is the TEGO_RUN_ID read from a process's environment when it is a run id, and "" when it is anything else:
// a sighting carries a validated identifier and no other value from another process's environment.
func envRunID(v string) string {
	if !identity.RunID(v).Valid() {
		return ""
	}
	return v
}
