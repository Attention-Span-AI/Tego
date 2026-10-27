// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"github.com/attention-span-ai/tego/internal/runscope"
)

// governance reads what a process's environment and cgroup say about whether a tego run holds it. It is governed
// when its cgroup is a run's (runscope.GovernedBy: read only where tego makes a run's cgroup, since a name of that kind
// anywhere else is anyone's to make). A cgroup path is the kernel's account of where a process is; unlike an
// environment variable it is not inherited by accident, and a process cannot move itself out of a cgroup it cannot
// write. The environment alone is a claim any child of a governed process inherits, so it is reported (RunID) and
// never believed: an agent whose environment names a run but whose cgroup does not is outside, and the note says why.
func governance(envRun, cgroup string) (outside bool, cgRun, note string) {
	cgRun = runscope.GovernedBy(cgroup)
	switch {
	case cgRun != "":
		return false, cgRun, ""
	case envRun != "":
		return true, "", "TEGO_RUN_ID names " + envRun + ", but the process is in no run's cgroup: it was moved out, or its run has ended"
	}
	return true, "", ""
}
