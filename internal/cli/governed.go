// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/attention-span-ai/tego/internal/runscope"
)

// codeGoverned is the diagnostic of a change refused because the caller sits inside a run.
const codeGoverned = "governed"

// selfInRun is runscope.InRun: whether this process sits inside a run's cgroup, or looks it, or cannot tell (it
// fails closed). Tests replace it.
var selfInRun = runscope.InRun

// selfRun is the run this process is inside, read strictly: runscope.GovernedBy of the one cgroup v2 path
// /proc/self/cgroup names (runscope.Unified). "" with no error when the path names no run (it may still look like
// one, which selfInRun reports). Tests replace it.
var selfRun = func() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	cg, err := runscope.Unified(b)
	if err != nil {
		return "", err
	}
	return runscope.GovernedBy(cg), nil
}

// refuseGoverned is the governed-agent refusal of the commands that would widen a run's governance: tego
// unblock, pause and resume, and a tego rule write that is not a narrowing. A process inside a run is that run's agent
// or one of its children, and an agent cannot lift what governs it, nor what governs another run, as the dashboard
// refuses the same change from a connection made inside a run (internal/control/web governed.go) and ask.sock refuses
// an answer from one (internal/platform/peer). It writes the refusal and reports true when the caller is inside a run.
// What it does not stop: a same-user process outside every run, which can write the files itself
// (docs/adr/0123-dashboard-threat-model.md).
func refuseGoverned(name string, stderr io.Writer) bool {
	in, err := selfInRun()
	if !in {
		return false
	}
	why := "this process is inside a tego run's cgroup"
	if err != nil {
		why = "this process cannot be shown to be outside every tego run (" + err.Error() + ")"
	}
	// The target may be the caller's own run or another (pause and unblock name any run), so the words cover both.
	message(stderr, "", 0, 0, fmt.Sprintf("tego %s: a governed agent cannot change its own governance, nor another run's: %s; "+
		"run it from a terminal outside any tego run", name, why), codeGoverned)
	return true
}

// refuseCrossRun is the governed-agent refusal of a narrowing aimed at another run: tego block from inside a
// run. A block only takes away, so an agent may still narrow its own run; on another run it could starve that run's
// agent (block sh, or the agent's own program) while the record showed the block as placed from a terminal. It writes
// the refusal and reports true unless the caller is outside every run or target is the caller's own run. It fails
// closed: a caller whose own run cannot be named (selfInRun's error, an unreadable cgroup file, a path that only
// looks like a run's) is refused whatever the target.
func refuseCrossRun(name, target string, stderr io.Writer) bool {
	in, err := selfInRun()
	if !in {
		return false
	}
	own := ""
	if err == nil {
		own, err = selfRun()
	}
	if err == nil && own != "" && own == target {
		return false
	}
	var why string
	switch {
	case err != nil:
		why = "this process's own run cannot be named: " + err.Error()
	case own == "":
		why = "this process looks inside a tego run, but its cgroup names none, so its own run cannot be named"
	default:
		why = fmt.Sprintf("this process is inside run %s, and the change names run %s", own, target)
	}
	message(stderr, "", 0, 0, fmt.Sprintf("tego %s: a process inside a tego run cannot change another run's governance (%s); "+
		"run it from a terminal outside any tego run", name, why), codeGoverned)
	return true
}
