// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// codeUndumpable is the bracketed code of a secret-holding command that could not make its process undumpable.
const codeUndumpable = "undumpable"

// makeUndumpable is the one place this package sets PR_SET_DUMPABLE 0 on its own process (ADR 0126, "Amendment
// 2026-11-21: the secret-holding launcher is not dumpable"). A variable so a test can record when it is called and
// what it was called before, and fail it; TestMain gives every other test of this package a no-op, since the test
// binary is one process that runs every command in turn and would stay undumpable for the tests that follow.
var makeUndumpable = sys.MakeUndumpable

// holdSecrets is the first thing a command that holds a secret does (Command.HoldsSecrets), before its flags are read,
// its config is loaded or anything it could take a secret from is opened. It makes this process undumpable, so that
// no other process of this user reads its memory (/proc/<pid>/mem, process_vm_readv, ptrace) or its descriptors and
// environment (/proc/<pid>/fd, environ), and returns the exit code and false when it could not: the command does not
// run, since it would take the secret into a memory another process of the same user can read.
func holdSecrets(display string, stderr io.Writer) (code int, ok bool) {
	if err := makeUndumpable(); err != nil {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: this process could not be made undumpable, and it holds secrets (%v); "+
			"it did not start", display, err), codeUndumpable)
		return identity.ExitError, false
	}
	return identity.ExitOK, true
}

// selfCgroup is this process's /proc/self/cgroup; a variable so a test can describe a process inside a run.
var selfCgroup = func() ([]byte, error) { return os.ReadFile("/proc/self/cgroup") }

// refuseNestedRun is the refusal of a command that starts a run (Command.Supervises: run, watch, adopt), made before the
// hold and before anything else, when this process's cgroup path shows a run (runscope.LooksGoverned: the path the
// governed-agent guard of every other command reads). A run cannot start inside a run: the kernel allows one seccomp
// listener per filter chain, so the nested launcher can never install its own. It would also hold itself undumpable
// first, as every command that holds secrets does, and the outer run's supervisor, which reads the descriptors and the
// working directory of the process whose syscall it decides, cannot read those of an undumpable process of its run and
// refuses its file operations fail-closed (EACCES, GAPS C44): the nested launcher then died at its first open with
// "permission denied", and the person read that instead of why. The exit stays 125, nothing is held, loaded or started,
// and the outer run is not touched. A read that fails or a path that shows no run lets the command go on to its own
// refusals. It reports whether it refused.
func refuseNestedRun(display string, stderr io.Writer) bool {
	b, err := selfCgroup()
	if err != nil {
		return false
	}
	cg, err := runscope.Unified(b)
	if err != nil || !runscope.LooksGoverned(cg) {
		return false
	}
	outer := "a tego run"
	if id := runIDOfPath(cg); id != "" {
		outer = "run " + record.Printable(id)
	}
	message(stderr, "", 0, 0, "tego "+display+": this process is inside "+outer+" (its cgroup shows a run): a run cannot start inside a run, "+
		"so nothing was started and "+outer+" is untouched; run it from a terminal outside any tego run", codeGoverned)
	return true
}

// runIDOfPath is the run id of the first run-<id>.scope or adopt-<id>.scope segment of a cgroup path, "" when none names
// a valid one.
func runIDOfPath(cg string) string {
	for _, seg := range strings.Split(cg, "/") {
		for _, prefix := range []string{"run-", "adopt-"} {
			if id, ok := strings.CutPrefix(seg, prefix); ok {
				if id, ok = strings.CutSuffix(id, ".scope"); ok && ledger.IsRunID(id) {
					return id
				}
			}
		}
	}
	return ""
}
