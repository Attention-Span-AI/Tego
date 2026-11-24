// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// codeRootRun is the bracketed code of a live change refused because the run was launched as root (ADR 0042: a run
// launched with sudo keeps its folder root's until it ends, so the agent, which runs as the person, cannot reach the
// chain or the live files) and the person asking is not root.
const codeRootRun = "root-run"

// liveRunFailed writes the refusal of a command that found it could not open a live run's own files (its lock, its
// live-block file) and returns the exit code. When the run's folder is root's and the caller is not, the run was
// launched with sudo: the person is told so and what to do, exit 1 with [root-run] (a refusal, not an I/O failure),
// and nothing about the run is guessed from the error text. Any other failure keeps the words and the exit it had.
func liveRunFailed(name, dir string, err error, stderr io.Writer) int {
	if runlock.RootOwned(dir, err) {
		message(stderr, "", 0, 0, "tego "+name+": run "+filepath.Base(dir)+" was launched as root (with sudo), so its "+
			"folder is root's until the run ends and only root can change it while it runs; repeat this command as root "+
			"(with sudo), from a terminal outside any run", codeRootRun)
		return identity.ExitFinding
	}
	message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
	return identity.ExitError
}
