// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// codeRootRun is the bracketed code of a live change refused because the run was launched as root (ADR 0042: a run
// launched with sudo keeps its folder root's until it ends, so the agent, which runs as the person, cannot reach the
// chain or the live files) and the person asking is not root.
const codeRootRun = "root-run"

// runDirOwner is the uid that owns a run's folder, and false when it cannot be told (a seam of the tests: a test
// cannot make a root-owned folder).
var runDirOwner = func(dir string) (int, bool) {
	st, err := os.Stat(dir)
	if err != nil {
		return 0, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(sys.Uid), true
}

// callerIsRoot is whether this process runs as root (a seam of the tests).
var callerIsRoot = func() bool { return os.Geteuid() == 0 }

// liveRunFailed writes the refusal of a command that found it could not open a live run's own files (its lock, its
// live-block file) and returns the exit code. When the run's folder is root's and the caller is not, the run was
// launched with sudo: the person is told so and what to do, exit 1 with [root-run] (a refusal, not an I/O failure),
// and nothing about the run is guessed from the error text. Any other failure keeps the words and the exit it had.
func liveRunFailed(name, dir string, err error, stderr io.Writer) int {
	if errors.Is(err, fs.ErrPermission) && !callerIsRoot() {
		if uid, ok := runDirOwner(dir); ok && uid == 0 {
			message(stderr, "", 0, 0, "tego "+name+": run "+filepath.Base(dir)+" was launched as root (with sudo), so its "+
				"folder is root's until the run ends and only root can change it while it runs; repeat this command as root "+
				"(with sudo), from a terminal outside any run", codeRootRun)
			return identity.ExitFinding
		}
	}
	message(stderr, "", 0, 0, "tego "+name+": "+err.Error(), codeIO)
	return identity.ExitError
}
