// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strconv"
)

// LogindRuntimeRoot is where systemd-logind makes each user's XDG_RUNTIME_DIR, /run/user/<uid>.
const LogindRuntimeRoot = "/run/user"

// RuntimeDirBases is every XDG_RUNTIME_DIR under which a run of the invoking user may keep its private directory, in
// order: the user's logind directory, /run/user/<uid> (uid InvokingUID, SUDO_UID under sudo), whatever this
// process's environment says, then $XDG_RUNTIME_DIR when it is absolute and names another. agent-contract.md R10a
// keeps every write and ask entry off <base>/tego for each (agent.WithRuntimeDir at compile, the launcher's own check
// before it makes anything): a launcher whose environment lacks the variable (plain sudo resets it, cron and ssh
// without pam_systemd never set it) still protects the directory where the same user's runs from a login session keep
// theirs. Naming more bases only adds refusals.
//
// The list is kept here, in a package both binaries link, so that everything that compiles a contract or launches a
// run names the same one: tego's compile, run and rule (internal/cli), the launcher's check (internal/runtime), and
// the dashboard's rule service (internal/control/rules), which may not link internal/runtime. The service used to
// keep a copy of the launcher's list; had the two drifted, the dashboard would have refused a change tego runs, or
// written a contract the next run refuses.
func RuntimeDirBases() []string { return RuntimeDirBasesUnder(LogindRuntimeRoot) }

// RuntimeDirBasesUnder is RuntimeDirBases with logindRoot standing for LogindRuntimeRoot, so a test can keep the
// logind directories in a directory of its own (internal/runtime's fakeLogind); every product caller passes
// LogindRuntimeRoot.
func RuntimeDirBasesUnder(logindRoot string) []string {
	uid, _ := InvokingUID()
	out := []string{filepath.Join(logindRoot, strconv.Itoa(uid))}
	if x := os.Getenv("XDG_RUNTIME_DIR"); filepath.IsAbs(x) && filepath.Clean(x) != out[0] {
		out = append(out, filepath.Clean(x))
	}
	return out
}
