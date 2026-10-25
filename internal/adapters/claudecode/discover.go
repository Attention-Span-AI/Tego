// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// envReason is the variable the launcher names the run's reason file in (pkg/spec/identity EnvReason; the adapter
// may not import identity, and TestNamesMatchTheEngines keeps the two equal).
const envReason = "TEGO_REASON"

// envRuntimeDir is the variable under which an unprivileged run makes its runtime directory,
// <XDG_RUNTIME_DIR>/tego/<run> (the launcher's RuntimeDirBases).
const envRuntimeDir = "XDG_RUNTIME_DIR"

// runtimeDirName is the directory under a runtime base that holds the runs' directories (pkg/spec/agent
// RuntimeDirName, which the adapter may not import either).
const runtimeDirName = "tego"

// errReasonPath is a reason path the hook will not use.
var errReasonPath = errors.New("reason file path outside a run's runtime directory")

// target is the run the hook reports on: its reason file, the run named by the directory that holds it, and the
// directory itself, which holds hook-state/ too.
type target struct {
	reasonFile string
	run        string
	dir        string
}

// discover is the reason file the hook reads: the --reason value when one was given (set, even when empty), else
// $TEGO_REASON. Neither means the hook runs outside any tego run, and found is false: a hand install is a silent
// no-op. A path is used only when it is last-refusal.json, absolute and clean, in a directory that is a run's
// runtime directory by convention: reason.DirFor's /run/user/<uid>/tego/<run>/, or <XDG_RUNTIME_DIR>/tego/<run>/
// for the XDG_RUNTIME_DIR the hook inherited from the run, which is where a launcher whose XDG_RUNTIME_DIR names
// another directory makes it. $TEGO_REASON, which the launcher installs last and a contract cannot set (TEGO_ is
// runtime-reserved), is also taken in that shape under any base but the root, <base>/tego/<run>/: a contract whose
// env.pass leaves XDG_RUNTIME_DIR out of the agent's environment still hands the hook the launcher's own path. So is
// a --reason value that is exactly $TEGO_REASON, which is how the settings file the launcher provisions names it
// (Provision): the value is then the launcher's, whoever spelled it. The hook writes beside the file (hook-state/),
// so a path anywhere else is refused rather than written next to.
func discover(flagValue string, flagSet bool, getenv func(string) string, uid uint32) (t target, found bool, err error) {
	p := flagValue
	if !flagSet {
		if p = getenv(envReason); p == "" {
			return target{}, false, nil
		}
	}
	if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) != p || filepath.Base(p) != reason.FileName {
		return target{}, true, fmt.Errorf("%w: %q is not an absolute, clean path to %s", errReasonPath, p, reason.FileName)
	}
	dir := filepath.Dir(p)
	run := filepath.Base(dir)
	want, err := reason.DirFor(uid, run)
	if err != nil {
		return target{}, true, fmt.Errorf("%w: %q: %w", errReasonPath, p, err)
	}
	if dir+"/" == want {
		return target{reasonFile: p, run: run, dir: dir}, true, nil
	}
	if base := getenv(envRuntimeDir); filepath.IsAbs(base) && filepath.Join(filepath.Clean(base), runtimeDirName, run) == dir {
		return target{reasonFile: p, run: run, dir: dir}, true, nil
	}
	if parent := filepath.Dir(dir); (!flagSet || p == getenv(envReason)) && filepath.Base(parent) == runtimeDirName && filepath.Dir(parent) != "/" {
		return target{reasonFile: p, run: run, dir: dir}, true, nil // the launcher's own <base>/tego/<run>/
	}
	return target{}, true, fmt.Errorf("%w: %q is not in %s nor in $%s/%s/%s", errReasonPath, p, want, envRuntimeDir, runtimeDirName, run)
}
