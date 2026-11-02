// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// The variables a tego binary built with -tags tegotesthooks reads to keep its chain anchor and its own log
// out of the invoking user's ~/.tego (internal/cli/anchor_testhook.go, ownlog_testhook.go). They are spelled
// here because this package imports nothing of the tree's; tools/isocheck holds both spellings to each other.
const (
	envTestChainAnchor = "TEGO_TEST_CHAIN_ANCHOR"
	envTestOwnLogHome  = "TEGO_TEST_OWN_LOG_HOME"
)

// OwnStateDir is the directory under dir that TegoEnv keeps tego's own files in: the chain anchor
// (OwnStateDir/chain.log) and the own-log home (OwnStateDir/home). It is a directory of its own, never dir
// itself: tego refuses a run whose write entry lies inside the directory of its chain anchor ("lies inside tego's
// own directory"), and a test's project usually lives under the same temporary directory.
func OwnStateDir(dir string) string { return filepath.Join(dir, "tego-own") }

// TegoEnv is the environment for a tego binary built with -tags tegotesthooks that a test starts as a
// subprocess: os.Environ(), then the chain anchor OwnStateDir(dir)/chain.log, an own-log home OwnStateDir(dir)/home
// (made) and XDG_RUNTIME_DIR=OwnStateDir(dir)/run (made, mode 0700), then extra. The isolation variables come after
// the inherited environment, so a developer's own TEGO_TEST_* or XDG_RUNTIME_DIR never wins (a run under theirs
// made /run/user/<uid>/tego and swept their crashed runs' directories there: identity-config.md R27 clause b4), and
// before extra, so a test can still point one elsewhere on purpose.
//
// Call it where the command's Env is built, after every t.Setenv the test makes: an os.Environ() read earlier
// holds none of them. A test build that finds the anchor variable unset refuses to run or verify anything
// rather than append to the real ~/.tego/chain.log, so a test that forgets this fails instead of polluting.
func TegoEnv(t testing.TB, dir string, extra ...string) []string {
	t.Helper()
	state := OwnStateDir(dir)
	home, run := filepath.Join(state, "home"), filepath.Join(state, "run")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("testutil.TegoEnv: %v", err)
	}
	if err := privateDir(run); err != nil {
		t.Fatalf("testutil.TegoEnv: %v", err)
	}
	env := append(os.Environ(), envTestChainAnchor+"="+filepath.Join(state, "chain.log"), envTestOwnLogHome+"="+home,
		envXDGRuntimeDir+"="+run)
	return append(env, extra...)
}

// envXDGRuntimeDir is the variable under which a run makes its runtime directory, <XDG_RUNTIME_DIR>/tego/<run id>.
const envXDGRuntimeDir = "XDG_RUNTIME_DIR"

// PrivateRuntimeDir points this process's XDG_RUNTIME_DIR at parent/run, made with mode 0700, so the runs its tests
// start in-process, and the tego subprocesses they start with its environment, make their runtime directories, and
// sweep, there and never in the developer's /run/user/<uid>/tego (identity-config.md R27 clause b4). Every
// TestMain of a package whose tests start a run calls it with the package's own temporary parent before the tests
// run; GuardRealTego still watches the developer's parents, read from the environment the binary started with.
//
// As root it removes the variable and makes nothing: a root launcher makes no runtime directory, and a directory
// of root's would refuse the launches those tests make as the invoking user (the cross-owner and sudo cases), which
// then make none, as they do in the KVM guests, whose environment has no XDG_RUNTIME_DIR.
func PrivateRuntimeDir(parent string) error { return privateRuntimeDir(parent, os.Geteuid()) }

// privateRuntimeDir is PrivateRuntimeDir for the given effective uid.
func privateRuntimeDir(parent string, euid int) error {
	if euid == 0 {
		return os.Unsetenv(envXDGRuntimeDir)
	}
	dir := filepath.Join(parent, "run")
	if err := privateDir(dir); err != nil {
		return fmt.Errorf("testutil: private XDG_RUNTIME_DIR: %w", err)
	}
	return os.Setenv(envXDGRuntimeDir, dir)
}

// privateDir makes dir with mode 0700 whatever the umask or an earlier mode: tego makes its directory only under
// an XDG_RUNTIME_DIR no group or other user can write.
func privateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}
