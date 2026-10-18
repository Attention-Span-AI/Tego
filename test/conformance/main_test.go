// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"os"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestMain fails the binary when the conformance runs touched the invoking user's real ~/.tego or
// ~/.bash_history (testutil.GuardedMain, tools/isocheck GO-4): they run the tegotesthooks binary, which keeps
// its chain anchor and own log out of the real home only when the harness's environment names where.
//
// The runs' runtime directories go to a private XDG_RUNTIME_DIR the binaries inherit (testutil.PrivateRuntimeDir):
// under the developer's /run/user/<uid> each run made $XDG_RUNTIME_DIR/tego and swept the directories of their runs
// whose launcher is gone (identity-config.md R27 clause b4).
//
// A process started with mountnsEnv is the mount namespace helper of a fixture with mounts (mountns_test.go), not a
// test run.
func TestMain(m *testing.M) {
	if spec := os.Getenv(mountnsEnv); spec != "" {
		mountnsMain(spec)
	}
	parent, err := os.MkdirTemp("", "tego-conformance-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "temp dir: %v\n", err)
		os.Exit(1)
	}
	if err := testutil.PrivateRuntimeDir(parent); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	code := testutil.GuardedMain(m)
	_ = os.RemoveAll(parent)
	os.Exit(code)
}
