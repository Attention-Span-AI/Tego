// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestIntegrationRootStopMarkerFollowsNoLink: `sudo tego stop` created its stop marker by path, as root, in the run
// directory of a ledger root the user owns, so a run directory the user had replaced with a link to a directory of
// root's got a root-created file there. The marker is now placed through the ledger's walk, which refuses a link in a
// directory that is not root's alone, and the link's target is left empty.
func TestIntegrationRootStopMarkerFollowsNoLink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root only: only root's walk refuses a link the directory's owner planted")
	}
	uid, gid := 65534, 65534
	if u, g, ok := agentUID(t); ok {
		uid, gid = u, g
	}
	root := filepath.Join(t.TempDir(), "runs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	victim := t.TempDir() // root's own 0700 directory
	run := filepath.Join(root, "r-00000000-000000000000a-link00")
	if err := os.Symlink(victim, run); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(run, uid, gid); err != nil {
		t.Fatal(err)
	}
	err := RequestStopGrace(run, 4*time.Second)
	if !errors.Is(err, ledger.ErrLinkRefused) {
		t.Errorf("RequestStopGrace through a linked run directory: %v, want ErrLinkRefused", err)
	}
	if entries, _ := os.ReadDir(victim); len(entries) != 0 {
		t.Fatalf("root created %v in the link's target", entries)
	}
}
