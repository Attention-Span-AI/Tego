// SPDX-License-Identifier: Apache-2.0

//go:build integration

package doctor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
)

// TestIntegrationKnownAnswerChildIsSeenThroughProcRoot: the known answers' child makes its mount namespace (the tmpfs
// at x holding xf/run and its links, the tmpfs at dr/m) on the thread its main is locked to, and doctor holds those
// paths through /proc/<pid>/root, which shows the thread-group leader's namespace. When the scheduler had moved the
// child's main goroutine off the leader before it locked, the leader's view had no tmpfs at x, doctor's hold of x/xd
// failed ENOENT, and the plane mode was not offered: TestPlaneExecCommandRulesEndToEnd failed once that way in the 7.0
// guest's cgroup-1 shard (acceptance 2C, 2026-11-11). The child's main is now kept on the leader (onLeader), and a
// child on another thread refuses to start rather than answer from a namespace doctor cannot see. Each try starts the
// child beside busy loops and finds its files through /proc/<pid>/root.
func TestIntegrationKnownAnswerChildIsSeenThroughProcRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the known answers' child makes a mount namespace and mounts a tmpfs, as root (CAP_SYS_ADMIN)")
	}
	ctx, cancel := context.WithCancel(t.Context())
	var busy sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		busy.Go(func() {
			for ctx.Err() == nil {
			}
		})
	}
	defer busy.Wait()
	defer cancel()
	const tries = 20
	for i := range tries {
		dir := filepath.Join(t.TempDir(), "k")
		if err := makePlaneKnownFixtures(dir); err != nil {
			t.Fatal(err)
		}
		child, err := startPlaneChildAs(nil, planeKnownRole, dir, -1)
		if err != nil {
			t.Fatalf("try %d: %v", i, err)
		}
		root := filepath.Join("/proc", strconv.Itoa(child.cmd.Process.Pid), "root")
		for _, p := range []string{"x/xd/img", "x/xf/run", "x/xf/alias", "dr/m/f"} {
			if _, err := os.Stat(root + filepath.Join(dir, p)); err != nil {
				child.stop()
				t.Fatalf("try %d: doctor does not see the child's %s: %v", i, p, err)
			}
		}
		child.stop()
	}
}
