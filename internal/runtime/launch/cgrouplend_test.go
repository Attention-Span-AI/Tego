// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"context"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"golang.org/x/sys/unix"
)

// TestStartRefusesAClosedCgroup: Start borrows the run cgroup's directory across the clone alone (ADR 0023
// C13, T2.3), so a lender whose descriptor was closed is sys.ErrClosed before anything is cloned, where an int
// argument would have handed clone3 whatever file the number named by then; the handshake it made first is
// unwound with no descriptor left behind.
func TestStartRefusesAClosedCgroup(t *testing.T) {
	testutil.NoFDLeak(t)
	dir, err := sys.Own(unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	child, err := (&Launcher{Exe: "/bin/false", Args: []string{}}).Start(context.Background(), validSpec(), dir)
	if child != nil || !errors.Is(err, sys.ErrClosed) {
		t.Fatalf("Start with a closed cgroup = %v, %v; want sys.ErrClosed and no child", child, err)
	}
}
