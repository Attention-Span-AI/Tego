// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
)

// TestStagePidsCapNamesTheCap is runtime-launch.md §5 case 3: a child stage that dies before its handoff
// while the run cgroup's pids.events max rose above the baseline is reported as ErrStagePidsCap, still
// wrapping ErrChildDied; a stage death with no rise, or any other error, is left as it is.
func TestStagePidsCapNamesTheCap(t *testing.T) {
	dir := t.TempDir()
	write := func(v string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "pids.events"), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &runner{cg: cgroup.Cgroup{Path: dir}}
	r.limitBase.pids, r.limitBase.ok = 2, true
	died := fmt.Errorf("%w: exit status 2", launch.ErrChildDied)

	write("max 2\n")
	if err := r.stagePidsCap(died); errors.Is(err, ErrStagePidsCap) || !errors.Is(err, launch.ErrChildDied) {
		t.Fatalf("no rise: %v", err)
	}
	write("max 3\n")
	err := r.stagePidsCap(died)
	if !errors.Is(err, ErrStagePidsCap) || !errors.Is(err, launch.ErrChildDied) {
		t.Fatalf("rise: %v; want ErrStagePidsCap wrapping ErrChildDied", err)
	}
	other := errors.New("launch: something else")
	if err := r.stagePidsCap(other); err != other {
		t.Fatalf("other error: %v", err)
	}
	r.limitBase.ok = false
	if err := r.stagePidsCap(died); errors.Is(err, ErrStagePidsCap) {
		t.Fatalf("no baseline: %v", err)
	}
}
