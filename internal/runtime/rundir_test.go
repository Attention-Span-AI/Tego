// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// ownerUID is the uid that owns the directory, ok false when it cannot be read.
// Production scope decisions use lstat and preserve its error.
func (d runDir) ownerUID() (int, bool) {
	st, err := d.lstat()
	if err != nil {
		return 0, false
	}
	return int(st.Uid), true
}

// TestRunDirLooksUpUnderTheLentDirectory: a sweep hook is lent the run's directory (ledger.WithSweepHook), and the
// orphan checks it runs read that directory, never what its path names by then. The run is moved away after the
// directory was opened and a decoy put at its path: an empty directory with a FIFO for a lock. Through the lent
// directory the checks read the moved run (its run_start's cgroup id, its identity, its free lock); by path they
// read the decoy. No descriptor outlives the checks (ADR 0023 A8).
func TestRunDirLooksUpUnderTheLentDirectory(t *testing.T) {
	testutil.NoFDLeak(t)
	const id = "r-00000000-000000000000a-lent00"
	root := t.TempDir()
	lostRunIn(t, root, id, 77)
	path := filepath.Join(root, id)
	at, err := sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = at.Close() }()
	moved := path + ".held"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(path, ledger.LockFile), 0o600); err != nil {
		t.Fatal(err)
	}
	lent, byPath := runDir{path: path, at: at}, pathDir(path)

	if got := runCgroupID(lent); got != 77 {
		t.Errorf("run_start's cgroup id through the lent directory = %d, want 77", got)
	}
	if got := runCgroupID(byPath); got != 0 {
		t.Errorf("run_start's cgroup id by path = %d, want the decoy's 0", got)
	}
	if !sameDirectory(moved, lent) || sameDirectory(path, lent) {
		t.Error("the lent directory must be the moved run's, not the decoy at its path")
	}
	if !sameDirectory(path, byPath) {
		t.Error("by path the directory is the decoy")
	}
	if uid, ok := lent.ownerUID(); !ok || uid != os.Getuid() {
		t.Errorf("owner through the lent directory = %d, %v", uid, ok)
	}
	if held, _, err := probeLock(lent); err != nil || held {
		t.Errorf("the moved run's lock through the lent directory: held=%v, %v; want free", held, err)
	}
	if _, _, err := probeLock(byPath); err == nil {
		t.Error("by path the probe meets the decoy's FIFO and must refuse it")
	}
	if lent.id() != id {
		t.Errorf("id = %q", lent.id())
	}
}
