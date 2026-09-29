// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// missingWriteTable is a table whose one write entry, dir/new, does not exist yet.
func missingWriteTable(dir string) *agent.RuleTable {
	return &agent.RuleTable{
		Contract: contractWith(true, true),
		FS:       []agent.FSRule{{Path: filepath.Join(dir, "new"), Kind: agent.FSWrite, Access: agent.AccessWriteSet, Missing: true}},
	}
}

// TestMissingWriteDirIsCreatedAsTheDroppedUser: at a root launch the child drops to the invoking user, so a
// write directory Prepare creates for the run is made with those credentials. Made as root, 0755, it refused
// the dropped agent every create in it by DAC while Landlock granted write, and the user could not remove it.
// Without Drop the directory is made by this process as before.
//
// Spec: docs/p0/enforce-landlock.md §7 (path vanished row).
func TestMissingWriteDirIsCreatedAsTheDroppedUser(t *testing.T) {
	type call struct {
		path     string
		uid, gid int
	}
	var calls []call
	orig := mkdirAs
	mkdirAs = func(path string, uid, gid int) error {
		calls = append(calls, call{path, uid, gid})
		return os.Mkdir(path, 0o755)
	}
	t.Cleanup(func() { mkdirAs = orig })

	dir := tempDir(t)
	b := New(Options{syscalls: &fakeSyscalls{abi: 7}})
	h, err := b.Prepare(context.Background(), missingWriteTable(dir), Run{Drop: true, DropUID: 4242, DropGID: 4343})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	_ = h.Close()
	if want := (call{filepath.Join(dir, "new"), 4242, 4343}); len(calls) != 1 || calls[0] != want {
		t.Fatalf("mkdirAs calls = %+v, want one %+v", calls, want)
	}

	calls = nil
	dir2 := tempDir(t)
	h, err = b.Prepare(context.Background(), missingWriteTable(dir2), Run{})
	if err != nil {
		t.Fatalf("Prepare without Drop: %v", err)
	}
	_ = h.Close()
	if len(calls) != 0 {
		t.Errorf("mkdirAs called without Drop: %+v", calls)
	}
	if fi, err := os.Stat(filepath.Join(dir2, "new")); err != nil || !fi.IsDir() {
		t.Errorf("missing write dir not created without Drop: %v", err)
	}
}

// TestRootMissingWriteDirIsTheDroppedUsers is the same with the real credential switch: root prepares a run
// that drops to nobody, and the created directory is nobody's, so the agent can create inside it.
func TestRootMissingWriteDirIsTheDroppedUsers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a directory as another uid")
	}
	const uid, gid = 65534, 65534
	// Under /tmp, not t.TempDir: every directory above the new one must be searchable by nobody, since the
	// mkdir is judged as nobody's, and the test's temporary tree is root's 0700.
	dir, err := os.MkdirTemp("/tmp", "tego-mkdirowner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	b := New(Options{syscalls: &fakeSyscalls{abi: 7}})
	h, err := b.Prepare(context.Background(), missingWriteTable(dir), Run{Drop: true, DropUID: uid, DropGID: gid})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	_ = h.Close()
	fi, err := os.Stat(filepath.Join(dir, "new"))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != uid || st.Gid != gid {
		t.Errorf("created write dir is %d:%d, want %d:%d", st.Uid, st.Gid, uid, gid)
	}
	if os.Geteuid() != 0 {
		t.Errorf("euid after Prepare = %d, want 0", os.Geteuid())
	}
}
