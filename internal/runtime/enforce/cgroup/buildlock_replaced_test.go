// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReplacedBuildLockPathIsAnAcceptedGap is runtime-launch.md E34: when the lock path is replaced by a new
// inode (not merely deleted) while a first-generation launcher still holds the old one, the two generations
// lock different inodes, so both are told they are the only holder and both are last out. The spec accepts this
// as operator interference, a doctor finding, not auto-healed: this pins that behaviour, so a change that
// starts to heal it (or to make it worse) is a deliberate one.
func TestReplacedBuildLockPathIsAnAcceptedGap(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	path := filepath.Join(dir, "bpf-hash.lock")
	old, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Replace, do not delete: a new file renamed over the path is a new inode at the same name.
	repl := filepath.Join(dir, "replacement")
	if err := os.WriteFile(repl, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(repl, path); err != nil {
		t.Fatal(err)
	}
	if now, err := os.Stat(path); err != nil || os.SameFile(old, now) {
		t.Fatalf("the path still names the old inode (%v): the setup did not replace it", err)
	}

	second, err := acquireBuildLock(dir, "hash")
	if err != nil {
		t.Fatalf("a launcher arriving after the replacement: %v", err)
	}
	defer second.Close()
	// The still-live first generation holds LOCK_SH on the unlinked inode, so it does not stop the second from
	// finding itself the last holder: two unsynchronized "last" launchers for one hash.
	last, err := second.lastOut()
	if err != nil || !last {
		t.Fatalf("second generation lastOut = %v, %v; E34 says it wins LOCK_EX on the new inode beside the live first", last, err)
	}
}
