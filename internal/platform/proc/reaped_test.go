// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestReadAfterReapIsGone opens a child's /proc files, reaps the child, then reads them: the kernel
// fails those reads with ESRCH, and each one must come back as ErrGone like a failed open.
func TestReadAfterReapIsGone(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start sleep: %v", err)
	}
	pid := cmd.Process.Pid
	f := New()
	names := []string{"stat", "cmdline", "cgroup"}
	files := make([]*os.File, len(names))
	for i, name := range names {
		file, err := os.Open(filepath.Join(f.Root(), strconv.Itoa(pid), name))
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("open %s: %v", name, err)
		}
		defer func() { _ = file.Close() }()
		files[i] = file
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	for i, name := range names {
		_, err := f.slurp(pid, name, files[i])
		if err == nil {
			t.Skipf("%s: read after reap succeeded on this kernel", name)
		}
		if !errors.Is(err, ErrGone) {
			t.Errorf("%s: read after reap = %v, want ErrGone", name, err)
		}
	}
}
