// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/watch/sig"
)

// Proc is the /proc the watcher reads. *proc.FS gives most of it; FS adds the two files it does not read, and the
// tests give a map. Every read may fail for a process that has already exited, which the watcher expects:
// proc.ErrGone (or any error) means "skip it", never "stop".
type Proc interface {
	PIDs() ([]int, error)
	Stat(pid int) (proc.Stat, error)
	Exe(pid int) (string, error)
	Argv(pid int) ([]string, error)
	Cgroup(pid int) (string, error)
	// ExeFile is the identity of the file /proc/<pid>/exe opens; the zero FileID with a nil error when unknown.
	ExeFile(pid int) (sig.FileID, error)
	// RunID is TEGO_RUN_ID from the process's initial environment, "" when it has none or cannot be read.
	RunID(pid int) (string, error)
	// Tasks is /proc/<pid>/task as a Proc of its own, with the thread ids it lists: a read through it by a thread id
	// reaches that thread of process pid or nothing, since the kernel looks a task up there only within pid's
	// thread group. A process whose leader exited while its threads run is read through it (Watcher.facts).
	Tasks(pid int) (Proc, []int, error)
}

// maxEnviron caps how much of /proc/<pid>/environ the watcher reads to find one variable.
const maxEnviron = 4 << 20

// FS is the system's /proc as a Proc.
type FS struct {
	*proc.FS
	root string
}

// NewFS reads the proc filesystem mounted at root ("/proc" when empty).
func NewFS(root string) *FS {
	if root == "" {
		root = proc.DefaultRoot
	}
	return &FS{FS: proc.NewAt(root), root: root}
}

// ExeFile stats /proc/<pid>/exe, which follows the link to the file itself.
func (f *FS) ExeFile(pid int) (sig.FileID, error) {
	fi, err := os.Stat(filepath.Join(f.root, strconv.Itoa(pid), "exe"))
	if err != nil {
		return sig.FileID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return sig.FileID{}, nil
	}
	return sig.FileID{Dev: uint64(st.Dev), Ino: st.Ino}, nil
}

// Tasks lists /proc/<pid>/task and reads it as a Proc.
func (f *FS) Tasks(pid int) (Proc, []int, error) {
	tids, err := f.FS.Tasks(pid)
	if err != nil {
		return nil, nil, err
	}
	return NewFS(filepath.Join(f.root, strconv.Itoa(pid), "task")), tids, nil
}

// RunID reads the process's environment for TEGO_RUN_ID. The file is the environment the process started with
// (a later setenv does not change it), which is what an agent launched by tego inherited.
func (f *FS) RunID(pid int) (string, error) {
	file, err := os.Open(filepath.Join(f.root, strconv.Itoa(pid), "environ"))
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	b, err := io.ReadAll(io.LimitReader(file, maxEnviron))
	if err != nil {
		return "", err
	}
	return runIDFromEnviron(b), nil
}

// runIDFromEnviron finds TEGO_RUN_ID in a NUL-separated environment block.
func runIDFromEnviron(env []byte) string {
	const key = "TEGO_RUN_ID="
	for _, kv := range bytes.Split(env, []byte{0}) {
		if bytes.HasPrefix(kv, []byte(key)) {
			return string(kv[len(key):])
		}
	}
	return ""
}
