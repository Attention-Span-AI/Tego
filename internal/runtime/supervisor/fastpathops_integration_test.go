// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// modeBenchOps is a target that times one kind of notified fs syscall (helperOp) in a tree of a project's
// usual depth, under the record: full filter, which notifies read-opens and mode changes too.
const (
	modeBenchOps = "bench-ops"
	helperOp     = "TEGO_SUPERVISOR_OP"
)

// fastPathOps are the common fs cases a run's agent makes, each timed over the real ioctl round trip: a
// read-open and a write-open of an existing file in the write entry, an O_CREAT open, a mkdir of a directory
// that exists (the original fast-path figure), a truncate, an fchmodat, and a read-open reached through a
// symlink the contract does not declare, which is the one the walk must follow.
var fastPathOps = []string{"read_open", "write_open", "create_open", "mkdir", "truncate", "fchmodat", "read_open_via_symlink"}

// fastPathTree makes the tree targetOpLoop works in under the harness's directory.
func fastPathTree(t testing.TB, dir string) {
	deep := filepath.Join(dir, "src", "pkg", "internal", "module")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "file.go"), []byte("package module\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "src"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
}

// targetOpLoop times helperOp's syscall, helperLoops times over.
func targetOpLoop() (int, int64) {
	n, err := strconv.Atoi(os.Getenv(helperLoops))
	if err != nil || n <= 0 {
		return 0, 0
	}
	dir := os.Getenv(helperDir)
	deep := filepath.Join(dir, "src", "pkg", "internal", "module")
	file := filepath.Join(deep, "file.go")
	open := func(p string, flags int) {
		if fd, err := unix.Openat(unix.AT_FDCWD, p, flags|unix.O_CLOEXEC, 0o644); err == nil {
			_ = unix.Close(fd)
		}
	}
	var op func()
	switch os.Getenv(helperOp) {
	case "read_open":
		op = func() { open(file, unix.O_RDONLY) }
	case "read_open_via_symlink":
		p := filepath.Join(dir, "alias", "pkg", "internal", "module", "file.go")
		op = func() { open(p, unix.O_RDONLY) }
	case "write_open":
		op = func() { open(file, unix.O_WRONLY) }
	case "create_open":
		op = func() { open(filepath.Join(deep, "new.go"), unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC) }
	case "mkdir":
		op = func() { _ = unix.Mkdirat(unix.AT_FDCWD, deep, 0o755) }
	case "truncate":
		op = func() { _ = unix.Truncate(file, 0) }
	case "fchmodat":
		op = func() { _ = unix.Fchmodat(unix.AT_FDCWD, file, 0o644, 0) }
	default:
		return 0, 0
	}
	slow := injectedSlowdown()
	start := time.Now()
	for i := 0; i < n; i++ {
		if slow > 0 {
			spin(slow)
		}
		op()
	}
	return n, time.Since(start).Nanoseconds()
}

// TestIntegrationFastPathOps is TestIntegrationFastPath for each common fs case: the round trip the agent sees
// per notified syscall, logged per case as the best of three runs (a loaded box's stalls are not the path's cost)
// and held to the soft ceiling, or to noiseFactor ping-pongs measured in the same run when the box is loaded.
func TestIntegrationFastPathOps(t *testing.T) {
	const ops, attempts = 2000, 3
	for _, op := range fastPathOps {
		t.Run(op, func(t *testing.T) {
			best := time.Duration(1<<63 - 1)
			ceiling, gauge := SoftCeiling, new(noiseGauge)
			for i := 0; i < attempts && best > ceiling; i++ {
				h := startHarnessWith(t, harnessOpts{
					loops:   ops,
					mode:    modeBenchOps,
					env:     []string{helperOp + "=" + op},
					prepare: func(dir string) { fastPathTree(t, dir) },
				})
				m := h.stop(t)
				if h.report.LoopOps != ops {
					t.Fatalf("the target reported %d operations, want %d", h.report.LoopOps, ops)
				}
				if m.Notifications < ops {
					t.Errorf("%d notifications for %d notified calls", m.Notifications, ops)
				}
				best = min(best, time.Duration(h.report.LoopNS/int64(ops)))
				if best > ceiling {
					ceiling = max(ceiling, gauge.ceiling(t))
				}
			}
			t.Logf("FASTPATH %s: %v per notification (best of %d runs of %d)", op, best, attempts, ops)
			if best > ceiling {
				t.Errorf("round trip %v exceeds the ceiling %v", best, ceiling)
			}
		})
	}
}
