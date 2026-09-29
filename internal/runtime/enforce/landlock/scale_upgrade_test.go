// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPrepareOverManyExecBinaries is docs/p0/enforce-landlock.md E22 for exec.allow: thousands of
// individually listed binaries build in one Prepare that holds one fd each, finishes far inside a bound a
// quadratic build would miss, and stays cancellable through the ctxCheckEvery tick. The deny_read half of
// E22 is TestOutermostScalesLinearly.
//
// Spec: docs/p0/enforce-landlock.md E22.
func TestPrepareOverManyExecBinaries(t *testing.T) {
	const n = 3000
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Cur < n+uint64(openFDs(t))+256 {
		t.Skipf("RLIMIT_NOFILE soft limit %d too low for %d held fds", lim.Cur, n)
	}
	root := tempDir(t)
	rt := &agent.RuleTable{Contract: contractWith(true, false)}
	for i := 0; i < n; i++ {
		p := filepath.Join(root, "bin"+strconv.Itoa(i))
		staticELF(t, p)
		rt.Exec = append(rt.Exec, agent.ExecRule{Path: p, Basename: filepath.Base(p), Source: agent.ExecSourceCommand})
	}
	before := openFDs(t)
	start := time.Now()
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatalf("Prepare over %d binaries: %v", n, err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("Prepare over %d binaries took %v: not linear", n, took)
	}
	held := 0
	for _, p := range h.fds.open {
		if strings.HasPrefix(p.Path, root) {
			held++
		}
	}
	if held != n {
		t.Errorf("held %d of %d exec entries", held, n)
	}
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak: %d -> %d", before, after)
	}
	// Cancellable: the context is live at the first check and cancelled at the next tick, well before the end.
	ctx := &cancelAfterFirstCheck{Context: context.Background()}
	h2, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(ctx, rt, Run{})
	if !errors.Is(err, context.Canceled) || h2 != nil {
		t.Errorf("cancel mid-table: handle %v, error %v", h2, err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak after cancel: %d -> %d", before, after)
	}
}

// TestBinaryUpgradeMidRunLeavesTheLiveHandleAlone is docs/p0/enforce-landlock.md E24: an exec.allow binary
// replaced by rename-install (VERSIONING.md) while a run is live leaves that run's Handle holding the
// inode it opened, and a Prepare after the upgrade builds independently and holds the new file.
//
// Spec: docs/p0/enforce-landlock.md E24.
func TestBinaryUpgradeMidRunLeavesTheLiveHandleAlone(t *testing.T) {
	root := tempDir(t)
	bin := filepath.Join(root, "tool")
	staticELF(t, bin)
	rt := &agent.RuleTable{
		Contract: contractWith(true, false),
		Exec:     []agent.ExecRule{{Path: bin, Basename: "tool", Source: agent.ExecSourceCommand}},
	}
	old, _ := prepare(t, 7, rt)
	oldEnt, ok := old.entry(bin)
	if !ok {
		t.Fatal("no entry for the binary before the upgrade")
	}
	var oldSt unix.Stat_t
	if err := unix.Stat(bin, &oldSt); err != nil {
		t.Fatal(err)
	}

	next := bin + ".new"
	staticELF(t, next)
	if err := os.Rename(next, bin); err != nil {
		t.Fatal(err)
	}
	var newSt unix.Stat_t
	if err := unix.Stat(bin, &newSt); err != nil {
		t.Fatal(err)
	}
	if newSt.Ino == oldSt.Ino {
		t.Skip("filesystem reused the inode number; cannot tell the two binaries apart")
	}

	// The live handle still names the inode it opened.
	var heldSt unix.Stat_t
	if err := unix.Fstat(oldEnt.FD, &heldSt); err != nil {
		t.Fatalf("live handle's fd after upgrade: %v", err)
	}
	if heldSt.Ino != oldSt.Ino {
		t.Errorf("live handle now holds inode %d, opened %d", heldSt.Ino, oldSt.Ino)
	}
	if _, isLL := old.LandlockRuleset(); !isLL {
		t.Error("live handle lost its ruleset")
	}

	// A run after the upgrade builds on its own and holds the new file.
	fresh, _ := prepare(t, 7, rt)
	freshEnt, ok := fresh.entry(bin)
	if !ok {
		t.Fatal("no entry for the binary after the upgrade")
	}
	var freshSt unix.Stat_t
	if err := unix.Fstat(freshEnt.FD, &freshSt); err != nil {
		t.Fatal(err)
	}
	if freshSt.Ino != newSt.Ino {
		t.Errorf("new run holds inode %d, want the upgraded %d", freshSt.Ino, newSt.Ino)
	}
	if freshEnt.FD == oldEnt.FD {
		t.Error("the two handles share a descriptor")
	}
	if err := old.Close(); err != nil {
		t.Errorf("closing the live handle after the upgrade: %v", err)
	}
	if err := unix.Fstat(freshEnt.FD, &freshSt); err != nil {
		t.Errorf("closing the old handle disturbed the new one: %v", err)
	}
}
