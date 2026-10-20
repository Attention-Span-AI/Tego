// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestBuildRemovalReleasesLinksBeforeReturn is perf-cold C3 (roadmap TEARDOWN-SYNC) against the running kernel, as
// root: every way a build is removed returns only once the kernel has torn it down. Right after the removal returns,
// none of the build's links and none of its programs is still enumerable by ID: a program goes only once each link
// over it has been released (detached from its trampoline, tracepoint or cgroup) and its pin is gone, so a program
// still there is a link whose release had not run yet. Before C3 the removal left the last reference of every link to
// the bpf filesystem's release of its pin, which the kernel does from a workqueue on 6.x and after an RCU grace
// period on RHEL 9's 5.14: `gc --builds`, the linger sweep and a reaper's ReapBuild returned while the kernel still
// released 27 to 37 trampolines, and the next run's load waited for them in bpf_trampoline_get (enforce-plane §10.1,
// gate G-H2). This test found 17 of the build's programs (43 with an LSM plane) still held on 6.17 then, and on 5.14
// every link as well.
//
// The three ways: the sweep's removal itself (pins.remove, which `gc --builds`, the linger timer and Prepare's
// sweep run), a reaper's ReapBuild with bpf.linger 0, and the last launcher out of a build that does not linger. The
// test asserts the outcome, not the kernel's path.
func TestBuildRemovalReleasesLinksBeforeReturn(t *testing.T) {
	requireRealPrepare(t)
	state := pinState(t)
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	cases := []struct {
		name   string
		linger time.Duration
		// remove removes the build after its only run has left it lingering; nil when the run's Close removes it.
		remove func(hash string, pins pinLayout) error
	}{
		{"sweep", time.Hour, func(_ string, pins pinLayout) error { return pins.remove() }},
		{"reaper", time.Hour, func(hash string, _ pinLayout) error {
			return ReapBuild(ReapTarget{Hash: hash, BPFFS: DefaultBPFFS, StateDir: state}, "", nil)
		}},
		{"last-out", 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hash := fmt.Sprintf("teardown-%s-%d", c.name, os.Getpid())
			pins, err := newPinLayout(DefaultBPFFS, hash)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = pins.remove() })
			b := New(Options{Machine: machineLinger(c.linger), BPFFS: DefaultBPFFS, StateDir: state, Hash: hash,
				Events: &sink{}, startTimer: func(string) error { return nil }})
			rel, id := runCgroup(t, "teardown-"+c.name)
			h, err := b.Prepare(context.Background(), table, Run{ID: c.name, Agent: "a", CgroupID: id, CgroupPath: rel})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			links, progs := buildObjectIDs(t, pins)
			if len(links) == 0 || len(progs) == 0 {
				_ = h.Close()
				t.Fatalf("the build pins %d links and %d programs; the test needs both", len(links), len(progs))
			}
			start := time.Now()
			if err := h.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if c.remove != nil {
				if _, err := os.Stat(pins.Root); err != nil {
					t.Fatalf("the build should linger after its run: %v", err)
				}
				start = time.Now()
				if err := c.remove(hash, pins); err != nil {
					t.Fatalf("remove: %v", err)
				}
			}
			took := time.Since(start)
			if _, err := os.Stat(pins.Root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the removal left %s (%v)", pins.Root, err)
			}
			t.Logf("removal of %d links and %d programs returned in %v", len(links), len(progs), took)
			requireReleased(t, links, progs)
		})
	}
}

// requireReleased fails the test for each of a removed build's links and programs the kernel still holds.
func requireReleased(t *testing.T, links []link.Info, progs map[string]ebpf.ProgramID) {
	t.Helper()
	var left []string
	for _, info := range links {
		if l, err := link.NewFromID(info.ID); err == nil {
			_ = l.Close()
			left = append(left, fmt.Sprintf("link %d", info.ID))
		} else if !errors.Is(err, unix.ENOENT) {
			t.Errorf("link %d: %v", info.ID, err)
		}
	}
	for name, id := range progs {
		if p, err := ebpf.NewProgramFromID(id); err == nil {
			_ = p.Close()
			left = append(left, fmt.Sprintf("program %s (%d)", name, id))
		} else if !errors.Is(err, unix.ENOENT) {
			t.Errorf("program %s (%d): %v", name, id, err)
		}
	}
	if len(left) > 0 {
		t.Errorf("the removal returned before the kernel released %d of the build's objects: %v", len(left), left)
	}
}

// buildObjectIDs reads every link and program pinned for a build, its decision planes' included, without keeping a
// reference to any of them.
func buildObjectIDs(t *testing.T, pins pinLayout) (links []link.Info, progs map[string]ebpf.ProgramID) {
	t.Helper()
	progs = map[string]ebpf.ProgramID{}
	roots := []string{pins.Root}
	for _, m := range planeModes {
		roots = append(roots, filepath.Join(pins.Base, planeDirName(filepath.Base(pins.Root), m)))
	}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, os.ErrNotExist) && path == root {
					return filepath.SkipDir
				}
				return err
			}
			if d.IsDir() {
				return nil
			}
			if l, err := link.LoadPinnedLink(path, nil); err == nil {
				info, err := l.Info()
				_ = l.Close()
				if err != nil {
					return fmt.Errorf("link %s: %w", path, err)
				}
				links = append(links, *info)
				return nil
			}
			if p, err := ebpf.LoadPinnedProgram(path, nil); err == nil {
				info, err := p.Info()
				_ = p.Close()
				if err != nil {
					return fmt.Errorf("program %s: %w", path, err)
				}
				id, ok := info.ID()
				if !ok {
					return fmt.Errorf("program %s: the kernel reports no ID", path)
				}
				progs[path] = id
			}
			return nil // a map
		})
		if err != nil {
			t.Fatalf("read the build's pins under %s: %v", root, err)
		}
	}
	return links, progs
}
