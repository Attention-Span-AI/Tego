// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type watchedOpenCount struct{ opens, sharedSkips int }

// watchedOpenCoverage checks the watched opens of one round against its counters.
func watchedOpenCoverage(runs []watchedOpenCount, fileOpenSkips uint64) error {
	var missing uint64
	for i, r := range runs {
		missing += uint64(max(concurrentE2EOpens-r.opens, 0))
		if r.opens > concurrentE2EOpens || r.opens+r.sharedSkips < concurrentE2EOpens {
			return fmt.Errorf("run %d: %d watched opens with %d shared skipped executions", i, r.opens, r.sharedSkips)
		}
	}
	if missing > fileOpenSkips {
		return fmt.Errorf("round missing %d watched opens, but its file-open program skipped only %d executions", missing, fileOpenSkips)
	}
	return nil
}

func TestWatchedOpensCannotReuseOneSharedSkip(t *testing.T) {
	runs := []watchedOpenCount{{concurrentE2EOpens - 1, 1}, {concurrentE2EOpens - 1, 1}}
	if err := watchedOpenCoverage(runs, 1); err == nil {
		t.Fatal("two missing opens spent the same single shared file-open skip twice")
	}
}

func TestWatchedOpensCannotSpendOtherHooksSkips(t *testing.T) {
	if err := watchedOpenCoverage([]watchedOpenCount{{concurrentE2EOpens - 1, 99}}, 0); err == nil {
		t.Fatal("another tracing hook's skips excused a missing file open")
	}
}

func TestWatchedOpensWithinRoundBound(t *testing.T) {
	runs := []watchedOpenCount{{concurrentE2EOpens - 1, 2}, {concurrentE2EOpens - 1, 2}}
	if err := watchedOpenCoverage(runs, 2); err != nil {
		t.Fatal(err)
	}
}

// fileOpenCounter retains the instance executing through the link for the entire round. The independent
// program pin is deliberately never consulted, even if another loader won that pin's race.
type fileOpenCounter struct {
	link    link.Link
	program *ebpf.Program
	id      ebpf.ProgramID
	path    string
	linkID  link.ID
}

func openFileOpenCounter(path string) (*fileOpenCounter, error) {
	l, err := link.LoadPinnedLink(path, nil)
	if err != nil {
		return nil, err
	}
	info, err := l.Info()
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	p, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	return &fileOpenCounter{link: l, program: p, id: info.Program, path: path, linkID: info.ID}, nil
}

func (c *fileOpenCounter) read() (uint64, error) {
	info, err := c.link.Info()
	if err != nil {
		return 0, err
	}
	pinned, err := link.LoadPinnedLink(c.path, nil)
	if err != nil {
		return 0, err
	}
	current, err := pinned.Info()
	_ = pinned.Close()
	if err != nil {
		return 0, err
	}
	if info.Program != c.id || current.Program != c.id || current.ID != c.linkID {
		return 0, fmt.Errorf("file-open link changed program instance")
	}
	st, err := c.program.Stats()
	if err != nil {
		return 0, err
	}
	return st.RecursionMisses, nil
}

func (c *fileOpenCounter) close() { _ = c.program.Close(); _ = c.link.Close() }
