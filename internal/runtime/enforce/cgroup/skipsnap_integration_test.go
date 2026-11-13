// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// skipSnapshot is every host-wide link's program skip counter (recursion_misses) under the tego pin root, keyed
// <pin dir>/links/<name>: the build's tracking and recording links and each plane directory's links. A run's own
// cgroup links (links/run-<id>/) are cgroup programs, which the kernel never skips, and are not read.
func skipSnapshot(t *testing.T) map[string]uint64 {
	t.Helper()
	out := map[string]uint64{}
	root := filepath.Join(DefaultBPFFS, pinRoot)
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Logf("skip snapshot: %v", err)
		return out
	}
	for _, d := range dirs {
		links := filepath.Join(root, d.Name(), pinLinks)
		entries, err := os.ReadDir(links)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			l, err := link.LoadPinnedLink(filepath.Join(links, e.Name()), nil)
			if err != nil {
				t.Logf("skip snapshot: %s: %v", e.Name(), err)
				continue
			}
			info, err := l.Info()
			if err == nil {
				var p *ebpf.Program
				if p, err = ebpf.NewProgramFromID(info.Program); err == nil {
					var st *ebpf.ProgramStats
					if st, err = p.Stats(); err == nil {
						out[filepath.Join(d.Name(), e.Name())] = st.RecursionMisses
					}
					_ = p.Close()
				}
			}
			_ = l.Close()
			if err != nil {
				t.Logf("skip snapshot: %s: %v", e.Name(), err)
			}
		}
	}
	return out
}

// logSkipDelta logs each counter that moved between two snapshots, and every counter's name once.
func logSkipDelta(t *testing.T, label string, before, after map[string]uint64) {
	t.Helper()
	names := make([]string, 0, len(after))
	for name := range after {
		names = append(names, name)
	}
	slices.Sort(names)
	moved := 0
	for _, name := range names {
		b, seen := before[name]
		if !seen {
			t.Logf("%s: SKIPS %s new link, %d", label, name, after[name])
			continue
		}
		if after[name] != b {
			moved++
			t.Logf("%s: SKIPS %s %d -> %d (+%d)", label, name, b, after[name], after[name]-b)
		}
	}
	t.Logf("%s: SKIPS %d of %d host-wide link programs moved", label, moved, len(names))
}
