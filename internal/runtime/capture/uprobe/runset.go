// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// RunSet is the build's run membership map as the capture source needs it: the slot its own run's cgroup row
// names, and so which capture ring is the run's (ADR 0026 (1), (3)). The pinned tego_run_set satisfies it
// (pinnedRunSet); a test supplies its own.
type RunSet interface {
	// Slot returns the run_idx and the generation of cgroupID's row, ok=false when the map holds none.
	Slot(cgroupID uint64) (slot, gen uint32, ok bool, err error)
}

// pinnedRunSet reads a build's pinned tego_run_set; it never writes a row.
type pinnedRunSet struct{ m *ebpf.Map }

// openRunSet opens a build's pinned run set read-only.
func openRunSet(pinRoot, bpfHash string) (*pinnedRunSet, error) {
	path := filepath.Join(mapDir(pinRoot, bpfHash), bpf.MapRunSet)
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("uprobe: open pinned run set %s: %w", path, err)
	}
	return &pinnedRunSet{m: m}, nil
}

// Slot looks up one cgroup's row.
func (p *pinnedRunSet) Slot(cgroupID uint64) (uint32, uint32, bool, error) {
	var row bpf.Run
	if err := p.m.Lookup(cgroupID, &row); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("uprobe: read run set row of cgroup %d: %w", cgroupID, err)
	}
	return row.RunIdx, row.Gen, true, nil
}

// Close releases the map's descriptor; the pin keeps the map itself.
func (p *pinnedRunSet) Close() error { return p.m.Close() }
