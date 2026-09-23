// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// RunSet is the build's run membership map as the recorder needs it: which slot a cgroup's row names, and so
// which of the build's rings is the run's (ADR 0026 (1)). The pinned tego_run_set satisfies it (pinnedRunSet);
// a test supplies its own.
type RunSet interface {
	// Slot returns the run_idx and the generation of cgroupID's row, ok=false when the map holds none.
	Slot(cgroupID uint64) (slot, gen uint32, ok bool, err error)
}

// pinnedRunSet reads a build's pinned tego_run_set. It never writes: the rows are the tier-2 backend's and
// cgroup_track's (§3 "run_set"), and the recorder only asks for its own row's slot.
type pinnedRunSet struct{ m *ebpf.Map }

// openRunSet opens a build's pinned run set read-only.
func openRunSet(root, bpfHash string) (*pinnedRunSet, error) {
	path := pinnedMapPath(root, bpfHash, bpf.MapRunSet)
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("observe: open pinned run set %s: %w", path, err)
	}
	return &pinnedRunSet{m: m}, nil
}

// Slot looks up one cgroup's row.
func (p *pinnedRunSet) Slot(cgroupID uint64) (uint32, uint32, bool, error) {
	var row bpf.Run
	if err := p.m.Lookup(cgroupID, &row); err != nil {
		if isNotExist(err) {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("observe: read run set row of cgroup %d: %w", cgroupID, err)
	}
	return row.RunIdx, row.Gen, true, nil
}

// Close releases the map's descriptor; the pin keeps the map itself.
func (p *pinnedRunSet) Close() error { return p.m.Close() }

// isNotExist reports a lookup of a key the map does not hold.
func isNotExist(err error) bool { return errors.Is(err, ebpf.ErrKeyNotExist) }
