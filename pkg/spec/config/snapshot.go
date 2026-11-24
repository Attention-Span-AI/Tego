// SPDX-License-Identifier: Apache-2.0

package config

import "slices"

// Snapshot preserves the private baseline and layer facts when an offline
// checker transfers a selected machine context to a process with no config I/O.
// It is a value transport, not evidence that its sender is trusted.
type Snapshot struct {
	Machine         Machine
	Sources         []LayerSource
	Entries         []BaselineEntry
	Unknown         bool
	LayerBytes      map[Layer][]byte
	LayerIdentities [3]layerIdentity
}

// Snapshot returns the complete selected context, including observation failures.
func (m *Machine) Snapshot() Snapshot {
	return Snapshot{Machine: *m, Sources: m.LayerSources(), Entries: m.baseline.Entries(), Unknown: m.baseline.unknown, LayerBytes: cloneLayerBytes(m.layerBytes), LayerIdentities: m.layerIdentities}
}

// Restore reconstructs a context without re-reading any layer or path.
func (s Snapshot) Restore() *Machine {
	m := s.Machine
	m.sources = slices.Clone(s.Sources)
	m.layerBytes = cloneLayerBytes(s.LayerBytes)
	m.layerIdentities = s.LayerIdentities
	m.baseline = Baseline{entries: s.Entries, unknown: s.Unknown}
	m.baseline.entries = m.baseline.Entries()
	return &m
}

func cloneLayerBytes(src map[Layer][]byte) map[Layer][]byte {
	if src == nil {
		return nil
	}
	out := make(map[Layer][]byte, len(src))
	for layer, data := range src {
		out[layer] = slices.Clone(data)
	}
	return out
}
