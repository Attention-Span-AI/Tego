// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"slices"
)

// LayerState distinguishes an empty present file from absence and from an unselected layer.
type LayerState string

// Layer states returned by complete or degraded loads. Strict failures return no Machine.
const (
	LayerPresent    LayerState = "present"
	LayerAbsent     LayerState = "absent"
	LayerUnselected LayerState = "unselected"
	LayerUnknown    LayerState = "unknown"
)

// LayerSource records exactly what was consulted. SHA256 hashes the bytes read from the trusted
// descriptor, never a reopen. It is empty for absent, unselected and unknown layers.
type LayerSource struct {
	Layer  Layer
	File   string
	State  LayerState
	SHA256 string
	Reason string // why an unknown layer could not be read; never an absence assertion
}

// LayerSources returns a copy of all three file-layer observations in merge order.
func (m *Machine) LayerSources() []LayerSource { return slices.Clone(m.sources) }

// BaselineKnown reports whether every selected layer was read successfully.
// A missing passwd home selects no user layer; only resolving a ~/ entry needs an owner home.
// A nil Machine has no known baseline. Observation callers must preserve this state in output.
func (m *Machine) BaselineKnown() bool {
	if m == nil || m.baseline.unknown {
		return false
	}
	for _, source := range m.sources {
		if source.State == LayerUnknown {
			return false
		}
	}
	return true
}

// BaselineSnapshot returns the immutable snapshot with its known state. A false known value
// must never be used to decide agent permissions, even when Entries contains some known rows.
func (m *Machine) BaselineSnapshot() (baseline Baseline, known bool) {
	if m == nil {
		return Baseline{unknown: true}, false
	}
	baseline, known = m.baseline, m.BaselineKnown()
	baseline.unknown = !known
	return baseline, known
}

// LayerBytes returns the exact bytes retained from the trusted load, never a reopen.
func (m *Machine) LayerBytes(layer Layer) []byte { return slices.Clone(m.layerBytes[layer]) }

// ReplayLayer is a recorded layer, used only to reconstruct baseline membership.
type ReplayLayer struct {
	LayerSource
	Bytes []byte
}

// ReplayBaseline parses recorded bytes without file discovery, trust checks or path resolution.
// Historical facts do not establish today's ownership or authorize any launch.
func ReplayBaseline(layers []ReplayLayer) (Baseline, error) {
	var b Baseline
	for _, l := range layers {
		if l.State != LayerPresent {
			continue
		}
		d, ds := parseLayer(l.File, l.Bytes)
		if HasErrors(ds) {
			return Baseline{}, fmt.Errorf("baseline sources %s: recorded bytes do not parse", l.File)
		}
		b = (merger{file: l.File, layer: l.Layer}).baseline(b, d.baseline)
	}
	return b, nil
}
