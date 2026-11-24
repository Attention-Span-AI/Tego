// SPDX-License-Identifier: Apache-2.0

package config

import "slices"

// BaselineKey names one of ADR 0144's four additive lists.
type BaselineKey string

// The only baseline keys. Enforcement consumers materialize their immutable union (ADR 0144).
const (
	BaselineDenyRead  BaselineKey = "fs.deny_read"
	BaselineDenyWrite BaselineKey = "fs.deny_write"
	BaselineDenyExec  BaselineKey = "exec.deny"
	BaselineDenyEnv   BaselineKey = "env.deny"
)

var baselineKeys = [...]BaselineKey{BaselineDenyRead, BaselineDenyWrite, BaselineDenyExec, BaselineDenyEnv}

// BaselineEntry is a declared spelling and every contributing source, including repeated entries
// on different lines. Sources describe membership, never a winning override.
type BaselineEntry struct {
	Key     BaselineKey
	Value   string
	Sources []Provenance
}

// Baseline is an immutable union. Its zero value is the empty built-in baseline.
// Accessors return deep copies; merging allocates new storage, including for source lists.
// Paths remain unexpanded until an explicit agent owner context is supplied to Resolve.
type Baseline struct {
	entries []BaselineEntry
	unknown bool
}

// Entries returns entries grouped in schema order, retaining first occurrence order within each key.
func (b Baseline) Entries() []BaselineEntry {
	out := slices.Clone(b.entries)
	for i := range out {
		out[i].Sources = slices.Clone(out[i].Sources)
	}
	return out
}

// Empty reports a known baseline with no entries. An unknown baseline is never empty.
func (b Baseline) Empty() bool { return !b.unknown && len(b.entries) == 0 }

func (g merger) baseline(b Baseline, d []baselineValue) Baseline {
	entries := b.Entries()
	type identity struct {
		key   BaselineKey
		value string
	}
	positions := make(map[identity]int, len(entries))
	for i, e := range entries {
		positions[identity{e.Key, e.Value}] = i
	}
	// Build a source set only when an entry repeats. Each source is indexed once,
	// including those from earlier layers, instead of scanning a growing list.
	sources := make(map[int]map[Provenance]struct{})
	for _, v := range d {
		id, source := identity{v.key, v.value}, g.prov(v.line)
		if i, ok := positions[id]; ok {
			seen := sources[i]
			if seen == nil {
				seen = make(map[Provenance]struct{}, len(entries[i].Sources)+1)
				for _, existing := range entries[i].Sources {
					seen[existing] = struct{}{}
				}
				sources[i] = seen
			}
			if _, present := seen[source]; !present {
				entries[i].Sources = append(entries[i].Sources, source)
				seen[source] = struct{}{}
			}
		} else {
			positions[id] = len(entries)
			entries = append(entries, BaselineEntry{Key: v.key, Value: v.value, Sources: []Provenance{source}})
		}
	}
	var ordered []BaselineEntry
	for _, key := range baselineKeys {
		for _, e := range entries {
			if e.Key == key {
				ordered = append(ordered, e)
			}
		}
	}
	return Baseline{entries: ordered, unknown: b.unknown}
}
