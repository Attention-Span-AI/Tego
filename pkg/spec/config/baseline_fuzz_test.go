// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// FuzzBaselineConfig checks independent input completeness, parser determinism, line diagnostics, monotonic union, exact
// deduplication, provenance and immutable snapshots. It never calls Baseline.Resolve.
func FuzzBaselineConfig(f *testing.F) {
	if d, ds := parseLayer("seed.yaml", []byte("baseline: {env: {deny: [TOKEN]}}")); HasErrors(ds) || len(d.baseline) != 1 {
		f.Fatalf("positive seed rejected: %v", ds)
	}
	for _, s := range []string{"baseline: {}", "baseline: {exec: {deny: [KEEP_ME, !!str DROP_ME]}}", "baseline: null", "baseline: {fs: {deny_read: [~/secret, /srv/x]}, exec: {deny: ['git push']}, env: {deny: [TOKEN]}}", "baseline: {exec: {deny: [a, a]}}", "baseline: {fs: {deny_reed: [/x]}}", "baseline: {fs: {<<: {deny_read: []}}}", "baseline: {env: {deny: [null]}}", "baseline: {}\nbaseline: {}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxLayerSize {
			return
		}
		d, ds := parseLayer("fuzz.yaml", data)
		d2, ds2 := parseLayer("fuzz.yaml", data)
		if !reflect.DeepEqual(d, d2) || !reflect.DeepEqual(ds, ds2) {
			t.Fatal("nondeterministic parse")
		}
		for _, dg := range ds {
			if dg.File != "fuzz.yaml" || dg.Line < 0 || dg.Line > yamlLines(data)+1 || dg.Code == "" {
				t.Fatalf("invalid diagnostic: %+v", dg)
			}
		}
		if HasErrors(ds) {
			return
		}
		if err := checkBaselineInputEntries(data, d.baseline); err != nil {
			t.Fatal(err)
		}
		b := Baseline{entries: []BaselineEntry{{BaselineDenyEnv, "SENTINEL", []Provenance{{"system.yaml", 1, LayerEtc}}}}}
		saved := b.Entries()
		g := merger{file: "fuzz.yaml", layer: LayerUser}
		union := g.baseline(b, d.baseline)
		if !reflect.DeepEqual(saved, b.Entries()) {
			t.Fatal("merge changed earlier snapshot")
		}
		if !reflect.DeepEqual(union.Entries(), g.baseline(union, d.baseline).Entries()) {
			t.Fatal("union not idempotent")
		}
		seen := map[struct {
			key   BaselineKey
			value string
		}]bool{}
		for _, entry := range union.Entries() {
			id := struct {
				key   BaselineKey
				value string
			}{entry.Key, entry.Value}
			if seen[id] || len(entry.Sources) == 0 {
				t.Fatal("lost source or duplicate entry")
			}
			seen[id] = true
		}
		if !seen[struct {
			key   BaselineKey
			value string
		}{BaselineDenyEnv, "SENTINEL"}] {
			t.Fatal("union lost prior refusal")
		}
	})
}

// checkBaselineInputEntries decodes into Go containers independently of the production node
// walker. Counting each (key, value) occurrence detects losses even when merge deduplicates it.
func checkBaselineInputEntries(data []byte, parsed []baselineValue) error {
	var input struct {
		Baseline map[string]map[string][]string `yaml:"baseline"`
	}
	if err := yaml.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("independent baseline decode of accepted input: %w", err)
	}
	type identity struct {
		key   BaselineKey
		value string
	}
	want := make(map[identity]int)
	count := 0
	for section, lists := range input.Baseline {
		for list, entries := range lists {
			for _, entry := range entries {
				want[identity{BaselineKey(section + "." + list), entry}]++
				count++
			}
		}
	}
	if len(parsed) != count {
		return fmt.Errorf("accepted baseline dropped entries: parsed %d, input contains %d", len(parsed), count)
	}
	for _, entry := range parsed {
		id := identity{entry.key, entry.value}
		if want[id] == 0 {
			return fmt.Errorf("accepted baseline changed entry %s %q", entry.key, entry.value)
		}
		want[id]--
	}
	return nil
}

func TestBaselineFuzzOracleDetectsDroppedEntry(t *testing.T) {
	data := []byte("baseline: {fs: {deny_read: [/a]}, exec: {deny: [same, same]}, env: {deny: [TOKEN]}}")
	d, ds := parseLayer("oracle.yaml", data)
	if HasErrors(ds) {
		t.Fatal(ds)
	}
	if err := checkBaselineInputEntries(data, d.baseline); err != nil {
		t.Fatal(err)
	}
	if err := checkBaselineInputEntries(data, d.baseline[1:]); err == nil {
		t.Fatal("independent oracle accepted a silently dropped entry")
	}
	changed := append([]baselineValue(nil), d.baseline...)
	changed[0] = changed[1]
	if err := checkBaselineInputEntries(data, changed); err == nil {
		t.Fatal("independent oracle accepted an equal-count changed multiset")
	}
}
