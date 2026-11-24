// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

type baselineValue struct {
	key   BaselineKey
	value string
	line  int
}

// MaxBaselineEntries bounds all declared list items in one layer, including repeated values.
// Alongside MaxLayerSize it bounds parse, provenance and union work for every config load.
const MaxBaselineEntries = 100_000

var baselineEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EnvEntryName is the variable an environment entry names, for a message: the text before its first "=" (the whole
// entry when it has none), when that text is a variable name. ok is false when it is not: the entry's name cannot
// be told from its value, so the message calls it by its position and echoes nothing of it. It restates
// pkg/spec/identity's EnvEntryName, which this leaf package may not import (the depguard rule in .golangci.yml);
// internal/adapters' TestEnvEntryNameParity holds the two to the same answers.
func EnvEntryName(entry string) (name string, ok bool) {
	name, _, _ = strings.Cut(entry, "=")
	if !baselineEnvName.MatchString(name) {
		return "", false
	}
	return name, true
}

func (p *parser) baseline(d *layerData, n *yaml.Node) {
	count := 0
	for _, section := range p.baselineMapping(n) {
		switch section.name {
		case "fs", "exec", "env":
			for _, list := range p.baselineMapping(section.value) {
				key := BaselineKey(section.name + "." + list.name)
				switch key {
				case BaselineDenyRead, BaselineDenyWrite, BaselineDenyExec, BaselineDenyEnv:
					if list.value.Kind == yaml.SequenceNode {
						count += len(list.value.Content)
						if count > MaxBaselineEntries {
							p.errorf(list.value, "baseline: exceeds the limit of %d entries per layer across all lists; reduce the baseline entries", MaxBaselineEntries)
							return
						}
					}
					p.baselineList(d, key, list.value)
				default:
					p.errorf(list.key, "unknown key baseline.%s", key)
				}
			}
		default:
			p.errorf(section.key, "unknown key baseline.%s", section.name)
		}
	}
}

func (p *parser) baselineList(d *layerData, key BaselineKey, n *yaml.Node) {
	if n.Kind != yaml.SequenceNode || n.Tag != "!!seq" {
		p.errorf(n, "baseline.%s: expected a list, null is not allowed", key)
		return
	}
	for _, item := range n.Content {
		v := item.Value
		if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || strings.TrimSpace(v) == "" || !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			p.errorf(item, "baseline.%s: expected a nonempty UTF-8 string, null is not allowed", key)
			continue
		}
		switch key {
		case BaselineDenyRead, BaselineDenyWrite:
			if (!filepath.IsAbs(v) && !strings.HasPrefix(v, "~/")) || strings.ContainsAny(v, "*?[") {
				p.errorf(item, "baseline.%s: %q must be a literal absolute or ~/ path, without patterns", key, v)
				continue
			}
		case BaselineDenyEnv:
			if !baselineEnvName.MatchString(v) {
				// The name alone, and only when it is one: any other text may be a value put where a name belongs,
				// and the diagnostic's position says which entry it is (EnvEntryName).
				if name, ok := EnvEntryName(v); ok {
					p.errorf(item, "baseline.%s: entry for variable %q is not an environment variable name; supply only the name (value hidden)", key, name)
				} else {
					p.errorf(item, "baseline.%s: this entry is not an environment variable name (the entry is not shown)", key)
				}
				continue
			}
		case BaselineDenyExec:
			// Command patterns are the compiler's to interpret when baselines are applied (slice 3); any
			// nonempty string is kept here.
		}
		d.baseline = append(d.baseline, baselineValue{key: key, value: v, line: item.Line})
	}
}

func (p *parser) baselineMapping(n *yaml.Node) []keyed {
	if n.Kind != yaml.MappingNode || n.Tag != "!!map" {
		p.errorf(n, "baseline: expected a mapping")
		return nil
	}
	var out []keyed
	for _, kv := range p.mapping(n) {
		if kv.key.Kind != yaml.ScalarNode || kv.key.Tag != "!!str" {
			p.errorf(kv.key, "baseline: expected a string key")
			continue
		}
		out = append(out, kv)
	}
	return out
}
