// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/compiledview"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// ShowSchema names the versioned compiled-view format under spec/contracts/v1.
const ShowSchema = "tego.contracts.show.v1"

// ErrAmbiguous is a name held by more than one catalog entry.
var ErrAmbiguous = errors.New("ambiguous contract name")

// ErrNotFound is a name or path absent from the catalog.
var ErrNotFound = errors.New("contract not found")

// Source is an extensible provenance relation, separate from a rule's identity.
// A rule may have both a contract/profile source and a machine ceiling.
type Source struct {
	Kind string `json:"kind"`
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
	Key  string `json:"key,omitempty"`
}

// Rule is one compiled rule in the existing read view's words. The full compiler
// table is also retained verbatim in Show.Table, including expanded image rules.
type Rule struct {
	Key     string   `json:"key"`
	Entry   string   `json:"entry,omitempty"`
	Words   string   `json:"words"`
	Sources []Source `json:"sources"`
}

// Show is the read-only response for one unambiguously selected file.
type Show struct {
	Schema   string `json:"schema"`
	Contract Entry  `json:"contract"`
	Rules    []Rule `json:"rules"`
	Table    string `json:"table"`
	Context  string `json:"context"`
	Footer   string `json:"footer"`
}

// Select finds a name or absolute path. A duplicate name never wins by order.
func (c Catalog) Select(name string) (*Entry, error) {
	var found *Entry
	for i := range c.Contracts {
		e := &c.Contracts[i]
		if e.Path != name && e.Name != name && !slices.Contains(e.Aliases, name) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: %q names more than one contract; give the path of the one you mean", ErrAmbiguous, name)
		}
		found = e
	}
	if found == nil {
		return nil, fmt.Errorf("%w: no contract named %q was found in these registries and runs; give its path", ErrNotFound, name)
	}
	return found, nil
}

// Describe renders the already compiled state. It never loads or compiles again.
func (c Catalog) Describe(e Entry) (Show, error) {
	if e.description != nil {
		s := *e.description
		s.Contract = e
		return s, nil
	}
	s := Show{Schema: ShowSchema, Contract: e, Rules: []Rule{}, Context: ContextNote, Footer: Footer}
	if e.table == nil {
		if e.State == "compiles" {
			return s, errors.New("compiled state was not retained; select this name or path with KeepTableFor")
		}
		return s, nil
	}
	var b bytes.Buffer
	if err := agent.PrintRuleTable(&b, e.table); err != nil {
		return s, err
	}
	s.Table = b.String()
	for _, h := range []struct {
		key, value string
		source     config.Provenance
		bounded    bool
	}{
		{"tier", string(e.table.Tier), c.machine.Tier.Source, c.machine.Tier.Bounded},
		{"capture", string(e.table.Capture), c.machine.Capture.Source, c.machine.Capture.Bounded},
		{"record", string(e.table.Record), config.Provenance{}, false},
	} {
		sources := []Source{{Kind: "built-in default", Key: h.key}}
		if p, ok := e.table.Contract.Pos(h.key); ok {
			sources = []Source{sourceAt(e.Path, h.key, p)}
		}
		if h.bounded {
			sources = append(sources, Source{Kind: "machine-config ceiling", File: h.source.File, Line: h.source.Line, Key: h.key})
		}
		s.Rules = append(s.Rules, Rule{Key: h.key, Entry: h.value, Words: h.key + " " + h.value, Sources: sources})
	}
	v := compiledview.Of(e.table, e.table.Tier, "")
	for _, r := range v.Rules() {
		source := Source{Kind: r.Source.Origin, File: r.Source.File, Line: r.Source.Line, Key: r.Key}
		if source.Kind == compiledview.OriginProfile && strings.HasPrefix(source.File, presets.PathPrefix) {
			source.Kind = "preset"
		}
		rule := Rule{Key: r.Key, Entry: r.Entry, Words: r.Sentence, Sources: []Source{source}}
		if p, ok := ceilingSource(c.machine, r.Key); ok {
			ceiling := Source{Kind: "machine-config ceiling", File: p.File, Line: p.Line, Key: r.Key}
			if source.Kind == compiledview.OriginMachine {
				rule.Sources = []Source{ceiling}
			} else {
				rule.Sources = append(rule.Sources, ceiling)
			}
		}
		s.Rules = append(s.Rules, rule)
	}
	for _, g := range v.Groups {
		if g.Default == "" {
			continue
		}
		source := Source{Kind: "built-in default"}
		key := ""
		switch g.ID {
		case compiledview.GroupPrograms:
			key = "exec"
		case compiledview.GroupNetwork:
			key = "net"
		case compiledview.GroupEnv:
			key = "env"
		case compiledview.GroupChange:
			key = "fs"
		}
		if p, ok := e.table.Contract.Pos(key); ok {
			source = Source{Kind: "contract", File: p.File, Line: p.Line, Key: key}
			if p.File != e.Path {
				source.Kind = "profile"
			}
			if strings.HasPrefix(p.File, presets.PathPrefix) {
				source.Kind = "preset"
			}
		}
		s.Rules = append(s.Rules, Rule{Key: g.ID + ".default", Words: g.Default, Sources: []Source{source}})
	}
	return s, nil
}

func sourceAt(top, key string, p agent.Pos) Source {
	s := Source{Kind: "contract", File: p.File, Line: p.Line, Key: key}
	if p.File != top {
		s.Kind = "profile"
	}
	if strings.HasPrefix(p.File, presets.PathPrefix) {
		s.Kind = "preset"
	}
	return s
}

func ceilingSource(m *config.Machine, key string) (config.Provenance, bool) {
	if m == nil {
		return config.Provenance{}, false
	}
	switch key {
	case "limits.cpu":
		return m.Limits.CPU.Source, m.Limits.CPU.Bounded
	case "limits.cpu_weight":
		return m.Limits.CPUWeight.Source, m.Limits.CPUWeight.Bounded
	case "limits.memory":
		return m.Limits.Memory.Source, m.Limits.Memory.Bounded
	case "limits.memory_high":
		return m.Limits.MemoryHigh.Source, m.Limits.MemoryHigh.Bounded
	case "limits.pids":
		return m.Limits.Pids.Source, m.Limits.Pids.Bounded
	case "limits.tokens":
		return m.Limits.Tokens.Source, m.Limits.Tokens.Bounded
	case "limits.cost_usd":
		return m.Limits.CostUSD.Source, m.Limits.CostUSD.Bounded
	case "limits.wall":
		return m.Limits.Wall.Source, m.Limits.Wall.Bounded
	case "limits.stall_after":
		return m.Limits.StallAfter.Source, m.Limits.StallAfter.Bounded
	case "limits.repeats":
		return m.Limits.Repeats.Source, m.Limits.Repeats.Bounded
	}
	return config.Provenance{}, false
}

type noDNS struct{}

func (noDNS) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("DNS deferred by the contracts view")
}
