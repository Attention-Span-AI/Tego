// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// loadsAsItself reports whether b, a reloaded copy of a's Canonical, is a: every exported field equal, the
// schema-only nodes included. Positions, the file name and the profile list are not part of a contract's value, and
// neither is a nil list or map against an empty one: R2 reads an explicit empty value as absent, and the empty
// lists whose emptiness means something (deny_read, env.pass, exec's mode, net's admission lists) Canonical writes
// as `[]` and their own tests pin. A pointer to an empty section is not nil (`exec: {}` restricts every image).
func loadsAsItself(a, b *Contract) bool {
	x, y := reflect.ValueOf(*a), reflect.ValueOf(*b)
	for i := range x.NumField() {
		if x.Type().Field(i).IsExported() && !equalUpToEmpty(x.Field(i), y.Field(i)) {
			return false
		}
	}
	return true
}

// equalUpToEmpty is reflect.DeepEqual with a nil slice or map equal to an empty one. A struct with an unexported
// field is compared whole by DeepEqual.
func equalUpToEmpty(x, y reflect.Value) bool {
	switch x.Kind() {
	case reflect.Slice, reflect.Map:
		if x.Len() == 0 && y.Len() == 0 {
			return true
		}
		if x.Len() != y.Len() {
			return false
		}
		if x.Kind() == reflect.Map {
			for it := x.MapRange(); it.Next(); {
				e := y.MapIndex(it.Key())
				if !e.IsValid() || !equalUpToEmpty(it.Value(), e) {
					return false
				}
			}
			return true
		}
		fallthrough
	case reflect.Array:
		for i := range x.Len() {
			if !equalUpToEmpty(x.Index(i), y.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Pointer, reflect.Interface:
		if x.IsNil() || y.IsNil() {
			return x.IsNil() == y.IsNil()
		}
		return equalUpToEmpty(x.Elem(), y.Elem())
	case reflect.Struct:
		for i := range x.NumField() {
			if !x.Type().Field(i).IsExported() {
				return reflect.DeepEqual(x.Interface(), y.Interface())
			}
		}
		for i := range x.NumField() {
			if !equalUpToEmpty(x.Field(i), y.Field(i)) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(x.Interface(), y.Interface())
}

// canonicalRoundTrip loads src, writes its Canonical, loads that back and checks R13 on it: the copy loads, is the
// contract it was written from, compiles to the same gate, and writes the same bytes again.
func canonicalRoundTrip(t *testing.T, src string) (*Contract, []byte) {
	t.Helper()
	c, ds, err := LoadBytes("a.yaml", []byte(src), nil)
	if err != nil {
		t.Fatalf("does not load: %v\n%s", err, render(ds))
	}
	out, err := c.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	back, ds, err := LoadBytes("contract.yaml", out, nil)
	if err != nil {
		t.Fatalf("Canonical's copy does not load back: %v\n%s\n%s", err, render(ds), out)
	}
	if !loadsAsItself(c, back) {
		t.Errorf("Canonical's copy loads back as another contract:\n%s", out)
	}
	g1, e1 := CompileGateConfig(c)
	g2, e2 := CompileGateConfig(back)
	if (e1 == nil) != (e2 == nil) || !reflect.DeepEqual(g1, g2) {
		t.Errorf("the copy compiles to another gate: %+v (%v), the source to %+v (%v)\n%s", g2, e2, g1, e1, out)
	}
	again, err := back.Canonical()
	if err != nil || !bytes.Equal(out, again) {
		t.Errorf("Canonical is not a fixed point (%v):\n%s\n---\n%s", err, out, again)
	}
	return c, out
}

// TestCanonicalExpandsAliasesInSchemaOnlyNodes pins R13 for a YAML alias in gate:, ask: or docker:, the fields Load
// keeps as YAML nodes. Load cleared each anchor there but kept the alias, so Canonical wrote `- *r` with no `&r`:
// the run's contract.yaml did not load back ("unknown anchor 'r' referenced"). Each such contract now writes
// exactly what the same contract with every alias written out writes, so its contract_hash is that contract's,
// and the copy loads back as the contract it came from. An alias whose anchor sits in a typed field (limits,
// command, reason) is expanded the same way.
func TestCanonicalExpandsAliasesInSchemaOnlyNodes(t *testing.T) {
	const head = "version: 0\nname: a\n"
	for name, tc := range map[string]struct{ alias, written string }{
		"review: a repeated rule": {
			`command: [x]` + "\n" + `gate: {rules: [&r {"exec matches a": 10}, *r]}`,
			`command: [x]` + "\n" + `gate: {rules: [{"exec matches a": 10}, {"exec matches a": 10}]}`,
		},
		"a score anchored in limits": {
			`command: [x]` + "\n" + `limits: {pids: &s 10}` + "\n" + `gate: {rules: [{"exec matches a": *s}]}`,
			`command: [x]` + "\n" + `limits: {pids: 10}` + "\n" + `gate: {rules: [{"exec matches a": 10}]}`,
		},
		"thresholds anchored in the gate": {
			`command: [x]` + "\n" + `gate: {thresholds: &t {allow: 40, ask: 90}, rules: [{"exec matches a": 50}], completion: held}` + "\n" +
				`reason: {reads: auto}`,
			`command: [x]` + "\n" + `gate: {thresholds: {allow: 40, ask: 90}, rules: [{"exec matches a": 50}], completion: held}` + "\n" +
				`reason: {reads: auto}`,
		},
		"an alias of an alias": {
			`command: [x]` + "\n" + `limits: {pids: &n 10}` + "\n" + `gate: {rules: [&o {"exec matches a": *n}, *o]}`,
			`command: [x]` + "\n" + `limits: {pids: 10}` + "\n" + `gate: {rules: [{"exec matches a": 10}, {"exec matches a": 10}]}`,
		},
		"the rule list itself": {
			`command: [x]` + "\n" + `gate: {rules: &l [{"exec matches a": 10}, {"exec matches b": 20}]}` + "\n" +
				`mcp: [{name: m, command: [srv]}]`,
			`command: [x]` + "\n" + `gate: {rules: [{"exec matches a": 10}, {"exec matches b": 20}]}` + "\n" +
				`mcp: [{name: m, command: [srv]}]`,
		},
		"an ask timeout anchored in command": {
			`command: [&t 5s]` + "\n" + `ask: {timeout: *t}`,
			`command: [5s]` + "\n" + `ask: {timeout: 5s}`,
		},
		"a whole gate aliasing an empty mapping": {
			`command: [x]` + "\n" + `reason: &e {}` + "\n" + `gate: *e`,
			`command: [x]` + "\n" + `reason: {}` + "\n" + `gate: {}`,
		},
		"an empty docker aliasing an empty mapping": {
			`command: [x]` + "\n" + `reason: &e {}` + "\n" + `docker: *e`,
			`command: [x]` + "\n" + `reason: {}`,
		},
		"beside a block-lossy string": {
			`command: ["\tx\n"]` + "\n" + `gate: {rules: [&r {"exec matches a": 10}, *r]}`,
			`command: ["\tx\n"]` + "\n" + `gate: {rules: [{"exec matches a": 10}, {"exec matches a": 10}]}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, out := canonicalRoundTrip(t, head+tc.alias+"\n")
			if bytes.ContainsAny(out, "*&") {
				t.Errorf("Canonical still writes an alias or an anchor:\n%s", out)
			}
			_, want := canonicalRoundTrip(t, head+tc.written+"\n")
			if !bytes.Equal(out, want) {
				t.Errorf("the aliased contract writes\n%s\nthe written-out one\n%s", out, want)
			}
		})
	}
}

// TestCanonicalAliasedGatesHashApart is the review's collision: the two contracts' third rule is an alias of a
// different rule, so their gates score `exec matches a` and `exec matches b` differently, and gate scores add up.
// With the alias kept and its anchor cleared, both wrote the same canonical bytes and the same contract_hash.
func TestCanonicalAliasedGatesHashApart(t *testing.T) {
	const head = "version: 0\nname: a\ncommand: [x]\n"
	a, outA := canonicalRoundTrip(t, head+`gate: {rules: [&r {"exec matches a": 10}, {"exec matches b": 90}, *r]}`+"\n")
	b, outB := canonicalRoundTrip(t, head+`gate: {rules: [{"exec matches a": 10}, &r {"exec matches b": 90}, *r]}`+"\n")
	ga, ea := CompileGateConfig(a)
	gb, eb := CompileGateConfig(b)
	if ea != nil || eb != nil {
		t.Fatalf("CompileGateConfig: %v, %v", ea, eb)
	}
	if reflect.DeepEqual(ga, gb) {
		t.Fatal("the two gates compile alike; the test proves nothing")
	}
	if bytes.Equal(outA, outB) {
		t.Fatalf("two contracts whose gates differ write the same canonical bytes:\n%s", outA)
	}
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	if ha == hb {
		t.Fatal("two contracts whose gates differ share a contract_hash")
	}
	if !strings.Contains(string(outA), "- exec matches a: 10\n    - exec matches b: 90\n    - exec matches a: 10\n") ||
		!strings.Contains(string(outB), "- exec matches a: 10\n    - exec matches b: 90\n    - exec matches b: 90\n") {
		t.Errorf("the third rule is not written out as the rule it aliases:\n%s\n---\n%s", outA, outB)
	}
}

// TestCanonicalRefusesAnAliasLeftInASchemaOnlyNode: should a later change to Load leave an alias or an anchor in
// gate:, ask: or docker:, Canonical fails, and with it Compile, rather than write bytes that do not load back or
// that another policy shares.
func TestCanonicalRefusesAnAliasLeftInASchemaOnlyNode(t *testing.T) {
	rule := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "exec matches a"}, {Kind: yaml.ScalarNode, Tag: "!!int", Value: "10"},
	}}
	gate := func(rules ...*yaml.Node) yaml.Node {
		return yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}, {Kind: yaml.SequenceNode, Tag: "!!seq", Content: rules},
		}}
	}
	anchored := *rule
	anchored.Anchor = "r"
	for name, set := range map[string]func(c *Contract){
		"gate alias":   func(c *Contract) { c.Gate = gate(rule, &yaml.Node{Kind: yaml.AliasNode, Value: "r", Alias: rule}) },
		"gate anchor":  func(c *Contract) { c.Gate = gate(&anchored) },
		"ask alias":    func(c *Contract) { c.Ask = yaml.Node{Kind: yaml.AliasNode, Value: "r", Alias: rule} },
		"docker alias": func(c *Contract) { c.Docker = gate(&yaml.Node{Kind: yaml.AliasNode, Value: "r", Alias: rule}) },
	} {
		t.Run(name, func(t *testing.T) {
			c, ds, err := LoadBytes("a.yaml", []byte("version: 0\nname: a\ncommand: [x]\n"), nil)
			if err != nil {
				t.Fatalf("%v\n%s", err, render(ds))
			}
			set(c)
			if out, err := c.Canonical(); err == nil {
				t.Fatalf("Canonical wrote a node holding an alias or an anchor:\n%s", out)
			}
			if _, err := c.Hash(); err == nil {
				t.Fatal("Hash hashed a node holding an alias or an anchor")
			}
		})
	}
}

// TestLoadRefusesMergeKeysInEveryContractMapping pins that no merge key (`<<`) loads in a contract, so none reaches
// a schema-only node, which Canonical writes as Load kept it: a fixed mapping names it an unknown field, a gate
// rule an unknown predicate, env.set an invalid name, and a docker: that holds one is not yet supported.
func TestLoadRefusesMergeKeysInEveryContractMapping(t *testing.T) {
	for _, body := range []string{
		`gate: {rules: [&r {"exec matches a": 10}, {<<: *r}]}`,
		`gate: {rules: [{"exec matches a": 10}], thresholds: {<<: {allow: 40}, ask: 90}}`,
		`gate: {<<: {rules: [{"exec matches a": 10}]}}`,
		`ask: {<<: {timeout: 5s}}`,
		`reason: &e {reads: auto}` + "\n" + `ask: {<<: *e}`,
		`docker: {<<: {image: x}}`,
		`fs: {<<: {write: ["/w"]}}`,
		`env: {set: {<<: {A: b}}}`,
		`limits: {<<: {pids: 10}}`,
		`mcp: [{<<: {name: m}, command: [srv]}]`,
		// A key that is a list where a merge key applies made the typed decode panic (config.GuardYAML).
		"<<: {}\n[]: 0",
		`fs: {<<: {}, []: 0}`,
	} {
		src := "version: 0\nname: a\ncommand: [x]\n" + body + "\n"
		if c, _, err := LoadBytes("a.yaml", []byte(src), nil); err == nil {
			out, _ := c.Canonical()
			t.Errorf("%q loads, with a merge key:\n%s", body, out)
		}
	}
}

// An alias fan-out under gate: is refused by the whole-document bound before the typed decode, so the copy Load
// makes of each alias never starts on it.
func TestGateAliasFanOutIsRefusedQuickly(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 0\nname: a\ncommand: [x]\nskills: &m [")
	for i := range 4000 {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("s")
	}
	b.WriteString("]\ngate:\n  rules:\n")
	for range 4000 {
		b.WriteString("    - {\"exec matches a\": 10, x: *m}\n")
	}
	start := time.Now()
	_, ds, err := LoadBytes("agent.yaml", []byte(b.String()), nil)
	if err == nil {
		t.Fatal("a gate expanding to 16M nodes through aliases loaded")
	}
	if !strings.Contains(render(ds), "expands to more than") {
		t.Errorf("refused, but not by the expansion bound:\n%s", render(ds))
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("refusing it took %v", d)
	}
}

// expandAliases is bounded by its own limit and by hops per alias, whatever built the node.
func TestExpandAliasesIsBounded(t *testing.T) {
	leaf := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "x"}
	wide := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for range 10 {
		wide.Content = append(wide.Content, leaf)
	}
	fan := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for range 10 {
		fan.Content = append(fan.Content, &yaml.Node{Kind: yaml.AliasNode, Alias: wide})
	}
	if _, err := expandAliases(fan, 100); err == nil {
		t.Error("a node expanding to 111 nodes was copied under a limit of 100")
	}
	if got, err := expandAliases(fan, 111); err != nil || len(got.Content) != 10 || got.Content[3].Kind != yaml.SequenceNode ||
		len(got.Content[3].Content) != 10 || got.Content[3] == wide {
		t.Errorf("expandAliases(fan, 111) = %+v, %v; want ten fresh copies of the list", got, err)
	}
	loop := &yaml.Node{Kind: yaml.AliasNode}
	loop.Alias = loop
	if _, err := expandAliases(&yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{loop}}, 100); err == nil {
		t.Error("an alias naming itself was expanded")
	}
	if _, err := expandAliases(&yaml.Node{Kind: yaml.AliasNode}, 100); err == nil {
		t.Error("an alias naming no node was expanded")
	}
	deep := leaf
	for range maxAliasDepth*64 + 1 {
		deep = &yaml.Node{Kind: yaml.SequenceNode, Content: []*yaml.Node{deep}}
	}
	if _, err := expandAliases(deep, maxExpandedNodes); err == nil {
		t.Error("a node nested past the depth bound was copied")
	}
}

// TestCanonicalRefusesANewlineMapKeyOnTheNodePath: canonicalNode's stand-ins would reorder a Go map key that holds
// a line break (the encoder sorts keys), so such a key fails rather than write bytes that depend on map order.
func TestCanonicalRefusesANewlineMapKeyOnTheNodePath(t *testing.T) {
	v := struct {
		M map[string]string `yaml:"m"`
		S string            `yaml:"s"`
	}{M: map[string]string{"a\nb": "1", "c": "2"}, S: "\tx\n"}
	if out, err := EncodeYAML(v); err == nil {
		t.Errorf("a map key holding a line break was written on the node path:\n%s", out)
	}
	v.S = "plain"
	if _, err := EncodeYAML(v); err != nil {
		t.Errorf("off the node path the encoder writes the key itself, sorted by its own value: %v", err)
	}
}
