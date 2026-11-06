// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCanonicalBlockLossyStringLoadsBack pins R13 for a string yaml.v3 writes as a block that does not load back:
// one holding a line break that starts with a tab, written as a `|` block its own scanner refuses, so the run's
// contract.yaml did not load (the nightly fuzz run's FuzzLoad/0de5fd1b2ddbbf92, `command: ["\t0\n"]`), or with a
// line break, which the block dropped. Canonical writes each double-quoted, loads back to the same strings, and is
// a fixed point, in every field that takes free text, beside block strings that start with a space, under
// sections whose MarshalYAML re-encodes through a node, and when the contract already holds a stand-in's spelling.
func TestCanonicalBlockLossyStringLoadsBack(t *testing.T) {
	for name, body := range map[string]string{
		"fuzz find":       `command: ["\t0\n"]`,
		"shell script":    `command: [sh, -c, "\tset -e\n\techo hi\n"]`,
		"strip and keep":  `command: ["\tx\ny", "\tx\n\n", "\t.\n"]`,
		"leading break":   `command: ["\nz\n", "\n\nz", "\n\tz\n", "\n z\n"]`,
		"line separator":  `command: [" z\n", " z\n"]`,
		"mcp command":     `command: [x]` + "\n" + `mcp: [{name: m, command: [srv, "\t--flag\n", "\n--flag\n"]}]`,
		"models provider": `command: [x]` + "\n" + `models: [{provider: "\tp\n", host: a.example, port: 443}]`,
		"beside blocks": `command: ["\tx\n", " y\n", "  y\nz\n", "a\n\tb\n", "plain\nlines\n"]` + "\n" +
			`net: {listen: []}` + "\n" + `env: {pass: []}` + "\n" + `fs: {deny_read: []}`,
		"stand-in spelling": `command: ["\tx\n", " y\n", tego-canonical-0, "tego-canonical-1"]`,
	} {
		t.Run(name, func(t *testing.T) {
			src := "version: 0\nname: a\n" + body + "\n"
			c, ds, err := LoadBytes("a.yaml", []byte(src), nil)
			if err != nil {
				t.Fatalf("%v\n%s", err, render(ds))
			}
			b, err := c.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			c2, ds2, err := LoadBytes("b.yaml", b, nil)
			if err != nil {
				t.Fatalf("Canonical does not load back: %v\n%s\n%s", err, render(ds2), b)
			}
			for _, f := range []string{"Command", "MCP", "Models"} {
				if x, y := reflect.ValueOf(c).Elem().FieldByName(f).Interface(), reflect.ValueOf(c2).Elem().FieldByName(f).Interface(); !reflect.DeepEqual(x, y) {
					t.Errorf("%s loads back as %q, want %q\n%s", f, y, x, b)
				}
			}
			b2, err := c2.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(b, b2) {
				t.Errorf("Canonical is not a fixed point:\n%s---\n%s", b, b2)
			}
			if strings.Count(string(b), "tego-canonical-") != strings.Count(src, "tego-canonical-") {
				t.Errorf("a stand-in reached the output:\n%s", b)
			}
		})
	}
	c, _, err := LoadBytes("a.yaml", []byte("version: 0\nname: a\ncommand: [\"\\t0\\n\", \" y\\n\"]\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if want := "version: 0\nname: a\ncommand:\n  - \"\\t0\\n\"\n  - |2\n     y\n"; string(b) != want {
		t.Errorf("Canonical = %q, want %q", b, want)
	}
}

// TestCanonicalNodeIsTheEncoders: canonicalNode, the path a contract with a blockLossy string takes, writes every
// other contract byte for byte as the encoder writes it from the struct, so the only bytes that path changes are
// the blockLossy strings themselves; and such a contract still takes the encoder's own path, so its contract_hash
// is what it was. Every contract in the repository is checked, and contracts whose block strings start with a
// space or neither, kept and stripped, in sequences and mapping values, under sections whose MarshalYAML
// re-encodes through a node.
func TestCanonicalNodeIsTheEncoders(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	sources := []ProfileSource{dirSource{root: filepath.Join(root, "examples", "profiles")}, testProfiles()}
	var contracts []*Contract
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".github", "node_modules", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(p); ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, src := range sources {
			if c, _, err := LoadBytes(p, data, src); err == nil {
				contracts = append(contracts, c)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(contracts) < 30 {
		t.Fatalf("loaded %d contracts: the walk found too few to prove anything", len(contracts))
	}
	for _, body := range []string{
		`command: [" y\n", "  y\nz\n", "y\n", "y\n\n", "y\nz", " \ty\n", "a\n\tb\n", "a\n\nb\n"]`,
		`command: [x]` + "\n" + `mcp: [{name: m, command: [" y\n", "y\nz"]}]` + "\n" +
			`models: [{provider: " p\n", host: a.example, port: 443}]`,
		`command: [" y\n"]` + "\n" + `net: {listen: [], dns: {mode: broker, types: []}}` + "\n" +
			`env: {pass: [], set: {A: "<<"}}` + "\n" + `fs: {write: ["<<"], deny_read: []}`,
	} {
		src := "version: 0\nname: a\n" + body + "\n"
		c, ds, err := LoadBytes("a.yaml", []byte(src), nil)
		if err != nil {
			t.Fatalf("%q: %v\n%s", src, err, render(ds))
		}
		contracts = append(contracts, c)
	}
	for _, c := range contracts {
		if doc, err := canonicalDoc(c); err != nil || doc != any(c) {
			t.Errorf("%s: canonicalDoc = %T, %v; want the contract itself", c.File(), doc, err)
		}
		n, err := canonicalNode(c)
		if err != nil {
			t.Fatalf("%s: %v", c.File(), err)
		}
		if got, want := encode2(t, n), encode2(t, c); got != want {
			t.Errorf("%s: canonicalNode writes\n%s\nthe encoder writes\n%s", c.File(), got, want)
		}
	}
}

// TestBlockLossyNamesEveryBlockYAMLCannotReadBack ties blockLossy to the yaml.v3 this module builds with. For every
// string of up to five characters over a, space, tab, \n, \r, U+2028 and # that holds a line break, encoded as
// Canonical encodes (indent 2) as a sequence item, an item of a sequence in a list of mappings, and a mapping
// value there: one that does not load back is one blockLossy names; one blockLossy names loads back
// double-quoted; and one blockLossy names that the encoder already writes faithfully, it writes exactly as the
// double-quoted node, so naming it changes no byte. A yaml.v3 that writes these differently fails here.
func TestBlockLossyNamesEveryBlockYAMLCannotReadBack(t *testing.T) {
	type item struct {
		Name     string   `yaml:"name"`
		Command  []string `yaml:"command"`
		Provider string   `yaml:"provider"`
	}
	type doc struct {
		Command []string `yaml:"command"`
		Items   []item   `yaml:"items"`
	}
	str := func(v string, style yaml.Style) *yaml.Node {
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v, Style: style}
	}
	seq := func(c ...*yaml.Node) *yaml.Node { return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: c} }
	mapping := func(c ...*yaml.Node) *yaml.Node { return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: c} }
	loadsBack := func(text, s string) bool {
		var back doc
		return yaml.Unmarshal([]byte(text), &back) == nil && len(back.Command) == 1 && back.Command[0] == s &&
			len(back.Items) == 1 && len(back.Items[0].Command) == 1 && back.Items[0].Command[0] == s && back.Items[0].Provider == s
	}
	var all []string
	var grow func(prefix string, n int)
	grow = func(prefix string, n int) {
		for _, r := range []string{"a", " ", "\t", "\n", "\r", " ", "#"} {
			all = append(all, prefix+r)
			if n > 1 {
				grow(prefix+r, n-1)
			}
		}
	}
	grow("", 5)
	lossy, named := 0, 0
	for _, s := range all {
		if !strings.Contains(s, "\n") {
			continue
		}
		encoded := encode2(t, doc{Command: []string{s}, Items: []item{{Name: "m", Command: []string{s}, Provider: s}}})
		faithful := loadsBack(encoded, s)
		if !faithful {
			lossy++
		}
		if !blockLossy(s) {
			if !faithful {
				t.Errorf("%q does not load back as %q, and blockLossy does not name it", s, encoded)
			}
			continue
		}
		named++
		q := str(s, yaml.DoubleQuotedStyle)
		quoted := encode2(t, mapping(str("command", 0), seq(q), str("items", 0),
			seq(mapping(str("name", 0), str("m", 0), str("command", 0), seq(q), str("provider", 0), q))))
		if !loadsBack(quoted, s) {
			t.Errorf("%q double-quoted, %q, does not load back", s, quoted)
		}
		if faithful && quoted != encoded {
			t.Errorf("%q: the encoder writes %q, double-quoting writes %q", s, encoded, quoted)
		}
	}
	if lossy == 0 || named < lossy {
		t.Fatalf("%d strings do not load back, blockLossy names %d: the enumeration proves nothing", lossy, named)
	}
}

// encode2 is v as Canonical's encoder writes it: two spaces an indent level.
func encode2(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
