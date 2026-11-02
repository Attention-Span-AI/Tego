// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var repoRoot = filepath.Join("..", "..", "..")

// TestExampleLoadsWithWarningsOnly: examples/agents/retriever.yaml, the P0
// subset of the spec example, loads with only warnings. It names no deny_read
// of its own (the built-in list holds the credential paths it once named), so
// the merged list is the profile's one entry, which the merge never drops (R5).
func TestExampleLoadsWithWarningsOnly(t *testing.T) {
	c, ds, err := Load(filepath.Join(repoRoot, "examples", "agents", "retriever.yaml"), testProfiles())
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if c.Name != "retriever" || c.FS == nil || !slices.Equal(c.FS.DenyRead, []string{"~/.gnupg/"}) || len(c.Net.Allow) != 3 {
		t.Errorf("merged contract: %+v", c)
	}
	for _, d := range ds {
		if d.Severity != SeverityWarning {
			t.Errorf("not a warning: %v", d)
		}
	}
}

// TestSpecExampleSchema: the full spec/agent/v0 example parses with every
// field known (I1). Implemented ask fields load; remaining roadmap fields
// and the example's unsupported unrestricted HTTP rule are diagnosed.
func TestSpecExampleSchema(t *testing.T) {
	c, ds, err := Load(filepath.Join(repoRoot, "spec", "agent", "v0", "example.retriever.yaml"), testProfiles())
	if !errors.Is(err, ErrInvalidContract) || c != nil {
		t.Fatalf("want not-yet-supported errors, got err=%v", err)
	}
	var got []string
	for _, d := range ds {
		if d.Severity == SeverityError {
			if d.Code != CodeNotYetSupported && !(d.Code == CodeSchema && strings.HasPrefix(d.Message, "net.http ")) {
				t.Errorf("unexpected error on the spec example: %v", d)
			}
			got = append(got, strings.Fields(d.Message)[0])
		}
	}
	sort.Strings(got)
	want := []string{"docker", "env.mask", "net.http", "prompt", "skills", "visibility"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("rejected fields %v want %v", got, want)
	}
}

// TestNotYetSupportedTable crosses every schema-only field with absent,
// explicitly empty and non-empty values (R2, R17).
// agent-contract.md R17: env.mask is schema-only, rejected while non-empty, with no runtime behavior to test until it ships.
func TestNotYetSupportedTable(t *testing.T) {
	base := "version: 0\nname: a\ncommand: [x]\n"
	tests := []struct {
		field    string
		empty    string
		nonEmpty string
	}{
		{"exec.privileged", "exec:\n  privileged: []\n", "exec:\n  privileged: [\"docker *\"]\n"},
		{"env.mask", "env:\n  mask: []\n", "env:\n  mask: [KEY]\n"},
		{"docker", "docker: {}\n", "docker:\n  allow: [privileged]\n"},
		{"containers", "containers: none\n", "containers: rootless\n"},
		{"prompt", "prompt: \"\"\n", "prompt: hello\n"},
		{"skills", "skills: []\n", "skills: [go]\n"},
		{"visibility", "visibility: []\n", "visibility: [builder]\n"},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			for _, variant := range []string{"", tc.empty} {
				if _, ds, err := LoadBytes("a.yaml", []byte(base+variant), nil); err != nil {
					t.Errorf("%q must load: %v\n%s", variant, err, render(ds))
				}
			}
			_, ds, err := LoadBytes("a.yaml", []byte(base+tc.nonEmpty), nil)
			if !errors.Is(err, ErrInvalidContract) || len(ds) != 1 || ds[0].Code != CodeNotYetSupported || !strings.HasPrefix(ds[0].Message, tc.field+" ") {
				t.Errorf("non-empty %s: err=%v\n%s", tc.field, err, render(ds))
			}
		})
	}
}

// schemaNode is one node of spec/agent/v0/agent.schema.json, decoded as far as the agreement tests read it.
type schemaNode struct {
	Ref                  string                     `json:"$ref"`
	Type                 string                     `json:"type"`
	Properties           map[string]json.RawMessage `json:"properties"`
	PatternProperties    map[string]json.RawMessage `json:"patternProperties"`
	AdditionalProperties json.RawMessage            `json:"additionalProperties"`
	Items                json.RawMessage            `json:"items"`
	Required             []string                   `json:"required"`
	Pattern              string                     `json:"pattern"`
	OneOf                []json.RawMessage          `json:"oneOf"`
	MinItems             int                        `json:"minItems"`
	MaxItems             int                        `json:"maxItems"`
}

// loadSchemaJSON reads agent.schema.json and returns its root and a decoder that follows a "#/$defs/x" $ref.
func loadSchemaJSON(t *testing.T) (json.RawMessage, func(string, json.RawMessage) schemaNode) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "spec", "agent", "v0", "agent.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var root struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatal(err)
	}
	var decode func(string, json.RawMessage) schemaNode
	decode = func(path string, raw json.RawMessage) schemaNode {
		var n schemaNode
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if n.Ref != "" {
			def, ok := root.Defs[strings.TrimPrefix(n.Ref, "#/$defs/")]
			if !ok || !strings.HasPrefix(n.Ref, "#/$defs/") {
				t.Fatalf("%s: unresolvable $ref %q", path, n.Ref)
			}
			return decode(path, def)
		}
		return n
	}
	return data, decode
}

// TestSchemaJSONMatchesGo: spec/agent/v0/agent.schema.json and the Go schema tree (schema.go) have the same shape
// at every depth (I1): the same keys in every mapping, a list where the other has a list, a free map where the
// other has one, and the same required keys. It compared only the top level and the first level of five $defs,
// so ask, gate, net.dns, net.proxy, net.limits, net.ingress and net.http (30 keys) went unchecked, and a key
// renamed or added in one of them in schema.go alone passed (2026-10-05). The top level's
// required keys are the one exception: Load checks them after the profile merge, not in the walk (R1).
func TestSchemaJSONMatchesGo(t *testing.T) {
	raw, decode := loadSchemaJSON(t)
	var walk func(path string, raw json.RawMessage, f *field)
	walk = func(path string, raw json.RawMessage, f *field) {
		n := decode(path, raw)
		switch f.kind {
		case kindMap:
			var a, b []string
			for k := range n.Properties {
				a = append(a, k)
			}
			for k := range f.fields {
				b = append(b, k)
			}
			sort.Strings(a)
			sort.Strings(b)
			if strings.Join(a, ",") != strings.Join(b, ",") {
				t.Errorf("%s: json keys %v vs go %v", path, a, b)
			}
			if path != "top" {
				req, goReq := slices.Clone(n.Required), slices.Clone(f.required)
				sort.Strings(req)
				sort.Strings(goReq)
				if !slices.Equal(req, goReq) {
					t.Errorf("%s: json required %v vs go %v", path, req, goReq)
				}
			}
			for k, sub := range f.fields {
				if p, ok := n.Properties[k]; ok {
					walk(path+"."+k, p, sub)
				}
			}
		case kindSeq:
			if n.Type != "array" || n.Items == nil {
				t.Errorf("%s: go has a list, json type %q items %s", path, n.Type, n.Items)
				return
			}
			walk(path+"[]", n.Items, f.elem)
		case kindMapFree:
			if n.Type != "object" || n.Properties != nil || (n.PatternProperties == nil && n.AdditionalProperties == nil) {
				t.Errorf("%s: go has a free map, json %+v", path, n)
			}
		case kindAny:
			if n.Type != "object" || n.Properties != nil {
				t.Errorf("%s: go accepts any mapping, json %+v", path, n)
			}
		case kindScalar:
			if n.Type == "object" || n.Type == "array" || n.Properties != nil || n.Items != nil {
				t.Errorf("%s: go has a scalar, json type %q", path, n.Type)
			}
		case kindOneOrSeq:
			// One value or a list of 1 to maxItems (extends, ADR 0066): json writes the two as a oneOf.
			if len(n.OneOf) != 2 {
				t.Errorf("%s: go takes one value or a list of 1 to %d, json oneOf has %d branches", path, f.maxItems, len(n.OneOf))
				return
			}
			one, list := decode(path, n.OneOf[0]), decode(path, n.OneOf[1])
			if one.Type != "string" || list.Type != "array" || list.Items == nil || list.MinItems != 1 || list.MaxItems != f.maxItems {
				t.Errorf("%s: go takes one value or a list of 1 to %d, json %+v or %+v", path, f.maxItems, one, list)
				return
			}
			walk(path, n.OneOf[0], f.elem)
			walk(path+"[]", list.Items, f.elem)
			if item := decode(path, list.Items); item.Pattern != one.Pattern {
				t.Errorf("%s: the one value's pattern %q differs from a list entry's %q", path, one.Pattern, item.Pattern)
			}
		}
	}
	walk("top", raw, contractSchema)
	// The Go struct tags agree with the tree too.
	var tags []string
	var node yaml.Node
	if err := node.Encode(&Contract{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		tags = append(tags, node.Content[i].Value)
	}
	for _, tag := range tags {
		if _, ok := contractSchema.fields[tag]; !ok {
			t.Errorf("struct tag %q not in the schema tree", tag)
		}
	}
}

// TestSchemaJSONValuesMatchGo: where agent.schema.json writes a value constraint as a pattern, it refuses what the
// Go schema walk's check refuses and accepts what it accepts. The patterns took a zero size or duration that
// checkByteSize and checkDuration refuse, a bare host:port in net.ask that checkAskEndpoint refuses (tcp:// only,
// R22), and a glob in fs.ask that checkAskPath refuses, so an editor validating against the file accepted
// contracts Load refuses (2026-10-05).
func TestSchemaJSONValuesMatchGo(t *testing.T) {
	raw, decode := loadSchemaJSON(t)
	for _, tc := range []struct {
		path              string // dotted, "[]" for a list's element
		refused, accepted string
	}{
		{"net.proxy.max_tunnel_bytes", "0", "1MiB"},
		{"net.proxy.max_frame_bytes", "0 KiB", "64KiB"},
		{"limits.memory", "0", "512MiB"},
		{"limits.memory_high", "00MiB", "1GiB"},
		{"net.proxy.tunnel_idle", "0s", "30s"},
		{"net.proxy.tunnel_wall", "0m", "10m"},
		{"limits.wall", "0s", "1h"},
		{"limits.stall_after", "0ms", "500ms"},
		// net.ask (R22 as amended 2026-10-19, ASK-UNIX and ASK-UDP): tcp://, udp://, a bare host:port and unix:, each
		// IP one with a port in 1..65535; another transport, a missing port and port 0 are refused.
		{"net.ask[]", "host.example", "tcp://host.example:443"},
		{"net.ask[]", "host.example:0", "host.example:443"},
		{"net.ask[]", "sctp://host.example:443", "udp://192.0.2.1:53"},
		{"net.ask[]", "udp://host.example:65536", "[2001:db8::1]:65535"},
		{"net.ask[]", "10.0.0.0/8", "10.0.0.0/8:443"},
		{"net.ask[]", "tcp://host.example", "unix:/run/app.sock"},
		{"net.ask[]", "udp://host.example", "unix:@bus"},
		{"fs.ask[]", "/work/*.env", "/work/out"},
		{"fs.ask_read[]", "~/.aws/cred?", "~/.aws/credentials"},
		// revision (agent-contract.md R28).
		{"revision", "", "2026.10.25+1"},
		{"revision", "-1", "v1.2.3-rc_1"},
		{"revision", "A" + strings.Repeat("b", 64), "A" + strings.Repeat("b", 63)},
	} {
		n, f := decode("top", raw), contractSchema
		for _, seg := range strings.Split(strings.ReplaceAll(tc.path, "[]", ".[]"), ".") {
			if seg == "[]" {
				n, f = decode(tc.path, n.Items), f.elem
				continue
			}
			n, f = decode(tc.path, n.Properties[seg]), f.fields[seg]
		}
		if f == nil || f.check == nil || n.Pattern == "" {
			t.Errorf("%s: go check %v, json pattern %q; want both", tc.path, f != nil && f.check != nil, n.Pattern)
			continue
		}
		re, err := regexp.Compile(n.Pattern)
		if err != nil {
			t.Fatalf("%s: pattern %q: %v", tc.path, n.Pattern, err)
		}
		if msg, _ := f.check(tc.refused); msg == "" || re.MatchString(tc.refused) {
			t.Errorf("%s: %q go refuses %v, json pattern %q accepts %v; want both to refuse", tc.path, tc.refused, msg != "", n.Pattern, re.MatchString(tc.refused))
		}
		if msg, _ := f.check(tc.accepted); msg != "" || !re.MatchString(tc.accepted) {
			t.Errorf("%s: %q go refuses (%s), json pattern %q accepts %v; want both to accept", tc.path, tc.accepted, msg, n.Pattern, re.MatchString(tc.accepted))
		}
	}
}

func FuzzLoad(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("testdata", "*", "*.yaml"))
	for _, s := range seeds {
		if data, err := os.ReadFile(s); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, ds, err := LoadBytes("fuzz.yaml", data, nil)
		if (err == nil) != (c != nil) {
			t.Fatalf("err=%v c=%v", err, c)
		}
		if err != nil && !HasErrors(ds) && !errors.Is(err, ErrInvalidContract) {
			t.Fatalf("error without an error diagnostic: %v", err)
		}
		if c == nil {
			return
		}
		a, err := c.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		c2, ds2, err := LoadBytes("fuzz2.yaml", a, nil)
		if err != nil {
			t.Fatalf("canonical output does not reload: %v\n%s\n%s", err, render(ds2), a)
		}
		b, _ := c2.Canonical()
		if string(a) != string(b) {
			t.Fatalf("canonical not a fixed point:\n%s\n---\n%s", a, b)
		}
	})
}
