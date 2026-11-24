// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

const mcpCanary = "MCP_CANARY_18"

func fixtureContent(t testing.TB, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// Reflection is a heap-independent privacy proxy: walk all returned strings,
// including private fields and errors, rather than trusting JSON tags.
func assertNoCanary(t testing.TB, v any) {
	t.Helper()
	var walk func(reflect.Value)
	walk = func(x reflect.Value) {
		if !x.IsValid() {
			return
		}
		switch x.Kind() {
		case reflect.Interface, reflect.Pointer:
			if !x.IsNil() {
				walk(x.Elem())
			}
		case reflect.String:
			if strings.Contains(x.String(), mcpCanary) {
				t.Fatal("canary retained")
			}
		case reflect.Struct:
			for i := 0; i < x.NumField(); i++ {
				walk(x.Field(i))
			}
		case reflect.Array, reflect.Slice:
			if x.Kind() == reflect.Slice && x.Type().Elem().Kind() == reflect.Uint8 {
				if bytes.Contains(x.Bytes(), []byte(mcpCanary)) {
					t.Fatal("canary bytes retained")
				}
			}
			for i := 0; i < x.Len(); i++ {
				walk(x.Index(i))
			}
		case reflect.Map:
			for _, k := range x.MapKeys() {
				walk(k)
				walk(x.MapIndex(k))
			}
		}
	}
	walk(reflect.ValueOf(v))
}
func TestMCPParsersCanaryAndRefusals(t *testing.T) {
	for _, format := range []string{"json", "toml"} {
		t.Run(format, func(t *testing.T) {
			parse := parseMCPJSON
			if format == "toml" {
				parse = parseMCPTOML
			}
			raw := fixtureContent(t, "mcp."+format)
			got, e := parse(t.Context(), bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			assertNoCanary(t, got)
			if len(got) < 2 || got[0].Program != "codex-native" || got[0].Arguments < 2 {
				t.Fatalf("lost observations: %+v", got)
			}
			cases := []string{string(raw) + "!", strings.Repeat(" ", manifestBytes+1)}
			if format == "json" {
				cases = append(cases, `{"mcpServers":{"s":{"command":"codex","command":"`+mcpCanary+`"}}}`, `{"mcpServers":{"s":{"command":{"token":"`+mcpCanary+`"}}}}`, `{"mcpServers":{"s":{"args":[{"token":"`+mcpCanary+`"}]}}}`, strings.Repeat(`{"a":`, 34)+`0`+strings.Repeat(`}`, 34), `{"mcpServers":{"s":{"args":[],"args":["`+mcpCanary+`"]}}}`)
			} else {
				cases = append(cases, "[mcp_servers.s]\ncommand='codex'\ncommand='"+mcpCanary+"'\n", "[mcp_servers.s]\ncommand={key='"+mcpCanary+"'}\n", "[mcp_servers.s]\nargs=[{key='"+mcpCanary+"'}]\n", "[mcp_servers.s]\nenv={a='"+mcpCanary+"',a='"+mcpCanary+"'}\n")
			}
			for i, input := range cases {
				rows, e := parse(t.Context(), strings.NewReader(input))
				if e == nil || len(rows) != 0 {
					t.Fatalf("accepted malformed case %d", i)
				}
				assertNoCanary(t, rows)
				assertNoCanary(t, e)
			}
		})
	}
}
func TestMCPTransportOrderAndAmbiguity(t *testing.T) {
	for _, input := range []string{`{"mcpServers":{"s":{"type":"sse","url":"https://example.invalid"}}}`, `{"mcpServers":{"s":{"url":"https://example.invalid","type":"sse"}}}`} {
		rows, e := parseMCPJSON(t.Context(), strings.NewReader(input))
		if e != nil || len(rows) != 1 || rows[0].Transport != "sse" {
			t.Fatalf("field order changed transport: %+v %v", rows, e)
		}
	}
	for _, input := range []string{`{"mcpServers":{"s":{"command":"codex","url":"https://example.invalid"}}}`, `{"mcpServers":{"s":{"url":"https://example.invalid","command":"codex"}}}`} {
		if _, e := parseMCPJSON(t.Context(), strings.NewReader(input)); e == nil {
			t.Fatal("ambiguous transport accepted")
		}
	}
	for _, input := range []string{"[mcp_servers.s]\ncommand='codex'\nurl='https://example.invalid'\n", "[mcp_servers.s]\nurl='https://example.invalid'\ncommand='codex'\n", "a.b=1\na=2\n"} {
		if _, e := parseMCPTOML(t.Context(), strings.NewReader(input)); e == nil {
			t.Fatal("ambiguous or conflicting TOML accepted")
		}
	}
}

func TestExecStartAndUnits(t *testing.T) {
	doc, e := parseUnit(t.Context(), bytes.NewReader(fixtureContent(t, "agent.service")))
	if e != nil {
		t.Fatal(e)
	}
	assertNoCanary(t, doc)
	crlf, e := parseUnit(t.Context(), bytes.NewReader(bytes.ReplaceAll(fixtureContent(t, "agent.service"), []byte{'\n'}, []byte{'\r', '\n'})))
	if e != nil || !reflect.DeepEqual(crlf, doc) {
		t.Fatal("CRLF continuation differs", e)
	}
	if len(doc.Exec) != 2 || doc.Exec[0].Program != "codex-native" || !doc.Exec[0].Specifiers {
		t.Fatalf("lost starts %+v", doc)
	}
	for _, tc := range []struct {
		raw     string
		good    bool
		program string
		args    int
	}{{`-@:/opt/codex alias "a b" '\x61'`, true, "codex-native", 2}, {`!!codex --key ` + mcpCanary, true, "codex-native", 2}, {`+codex`, true, "codex-native", 0}, {`codex`, true, "codex-native", 0}, {`"/opt/codex" "a"`, true, "codex-native", 1}, {`codex "bad`, false, "", 0}, {`codex a"b"`, true, "codex-native", 1}, {`codex ; gemini`, false, "", 0}, {`%h/codex`, false, "", 0}, {`$CMD`, false, "", 0}, {`/bin/sh -c codex`, false, "", 0}, {`@codex`, false, "", 0}, {`+!codex`, false, "", 0}} {
		x, e := parseExecStart([]byte(tc.raw))
		if (e == nil) != tc.good {
			t.Fatalf("parse state for %q: %v", tc.raw, e)
		}
		if tc.good && (x.Program != tc.program || x.Arguments != tc.args) {
			t.Fatalf("wrong words %+v", x)
		}
		assertNoCanary(t, x)
		assertNoCanary(t, e)
	}
}
func writeSettings(t *testing.T, root, name string, raw []byte) {
	t.Helper()
	p := filepath.Join(root, name)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
func TestUnitPrecedenceDropinsAndFailures(t *testing.T) {
	high, low := unitFixtureRoot(t), unitFixtureRoot(t)
	for _, p := range []string{high, low} {
		if e := os.Chmod(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	uid := uint32(os.Getuid())
	writeSettings(t, low, "a-b.service", []byte("[Service]\nExecStart=claude\n"))
	writeSettings(t, high, "a-b.service", []byte("[Service]\nType=oneshot\nExecStart=gemini\n"))
	writeSettings(t, low, "a-.service.d/10-reset.conf", []byte("[Service]\nExecStart=\nExecStart=claude\n"))
	writeSettings(t, high, "a-b.service.d/10-reset.conf", []byte("[Service]\nExecStart=\nExecStart=codex\n"))
	writeSettings(t, low, "service.d/20-more.conf", []byte("[Service]\nType=oneshot\nExecStart=gemini\n"))
	got := collectUnits(t.Context(), []string{high, low}, uid, &contentBudget{remaining: 8 << 20})
	if len(got.Items) != 2 || got.Items[0].Exec.Program != "codex-native" || got.Items[1].Exec.Program != "gemini-native" {
		t.Fatalf("merge %+v", got)
	}
	if e := os.Symlink(filepath.Join(low, "a-b.service"), filepath.Join(high, "a-b.service.d/30-link.conf")); e != nil {
		t.Fatal(e)
	}
	got = collectUnits(t.Context(), []string{high, low}, uid, &contentBudget{remaining: 8 << 20})
	if len(got.Items) != 0 {
		t.Fatal("salvaged unit with unresolved override")
	}
	found := false
	for _, s := range got.Sources {
		found = found || s.Reason == "symlink"
	}
	if !found {
		t.Fatal("symlink not disclosed")
	}
}
func TestUnitMatchesCatalogWrappers(t *testing.T) {
	for _, row := range catalog.Rows() {
		t.Run(row.ID, func(t *testing.T) {
			input := row.Rule.Basename
			if len(row.Rule.Argv) > 0 {
				if len(row.Rule.Argv) != 2 {
					t.Fatal("extend the streamed unit matcher for the catalog shape")
				}
				input = row.Rule.Argv[0] + " " + strings.ReplaceAll(row.Rule.Argv[1], ".../", "/opt/")
			}
			x, e := parseExecStart([]byte(input + " --token " + mcpCanary))
			if e != nil || x.Program != row.ID {
				t.Fatalf("catalog rule missed: got %s want %s (%v)", x.Program, row.ID, e)
			}
			assertNoCanary(t, x)
		})
	}
	x, e := parseExecStart([]byte("node --token /opt/@openai/codex/bin/codex.js"))
	if e != nil || x.Program != "" {
		t.Fatal("a secret flag value became program evidence")
	}
	o := commandOptions(t)
	writeSettings(t, o.Directory, ".config/systemd/user/wrapper.service", []byte("[Service]\nExecStart=node /opt/@openai/codex/bin/codex.js --token "+mcpCanary+"\n"))
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.Units != 1 {
		t.Fatal("missing wrapper unit")
	}
	if _, e := result.Encode(s); e != nil {
		t.Fatal(e)
	}
}

func TestUnitRulesListedWithoutFindings(t *testing.T) {
	s := Collect(t.Context(), commandOptions(t)).Snapshot
	for _, name := range []string{"claude", "codex", "opencode", "gemini"} {
		found := false
		for _, r := range s.Rules {
			found = found || r.ID == "unit-"+name
		}
		if !found {
			t.Fatalf("effective unit rule omitted: %s", name)
		}
	}
}

func TestUnitRetentionIsBounded(t *testing.T) {
	root := unitFixtureRoot(t)
	for range 35 {
		root = filepath.Join(root, strings.Repeat("a", 80))
	}
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 160; i++ {
		writeSettings(t, root, fmt.Sprintf("u%03d.service", i), []byte("[Service]\nExecStart=codex\n"))
	}
	u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	sources, _ := json.Marshal(u.Sources)
	items, _ := json.Marshal(u.Items)
	limited := false
	for _, p := range u.Sources {
		limited = limited || p.Reason == "limit"
	}
	if len(sources) > 402<<10 || len(items) > 452<<10 || len(u.Items) == 0 || !limited {
		t.Fatalf("unbounded retained units: sources=%d items=%d rows=%d limited=%v", len(sources), len(items), len(u.Items), limited)
	}
}

func TestContentSourcesCountedOnce(t *testing.T) {
	t.Run("settings", func(t *testing.T) {
		o := commandOptions(t)
		writeSettings(t, o.Directory, ".codex/config.toml", []byte("[mcp_servers."))
		d := collectMCP(t.Context(), o.Directory, o.Directory, o.Caller.UID, &contentBudget{remaining: 6 << 20})
		n := 0
		for _, p := range d.Sources {
			if p.Path == filepath.Join(o.Directory, ".codex/config.toml") {
				n += p.NotRead
			}
		}
		if n != 1 {
			t.Fatalf("same failed file counted %d times", n)
		}
	})
	t.Run("units", func(t *testing.T) {
		root := unitFixtureRoot(t)
		if e := os.Chmod(root, 0700); e != nil {
			t.Fatal(e)
		}
		for _, name := range []string{"a.service", "b.service"} {
			writeSettings(t, root, name, []byte("[Service]\nExecStart=codex\n"))
		}
		if e := os.Symlink(unitFixtureRoot(t), filepath.Join(root, "service.d")); e != nil {
			t.Fatal(e)
		}
		u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
		n := 0
		for _, p := range u.Sources {
			if p.Path == filepath.Join(root, "service.d") {
				n += p.NotRead
			}
		}
		if n != 1 {
			t.Fatalf("same failed directory counted %d times", n)
		}
	})
}

func TestUnitsUnsupportedNamesDisclosed(t *testing.T) {
	root := unitFixtureRoot(t)
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{".agent.service", "odd name.service"} {
		writeSettings(t, root, name, []byte("[Service]\nExecStart=codex\n"))
	}
	s := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	n := 0
	for _, p := range s.Sources {
		if p.State == "not-read" && p.Reason == "unsupported" {
			n++
		}
	}
	if n != 2 || len(s.Items) != 0 {
		t.Fatalf("unsupported names silently skipped: %+v", s)
	}
}

func TestUnitMultipleStartsNeedOneshot(t *testing.T) {
	root := unitFixtureRoot(t)
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	for _, typ := range []string{"simple", "oneshot"} {
		writeSettings(t, root, "a.service", []byte("[Service]\nType="+typ+"\nExecStart=codex\nExecStart=gemini\n"))
		s := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 8 << 20})
		want := 0
		if typ == "oneshot" {
			want = 2
		}
		if len(s.Items) != want {
			t.Fatalf("wrong effective type %s: %+v", typ, s)
		}
	}
}

func TestMCPShapeBounds(t *testing.T) {
	var servers strings.Builder
	for i := 0; i < 129; i++ {
		if i > 0 {
			servers.WriteByte(',')
		}
		fmt.Fprintf(&servers, `"s%d":{}`, i)
	}
	for _, tc := range []struct{ name, format, raw string }{
		{"json-depth", "json", strings.Repeat(`{"a":`, 33) + `0` + strings.Repeat(`}`, 33)},
		{"json-count", "json", `{"mcpServers":{` + servers.String() + `}}`},
		{"json-token", "json", `{"mcpServers":{"s":{"command":"` + strings.Repeat("a", 4097) + `"}}}`},
		{"toml-depth", "toml", "x=" + strings.Repeat("[", 33) + "'ignored'" + strings.Repeat("]", 33)},
		{"toml-count", "toml", "x=[" + strings.TrimSuffix(strings.Repeat("'ignored',", 129), ",") + "]"},
		{"toml-token", "toml", "x='" + strings.Repeat("a", 4097) + "'"},
		{"toml-wrong-mcp", "toml", "mcp_servers='" + mcpCanary + "'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parse := parseMCPJSON
			if tc.format == "toml" {
				parse = parseMCPTOML
			}
			v, e := parse(t.Context(), strings.NewReader(tc.raw))
			if e == nil || len(v) != 0 {
				t.Fatal("shape bound accepted")
			}
			assertNoCanary(t, e)
		})
	}
}

func TestUnitTimersAndWants(t *testing.T) {
	o := commandOptions(t)
	root := filepath.Join(o.Directory, ".config/systemd/user")
	writeSettings(t, root, "agent.service", []byte("[Service]\nExecStart=codex --token "+mcpCanary+"\n"))
	writeSettings(t, root, "agent.timer", []byte("[Timer]\nUnit=agent.service\n"))
	if e := os.MkdirAll(filepath.Join(root, "default.target.wants"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("/outside/never-read", filepath.Join(root, "default.target.wants/agent.service")); e != nil {
		t.Fatal(e)
	}
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.Units != 2 {
		t.Fatalf("timer omitted %+v", s.Counts)
	}
	found := false
	for _, i := range s.Items {
		if i.Kind == "timer" {
			found = i.Unit().Triggers != nil && *i.Unit().Triggers == "agent.service"
		}
		if i.Kind == "user_unit" && i.Unit().Enablement == nil {
			t.Fatal("wants metadata omitted")
		}
	}
	if !found {
		t.Fatal("timer relationship missing")
	}
	if _, e := result.Encode(s); e != nil {
		t.Fatal(e)
	}
}

func TestContentChangesAndBounds(t *testing.T) {
	root := unitFixtureRoot(t)
	writeSettings(t, root, "settings", []byte(`{}`))
	fd, _, e := metadataPath(t.Context(), root, false)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = fd.Close() }()
	e = readContent(t.Context(), fd, "settings", uint32(os.Getuid()), &contentBudget{remaining: 8 << 20}, func(r io.Reader) error {
		_, x := io.Copy(io.Discard, r)
		writeSettings(t, root, "settings", []byte("changed"))
		return x
	})
	if e != errChanged {
		t.Fatalf("change accepted %v", e)
	}
	for _, tc := range []struct {
		name   string
		mode   os.FileMode
		raw    []byte
		reason string
	}{{"size", 0600, bytes.Repeat([]byte{' '}, manifestBytes+1), "size"}, {"mode", 0666, []byte(`{}`), "mode"}} {
		writeSettings(t, root, tc.name, tc.raw)
		if e = os.Chmod(filepath.Join(root, tc.name), tc.mode); e != nil {
			t.Fatal(e)
		}
		e = readContent(t.Context(), fd, tc.name, uint32(os.Getuid()), &contentBudget{remaining: 8 << 20}, func(io.Reader) error { t.Fatal("unsafe data opened"); return nil })
		if projectSource(tc.name, e).Reason != tc.reason {
			t.Fatalf("wrong refusal %v", e)
		}
	}
}
func TestMCPSelectsOnlyDocumentedSubtrees(t *testing.T) {
	o := commandOptions(t)
	path, e := json.Marshal(o.Directory)
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"projects":{` + string(path) + `:{"mcpServers":{"local":{"command":"codex"}}}}}`)
	for _, name := range []string{".claude.json", ".mcp.json", ".gemini/settings.json"} {
		writeSettings(t, o.Directory, name, raw)
	}
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.MCP != 1 {
		t.Fatalf("selected an undocumented subtree: %+v", s.Counts)
	}
	for _, i := range s.Items {
		if i.Kind == "mcp_server" {
			v := i.Config()
			if v.Client != "claude" || v.Scope != "local" {
				t.Fatalf("wrong local-project scope: %+v", v)
			}
		}
	}
}

func TestSettingsAndUnitsJoinSnapshot(t *testing.T) {
	o := commandOptions(t)
	writeSettings(t, o.Directory, ".mcp.json", fixtureContent(t, "mcp.json"))
	writeSettings(t, o.Directory, ".codex/config.toml", fixtureContent(t, "mcp.toml"))
	writeSettings(t, o.Directory, ".config/systemd/user/a.service", fixtureContent(t, "agent.service"))
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.MCP < 4 || s.Counts.Units != 2 {
		t.Fatalf("missing kinds %+v", s.Counts)
	}
	if _, e := result.Encode(s); e != nil {
		t.Fatal(e)
	}
	assertNoCanary(t, s)
	for _, jsonMode := range []bool{false, true} {
		for _, verbose := range []bool{false, true} {
			var out, errs bytes.Buffer
			if e := result.Render(&out, &errs, s, jsonMode, verbose, nil); e != nil {
				t.Fatal(e)
			}
			assertNoCanary(t, out.String())
			assertNoCanary(t, errs.String())
		}
	}
	// Configured-source failures keep partial status without deciding the process check.
	if e := os.RemoveAll(filepath.Join(o.ProcRoot, "20")); e != nil {
		t.Fatal(e)
	}
	o.Check = true
	writeSettings(t, o.Directory, ".mcp.json", []byte(`{"mcpServers":`))
	s = Collect(t.Context(), o).Snapshot
	if s.ExitCode() != 0 || s.Check != "none-observed" || s.Status != "partial" {
		t.Fatalf("configured failure changed process check %s", s.Check)
	}
}
func TestConfiguredSnapshotRejectsBrokenEvidence(t *testing.T) {
	o := commandOptions(t)
	writeSettings(t, o.Directory, ".mcp.json", fixtureContent(t, "mcp.json"))
	writeSettings(t, o.Directory, ".config/systemd/user/a.service", fixtureContent(t, "agent.service"))
	good := Collect(t.Context(), o).Snapshot
	wire, e := result.Encode(good)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*result.Snapshot){
		func(s *result.Snapshot) { s.Catalog = "c2" },
		func(s *result.Snapshot) { s.Counts.MCP++ },
		func(s *result.Snapshot) {
			for j, i := range s.Items {
				if i.Kind == "mcp_server" {
					v := i.Config()
					v.Program = result.Path("codex --token " + mcpCanary)
					s.Items[j].Detail = result.Detail(v)
					break
				}
			}
		},
		func(s *result.Snapshot) {
			for j, i := range s.Items {
				if i.Kind == "mcp_server" {
					v := i.Config()
					v.Server = "x\u202ey"
					s.Items[j].Detail = result.Detail(v)
					break
				}
			}
		},
		func(s *result.Snapshot) {
			for j, i := range s.Items {
				if i.Kind == "user_unit" {
					s.Items[j].Evidence[0].Fact = "path"
					break
				}
			}
		},
	} {
		s, e := result.Decode(wire)
		if e != nil {
			t.Fatal(e)
		}
		mutate(&s)
		b, e := json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = result.Decode(b); e == nil {
			t.Fatal("broken configured evidence accepted")
		}
	}
}

func FuzzMCPJSON(f *testing.F) {
	f.Add(fixtureContent(f, "mcp.json"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := parseMCPJSON(context.Background(), bytes.NewReader(b))
		assertFuzzValuePrivacy(t, v)
		assertFuzzValuePrivacy(t, e)
		if e == nil && (!utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0) {
			t.Fatal("invalid text accepted")
		}
		if e != nil && len(v) != 0 {
			t.Fatal("partial evidence")
		}
	})
}
func FuzzMCPTOML(f *testing.F) {
	f.Add(fixtureContent(f, "mcp.toml"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := parseMCPTOML(context.Background(), bytes.NewReader(b))
		assertFuzzValuePrivacy(t, v)
		assertFuzzValuePrivacy(t, e)
		if e == nil && (!utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0) {
			t.Fatal("invalid text accepted")
		}
		if e != nil && len(v) != 0 {
			t.Fatal("partial evidence")
		}
	})
}
func FuzzExecStart(f *testing.F) {
	f.Add([]byte(`-@:/opt/codex alias --token ` + mcpCanary))
	for _, fixture := range []string{"agent.service", "agent-node.service"} {
		for _, line := range bytes.Split(fixtureContent(f, fixture), []byte{'\n'}) {
			if raw, ok := bytes.CutPrefix(line, []byte("ExecStart=")); ok {
				f.Add(raw)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := parseExecStart(b)
		assertFuzzValuePrivacy(t, v)
		assertFuzzValuePrivacy(t, e)
		if e == nil && (!utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0) {
			t.Fatal("invalid text accepted")
		}
		if e == nil && v.Program != "" {
			known := false
			for _, r := range catalog.Rows() {
				known = known || r.ID == v.Program
			}
			if !known {
				t.Fatal("open program id")
			}
		}
	})
}
func FuzzUnitFile(f *testing.F) {
	f.Add(fixtureContent(f, "agent.service"))
	f.Add(fixtureContent(f, "agent-node.service"))
	f.Add([]byte("[Service]\nEnvironment=A=b\\\\\nExecStart=/usr/bin/codex\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, e := parseUnit(context.Background(), bytes.NewReader(b))
		assertFuzzValuePrivacy(t, v)
		assertFuzzValuePrivacy(t, e)
		if e == nil && (!utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0) {
			t.Fatal("invalid text accepted")
		}
		if e != nil && len(v.Exec) != 0 {
			t.Fatal("partial unit")
		}
	})
}

func TestUnitTokenCountIncludesArgv0(t *testing.T) {
	var text strings.Builder
	text.WriteString("[Service]\nType=oneshot\n")
	for range 31 {
		text.WriteString("ExecStart=@codex alias " + strings.Repeat("a ", 126) + "\n")
	}
	text.WriteString("ExecStart=@codex alias " + strings.Repeat("a ", 93) + "\n")
	if _, e := parseUnit(t.Context(), strings.NewReader(text.String())); e == nil {
		t.Fatal("accepted 4097 unit tokens including overridden argv0 words")
	}
}

func TestIgnoredSettingsBytesAreStillValidated(t *testing.T) {
	for _, raw := range []string{"# \xff\n[mcp_servers.s]\ncommand='codex'\n", "# \x00\n[mcp_servers.s]\ncommand='codex'\n"} {
		if _, e := parseMCPTOML(t.Context(), strings.NewReader(raw)); e == nil {
			t.Error("invalid TOML comment accepted")
		}
	}
	if _, e := parseUnit(t.Context(), strings.NewReader("[Service]\nDescription=\x00\nExecStart=codex\n")); e == nil {
		t.Error("invalid ignored unit value accepted")
	}
}

func TestEnabledInstanceUsesTemplateAndInstanceDropins(t *testing.T) {
	root := unitFixtureRoot(t)
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	writeSettings(t, root, "app@.service", []byte("[Service]\nExecStart=codex\n"))
	writeSettings(t, root, "app@foo.service.d/10-override.conf", []byte("[Service]\nExecStart=\nExecStart=gemini\n"))
	if e := os.MkdirAll(filepath.Join(root, "default.target.wants"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("../app@.service", filepath.Join(root, "default.target.wants/app@foo.service")); e != nil {
		t.Fatal(e)
	}
	u := collectUnits(t.Context(), []string{root}, uint32(os.Getuid()), &contentBudget{remaining: 6 << 20})
	found := false
	for _, i := range u.Items {
		if i.Name == "app@foo.service" {
			found = i.Exec.Program == "gemini-native" && strings.HasSuffix(i.Path, "10-override.conf") && i.Enablement != nil && *i.Enablement
		}
	}
	if !found {
		t.Fatal("enabled instance did not apply its template and instance override")
	}
}
