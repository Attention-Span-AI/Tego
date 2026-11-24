// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

// This synthetic shape extends the review's 74-key, 1,256-entry reproduction.
// No fixture reads a real settings file or derives data from one.
func TestMCPJSONLargeIgnoredSubtrees(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"mcpServers":{"kept":{"command":"codex","args":["MCP_CANARY_18"],"env":{`)
	for i := range 1256 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"MCP_CANARY_18_%d":{"n":%d,"secret":"MCP_CANARY_18"}`, i, i)
	}
	b.WriteString(`}}}`)
	for i := range 2500 {
		fmt.Fprintf(&b, `,"k%d":{"MCP_CANARY_18":[true,null,%d]}`, i, i)
	}
	fmt.Fprintf(&b, `,"%s":"%s","number":0.%s}`, strings.Repeat(mcpCanary, 600), strings.Repeat(mcpCanary, 4000), strings.Repeat("1", 5000))
	v, e := parseMCPJSON(t.Context(), strings.NewReader(b.String()))
	if e != nil || len(v) != 1 || v[0].Name != "kept" || v[0].Program != "codex-native" || v[0].Arguments != 1 {
		t.Fatalf("synthetic settings (%d bytes): servers=%+v err=%v", b.Len(), v, e)
	}
	assertNoCanary(t, v)
	assertNoCanary(t, e)
	o := commandOptions(t)
	writeSettings(t, o.Directory, ".claude.json", []byte(b.String()))
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.MCP != 1 {
		t.Fatalf("synthetic settings were not collected: %+v", s.Counts)
	}
	assertNoCanary(t, s)
	encoded, e := result.Encode(s)
	if e != nil {
		t.Fatal(e)
	}
	assertNoCanary(t, encoded)
	for _, asJSON := range []bool{false, true} {
		for _, verbose := range []bool{false, true} {
			var out, errs bytes.Buffer
			if e = result.Render(&out, &errs, s, asJSON, verbose, nil); e != nil {
				t.Fatal(e)
			}
			assertNoCanary(t, out.Bytes())
			assertNoCanary(t, errs.Bytes())
		}
	}
}

func TestMCPJSONIgnoredBoundsAndGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      error
	}{
		{"duplicate-ignored", `{"ignored":{"x":1,"x":2},"ignored":false}`, nil},
		{"long-ignored", `{"ignored":"` + strings.Repeat("x", 16384) + `"}`, nil},
		{"depth", `{"ignored":` + strings.Repeat("[", 33) + `0` + strings.Repeat("]", 33) + `}`, errLimit},
		{"size", `{"ignored":"` + strings.Repeat("x", manifestBytes) + `"}`, errSize},
		{"trailing-comma", `{"ignored":{"x":1,}}`, errSyntax},
		{"missing-value", `{"ignored":[1,]}`, errSyntax},
		{"leading-zero", `{"ignored":01}`, errSyntax},
		{"missing-fraction", `{"ignored":1.}`, errSyntax},
		{"missing-exponent", `{"ignored":1e+}`, errSyntax},
		{"invalid-escape", `{"ignored":"\q"}`, errSyntax},
		{"invalid-surrogate", `{"ignored":"\ud800x"}`, errSyntax},
		{"duplicate-selected", `{"mcpServers":{},"mcpServers":{}}`, errSyntax},
		{"escaped-duplicate-selected", `{"mcpServers":{},"\u006dcpServers":{}}`, errSyntax},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := parseMCPJSON(t.Context(), strings.NewReader(tc.raw))
			if !errors.Is(e, tc.want) || len(v) != 0 {
				t.Fatalf("got %v, %d servers; want %v", e, len(v), tc.want)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := parseMCPJSON(ctx, strings.NewReader(`{"ignored":"value"}`)); !errors.Is(e, context.Canceled) {
		t.Fatalf("cancellation: %v", e)
	}
}

func TestClaudeMCPSelectsCurrentLocalProject(t *testing.T) {
	o := commandOptions(t)
	current, e := json.Marshal(o.Directory)
	if e != nil {
		t.Fatal(e)
	}
	raw := []byte(`{"projects":{"/other/MCP_CANARY_18":{"mcpServers":{"elsewhere":{"command":"gemini"}}},` + string(current) + `:{"mcpServers":{"here":{"command":"codex","args":["MCP_CANARY_18"]}},"history":"MCP_CANARY_18"}},"mcpServers":{"user":{"command":"gemini"}}}`)
	writeSettings(t, o.Directory, ".claude.json", raw)
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.MCP != 2 {
		t.Fatalf("selected other projects: %+v", s.Counts)
	}
	seen := map[string]string{}
	for _, i := range s.Items {
		if i.Kind == "mcp_server" {
			v := i.Config()
			seen[v.Server] = v.Scope
		}
	}
	if len(seen) != 2 || seen["here"] != "local" || seen["user"] != "user" {
		t.Fatalf("wrong selected scopes: %+v", seen)
	}
	assertNoCanary(t, s)
	if _, e := result.Encode(s); e != nil {
		t.Fatal(e)
	}
	// Generic MCP files do not select Claude's projects tree.
	v, e := parseMCPJSON(t.Context(), bytes.NewReader(raw))
	if e != nil || len(v) != 1 || v[0].Name != "user" {
		t.Fatalf("generic JSON selected local projects: %+v %v", v, e)
	}
}

func TestClaudeMCPSkipsOtherProjectHistories(t *testing.T) {
	o := commandOptions(t)
	current, e := json.Marshal(o.Directory)
	if e != nil {
		t.Fatal(e)
	}
	child, e := json.Marshal(o.Directory + "/child")
	if e != nil {
		t.Fatal(e)
	}
	var b strings.Builder
	b.WriteString(`{"projects":{`)
	for i := range 1256 {
		fmt.Fprintf(&b, `"/other/MCP_CANARY_18/%d":{"mcpServers":{"elsewhere":{"command":"gemini"}},"history":"MCP_CANARY_18"},`, i)
	}
	b.WriteString(string(child) + `:{"mcpServers":{"descendant":{"command":"gemini"}}},`)
	// A project key is compared by its decoded value, never by a raw prefix.
	b.WriteString(strings.ReplaceAll(string(current), "/", `\/`) + `:{"mcpServers":{"here":{"command":"codex"}}}}}`)
	writeSettings(t, o.Directory, ".claude.json", []byte(b.String()))
	s := Collect(t.Context(), o).Snapshot
	if s.Counts.MCP != 1 {
		t.Fatalf("ignored project histories (%d bytes) changed selection: %+v", b.Len(), s.Counts)
	}
	for _, i := range s.Items {
		if i.Kind == "mcp_server" && (i.Config().Server != "here" || i.Config().Scope != "local") {
			t.Fatalf("selected another directory: %+v", i.Config())
		}
	}
	assertNoCanary(t, s)
}

func TestMCPTOMLPrefixWorkBound(t *testing.T) {
	var b strings.Builder
	b.WriteByte('[')
	for i := range 32 {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strings.Repeat(string(rune('a'+i%26)), 4000))
	}
	b.WriteString("]\n")
	for i := range 2000 {
		fmt.Fprintf(&b, "k%d=1\n", i)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	start := time.Now()
	v, e := parseMCPTOML(ctx, strings.NewReader(b.String()))
	if !errors.Is(e, errLimit) || len(v) != 0 || ctx.Err() != nil {
		t.Fatalf("prefix work (%d bytes) consumed its budget: %v after %s", b.Len(), e, time.Since(start))
	}
	t.Logf("bounded %d-byte hostile prefix fixture in %s", b.Len(), time.Since(start))
}

func TestMCPTOMLKeyByteBound(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      error
	}{
		{"section-at-bound", "[" + strings.Repeat("a", 4096) + "]\n", nil},
		{"dotted-section-over-bound", "[" + strings.Repeat("a", 2048) + "." + strings.Repeat("b", 2048) + "]\n", errLimit},
		{"key-at-bound", strings.Repeat("a", 4096) + "=1\n", nil},
		{"combined-at-bound", "[" + strings.Repeat("a", 4094) + "]\nk=1\n", nil},
		{"combined-over-bound", "[" + strings.Repeat("a", 4095) + "]\nk=1\n", errLimit},
		{"empty-section-counts-separator", "[\"\"]\n" + strings.Repeat("a", 4096) + "=1\n", errLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, e := parseMCPTOML(t.Context(), strings.NewReader(tc.raw))
			if !errors.Is(e, tc.want) || len(v) != 0 {
				t.Fatalf("got %v, %d servers; want %v", e, len(v), tc.want)
			}
		})
	}
}

func TestMCPJSONSelectedStructureBounds(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"mcpServers":{`)
	for i := range 128 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `"s%d":{"command":"codex","args":[`, i)
		b.WriteString(strings.TrimSuffix(strings.Repeat(`"ignored",`, 33), ","))
		b.WriteString(`]}`)
	}
	b.WriteString(`}}`)
	v, e := parseMCPJSON(t.Context(), strings.NewReader(b.String()))
	if !errors.Is(e, errLimit) || len(v) != 0 {
		t.Fatalf("selected structure token bound: %v, %d servers", e, len(v))
	}
}

func TestManifestJSONStringDecoding(t *testing.T) {
	for _, raw := range []string{`"plain"`, `"\b\f\n\r\t\/\\\""`, `"\u0063odex"`, `"\ud83d\ude00"`, `"é中😀"`} {
		t.Run(raw, func(t *testing.T) {
			var want string
			if e := json.Unmarshal([]byte(raw), &want); e != nil {
				t.Fatal(e)
			}
			s := manifestStream{ctx: t.Context(), r: bufio.NewReader(strings.NewReader(raw))}
			got, e := s.quoted(true)
			if e != nil || got != want {
				t.Fatalf("decoded %q %v; want %q", got, e, want)
			}
		})
	}
	v, e := parseMCPJSON(t.Context(), strings.NewReader(`{"\u006dcpServers":{"\ud83d\ude00":{"\u0063ommand":"\u0063odex"}}}`))
	if e != nil || len(v) != 1 || v[0].Name != "😀" || v[0].Program != "codex-native" {
		t.Fatalf("escaped selection: %+v %v", v, e)
	}
}
