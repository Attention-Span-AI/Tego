// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func fakeInfo(ver string, settings map[string]string) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		bi := &debug.BuildInfo{GoVersion: "go1.99"}
		bi.Main.Version = ver
		for k, v := range settings {
			bi.Settings = append(bi.Settings, debug.BuildSetting{Key: k, Value: v})
		}
		return bi, true
	}
}

func TestBuildInfo(t *testing.T) {
	tests := []struct {
		name       string
		read       func() (*debug.BuildInfo, bool)
		wantTego   string
		wantCommit string
		wantDate   string
	}{
		{"no build info", func() (*debug.BuildInfo, bool) { return nil, false }, "dev", none, none},
		{"devel clean", fakeInfo("(devel)", map[string]string{"vcs.revision": "abc", "vcs.time": "2026-09-22T00:00:00Z", "vcs.modified": "false"}), "dev", "abc", "2026-09-22T00:00:00Z"},
		{"devel dirty", fakeInfo("(devel)", map[string]string{"vcs.modified": "true"}), "dev+dirty", none, none},
		{"tag", fakeInfo("v0.1.0", map[string]string{"vcs.revision": "deadbeef"}), "v0.1.0", "deadbeef", none},
		{"tag dirty", fakeInfo("v0.1.0", map[string]string{"vcs.modified": "true"}), "v0.1.0+dirty", none, none},
		// Go >= 1.24 puts "+dirty" in Main.Version itself; the suffix must not be doubled.
		{"tag already dirty", fakeInfo("v0.1.0+dirty", map[string]string{"vcs.modified": "true"}), "v0.1.0+dirty", none, none},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := buildInfo(tc.read)
			if b.Tego != tc.wantTego || b.Commit != tc.wantCommit || b.Date != tc.wantDate {
				t.Fatalf("got %+v", b)
			}
			if b.RecordV != 1 || len(b.RecordReaders) != 1 || b.ContractSchema != 0 || b.Go == "" {
				t.Fatalf("static fields: %+v", b)
			}
		})
	}
}

// TestVersionText is limits-check-doctor-cli.md R30: one key=value line per field.
func TestVersionText(t *testing.T) {
	var buf bytes.Buffer
	b := buildInfo(fakeInfo("v0.1.0", map[string]string{"vcs.revision": "abc", "vcs.time": "d"}))
	if err := b.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	wantKeys := []string{"tego", "commit", "date", "go", "contract_schema", "record_v", "record_readers", "bpf_hash", "parsers", "control_sha256"}
	if len(lines) != len(wantKeys) {
		t.Fatalf("%d lines: %q", len(lines), lines)
	}
	for i, l := range lines {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k != wantKeys[i] || v == "" {
			t.Fatalf("line %d %q, want key %s", i, l, wantKeys[i])
		}
	}
	// parsers was asserted as "none" here while the binary linked the anthropic parser and stamped
	// anthropic-2026-09-1 on every ssl_response: BuildInfo.Parsers was hard-coded empty (R30).
	if lines[0] != "tego=v0.1.0" || lines[6] != "record_readers=1" || lines[8] != "parsers=anthropic" || lines[9] != "control_sha256=none" {
		t.Fatalf("%q", lines)
	}
}

// TestVersionReportsTheParsersItLinks pins both readings of R30's parsers field to the parsers this
// build actually carries: the line a bug report starts with, and the run_start.parsers map a later
// status/drift reads to know which deriver produced an archived run's decisions (VERSIONING.md §2).
func TestVersionReportsTheParsersItLinks(t *testing.T) {
	b := buildInfo(fakeInfo("v0.1.0", nil))
	if !slices.Contains(b.Parsers, anthropic.Provider) {
		t.Fatalf("parsers %v, want the linked %q parser", b.Parsers, anthropic.Provider)
	}
	for _, p := range linkedParsers(nil) {
		if !slices.Contains(b.Parsers, p.Provider()) {
			t.Errorf("parser %q is linked but version does not report it", p.Provider())
		}
	}
	if got := runBuild().Parsers[anthropic.Provider]; got != "1" {
		t.Errorf("run_start.parsers[%q] = %q, want \"1\": an empty map answers nothing", anthropic.Provider, got)
	}
}

// TestVersionJSON is limits-check-doctor-cli.md R30's --json: the same fields as one object.
func TestVersionJSON(t *testing.T) {
	code, out, errs := run(t, "version", "--json")
	if code != identity.ExitOK || errs != "" {
		t.Fatalf("exit %d stderr %q", code, errs)
	}
	if strings.Count(strings.TrimSpace(out), "\n") != 0 {
		t.Fatalf("one object per line: %q", out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tego", "commit", "date", "go", "contract_schema", "record_v", "record_readers", "bpf_hash", "parsers", "control_sha256"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s in %s", k, out)
		}
	}
	if idx := strings.Index(out, `"tego"`); idx != 1 {
		t.Fatalf("fields in R30 order, tego first: %s", out)
	}
}
