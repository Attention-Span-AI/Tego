// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"strings"
	"testing"
)

func TestFormatMessage(t *testing.T) {
	cases := []struct {
		name       string
		file       string
		line, col  int
		what, code string
		want       string
	}{
		{"full", "agent.yaml", 12, 3, "unknown key", "schema", "agent.yaml:12:3: unknown key [schema]"},
		{"no col", "agent.yaml", 12, 0, "unknown key", "schema", "agent.yaml:12: unknown key [schema]"},
		{"no line drops col", "agent.yaml", 0, 4, "unsupported version 1", "config-untrusted", "agent.yaml: unsupported version 1 [config-untrusted]"},
		{"no file", "", 3, 3, "no tier available", "tier-unavailable", "no tier available [tier-unavailable]"},
		{"no code", "f", 1, 1, "fine", "", "f:1:1: fine"},
		{"negative numbers", "f", -1, -1, "x", "c", "f: x [c]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FormatMessage(tc.file, tc.line, tc.col, tc.what, tc.code); got != tc.want {
				t.Errorf("FormatMessage = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiagnosticString(t *testing.T) {
	d := Diagnostic{File: "c.yaml", Line: 4, Message: "machine config untrusted: /etc/tego/config.yaml 1001 0664",
		Code: CodeConfigUntrusted, Fix: "chmod g-w,o-w /etc/tego/config.yaml", Severity: "error"}
	want := "c.yaml:4: machine config untrusted: /etc/tego/config.yaml 1001 0664 [config-untrusted] chmod g-w,o-w /etc/tego/config.yaml"
	if got := d.String(); got != want {
		t.Errorf("String = %q\nwant %q", got, want)
	}
}

func FuzzFormatMessage(f *testing.F) {
	f.Add("f", 1, 2, "what", "code")
	f.Add("", 0, 0, "", "")
	f.Fuzz(func(t *testing.T, file string, line, col int, what, code string) {
		got := FormatMessage(file, line, col, what, code)
		if !strings.Contains(got, what) {
			t.Fatalf("message lost: %q", got)
		}
		if code != "" && !strings.HasSuffix(got, "["+code+"]") {
			t.Fatalf("code not a bracketed suffix: %q", got)
		}
	})
}

func BenchmarkFormatMessage(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = FormatMessage("agent.yaml", 12, 3, "unknown key", "schema")
	}
}
