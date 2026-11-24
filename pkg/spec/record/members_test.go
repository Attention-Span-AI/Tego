// SPDX-License-Identifier: Apache-2.0

package record

import (
	"errors"
	"slices"
	"testing"
)

// TestStringsReadsALineAsData: the members asked for are the line's top-level ones whatever the order of its keys, the
// spaces between its tokens or the spelling of a key or a value; a key inside a nested value is never one; and the
// lines Decode refuses for what is read here are refused.
func TestStringsReadsALineAsData(t *testing.T) {
	const attr = `"attribution":{"rule":"nested","kind":"nested","confidence":"exact","method":"pid"}`
	for _, tc := range []struct {
		name, line string
		want       []string // kind, rule, command_rule
		err        error
	}{
		{"canonical", `{"v":1,"seq":1,"kind":"fs","source":"landlock","rule":"fs.write[./out/]",` + attr + `,"command_rule":"x"}`, []string{"fs", "fs.write[./out/]", "x"}, nil},
		{"attribution first", `{"v":1,"kind":"fs",` + attr + `,"rule":"fs.write[./out/]"}`, []string{"fs", "fs.write[./out/]", ""}, nil},
		{"rule and kind after a nested object", `{"v":1,` + attr + `,"kind":"exec","rule":"exec[git]","command_rule":"git status"}`, []string{"exec", "exec[git]", "git status"}, nil},
		{"no rule", `{"v":1,"kind":"ssl_request",` + attr + `}`, []string{"ssl_request", "", ""}, nil},
		{"v last", `{"kind":"fs","rule":"r","v":1}`, []string{"fs", "r", ""}, nil},
		{"spaces", " {\"v\" : 1 , \"kind\" : \"fs\" , \"rule\" : \"r\" }\n", []string{"fs", "r", ""}, nil},
		{"escaped key", `{"v":1,"kind":"fs","ru\u006ce":"r"}`, []string{"fs", "r", ""}, nil},
		{"escaped value", `{"v":1,"kind":"fs","rule":"fs.write[./a\"b/]"}`, []string{"fs", `fs.write[./a"b/]`, ""}, nil},
		{"a payload key holding no string reads as absent", `{"v":1,"kind":"exec","rule":"r","command_rule":5}`, []string{"exec", "r", ""}, nil},
		{"newer writer", `{"v":2,"kind":"fs","rule":"r"}`, nil, ErrNewerVersion},
		{"no v", `{"kind":"fs","rule":"r"}`, nil, ErrUnsupportedVersion},
		{"a common field that is no string", `{"v":1,"kind":"fs","rule":5}`, nil, ErrMalformedLine},
		{"a repeated key", `{"v":1,"kind":"fs","rule":"a","rule":"b"}`, nil, ErrMalformedLine},
		{"a repeated key by escape", `{"v":1,"kind":"fs","rule":"a","ru\u006ce":"b"}`, nil, ErrMalformedLine},
		{"not JSON", `{"v":1,"kind":"fs"`, nil, ErrMalformedLine},
		{"not an object", `[1]`, nil, ErrMalformedLine},
		{"empty", ``, nil, ErrMalformedLine},
	} {
		got, err := Strings([]byte(tc.line), "kind", "rule", "command_rule")
		switch {
		case tc.err != nil:
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: err %v, want %v", tc.name, err, tc.err)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case !slices.Equal(got, tc.want):
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestStringsAgreesWithDecode: on every line above that Decode accepts, Strings gives the kind and rule Decode does,
// and a line Decode refuses for its version Strings refuses too.
func TestStringsAgreesWithDecode(t *testing.T) {
	const attr = `"attribution":{"confidence":"exact","method":"pid"}`
	for _, line := range []string{
		`{"v":1,"seq":1,"id":"` + ZeroID + `","prev":"","ts":"2026-11-01T00:00:00Z","mono_ns":1,"run":"r","agent":"a","pid":1,"tid":1,"cgroup":1,"kind":"fs","source":"landlock","rule":"fs.read","verdict":"allow","authority":"rule",` + attr + `}`,
		`{"v":1,"seq":1,"id":"` + ZeroID + `","prev":"","ts":"2026-11-01T00:00:00Z","mono_ns":1,"run":"r","agent":"a","pid":1,"tid":1,"cgroup":1,"kind":"fs","source":"landlock",` + attr + `,"rule":"fs.read","verdict":"allow","authority":"rule"}`,
		`{"v":2,"seq":1}`,
	} {
		got, serr := Strings([]byte(line), "kind", "rule")
		e, derr := Decode([]byte(line))
		if (serr == nil) != (derr == nil) {
			t.Errorf("%s: Strings err %v, Decode err %v", line, serr, derr)
			continue
		}
		if derr == nil && (got[0] != string(e.Kind) || got[1] != e.Rule) {
			t.Errorf("%s: Strings %q, Decode kind %q rule %q", line, got, e.Kind, e.Rule)
		}
	}
}

// BenchmarkStrings is the read a count makes of each line of a long run.
func BenchmarkStrings(b *testing.B) {
	line := []byte(`{"v":1,"seq":1,"id":"` + ZeroID + `","prev":"","ts":"2026-11-01T00:00:00Z","mono_ns":1,"run":"r","agent":"a","pid":1,"tid":1,"cgroup":1,"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","authority":"rule","attribution":{"confidence":"unattributed","method":"none"},"op":"write","path":"/home/u/proj/out/file.txt"}`)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Strings(line, "kind", "rule", "verdict", "command_rule", "command_list"); err != nil {
			b.Fatal(err)
		}
	}
}
