// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

const inlineHooks = `{"hooks":{"PostToolUse":[{"matcher":"Write|Edit","hooks":[{"type":"command","command":"/bin/true","args":["a b","c"],"timeout":10}]}],
 "Stop":[{"hooks":[{"type":"command","command":"echo hi"}]}]},"model":"ignored"}`

func TestParseArgsTakesSettingsAsOneArgvElement(t *testing.T) {
	// inline JSON with spaces and a leading dash-free brace is one element; both spellings of the flag work
	for _, args := range [][]string{
		{"--settings", inlineHooks, "-p", "do it"},
		{"-p", "do it", "--settings=" + inlineHooks},
	} {
		c, err := parseArgs(args)
		if err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		if c.settingsArg != inlineHooks || c.prompt != "do it" {
			t.Errorf("%q: settings %q prompt %q", args, c.settingsArg, c.prompt)
		}
	}
	// the last --settings wins; flags of the real CLI that change nothing here are accepted; a typo is not
	c, err := parseArgs([]string{"--settings", "a.json", "--permission-mode", "plan", "--settings", "b.json", "--bare"})
	if err != nil || c.settingsArg != "b.json" || !c.bare {
		t.Errorf("last wins: %+v %v", c, err)
	}
	for _, bad := range [][]string{{"--setings", "x"}, {"--settings"}, {"--bare=1"}, {"one", "two"}} {
		if _, err := parseArgs(bad); err == nil {
			t.Errorf("%q: accepted", bad)
		}
	}
}

func TestLoadSettingsInlineAndPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(inlineHooks), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, arg := range map[string]string{"inline": inlineHooks, "path": path} {
		s, err := LoadSettings(arg)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := s.HooksFor(EvPostToolUse, "Write")
		if len(got) != 1 || !reflect.DeepEqual(*got[0].Args, []string{"a b", "c"}) || got[0].TimeoutSeconds() != 10 {
			t.Errorf("%s: PostToolUse for Write: %+v", name, got)
		}
		if n := len(s.HooksFor(EvPostToolUse, "Bash")); n != 0 {
			t.Errorf("%s: a Write|Edit matcher ran for Bash", name)
		}
		if h := s.HooksFor(EvStop, ""); len(h) != 1 || h[0].Args != nil || h[0].TimeoutSeconds() != DefaultHookTimeout {
			t.Errorf("%s: Stop hook: %+v", name, h)
		}
	}
}

func TestLoadSettingsRefusesWhatClaudeCodeRefuses(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(`{}`+strings.Repeat(" ", MaxSettingsBytes-2)), 0o600); err != nil {
		t.Fatal(err)
	}
	over := filepath.Join(dir, "over.json")
	if err := os.WriteFile(over, []byte(`{}`+strings.Repeat(" ", MaxSettingsBytes-1)), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ arg, want string }{
		"directory":       {dir, "not a regular file"},
		"fifo":            {fifo, "not a regular file"},
		"symlink to dir":  {link, "not a regular file"},
		"over 2 MiB":      {over, "over the 2 MiB limit"},
		"missing":         {filepath.Join(dir, "none.json"), "no such file"},
		"empty":           {"  ", "needs a file path"},
		"malformed":       {`{"hooks":`, "settings:"},
		"two documents":   {`{} {}`, "data after"},
		"command type":    {`{"hooks":{"Stop":[{"hooks":[{"type":"http","command":"x"}]}]}}`, "not modeled"},
		"if filter":       {`{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"x","if":"Bash(git *)"}]}]}}`, "if filter"},
		"powershell":      {`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x","shell":"powershell"}]}]}}`, "bash only"},
		"zero timeout":    {`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x","timeout":0}]}]}}`, "timeout must be positive"},
		"empty command":   {`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":""}]}]}}`, "command is empty"},
		"bad matcher":     {`{"hooks":{"PostToolUse":[{"matcher":"(","hooks":[{"type":"command","command":"x"}]}]}}`, "matcher"},
		"asyncRewake":     {`{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x","asyncRewake":true}]}]}}`, "asyncRewake"},
		"inline not json": {`{not json}`, "settings:"},
	} {
		_, err := LoadSettings(tc.arg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
	// exactly 2 MiB is allowed: the limit is "no larger than"
	if _, err := LoadSettings(big); err != nil {
		t.Errorf("a file of exactly 2 MiB: %v", err)
	}
}

func TestSettingsMatchersDedupAndUnmodeledEvents(t *testing.T) {
	s, err := ParseSettings([]byte(`{"hooks":{
	  "PostToolUse":[
	    {"matcher":"Write","hooks":[{"type":"command","command":"h","args":["1"]}]},
	    {"matcher":"Write|Read","hooks":[{"type":"command","command":"h","args":["1"]},{"type":"command","command":"h","args":["2"]}]},
	    {"matcher":"^Bash.*","hooks":[{"type":"command","command":"rx"}]},
	    {"hooks":[{"type":"command","command":"any"}]}],
	  "PostToolBatch":[{"matcher":"ignored","hooks":[{"type":"command","command":"b"}]}],
	  "SessionStart":[{"matcher":"resume","hooks":[{"type":"command","command":"r"}]},{"matcher":"startup","hooks":[{"type":"command","command":"s"}]}],
	  "PreToolUse":[{"hooks":[{"type":"command","command":"never"}]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	names := func(hs []HookSpec) string {
		var out []string
		for _, h := range hs {
			out = append(out, h.Display())
		}
		return strings.Join(out, ",")
	}
	for _, tc := range []struct {
		ev, subject, want string
	}{
		{EvPostToolUse, "Write", "h 1,h 2,any"}, // identical commands run once
		{EvPostToolUse, "Read", "h 1,h 2,any"},
		{EvPostToolUse, "Bash", "rx,any"},
		{EvPostToolUse, "WriteFile", "any"}, // exact names, not prefixes
		{EvPostToolBatch, "", "b"},          // no matcher on this event
		{EvSessionStart, "startup", "s"},
		{EvSessionStart, "resume", "r"},
		{"PreToolUse", "Write", ""},
	} {
		if got := names(s.HooksFor(tc.ev, tc.subject)); got != tc.want {
			t.Errorf("%s/%s: %q, want %q", tc.ev, tc.subject, got, tc.want)
		}
	}
	if len(s.Warnings) != 1 || !strings.Contains(s.Warnings[0], "PreToolUse") {
		t.Errorf("warnings: %q", s.Warnings)
	}
	off, _ := ParseSettings([]byte(`{"disableAllHooks":true,"hooks":{"Stop":[{"hooks":[{"type":"command","command":"x"}]}]}}`))
	if len(off.HooksFor(EvStop, "")) != 0 {
		t.Error("disableAllHooks did not disable the hooks")
	}
}

// The hooks reference: a matcher of only letters, digits, _, -, spaces, commas and | is an exact string or a list of
// exact strings separated by | or , with optional whitespace; anything else is a regular expression.
func TestMatcherExactListsAcceptCommasSpacesAndHyphens(t *testing.T) {
	fires := func(matcher, tool string) bool {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"hooks": map[string]any{"PostToolUse": []any{map[string]any{
			"matcher": matcher, "hooks": []any{map[string]any{"type": "command", "command": "h"}}}}}})
		s, err := ParseSettings(b)
		if err != nil {
			t.Fatalf("%q: %v", matcher, err)
		}
		return len(s.HooksFor(EvPostToolUse, tool)) == 1
	}
	for _, tc := range []struct {
		matcher, tool string
		want          bool
	}{
		{"Write,Edit", "Write", true}, {"Write,Edit", "Edit", true}, {"Write,Edit", "Read", false},
		{"Write, Edit", "Edit", true}, {"Write, Edit", "Write", true}, {"Write, Edit", " Edit", false},
		{"Write | Edit", "Write", true}, {"Write | Edit", "Edit", true}, {"Write | Edit", "Bash", false},
		{"Edit|Write", "Write", true}, {"Write,Edit", "Write,Edit", false}, {"Write,Edit", "WriteEdit", false},
		{"mcp__my-server__run", "mcp__my-server__run", true}, {"mcp__my-server__run", "xmcp__my-server__run", false},
		{"mcp__my-server__run", "mcp__my-server__running", false},
		{"my-tool, other", "my-tool", true}, {"my-tool, other", "other", true},
		// a character outside the exact class makes it a regular expression, unanchored
		{"Write.*", "WriteFile", true}, {"^Bash$", "Bash", true}, {"^Bash$", "xBash", false},
		{"mcp__.*__run", "mcp__a__run", true},
	} {
		if got := fires(tc.matcher, tc.tool); got != tc.want {
			t.Errorf("matcher %q on %q: fires %v, want %v", tc.matcher, tc.tool, got, tc.want)
		}
	}
}

func TestBareFromFlagOrEnvironment(t *testing.T) {
	for _, tc := range []struct {
		args, env []string
		want      bool
	}{
		{nil, nil, false},
		{[]string{"--bare"}, nil, true},
		{nil, []string{"CLAUDE_CODE_SIMPLE=1"}, true},
		{nil, []string{"CLAUDE_CODE_SIMPLE=0"}, false},
		{nil, []string{"CLAUDE_CODE_SIMPLE=1", "CLAUDE_CODE_SIMPLE=0"}, false},
	} {
		c, _ := parseArgs(tc.args)
		if got := bareMode(c, tc.env); got != tc.want {
			t.Errorf("%v %v: bare %v", tc.args, tc.env, got)
		}
	}
}
