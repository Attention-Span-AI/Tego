// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata")

// TestMain makes the test binary three programs. Run as `<binary> __fakeclaude__ args...` it is fakeclaude itself, so
// an integration test starts the program under test without a go build; as `<binary> __hook__ mode` it is a stand-in
// hook. Hooks are the small helpers the acceptance asks for: one prints a fixed additionalContext, one exits 2, and a
// few more cover the other rows of the exit-code table.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__fakeclaude__":
			os.Exit(run(os.Args[2:], os.Environ(), os.Stdout, os.Stderr))
		case "__hook__":
			os.Exit(hookMain(os.Args[2:]))
		}
	}
	os.Exit(testutil.GuardedMain(m))
}

// FixedContext is what the "context" stand-in hook prints; tests and report.py look for it in the next request.
const FixedContext = "stand-in hook: this is a fixed additionalContext"

// hookMain is the stand-in hook. It reads stdin, appends one line per call to $FAKECLAUDE_HOOK_LOG when set (the
// event name and the payload), and then acts by mode.
func hookMain(args []string) int {
	payload, _ := io.ReadAll(os.Stdin)
	var p struct {
		Event string `json:"hook_event_name"`
		Tool  string `json:"tool_name"`
		Stop  bool   `json:"stop_hook_active"`
	}
	_ = json.Unmarshal(payload, &p)
	if path := os.Getenv("FAKECLAUDE_HOOK_LOG"); path != "" {
		if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			fmt.Fprintf(f, "%s\n", payload)
			f.Close()
		}
	}
	mode := ""
	if len(args) > 0 {
		mode = args[0]
	}
	switch mode {
	case "context": // a fixed additionalContext, as hookSpecificOutput names the event
		out, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": p.Event, "additionalContext": FixedContext + " (" + p.Event + ")"}})
		fmt.Println(string(out))
	case "exit2": // a blocking exit with a reason on stderr
		fmt.Fprint(os.Stderr, "stand-in hook: exit 2 reason")
		return 2
	case "exit2-once": // exit 2 on the first Stop only: the repeat has stop_hook_active and passes
		if !p.Stop {
			fmt.Fprint(os.Stderr, "stand-in hook: keep going")
			return 2
		}
	case "exit2-always":
		fmt.Fprint(os.Stderr, "stand-in hook: never satisfied")
		return 2
	case "exit1":
		fmt.Fprint(os.Stderr, "stand-in hook: exit 1")
		return 1
	case "sleep":
		time.Sleep(time.Hour)
	case "plain":
		fmt.Println("plain text from a hook")
	case "big":
		fmt.Println(`{"hookSpecificOutput":{"hookEventName":"` + p.Event + `","additionalContext":"` + strings.Repeat("x", 12000) + `"}}`)
	case "json-block":
		fmt.Println(`{"decision":"block","reason":"stand-in hook: json block"}`)
	case "json-stop":
		fmt.Println(`{"continue":false,"stopReason":"stand-in hook: json stop"}`)
	}
	return 0
}

// hookSpec is a command hook in exec form that runs this test binary as the stand-in in the given mode.
func hookSpec(mode string) HookSpec {
	args := []string{"__hook__", mode}
	return HookSpec{Type: "command", Command: os.Args[0], Args: &args}
}

// settingsJSON builds an inline settings document registering the stand-in in mode for each event (a mode of ""
// registers nothing for it).
func settingsJSON(t testing.TB, modes map[string]string) string {
	t.Helper()
	return settingsFor(t, modes, os.Args[0])
}

// settingsFor is settingsJSON with the stand-in's command given.
func settingsFor(t testing.TB, modes map[string]string, command string) string {
	t.Helper()
	hooks := map[string]any{}
	for ev, mode := range modes {
		if mode == "" {
			continue
		}
		args := []string{"__hook__", mode}
		hooks[ev] = []any{map[string]any{"matcher": "*", "hooks": []any{map[string]any{
			"type": "command", "command": command, "args": args, "timeout": 10}}}}
	}
	b, err := json.Marshal(map[string]any{"hooks": hooks})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// golden compares got with testdata/cc-2.1.310/name.golden.json (re-indented), or rewrites it under -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(got, &v); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, got)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	path := filepath.Join("testdata", "cc-"+DocsVersion, name+".golden.json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run %s -update)", err, t.Name())
	}
	if !bytes.Equal(want, buf.Bytes()) {
		t.Errorf("%s differs from %s:\n got: %s\nwant: %s", name, path, buf.Bytes(), want)
	}
}
