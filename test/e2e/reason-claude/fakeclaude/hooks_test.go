// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixedCommon(event string, withPrompt bool) common {
	c := common{
		SessionID: "abc123", TranscriptPath: "/home/user/.claude/projects/-work/abc123.jsonl",
		Cwd: "/work", PermissionMode: "default", HookEventName: event,
	}
	if withPrompt {
		c.PromptID = "550e8400-e29b-41d4-a716-446655440000"
	}
	return c
}

// Each payload is compared with a golden dated against the Claude Code 2.1.310 hooks reference. The goldens are the
// reference's own examples where it has one (PostToolUse for Write, PostToolUseFailure for Bash, PostToolBatch for two
// Reads, Stop) and the same field set filled in for the rest.
func TestPayloadShapes(t *testing.T) {
	writeIn := map[string]any{"file_path": "/work/note.txt", "content": "file content"}
	bashIn := map[string]any{"command": "npm test", "description": "Run test suite", "run_in_background": false}
	cases := map[string]any{
		"session-start":          sessionStartPayload{common: fixedCommon(EvSessionStart, false), Source: "startup", Model: "claude-stub-1"},
		"session-start-no-model": sessionStartPayload{common: fixedCommon(EvSessionStart, false), Source: "startup"},
		"post-tool-use-write": postToolUsePayload{common: fixedCommon(EvPostToolUse, true), ToolName: "Write", ToolInput: writeIn,
			ToolResponse: map[string]any{"filePath": "/work/note.txt", "type": "create"}, ToolUseID: "toolu_01ABC123", DurationMS: 12},
		"post-tool-use-bash": postToolUsePayload{common: fixedCommon(EvPostToolUse, true), ToolName: "Bash", ToolInput: bashIn,
			ToolResponse: map[string]any{"stdout": "ok\n", "stderr": "", "interrupted": false, "isImage": false}, ToolUseID: "toolu_01ABC124", DurationMS: 31},
		"post-tool-use-read": postToolUsePayload{common: fixedCommon(EvPostToolUse, true), ToolName: "Read", ToolInput: map[string]any{"file_path": "/work/note.txt"},
			ToolResponse: map[string]any{"type": "text", "file": map[string]any{"filePath": "/work/note.txt", "content": "a\nb\n", "numLines": 2, "startLine": 1, "totalLines": 2}},
			ToolUseID:    "toolu_01ABC125", DurationMS: 3},
		"post-tool-use-failure-bash": postToolUseFailurePayload{common: fixedCommon(EvPostToolUseFailure, true), ToolName: "Bash", ToolInput: bashIn,
			ToolUseID: "toolu_01ABC126", Error: "Exit code 1\nError: Cannot find module 'express'", DurationMS: 4187},
		"post-tool-batch": postToolBatchPayload{common: fixedCommon(EvPostToolBatch, true), ToolCalls: []batchCall{
			{ToolName: "Read", ToolInput: map[string]any{"file_path": "/work/a.py"}, ToolUseID: "toolu_01", ToolResponse: "1\tfrom __future__ import annotations\n"},
			{ToolName: "Write", ToolInput: writeIn, ToolUseID: "toolu_02", ToolResponse: "File created successfully at: /work/note.txt"},
		}},
		"stop": stopPayload{common: fixedCommon(EvStop, true), LastAssistantMessage: "I've completed the refactoring.",
			BackgroundTasks: []any{}, SessionCrons: []any{}},
		"stop-repeat": stopPayload{common: fixedCommon(EvStop, true), StopHookActive: true, LastAssistantMessage: "Done again.",
			BackgroundTasks: []any{}, SessionCrons: []any{}},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) { golden(t, name, marshalPayload(p)) })
	}
}

func TestPayloadIsJSONStringifyShaped(t *testing.T) {
	b := marshalPayload(stopPayload{common: fixedCommon(EvStop, true), LastAssistantMessage: "a <b> & c"})
	if strings.HasSuffix(string(b), "\n") || !strings.Contains(string(b), "a <b> & c") {
		t.Errorf("payload %q: a trailing newline or HTML escaping", b)
	}
}

func run1(t *testing.T, event, tool string, spec HookSpec) outcome {
	t.Helper()
	r := runHook(spec, []byte(`{"hook_event_name":"`+event+`"}`), t.TempDir(), os.Environ())
	r.Event, r.Tool = event, tool
	return interpret(r)
}

func TestInterpretFollowsTheExitCodeTable(t *testing.T) {
	// the context stand-in prints one JSON object with additionalContext, exit 0
	for _, ev := range []string{EvSessionStart, EvPostToolUse, EvPostToolUseFailure, EvPostToolBatch} {
		o := run1(t, ev, "Write", hookSpec("context"))
		if len(o.Context) != 1 || !strings.Contains(o.Context[0], FixedContext) || len(o.Feedback)+len(o.User) != 0 || o.StopLoop {
			t.Errorf("%s exit 0 + additionalContext: %+v", ev, o)
		}
	}
	// exit 2: stderr reaches the model for the two tool events, stops the loop on the batch, only the user sees it
	// at SessionStart, and Stop is blocked
	for _, ev := range []string{EvPostToolUse, EvPostToolUseFailure} {
		o := run1(t, ev, "Bash", hookSpec("exit2"))
		if len(o.Feedback) != 1 || !strings.Contains(o.Feedback[0], "exit 2 reason") || !strings.Contains(o.Feedback[0], ev+":Bash") || o.StopLoop || o.Continue {
			t.Errorf("%s exit 2: %+v", ev, o)
		}
	}
	if o := run1(t, EvPostToolBatch, "", hookSpec("exit2")); !o.StopLoop || len(o.Feedback) != 0 || len(o.User) != 1 {
		t.Errorf("PostToolBatch exit 2: %+v", o)
	}
	if o := run1(t, EvSessionStart, "", hookSpec("exit2")); len(o.Feedback) != 0 || len(o.Context) != 0 || o.StopLoop || len(o.User) != 1 || o.User[0] != "stand-in hook: exit 2 reason" {
		t.Errorf("SessionStart exit 2: %+v", o)
	}
	if o := run1(t, EvStop, "", hookSpec("exit2")); !o.Continue || len(o.Feedback) != 1 || !strings.Contains(o.Feedback[0], "exit 2 reason") {
		t.Errorf("Stop exit 2: %+v", o)
	}
	// any other exit code is a non-blocking error: the user sees one line, the model nothing
	for _, ev := range []string{EvPostToolUse, EvStop} {
		o := run1(t, ev, "", hookSpec("exit1"))
		if len(o.User) != 1 || !strings.Contains(o.User[0], "non-blocking status code: 1") || len(o.Feedback)+len(o.Context) != 0 || o.Continue || o.StopLoop {
			t.Errorf("%s exit 1: %+v", ev, o)
		}
	}
	// plain stdout is context at SessionStart and nothing elsewhere
	if o := run1(t, EvSessionStart, "", hookSpec("plain")); len(o.Context) != 1 || o.Context[0] != "plain text from a hook" {
		t.Errorf("SessionStart plain stdout: %+v", o)
	}
	if o := run1(t, EvPostToolUse, "Write", hookSpec("plain")); len(o.Context)+len(o.Feedback) != 0 {
		t.Errorf("PostToolUse plain stdout: %+v", o)
	}
	// JSON decisions
	if o := run1(t, EvPostToolBatch, "", hookSpec("json-block")); !o.StopLoop {
		t.Errorf("PostToolBatch decision block: %+v", o)
	}
	if o := run1(t, EvPostToolUse, "Write", hookSpec("json-block")); len(o.Feedback) != 1 || o.StopLoop {
		t.Errorf("PostToolUse decision block: %+v", o)
	}
	if o := run1(t, EvStop, "", hookSpec("json-block")); !o.Continue || len(o.Feedback) != 1 {
		t.Errorf("Stop decision block: %+v", o)
	}
	if o := run1(t, EvPostToolUse, "Write", hookSpec("json-stop")); !o.StopLoop || o.StopReason != "stand-in hook: json stop" {
		t.Errorf("continue false: %+v", o)
	}
}

func TestExitTwoIgnoresJSONOnStdout(t *testing.T) {
	// "Exit 2 blocks even if the hook also prints JSON": stdout is not read at all
	r := hookRun{Event: EvPostToolUse, Tool: "Write", Spec: hookSpec("x"), Started: true, ExitCode: 2,
		Stdout: `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"ignored"}}`, Stderr: "blocked"}
	if o := interpret(r); len(o.Context) != 0 || len(o.Feedback) != 1 {
		t.Errorf("%+v", o)
	}
}

func TestStdoutIsJSONOnlyWhenItIsOneObject(t *testing.T) {
	r := hookRun{Event: EvPostToolUse, Tool: "Write", Spec: hookSpec("x"), Started: true,
		Stdout: `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"a"}} trailing`}
	if o := interpret(r); len(o.Context) != 0 {
		t.Errorf("an object with text after it was read as JSON: %+v", o)
	}
	r.Stdout = " \n{\"hookSpecificOutput\":{\"hookEventName\":\"PostToolUse\",\"additionalContext\":\"a\"}}\n"
	if o := interpret(r); len(o.Context) != 1 {
		t.Errorf("an object with only whitespace around it was not read: %+v", o)
	}
}

func TestRunHookExecFormShellFormTimeoutAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	// exec form: the payload is on stdin, the arguments are not split by a shell
	args := []string{"__hook__", "context"}
	r := runHook(HookSpec{Type: "command", Command: os.Args[0], Args: &args}, []byte(`{"hook_event_name":"PostToolUse"}`), dir, os.Environ())
	if !r.Started || r.ExitCode != 0 || !strings.Contains(r.Stdout, "additionalContext") {
		t.Fatalf("exec form: %+v", r)
	}
	// shell form goes through bash: a pipe works, and CLAUDE_PROJECT_DIR is the session's directory
	r = runHook(HookSpec{Type: "command", Command: `cat | wc -c; echo "$CLAUDE_PROJECT_DIR" >&2; pwd >&2`}, []byte("12345"), dir, os.Environ())
	if r.ExitCode != 0 || strings.TrimSpace(strings.SplitN(r.Stdout, "\n", 2)[0]) != "5" || strings.Count(r.Stderr, dir) != 2 {
		t.Errorf("shell form: %+v", r)
	}
	// exec form has no shell: a metacharacter is an ordinary argument
	marker := filepath.Join(dir, "marker")
	a2 := []string{"x; touch " + marker}
	r = runHook(HookSpec{Type: "command", Command: "echo", Args: &a2}, nil, dir, os.Environ())
	if _, err := os.Stat(marker); err == nil || r.ExitCode != 0 {
		t.Errorf("exec form ran a shell: %+v", r)
	}
	// a command that is not there is a start error, not an exit status
	r = runHook(HookSpec{Type: "command", Command: "/nonexistent/hook", Args: &[]string{}}, nil, dir, os.Environ())
	if r.Started || r.StartErr == "" {
		t.Errorf("missing command: %+v", r)
	}
	// the timeout kills the hook and what it started (its own session)
	timeout := 0.3
	sleepArgs := []string{"__hook__", "sleep"}
	start := time.Now()
	r = runHook(HookSpec{Type: "command", Command: os.Args[0], Args: &sleepArgs, Timeout: &timeout}, nil, dir, os.Environ())
	if !r.TimedOut || time.Since(start) > 5*time.Second {
		t.Errorf("timeout: %+v after %v", r, time.Since(start))
	}
	o := interpret(hookRun{Event: EvStop, Spec: HookSpec{Command: "x"}, Started: true, TimedOut: true})
	if len(o.User) != 1 || o.Continue || o.StopLoop {
		t.Errorf("a timeout is a non-blocking error: %+v", o)
	}
}

// A hook that exits 0 but leaves a background child holding its stdout open has still answered: its additionalContext
// is delivered, and the run is not reported as a start failure.
func TestHookThatLeavesAChildHoldingStdoutStillAnswers(t *testing.T) {
	old := hookWaitDelay
	hookWaitDelay = 150 * time.Millisecond
	defer func() { hookWaitDelay = old }()
	cmd := `printf '%s' '{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"CTX"}}'; sleep 2 & exit 0`
	r := runHook(HookSpec{Type: "command", Command: cmd}, nil, t.TempDir(), os.Environ())
	if !r.Started || r.StartErr != "" || r.TimedOut || r.ExitCode != 0 {
		t.Fatalf("run: %+v", r)
	}
	r.Event, r.Tool = EvPostToolUse, "Write"
	if o := interpret(r); len(o.Context) != 1 || o.Context[0] != "CTX" || len(o.User) != 0 {
		t.Errorf("outcome: %+v", o)
	}
}

func TestContextOverTenThousandCharactersSpillsToAFile(t *testing.T) {
	dir := t.TempDir()
	small := strings.Repeat("é", contextCap)
	if got := capContext(small, nil); got != small {
		t.Error("10,000 characters were changed")
	}
	big := strings.Repeat("é", contextCap+1)
	got := capContext(big, func(s string) (string, error) { return writeSpill(dir, "c.txt", s) })
	if !strings.Contains(got, filepath.Join(dir, "c.txt")) || strings.Count(got, "é") != contextPreview || !strings.Contains(got, "10001 characters") {
		t.Errorf("spilled form: %.200q", got)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "c.txt")); err != nil || string(b) != big {
		t.Errorf("spill file: %v", err)
	}
}

func TestHookJSONOutputShapes(t *testing.T) {
	var j hookJSON
	if err := json.Unmarshal([]byte(`{"continue":false,"stopReason":"x","systemMessage":"w","decision":"block","reason":"r","hookSpecificOutput":{"hookEventName":"Stop","additionalContext":"c"}}`), &j); err != nil {
		t.Fatal(err)
	}
	if j.Continue == nil || *j.Continue || j.StopReason != "x" || j.HookSpecificOutput.AdditionalContext != "c" {
		t.Errorf("%+v", j)
	}
}
