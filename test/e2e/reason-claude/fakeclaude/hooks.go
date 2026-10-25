// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// The payloads below are the hooks reference's input shapes for Claude Code 2.1.310, field for field. Optional fields
// the reference marks as possibly absent are absent unless fakeclaude knows them; fields of events or tools that are
// not modeled (agent_id, agent_type, effort, scratchpad_dir) are never sent, as for a main agent without them.

type common struct {
	SessionID      string `json:"session_id"`
	PromptID       string `json:"prompt_id,omitempty"` // absent until the first user input, so absent at SessionStart
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	PermissionMode string `json:"permission_mode"`
	HookEventName  string `json:"hook_event_name"`
}

type sessionStartPayload struct {
	common
	Source string `json:"source"`
	Model  string `json:"model,omitempty"`
}

type postToolUsePayload struct {
	common
	ToolName     string         `json:"tool_name"`
	ToolInput    map[string]any `json:"tool_input"`
	ToolResponse any            `json:"tool_response"`
	ToolUseID    string         `json:"tool_use_id"`
	DurationMS   int64          `json:"duration_ms"`
}

type postToolUseFailurePayload struct {
	common
	ToolName    string         `json:"tool_name"`
	ToolInput   map[string]any `json:"tool_input"`
	ToolUseID   string         `json:"tool_use_id"`
	Error       string         `json:"error"`
	IsInterrupt bool           `json:"is_interrupt"`
	DurationMS  int64          `json:"duration_ms"`
}

type batchCall struct {
	ToolName     string         `json:"tool_name"`
	ToolInput    map[string]any `json:"tool_input"`
	ToolUseID    string         `json:"tool_use_id"`
	ToolResponse string         `json:"tool_response"` // the serialized tool_result content the model sees
}

type postToolBatchPayload struct {
	common
	ToolCalls []batchCall `json:"tool_calls"`
}

type stopPayload struct {
	common
	StopHookActive       bool   `json:"stop_hook_active"`
	LastAssistantMessage string `json:"last_assistant_message"`
	BackgroundTasks      []any  `json:"background_tasks"`
	SessionCrons         []any  `json:"session_crons"`
}

// marshalPayload is JSON.stringify's spelling: no HTML escaping, no trailing newline.
func marshalPayload(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // the payload types hold only strings, numbers, bools and maps of them
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

// A hookRun is one execution of one command hook.
type hookRun struct {
	Event    string
	Tool     string
	Spec     HookSpec
	Started  bool // false: the process could not be started
	ExitCode int
	TimedOut bool
	Stdout   string
	Stderr   string
	StartErr string
}

// hookWaitDelay is how long runHook waits for a hook's output pipes to close after the hook has exited; a variable so
// that a test can shorten it.
var hookWaitDelay = 2 * time.Second

// runHook runs a command hook in exec form (Args set) or shell form, as Claude Code does: stdin is the payload, the
// environment is the agent's own plus CLAUDE_PROJECT_DIR, the working directory is the session's, there is no
// terminal (the hook gets its own session), and the timeout is the hook's own, after which the process group is
// killed.
func runHook(spec HookSpec, payload []byte, cwd string, env []string) hookRun {
	r := hookRun{Spec: spec}
	timeout := time.Duration(spec.TimeoutSeconds() * float64(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var cmd *exec.Cmd
	if spec.Args != nil {
		cmd = exec.CommandContext(ctx, spec.Command, *spec.Args...)
	} else {
		cmd = exec.CommandContext(ctx, "bash", "-c", spec.Command)
	}
	cmd.Dir = cwd
	cmd.Env = append(append([]string(nil), env...), "CLAUDE_PROJECT_DIR="+cwd)
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr cappedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = hookWaitDelay
	err := cmd.Run()
	r.Stdout, r.Stderr = stdout.String(), stderr.String()
	var ee *exec.ExitError
	switch {
	case err == nil:
		r.Started = true
	case ctx.Err() != nil:
		r.Started, r.TimedOut, r.ExitCode = true, true, -1
	case errors.As(err, &ee):
		r.Started, r.ExitCode = true, ee.ExitCode()
	case errors.Is(err, exec.ErrWaitDelay):
		// The hook itself exited with success but a child it left behind still holds its stdout or stderr open. The
		// hook ran and answered: what it wrote before then is its output, read as for any other exit 0.
		r.Started, r.ExitCode = true, cmd.ProcessState.ExitCode()
	default:
		r.StartErr, r.ExitCode = err.Error(), -1
	}
	return r
}

// An outcome is what the harness does with a hook's result.
type outcome struct {
	Context    []string // additionalContext: delivered as notes (systemMessage), Stop's as a system reminder
	Feedback   []string // text for the model that is not a note: exit-2 stderr, a block reason
	User       []string // shown to the user only
	StopLoop   bool     // end the agentic loop before the next model call
	Continue   bool     // Stop only: the conversation goes on
	StopReason string
}

func (o *outcome) merge(p outcome) {
	o.Context = append(o.Context, p.Context...)
	o.Feedback = append(o.Feedback, p.Feedback...)
	o.User = append(o.User, p.User...)
	o.StopLoop = o.StopLoop || p.StopLoop
	o.Continue = o.Continue || p.Continue
	if o.StopReason == "" {
		o.StopReason = p.StopReason
	}
}

type hookJSON struct {
	Continue           *bool  `json:"continue"`
	StopReason         string `json:"stopReason"`
	SystemMessage      string `json:"systemMessage"`
	Decision           string `json:"decision"`
	Reason             string `json:"reason"`
	HookSpecificOutput *struct {
		HookEventName     string `json:"hookEventName"`
		AdditionalContext string `json:"additionalContext"`
	} `json:"hookSpecificOutput"`
}

// interpret applies the hooks reference's exit-code table and JSON output rules to one run.
//
//	exit 0: stdout is JSON only when the whole of it is one object; SessionStart's plain stdout is context; other
//	        events' plain stdout is nothing the model sees. Claude never sees stderr of an exit-0 hook.
//	exit 2: PostToolUse and PostToolUseFailure show stderr to Claude; Stop is blocked from stopping, stderr the
//	        reason; PostToolBatch stops the loop; SessionStart's stderr goes to the user only. Stdout JSON is ignored.
//	other:  a non-blocking error: one line for the user, nothing for the model, the action proceeds.
func interpret(r hookRun) outcome {
	var o outcome
	ev := r.Event
	label := ev
	if r.Tool != "" {
		label = ev + ":" + r.Tool
	}
	switch {
	case !r.Started:
		o.User = append(o.User, fmt.Sprintf("%s hook error: could not start %q: %s", label, r.Spec.Display(), r.StartErr))
		return o
	case r.TimedOut:
		o.User = append(o.User, fmt.Sprintf("%s hook error: %q timed out after %gs", label, r.Spec.Display(), r.Spec.TimeoutSeconds()))
		return o
	case r.ExitCode == 2:
		return interpretExit2(r, label)
	case r.ExitCode != 0:
		o.User = append(o.User, fmt.Sprintf("%s hook error: %q Failed with non-blocking status code: %d", label, r.Spec.Display(), r.ExitCode))
		return o
	}
	var j hookJSON
	dec := json.NewDecoder(strings.NewReader(r.Stdout))
	if strings.HasPrefix(strings.TrimSpace(r.Stdout), "{") && dec.Decode(&j) == nil && !dec.More() {
		return interpretJSON(r, j)
	}
	if ev == EvSessionStart && strings.TrimSpace(r.Stdout) != "" {
		o.Context = append(o.Context, strings.TrimRight(r.Stdout, "\n"))
	}
	return o
}

func blockingText(r hookRun, text string) string {
	label := r.Event
	if r.Tool != "" {
		label += ":" + r.Tool
	}
	return fmt.Sprintf("%s hook blocking error from command: \"%s\": %s", label, r.Spec.Display(), strings.TrimSpace(text))
}

func interpretExit2(r hookRun, label string) outcome {
	var o outcome
	switch r.Event {
	case EvPostToolUse, EvPostToolUseFailure:
		o.Feedback = append(o.Feedback, blockingText(r, r.Stderr))
	case EvStop:
		o.Feedback = append(o.Feedback, blockingText(r, r.Stderr))
		o.Continue = true
	case EvPostToolBatch:
		o.StopLoop = true
		o.StopReason = strings.TrimSpace(r.Stderr)
		o.User = append(o.User, fmt.Sprintf("%s hook stopped the loop: %s", label, strings.TrimSpace(r.Stderr)))
	default: // SessionStart: "shows stderr to the user only"
		o.User = append(o.User, strings.TrimSpace(r.Stderr))
	}
	return o
}

func interpretJSON(r hookRun, j hookJSON) outcome {
	var o outcome
	if j.SystemMessage != "" {
		o.User = append(o.User, j.SystemMessage)
	}
	if j.HookSpecificOutput != nil && j.HookSpecificOutput.AdditionalContext != "" {
		o.Context = append(o.Context, j.HookSpecificOutput.AdditionalContext)
		if r.Event == EvStop {
			o.Continue = true // additionalContext on Stop keeps the conversation going, through the same loop guards
		}
	}
	if j.Decision == "block" {
		switch r.Event {
		case EvPostToolUse:
			o.Feedback = append(o.Feedback, blockingText(r, j.Reason))
		case EvPostToolBatch:
			o.StopLoop, o.StopReason = true, j.Reason
		case EvStop:
			o.Feedback = append(o.Feedback, blockingText(r, j.Reason))
			o.Continue = true
		}
	}
	if j.Continue != nil && !*j.Continue {
		o.StopLoop, o.Continue = true, false
		o.StopReason = j.StopReason
		o.User = append(o.User, "hook stopped the session: "+j.StopReason)
	}
	return o
}

const (
	contextCap     = 10000
	contextPreview = 2000
)

// capContext applies the reference's cap on a hook's text: over 10,000 characters it is written to a file and
// replaced with the path and a 2,000-character preview. spill writes the file and returns its path.
func capContext(s string, spill func(string) (string, error)) string {
	n := utf8.RuneCountInString(s)
	if n <= contextCap {
		return s
	}
	path, err := spill(s)
	if err != nil {
		path = "(not saved: " + err.Error() + ")"
	}
	preview := string([]rune(s)[:contextPreview])
	return fmt.Sprintf("Output too large (%d characters). Full output saved to: %s\n\nPreview (first %d characters):\n%s", n, path, contextPreview, preview)
}

func writeSpill(dir, name, s string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := dir + string(os.PathSeparator) + name
	return p, os.WriteFile(p, []byte(s), 0o600)
}
