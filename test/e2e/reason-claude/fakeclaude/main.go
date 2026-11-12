// SPDX-License-Identifier: Apache-2.0

// Command fakeclaude is a stand-in for the Claude Code CLI for tests of anything that sits beside it: a hook, a
// settings file, a launcher. It models the harness side of Claude Code's public protocol and nothing else: it reads
// --settings as Claude Code does, performs a script's tool calls as itself with real system calls, calls the
// configured hooks with the documented payloads, and posts each next request, with the tool results and the hooks'
// text, to the model stub at ANTHROPIC_BASE_URL. README.md says what is and is not modeled.
//
// Usage: fakeclaude [--settings FILE|JSON] [--bare] [--script FILE] [--result FILE] [--cwd DIR] [--session-id ID]
// [--model NAME] [-p] [prompt]
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// batchHookDelay is how long after a turn's last call (and its hooks) PostToolBatch's hooks start: the real
// binary's started 13 ms after a refused Write's last system call (RESULTS.md R7). A refusal reaches the reason file
// up to 10 ms after the system call (the ledger's refusalWindow), so a stand-in that ran PostToolBatch at once would
// tell a late refusal one request later than the real binary does; the margin here is wider than the real binary's
// so that a loaded CI runner does not cross it.
const batchHookDelay = 50 * time.Millisecond

// defaultStopContinuationCap is how many times in a row Claude Code lets Stop hooks continue a turn before it ends it;
// CLAUDE_CODE_STOP_HOOK_BLOCK_CAP raises it (hooks reference, Stop).
const defaultStopContinuationCap = 8

// stopCap reads CLAUDE_CODE_STOP_HOOK_BLOCK_CAP: a positive integer, else the default.
func stopCap(env []string) int {
	if n, err := strconv.Atoi(strings.TrimSpace(getenv(env, "CLAUDE_CODE_STOP_HOOK_BLOCK_CAP"))); err == nil && n > 0 {
		return n
	}
	return defaultStopContinuationCap
}

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

type config struct {
	settingsArg   string
	settingsGiven bool // --settings was on the command line, whatever its value
	scriptPath    string
	resultPath    string
	cwd           string
	sessionID     string
	model         string
	spillDir      string
	sessionSocket bool
	bare          bool
	prompt        string
}

var (
	valueFlags   = map[string]bool{"--settings": true, "--script": true, "--result": true, "--cwd": true, "--session-id": true, "--model": true, "--spill-dir": true}
	ignoredValue = map[string]bool{"--permission-mode": true, "--output-format": true, "--allowedTools": true, "--allowed-tools": true, "--append-system-prompt": true, "--max-turns": true}
	boolFlags    = map[string]bool{"--bare": true, "--session-socket": true, "-p": true, "--print": true, "--verbose": true}
)

// parseArgs reads the command line. A flag's value is the next argv element whole (or follows =), so inline settings
// JSON with spaces needs no quoting inside this program. Flags of the real CLI that change nothing here are accepted
// and ignored; any other flag is an error, so a typo does not pass unseen.
func parseArgs(args []string) (config, error) {
	var c config
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			for _, p := range args[i+1:] {
				if err := c.positional(p); err != nil {
					return c, err
				}
			}
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			if err := c.positional(a); err != nil {
				return c, err
			}
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		switch {
		case boolFlags[name]:
			if hasVal {
				return c, fmt.Errorf("%s takes no value", name)
			}
			if name == "--session-socket" {
				c.sessionSocket = true
			}
			if name == "--bare" {
				c.bare = true
			}
		case valueFlags[name] || ignoredValue[name]:
			if !hasVal {
				if i+1 >= len(args) {
					return c, fmt.Errorf("%s needs a value", name)
				}
				i++
				val = args[i]
			}
			// An empty value is never "not given": a launcher that expands an unset variable into --script, --result
			// or --cwd would otherwise get a run with no script, no result file or another directory, unseen.
			// (--settings is refused by LoadSettings with its own message.)
			if val == "" && valueFlags[name] && name != "--settings" {
				return c, fmt.Errorf("%s needs a non-empty value", name)
			}
			switch name {
			case "--settings":
				c.settingsArg, c.settingsGiven = val, true // the last one wins, as an option given twice does
			case "--script":
				c.scriptPath = val
			case "--result":
				c.resultPath = val
			case "--cwd":
				c.cwd = val
			case "--session-id":
				c.sessionID = val
			case "--model":
				c.model = val
			case "--spill-dir":
				c.spillDir = val
			}
		default:
			return c, fmt.Errorf("unknown flag %s", name)
		}
	}
	return c, nil
}

func (c *config) positional(p string) error {
	if c.prompt != "" {
		return fmt.Errorf("a second prompt argument %q", p)
	}
	c.prompt = p
	return nil
}

func getenv(env []string, key string) string {
	v := ""
	for _, e := range env {
		if k, val, ok := strings.Cut(e, "="); ok && k == key {
			v = val // the last entry wins, as in a process's environment
		}
	}
	return v
}

// bareMode is true for --bare, which "sets CLAUDE_CODE_SIMPLE", and for CLAUDE_CODE_SIMPLE=1 in the environment.
// A bare session runs no hook at all, those of --settings included ("Minimal mode: skip hooks", claude --help
// 2.1.310; measured: RESULTS.md R2): the settings are still read and checked.
func bareMode(c config, env []string) bool {
	return c.bare || truthy(getenv(env, "CLAUDE_CODE_SIMPLE"))
}

func truthy(s string) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Summary is what a run did, written to --result for report.py and tests to read.
type Summary struct {
	DocsVersion       string       `json:"docs_version"`
	SessionID         string       `json:"session_id"`
	Bare              bool         `json:"bare"`
	Requests          []RequestRec `json:"requests"`
	Turns             []TurnRec    `json:"turns"`
	Hooks             []HookRec    `json:"hooks"`
	Ended             string       `json:"ended"`
	StopContinuations int          `json:"stop_continuations"`
	FinalText         string       `json:"final_text"`
	Error             string       `json:"error,omitempty"`
}

// RequestRec is one POST to the model: how many messages it carried, how the stub answered, and whether the stub's
// tool_use blocks are the script turn's tools (for the request that begins a script turn).
type RequestRec struct {
	N          int          `json:"n"`
	Messages   int          `json:"messages"`
	Status     int          `json:"status"`
	StopReason string       `json:"stop_reason"`
	ToolUses   []toolUseRef `json:"tool_uses"`
	Agrees     *bool        `json:"agrees_with_script,omitempty"`
}

type TurnRec struct {
	Index    int       `json:"index"`
	Parallel bool      `json:"parallel"`
	Calls    []CallRec `json:"calls"`
}

type CallRec struct {
	ToolUseID string         `json:"tool_use_id"`
	Tool      string         `json:"tool"`
	Input     map[string]any `json:"input"`
	OK        bool           `json:"ok"`
	Error     string         `json:"error,omitempty"`
	// Skipped is a call that did not run because an earlier call's hook said continue:false.
	Skipped bool `json:"skipped,omitempty"`
}

type HookRec struct {
	Event    string `json:"event"`
	Tool     string `json:"tool,omitempty"`
	Command  string `json:"command"`
	Exit     int    `json:"exit"`
	TimedOut bool   `json:"timed_out,omitempty"`
	Started  bool   `json:"started"`
	Async    bool   `json:"async,omitempty"`
	// Stdout and Stderr are the hook's own output, cut to recordedOutput bytes: a hook that exits 0 with a warning on
	// stderr says nothing to the model, and the result is the only place a test can read why.
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	// Recorded is when the stand-in took the hook's result (after every hook of its event ended), in UTC, to set
	// against the ledger's ts of a refusal the hook did or did not tell.
	Recorded string `json:"recorded,omitempty"`
	// Began is when the hook's process was started, in UTC: report.py e2e --result sets it against the ledger's ts of
	// a refusal and against the other hooks' Recorded (README.md, "End to end").
	Began string `json:"began,omitempty"`
	// ReasonSeq is the reason file's seq the stand-in read just before starting the hook (hookRun.ReasonSeq):
	// report.py e2e --result fails a tool hook that found a refusal listed this way, ended before the hook that told
	// it began, and left it out.
	ReasonSeq *int64 `json:"reason_seq,omitempty"`
}

// began is a hook's start as the result records it, "" for a hook that never started.
func began(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// recordedOutput is how much of a hook's stdout and stderr the result keeps.
const recordedOutput = 4096

// recorded is s cut to recordedOutput bytes.
func recorded(s string) string {
	if len(s) > recordedOutput {
		return s[:recordedOutput]
	}
	return s
}

type agent struct {
	cfg      config
	set      *Settings
	script   *Script
	env      []string
	cwd      string
	bare     bool
	stopCap  int
	cl       *client
	stderr   io.Writer
	promptID string

	mu     sync.Mutex // guards sum and stderr
	sum    Summary
	spillN atomic.Int32
	bg     sync.WaitGroup
}

func run(args, env []string, stdout, stderr io.Writer) int {
	cfg, err := parseArgs(args)
	if err != nil {
		fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
		return 2
	}
	a := &agent{cfg: cfg, env: env, stderr: stderr}
	a.bare = bareMode(cfg, env)
	a.stopCap = stopCap(env)
	if cfg.settingsGiven { // an empty value is refused by LoadSettings, never read as "no settings"
		if a.set, err = LoadSettings(cfg.settingsArg); err != nil {
			fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
			return 1
		}
		for _, w := range a.set.Warnings {
			fmt.Fprintf(stderr, "fakeclaude: %s\n", w)
		}
	}
	if cfg.scriptPath != "" {
		data, err := readRegular(cfg.scriptPath, maxScriptBytes)
		if err == nil {
			a.script, err = ParseScript(data)
		}
		if err != nil {
			if errors.Is(err, errNotRegular) {
				err = fmt.Errorf("script file %s is not a regular file", cfg.scriptPath)
			}
			fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
			return 1
		}
	} else {
		a.script = &Script{}
	}
	a.cwd = cfg.cwd
	if a.cwd == "" {
		if a.cwd, err = os.Getwd(); err != nil {
			fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
			return 1
		}
	}
	if a.cwd, err = filepath.Abs(a.cwd); err != nil {
		fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
		return 1
	}
	// Optional startup probe for the interactive examples: real Claude Code binds
	// a session socket under XDG_RUNTIME_DIR/cc-socks before using its tools.
	if cfg.sessionSocket {
		base := getenv(env, "XDG_RUNTIME_DIR")
		if base == "" {
			base = getenv(env, "CLAUDE_CODE_TMPDIR")
		}
		if base == "" {
			base = os.TempDir()
		}
		path, err := sessionSocketPath(base, os.Getuid(), os.Getpid())
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		socket, err := net.Listen("unix", path)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		defer socket.Close() //nolint:errcheck // startup fixture endpoint
		peer, err := net.DialTimeout("unix", socket.Addr().String(), 5*time.Second)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		_ = peer.Close() // the probe needs only the run-local connection
		fmt.Fprintln(stdout, "fakeclaude session socket:", path)
	}

	model := cfg.model
	if model == "" {
		model = getenv(env, "ANTHROPIC_MODEL")
	}
	clModel := model
	if clModel == "" {
		clModel = "claude-stub-1"
	}
	if a.cl, err = newClient(getenv(env, "ANTHROPIC_BASE_URL"), getenv(env, "ANTHROPIC_API_KEY"), clModel); err != nil {
		fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
		return 2
	}
	a.sum = Summary{DocsVersion: DocsVersion, Bare: a.bare, SessionID: cfg.sessionID, Requests: []RequestRec{}, Turns: []TurnRec{}, Hooks: []HookRec{}}
	if a.sum.SessionID == "" {
		a.sum.SessionID = uuid()
	}
	a.promptID = uuid()
	if a.cfg.spillDir == "" {
		a.cfg.spillDir = filepath.Join(os.TempDir(), "fakeclaude-"+a.sum.SessionID)
	}

	code := 0
	if err := a.loop(context.Background(), model); err != nil {
		fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
		a.sum.Error = err.Error()
		code = 1
	}
	a.bg.Wait()
	if a.sum.FinalText != "" {
		fmt.Fprintln(stdout, a.sum.FinalText)
	}
	if cfg.resultPath != "" {
		if err := writeJSON(cfg.resultPath, a.sum); err != nil {
			fmt.Fprintf(stderr, "fakeclaude: %v\n", err)
			code = 1
		}
	}
	return code
}

// sessionSocketPath models installed Claude Code 2.1.318, including the stricter
// application threshold that selects a shared fallback before sun_path overflows.
func sessionSocketPath(runtime string, uid, pid int) (string, error) {
	leaf := strconv.Itoa(pid) + ".sock"
	path, err := filepath.Abs(filepath.Join(runtime, "cc-socks", leaf))
	if err != nil {
		return "", err
	}
	if len(path) > 103 {
		return filepath.Join("/tmp", "cc-socks-"+strconv.Itoa(uid), leaf), nil
	}
	return path, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]`)

// transcriptPath is where Claude Code keeps the session's transcript. fakeclaude names the path in the payloads and
// never creates it (the reference says the file is written asynchronously and may lag), so it touches no config dir.
func (a *agent) transcriptPath() string {
	dir := getenv(a.env, "CLAUDE_CONFIG_DIR")
	if dir == "" {
		dir = filepath.Join(getenv(a.env, "HOME"), ".claude")
	}
	return filepath.Join(dir, "projects", nonAlnum.ReplaceAllString(a.cwd, "-"), a.sum.SessionID+".jsonl")
}

func (a *agent) common(event string, withPrompt bool) common {
	c := common{SessionID: a.sum.SessionID, TranscriptPath: a.transcriptPath(), Cwd: a.cwd, PermissionMode: "default", HookEventName: event}
	if withPrompt {
		c.PromptID = a.promptID
	}
	return c
}

func (a *agent) userf(format string, args ...any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fmt.Fprintf(a.stderr, format+"\n", args...)
}

func (a *agent) record(f func(*Summary)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f(&a.sum)
}

// fire runs the hooks registered for an event, concurrently as Claude Code does, and applies their results in the
// order they are listed. Async hooks are started and not waited for; their output is not used.
func (a *agent) fire(event, tool, subject string, payload []byte) outcome {
	if a.bare {
		return outcome{}
	}
	specs := a.set.HooksFor(event, subject)
	runs := make([]hookRun, len(specs))
	var wg sync.WaitGroup
	for i, s := range specs {
		if s.Async {
			a.bg.Add(1)
			go func() {
				defer a.bg.Done()
				r := runHook(s, payload, a.cwd, a.env)
				a.recordHook(event, tool, r, true)
			}()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			runs[i] = runHook(s, payload, a.cwd, a.env)
		}()
	}
	wg.Wait()
	var out outcome
	for i, r := range runs {
		if specs[i].Async {
			continue
		}
		r.Event, r.Tool = event, tool
		a.recordHook(event, tool, r, false)
		out.merge(interpret(r))
	}
	for i, c := range out.Context {
		out.Context[i] = capContext(c, func(s string) (string, error) {
			return writeSpill(a.cfg.spillDir, fmt.Sprintf("hook-context-%d.txt", a.spillN.Add(1)), s)
		})
	}
	for _, u := range out.User {
		a.userf("%s", u)
	}
	return out
}

func (a *agent) recordHook(event, tool string, r hookRun, async bool) {
	a.record(func(s *Summary) {
		s.Hooks = append(s.Hooks, HookRec{Event: event, Tool: tool, Command: r.Spec.Display(), Exit: r.ExitCode, TimedOut: r.TimedOut, Started: r.Started, Async: async,
			Stdout: recorded(r.Stdout), Stderr: recorded(r.Stderr), Recorded: time.Now().UTC().Format(time.RFC3339Nano),
			Began: began(r.Began), ReasonSeq: r.ReasonSeq})
	})
}

// delivered is an outcome as the next request carries it: each additionalContext as a note for the system message
// (systemMessage), each piece of feedback (exit-2 stderr, a block reason) as a plain text block of the user message.
func delivered(o outcome, label string) (notes []string, feedback []any) {
	for _, c := range o.Context {
		notes = append(notes, note(label, c))
	}
	for _, f := range o.Feedback {
		feedback = append(feedback, text(f))
	}
	return notes, feedback
}

// withNotes is the user message u, then the system message of notes when there are any.
func withNotes(u message, notes []string) []message {
	if len(notes) == 0 {
		return []message{u}
	}
	return []message{u, systemMessage(notes)}
}

type callResult struct {
	id      string
	run     toolRun
	out     outcome
	skipped bool // not performed: an earlier call's hook said continue:false
}

// skippedCall stands for a call that a hook's continue:false kept from running.
func skippedCall(c Call, id string) callResult {
	return callResult{id: id, skipped: true, run: toolRun{Name: c.ToolName(), Input: map[string]any{}, Err: "not run: a hook stopped the loop"}}
}

// runCall performs one call and fires the hook for its result: PostToolUse for a success, PostToolUseFailure for a
// failure.
func (a *agent) runCall(c Call, id string) callResult {
	tr := c.Execute(a.cwd, a.env)
	ms := tr.Duration.Milliseconds()
	res := callResult{id: id, run: tr}
	if tr.Err != "" {
		p := postToolUseFailurePayload{common: a.common(EvPostToolUseFailure, true), ToolName: tr.Name, ToolInput: tr.Input, ToolUseID: id, Error: tr.Err, DurationMS: ms}
		res.out = a.fire(EvPostToolUseFailure, tr.Name, tr.Name, marshalPayload(p))
		return res
	}
	p := postToolUsePayload{common: a.common(EvPostToolUse, true), ToolName: tr.Name, ToolInput: tr.Input, ToolResponse: tr.Response, ToolUseID: id, DurationMS: ms}
	res.out = a.fire(EvPostToolUse, tr.Name, tr.Name, marshalPayload(p))
	return res
}

func (a *agent) loop(ctx context.Context, model string) error {
	ss := a.fire(EvSessionStart, "", "startup", marshalPayload(sessionStartPayload{common: a.common(EvSessionStart, false), Source: "startup", Model: model}))
	prompt := a.cfg.prompt
	if prompt == "" {
		prompt = a.script.Prompt
	}
	if prompt == "" {
		prompt = "go"
	}
	if ss.StopLoop { // continue:false stops Claude "processing entirely": before the first request, no tool call runs
		a.record(func(s *Summary) { s.Ended = "stopped_by_hook" })
		return nil
	}
	notes, fb := delivered(ss, EvSessionStart)
	msgs := withNotes(message{Role: "user", Content: append([]any{text(prompt)}, fb...)}, notes)

	var last reply
	ended := "end_turn"
	for k := 0; ; k++ {
		r, err := a.post(ctx, msgs)
		if err != nil {
			return err
		}
		last = r
		if k >= len(a.script.Turns) {
			a.markExtraCalls(r)
			break
		}
		asst, after, stop := a.runTurn(k, a.script.Turns[k], r)
		msgs = append(append(msgs, asst), after...)
		if stop {
			ended = "stopped_by_hook"
			break
		}
	}
	var stopErr error
	if ended == "end_turn" {
		ended, stopErr = a.stopPhase(ctx, &msgs, &last)
	}
	a.record(func(s *Summary) { s.Ended, s.FinalText = ended, last.Text() })
	return stopErr
}

// runTurn performs script turn k, whose calls the model asked for in reply r: the calls (together for a parallel
// turn), their PostToolUse or PostToolUseFailure hooks, then PostToolBatch. It returns the assistant message, the
// messages that answer it (the user message of tool results and feedback, then the system message of the hooks'
// notes when there are any), and whether a hook stopped the loop before the next model call.
func (a *agent) runTurn(k int, turn Turn, r reply) (asst message, after []message, stop bool) {
	ids := make([]string, len(turn.Calls))
	for i := range ids {
		ids[i] = fmt.Sprintf("toolu_fake_%04d_%d", k, i)
		if len(r.ToolUses) == len(turn.Calls) {
			ids[i] = r.ToolUses[i].ID
		}
	}
	agrees := replyAgrees(r, turn.Calls)
	a.record(func(s *Summary) { s.Requests[len(s.Requests)-1].Agrees = &agrees })

	results := make([]callResult, len(turn.Calls))
	if turn.Parallel {
		var wg sync.WaitGroup
		for i, c := range turn.Calls {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[i] = a.runCall(c, ids[i])
			}()
		}
		wg.Wait()
	} else {
		// continue:false "stops processing entirely": the calls after the one whose hook said it do not run
		stopped := false
		for i, c := range turn.Calls {
			if stopped {
				results[i] = skippedCall(c, ids[i])
				continue
			}
			results[i] = a.runCall(c, ids[i])
			stopped = results[i].out.StopLoop
		}
	}

	batch := make([]batchCall, len(results))
	inputs := make([]map[string]any, len(results))
	rec := TurnRec{Index: k, Parallel: turn.Parallel}
	var resultBlocks, hookBlocks []any
	var notes []string
	for i, res := range results {
		content := res.run.Text
		if res.run.Err != "" {
			content = res.run.Err
		}
		batch[i] = batchCall{ToolName: res.run.Name, ToolInput: res.run.Input, ToolUseID: res.id, ToolResponse: content}
		inputs[i] = res.run.Input
		resultBlocks = append(resultBlocks, toolResultBlock{Type: "tool_result", ToolUseID: res.id, Content: content, IsError: res.run.Err != ""})
		ev := EvPostToolUse
		if res.run.Err != "" {
			ev = EvPostToolUseFailure
		}
		n, fb := delivered(res.out, ev+":"+res.run.Name)
		notes, hookBlocks = append(notes, n...), append(hookBlocks, fb...)
		rec.Calls = append(rec.Calls, CallRec{ToolUseID: res.id, Tool: res.run.Name, Input: res.run.Input, OK: res.run.Err == "", Error: res.run.Err, Skipped: res.skipped})
		stop = stop || res.out.StopLoop
	}
	a.record(func(s *Summary) { s.Turns = append(s.Turns, rec) })
	if stop { // continue:false from a call's hook: no PostToolBatch, no next request
		return assistantMessage(r, turn.Calls, ids, inputs), withNotes(message{Role: "user", Content: append(resultBlocks, hookBlocks...)}, notes), true
	}
	if len(a.set.HooksFor(EvPostToolBatch, "")) > 0 {
		time.Sleep(batchHookDelay)
	}
	bo := a.fire(EvPostToolBatch, "", "", marshalPayload(postToolBatchPayload{common: a.common(EvPostToolBatch, true), ToolCalls: batch}))
	n, fb := delivered(bo, EvPostToolBatch)
	notes, hookBlocks = append(notes, n...), append(hookBlocks, fb...)
	return assistantMessage(r, turn.Calls, ids, inputs), withNotes(message{Role: "user", Content: append(resultBlocks, hookBlocks...)}, notes), bo.StopLoop
}

// stopPhase runs the Stop hooks after the model's last answer. A hook that blocks the stop (exit 2, decision block,
// additionalContext) puts its text in a new user message and the model answers again; the next Stop payload then says
// stop_hook_active. After a.stopCap continuations in a row the turn ends whatever the hook says. A model
// request that fails here ends the run as "request_failed" and is returned, so the run exits 1 as it does for any
// other failed request.
func (a *agent) stopPhase(ctx context.Context, msgs *[]message, last *reply) (string, error) {
	active := false
	for {
		p := stopPayload{common: a.common(EvStop, true), StopHookActive: active, LastAssistantMessage: last.Text(), BackgroundTasks: []any{}, SessionCrons: []any{}}
		o := a.fire(EvStop, "", "", marshalPayload(p))
		if o.StopLoop {
			return "stopped_by_hook", nil
		}
		if !o.Continue {
			return "end_turn", nil
		}
		var blocks []any
		for _, c := range o.Context {
			blocks = append(blocks, reminder(EvStop, c))
		}
		for _, f := range o.Feedback {
			blocks = append(blocks, text(f))
		}
		if len(blocks) == 0 {
			return "end_turn", nil
		}
		if a.sum.StopContinuations >= a.stopCap {
			return "stop_hook_cap", nil
		}
		var asst []any
		for _, c := range last.Content {
			var b struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(c, &b) == nil && b.Type == "text" {
				asst = append(asst, c)
			}
		}
		if len(asst) == 0 {
			asst = []any{text("(no text)")}
		}
		*msgs = append(*msgs, message{Role: "assistant", Content: asst}, message{Role: "user", Content: blocks})
		r, err := a.post(ctx, *msgs)
		if err != nil {
			return "request_failed", err
		}
		*last = r
		a.markExtraCalls(r) // the reply to a continuation is past the script's last turn as well
		active = true
		a.record(func(s *Summary) { s.StopContinuations++ })
	}
}

// markExtraCalls records a disagreement with the script on the request just posted when the model's reply to it asks
// for tool calls although the script has no turn left to run them. The calls are not run; report.py check --result
// fails the run on the flag.
func (a *agent) markExtraCalls(r reply) {
	if len(r.ToolUses) == 0 {
		return
	}
	disagree := false
	a.record(func(s *Summary) { s.Requests[len(s.Requests)-1].Agrees = &disagree })
}

func (a *agent) post(ctx context.Context, msgs []message) (reply, error) {
	r, err := a.cl.post(ctx, msgs)
	a.record(func(s *Summary) {
		uses := r.ToolUses
		if uses == nil {
			uses = []toolUseRef{}
		}
		s.Requests = append(s.Requests, RequestRec{N: len(s.Requests), Messages: len(msgs), Status: r.Status, StopReason: r.StopReason, ToolUses: uses})
	})
	return r, err
}
