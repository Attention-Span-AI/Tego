// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxInputBytes bounds the payload the hook reads from stdin. A longer one (a PostToolUse whose tool_response is a
// large file) is refused as malformed: the hook prints nothing, and the refusals it would have shown stay unclaimed
// for the next event, whose payload is small (Stop carries no tool output at all).
const MaxInputBytes = 1 << 20

// The hook events the hook serves (Claude Code 2.1.310, hooks reference).
const (
	EventSessionStart       = "SessionStart"
	EventPostToolUse        = "PostToolUse"
	EventPostToolUseFailure = "PostToolUseFailure"
	EventPostToolBatch      = "PostToolBatch"
	EventStop               = "Stop"
)

// errInput is a payload the hook cannot route.
var errInput = errors.New("malformed hook input")

// input is the part of a hook payload the hook reads: the common fields and Stop's stop_hook_active. Every other
// field (tool_input, tool_response and the rest) is left unread, so a field a later Claude Code adds changes nothing.
type input struct {
	SessionID      string `json:"session_id"`
	AgentID        string `json:"agent_id,omitempty"`
	HookEventName  string `json:"hook_event_name"`
	Cwd            string `json:"cwd"`
	TranscriptPath string `json:"transcript_path"`
	StopHookActive bool   `json:"stop_hook_active"`
}

// decodeInput reads one payload from r: at most MaxInputBytes, one JSON object, with a hook_event_name.
func decodeInput(r io.Reader) (input, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxInputBytes+1))
	if err != nil {
		return input{}, fmt.Errorf("%w: read: %w", errInput, err)
	}
	if len(b) > MaxInputBytes {
		return input{}, fmt.Errorf("%w: more than %d bytes", errInput, MaxInputBytes)
	}
	// One object: Unmarshal into a struct accepts null and refuses an array or a scalar.
	if t := bytes.TrimLeft(b, " \t\r\n"); len(t) == 0 || t[0] != '{' {
		return input{}, fmt.Errorf("%w: not one JSON object", errInput)
	}
	var in input
	if err := json.Unmarshal(b, &in); err != nil {
		return input{}, fmt.Errorf("%w: %w", errInput, err)
	}
	if in.HookEventName == "" {
		return input{}, fmt.Errorf("%w: no hook_event_name", errInput)
	}
	return in, nil
}
