// SPDX-License-Identifier: Apache-2.0

package claudecode

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/reason"
)

// The output modes (--mode).
const (
	// ModeJSON prints hookSpecificOutput.additionalContext on stdout with exit 0: Claude Code adds it to the model's
	// next request after the tool results (PostToolUse, PostToolUseFailure, PostToolBatch), at the start of the
	// conversation (SessionStart) or at the end of the turn, which then goes on (Stop). Claude Code 2.1.310 sends
	// the tool events' and SessionStart's as a system-role message "<event>:<tool> hook additional context: <text>"
	// and Stop's as a system reminder (test/e2e/reason-claude/RESULTS.md R1). It is the mode the provisioner writes.
	ModeJSON = "json"
	// ModeStderr prints the text on stderr with exit 2, which Claude Code shows to Claude for PostToolUse and
	// PostToolUseFailure and which keeps a Stop going: for a hook wired by hand that wants that feedback channel. No
	// provision writes it: a bare session (--bare, CLAUDE_CODE_SIMPLE), for which it was meant, runs no hook at all
	// and is refused (RESULTS.md R2). PostToolBatch and SessionStart print nothing in this mode, since exit 2 there
	// ends the agent's loop or reaches the user only.
	ModeStderr = "stderr"
)

// Exit codes of Claude Code's hook protocol (hooks reference, the exit-code table).
const (
	exitOK = 0
	// exitFeedback is exit 2: stderr goes to Claude. Only --mode stderr ever uses it.
	exitFeedback = 2
)

// MaxContextChars bounds what the hook prints, in characters: Claude Code moves context over 10,000 characters to a
// file and shows Claude a preview, so the hook stays well under it (reason.MaxRenderBytes; a byte is at most one
// character).
const MaxContextChars = reason.MaxRenderBytes

// hookOutput is the JSON a command hook prints on stdout with exit 0 to add context for Claude.
type hookOutput struct {
	HookSpecificOutput specificOutput `json:"hookSpecificOutput"`
}

type specificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// bounded is text at most MaxContextChars bytes, cut with its length (reason.Cut) when longer. Render keeps itself
// under the bound; this keeps every text the hook prints there whatever produced it.
func bounded(text string) string { return reason.Cut(text, MaxContextChars) }

// writeContext prints text as event's additionalContext, one JSON object and a newline.
func writeContext(w io.Writer, event, text string) error {
	b, err := json.Marshal(hookOutput{specificOutput{HookEventName: event, AdditionalContext: bounded(text)}})
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// warn writes the one line the hook leaves on stderr when it prints nothing for a reason worth a look: on exit 0
// Claude Code does not pass a hook's stderr to Claude, so the line is for whoever reads the session's hook log.
func warn(w io.Writer, msg string) {
	msg = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, msg)
	_, _ = io.WriteString(w, "tego hook claude-code: "+msg+"\n") // stderr: nowhere else to report a failed write
}
