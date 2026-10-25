// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// A Script is what fakeclaude does in place of a model's decisions: the prompt it sends first and a list of turns.
// Each turn is one assistant message's tool calls (the model stub replies with the matching tool_use blocks, see the
// stub-script files beside the scripts). Parallel turns run their calls at the same time, each call's PostToolUse or
// PostToolUseFailure hooks right after that call and while the others still run; other turns run the calls one after
// another. PostToolBatch fires once after the turn either way, unless a hook said continue:false.
type Script struct {
	Prompt string `json:"prompt"`
	Turns  []Turn `json:"turns"`
}

// A Turn is one batch of tool calls.
type Turn struct {
	Parallel bool   `json:"parallel,omitempty"`
	Calls    []Call `json:"calls"`
}

// A Call is one tool action. Exactly one of Write, Read, Run, Bash and Connect is set.
//
//	write   a path: the Write tool; Content is the file's text; Inplace writes the path itself instead of a
//	        temporary file renamed over it (Claude Code's Write tool does the latter, and a contract that
//	        holds a directory sees the rename)
//	read    a path: the Read tool
//	run     an argv: the Bash tool, the argv exec'd directly (no shell), tool_input.command its quoted words
//	bash    a shell command line: the Bash tool, run as bash -c
//	connect host:port: a TCP connect(2) and close, reported as a tool named Connect. Claude Code has no such tool;
//	        it stands for a Bash curl or nc whose only effect that matters here is the connect
type Call struct {
	Write       string   `json:"write,omitempty"`
	Content     string   `json:"content,omitempty"`
	Inplace     bool     `json:"inplace,omitempty"`
	Read        string   `json:"read,omitempty"`
	Run         []string `json:"run,omitempty"`
	Bash        string   `json:"bash,omitempty"`
	Connect     string   `json:"connect,omitempty"`
	Description string   `json:"description,omitempty"`
	TimeoutMS   int      `json:"timeout_ms,omitempty"`
}

// Verb names the one action a call performs.
func (c Call) Verb() string {
	switch {
	case c.Write != "":
		return "write"
	case c.Read != "":
		return "read"
	case len(c.Run) > 0:
		return "run"
	case c.Bash != "":
		return "bash"
	case c.Connect != "":
		return "connect"
	}
	return ""
}

// ToolName is the tool_name the harness reports for the call.
func (c Call) ToolName() string {
	switch c.Verb() {
	case "write":
		return "Write"
	case "read":
		return "Read"
	case "run", "bash":
		return "Bash"
	case "connect":
		return "Connect"
	}
	return ""
}

// ParseScript reads a script and refuses what it cannot run: an unknown key, a call with no verb or two, a malformed
// host:port, a turn with no calls.
func ParseScript(data []byte) (*Script, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Script
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("script: %w", err)
	}
	if dec.More() {
		return nil, errors.New("script: data after the top-level object")
	}
	for i, t := range s.Turns {
		if len(t.Calls) == 0 {
			return nil, fmt.Errorf("script: turn %d has no calls", i)
		}
		for j, c := range t.Calls {
			if err := c.validate(); err != nil {
				return nil, fmt.Errorf("script: turn %d call %d: %w", i, j, err)
			}
		}
	}
	return &s, nil
}

func (c Call) validate() error {
	n := 0
	for _, set := range []bool{c.Write != "", c.Read != "", len(c.Run) > 0, c.Bash != "", c.Connect != ""} {
		if set {
			n++
		}
	}
	if n != 1 {
		return fmt.Errorf("a call sets exactly one of write, read, run, bash, connect (it sets %d)", n)
	}
	if c.Verb() != "write" && (c.Content != "" || c.Inplace) {
		return errors.New("content and inplace belong to write")
	}
	if c.Connect != "" {
		host, port, err := net.SplitHostPort(c.Connect)
		if err != nil || host == "" {
			return fmt.Errorf("connect %q is not host:port", c.Connect)
		}
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("connect %q: port %q is not 1-65535", c.Connect, port)
		}
	}
	if c.TimeoutMS < 0 {
		return errors.New("timeout_ms is negative")
	}
	return nil
}
