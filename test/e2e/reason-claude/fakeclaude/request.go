// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// A message is one entry of the Messages API's messages array. Content is a list of blocks; the assistant's blocks
// are kept as the stub sent them.
type message struct {
	Role    string `json:"role"`
	Content []any  `json:"content"`
}

type textBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResultBlock struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

type toolUseBlock struct {
	Type  string         `json:"type"`
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

func text(s string) textBlock { return textBlock{Type: "text", Text: s} }

// note is one hook's additionalContext as Claude Code 2.1.310 labels it, label saying which hook produced it
// ("PostToolUse:Write", "SessionStart", "Stop"): measured with the real binary (RESULTS.md R1), not documented.
func note(label, body string) string { return label + " hook additional context: " + body }

// noteSep is what the real binary puts after each note in one message (RESULTS.md R1).
const noteSep = "\n\n\n"

// systemMessage is how Claude Code 2.1.310 delivers the tool events' and SessionStart's additionalContext: one
// message of role "system", after the user message that holds a turn's tool results (or the prompt), its one text
// the turn's notes in order (RESULTS.md R1). The real binary also puts its own context there (a token counter, and
// with SessionStart its environment section); the stand-in does not.
func systemMessage(notes []string) message {
	return message{Role: "system", Content: []any{text(strings.Join(notes, noteSep))}}
}

// reminder is how the real binary delivers a Stop hook's additionalContext: a system reminder in a new user message
// (RESULTS.md R1).
func reminder(label, body string) textBlock {
	return text("<system-reminder>\n" + note(label, body) + "\n</system-reminder>")
}

// A reply is the part of the model's answer the loop reads.
type reply struct {
	Status     int
	Content    []json.RawMessage
	StopReason string
	ToolUses   []toolUseRef
}

type toolUseRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Text is the reply's text blocks joined, which is what Stop hooks receive as last_assistant_message.
func (r reply) Text() string {
	var parts []string
	for _, raw := range r.Content {
		var b struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if json.Unmarshal(raw, &b) == nil && b.Type == "text" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// A client posts to the model stub. It refuses any base URL that is not on this machine: fakeclaude exists so that
// no test needs a real model, and a mis-set ANTHROPIC_BASE_URL must not send a request anywhere else.
type client struct {
	endpoint string
	apiKey   string
	model    string
	http     *http.Client
}

func newClient(baseURL, apiKey, model string) (*client, error) {
	if baseURL == "" {
		return nil, errors.New("ANTHROPIC_BASE_URL is not set: fakeclaude talks only to a local model stub")
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("ANTHROPIC_BASE_URL %q is not an http(s) URL", baseURL)
	}
	if h := u.Hostname(); h != "localhost" && !isLoopback(h) {
		return nil, fmt.Errorf("ANTHROPIC_BASE_URL host %q is not loopback: fakeclaude never reaches a real model", h)
	}
	return &client{
		endpoint: strings.TrimRight(baseURL, "/") + "/v1/messages",
		apiKey:   apiKey,
		model:    model,
		// A redirect is a failed request, never followed: Go would resend the body and the x-api-key header to the
		// redirect target, and that target need not be loopback.
		http: &http.Client{
			Timeout:       60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// post sends one non-streaming request carrying the whole conversation so far, as Claude Code does, and reads the
// stub's message.
func (c *client) post(ctx context.Context, msgs []message) (reply, error) {
	body, err := json.Marshal(map[string]any{
		"model": c.model, "max_tokens": 4096, "stream": false, "messages": msgs,
	})
	if err != nil {
		return reply{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("user-agent", "fakeclaude/"+DocsVersion)
	if c.apiKey != "" {
		req.Header.Set("x-api-key", c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return reply{Status: resp.StatusCode}, err
	}
	r := reply{Status: resp.StatusCode}
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("model request: HTTP %d: %.200s", resp.StatusCode, raw)
	}
	var m struct {
		Content    []json.RawMessage `json:"content"`
		StopReason string            `json:"stop_reason"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return r, fmt.Errorf("model reply: %w", err)
	}
	r.Content, r.StopReason = m.Content, m.StopReason
	for _, c := range m.Content {
		var b struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if json.Unmarshal(c, &b) == nil && b.Type == "tool_use" {
			r.ToolUses = append(r.ToolUses, toolUseRef{ID: b.ID, Name: b.Name})
		}
	}
	return r, nil
}

// assistantMessage is the assistant side of a turn in the next request's history. When the stub answered with as many
// tool_use blocks as the script has calls, its own blocks (ids included) are kept; otherwise the message is built from
// the calls, so the history stays consistent whatever the stub's script said.
func assistantMessage(r reply, calls []Call, ids []string, inputs []map[string]any) message {
	if len(r.ToolUses) == len(calls) {
		blocks := make([]any, len(r.Content))
		for i, c := range r.Content {
			blocks[i] = c
		}
		return message{Role: "assistant", Content: blocks}
	}
	blocks := make([]any, len(calls))
	for i, c := range calls {
		blocks[i] = toolUseBlock{Type: "tool_use", ID: ids[i], Name: c.ToolName(), Input: inputs[i]}
	}
	return message{Role: "assistant", Content: blocks}
}

// replyAgrees says whether the stub's reply for a turn names the tools the script runs, in order: the check that the
// stub script and the fakeclaude script describe the same scenario.
func replyAgrees(r reply, calls []Call) bool {
	if len(r.ToolUses) != len(calls) {
		return false
	}
	for i, c := range calls {
		if r.ToolUses[i].Name != c.ToolName() && !(c.ToolName() == "Connect" && r.ToolUses[i].Name == "Bash") {
			return false
		}
	}
	return true
}
