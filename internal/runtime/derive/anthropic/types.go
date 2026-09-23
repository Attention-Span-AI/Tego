// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"encoding/json"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ParserVersion is stamped on every ssl_response this parser produces (R32, I6). It is bumped whenever
// the wire shape the parser depends on changes, so a view can tell which reading produced a row.
const ParserVersion = "anthropic-2026-10-5"

// Provider is the models[] provider name this parser claims (R25).
const Provider = "anthropic"

// DefaultHosts are the upstream hosts the parser claims when a run declared no provider for them.
var DefaultHosts = []string{"api.anthropic.com"}

// MessagesPath is Anthropic's Messages API endpoint. Other billed or unknown
// paths are classified separately; only known non-spending endpoints are silent.
const MessagesPath = "/v1/messages"

// Content block types of the Messages API.
const (
	BlockText             = "text"
	BlockToolUse          = "tool_use"
	BlockThinking         = "thinking"
	BlockRedactedThinking = "redacted_thinking"
)

// Stream event types of the Messages API, in the order one message emits them.
const (
	EventMessageStart      = "message_start"
	EventContentBlockStart = "content_block_start"
	EventContentBlockDelta = "content_block_delta"
	EventContentBlockStop  = "content_block_stop"
	EventMessageDelta      = "message_delta"
	EventMessageStop       = "message_stop"
	EventPing              = "ping"
	EventError             = "error"
)

// Delta types carried by a content_block_delta.
const (
	DeltaText      = "text_delta"
	DeltaInputJSON = "input_json_delta"
	DeltaThinking  = "thinking_delta"
	DeltaSignature = "signature_delta"
)

// Request is a Messages API request. The JSON tags mirror the wire format verbatim, not record v1.
// Messages keeps each item as raw bytes so the ledger can dedup a conversation by hash without the
// parser ever re-marshaling what the agent sent.
type Request struct {
	Model    string          `json:"model"`
	Messages []Message       `json:"messages"`
	System   json.RawMessage `json:"system,omitempty"`
	Tools    []Tool          `json:"tools,omitempty"`
	Stream   bool            `json:"stream,omitempty"`
	// max_tokens is not read here: encoding/json folds key case, and the bound is read exactly as written
	// (RequestMaxTokens, R29).
}

// Message is one conversation turn of a request.
type Message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// Tool is one tool definition of a request.
type Tool struct {
	Name        string          `json:"name"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// Usage is the token accounting of one response. Fields default to zero and are never clamped: a
// negative wire value is a schema error, not a zero.
type Usage struct {
	InputTokens              int `json:"input_tokens,omitempty"`
	OutputTokens             int `json:"output_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	// CacheCreation and ServerToolUse are the counters billed at rates of their own (usage_extra.go).
	CacheCreation *cacheCreation `json:"cache_creation,omitempty"`
	ServerToolUse serverToolUse  `json:"server_tool_use,omitempty"`
	// The billing modifiers a usage object can carry (usage_extra.go): read only to say the response was billed
	// under one the price table does not price.
	Speed        json.RawMessage `json:"speed,omitempty"`
	ServiceTier  json.RawMessage `json:"service_tier,omitempty"`
	InferenceGeo json.RawMessage `json:"inference_geo,omitempty"`
	Iterations   json.RawMessage `json:"iterations,omitempty"`
	// modified says one of them is not the plain rate (billingModified), and is sticky across merges.
	modified bool
	// unboundedIterations says extra/unreadable attempts may have spend outside the reported counters.
	// A later cumulative output count cannot recover those attempts, so it is sticky across merges.
	unboundedIterations bool
	// present says the body carried a usage object: a message with none reported no spend, which is not the
	// same as reporting zero (limits-check-doctor-cli.md R1 (a)).
	present bool
	// hasOutput says the object carried output_tokens: only such a usage is a message's final count (a
	// message_delta with "usage":{} carries none, ADR 0036).
	hasOutput bool
	hasInput  bool
}

// UnmarshalJSON reads a usage object as written (keys.go) and marks it present; null is no usage.
func (u *Usage) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	if err := uniqueAccounting(b, usageAccounting); err != nil {
		return err
	}
	type plain Usage
	var p plain
	if err := unmarshal(b, &p); err != nil {
		return err
	}
	*u = Usage(p)
	u.present = true
	var probe struct {
		Out *json.RawMessage `json:"output_tokens"`
		In  *json.RawMessage `json:"input_tokens"`
	}
	u.hasOutput = unmarshal(b, &probe) == nil && probe.Out != nil && string(*probe.Out) != "null"
	u.hasInput = probe.In != nil && string(*probe.In) != "null"
	u.modified = u.billingModified()
	u.unboundedIterations = iterationsExtra(u.Iterations)
	return nil
}

// validate rejects a negative count (R-validation in §2): the wire has no meaning for one.
func (u Usage) validate() error {
	if err := u.validateExtra(); err != nil {
		return err
	}
	for name, v := range map[string]int{
		"input_tokens":                u.InputTokens,
		"output_tokens":               u.OutputTokens,
		"cache_read_input_tokens":     u.CacheReadInputTokens,
		"cache_creation_input_tokens": u.CacheCreationInputTokens,
	} {
		if v < 0 {
			return fmt.Errorf("%w: usage.%s is %d", ErrSchema, name, v)
		}
	}
	return nil
}

// Record converts the wire usage to the ledger's four counters.
func (u Usage) Record() record.Usage {
	r := record.Usage{
		Input:      u.InputTokens,
		Output:     u.OutputTokens,
		CacheRead:  u.CacheReadInputTokens,
		CacheWrite: u.CacheCreationInputTokens,
	}
	u.recordExtra(&r)
	r.Modified = u.modified
	return r
}

// merge folds a later usage report into an earlier one.
//
// The Messages API reports usage cumulatively: message_start seeds input and cache counts (with a
// placeholder output count), and each message_delta carries the totals for the message so far, not an
// increment — verified against the documented event sequence, where a single-block message ends with one
// message_delta carrying "usage":{"output_tokens":12}. Adding the two as R29's wording suggests would
// count the seed twice, so each field takes the larger of the two values: monotonic totals fold
// correctly whichever way the server reports them, and neither reading double-counts.
func (u *Usage) merge(n Usage) {
	u.InputTokens = max(u.InputTokens, n.InputTokens)
	u.OutputTokens = max(u.OutputTokens, n.OutputTokens)
	u.CacheReadInputTokens = max(u.CacheReadInputTokens, n.CacheReadInputTokens)
	u.CacheCreationInputTokens = max(u.CacheCreationInputTokens, n.CacheCreationInputTokens)
	u.mergeExtra(n)
	u.modified = u.modified || n.modified
	u.unboundedIterations = u.unboundedIterations || n.unboundedIterations
}

// Response is one assembled model response, from a JSON body or from a whole event stream.
type Response struct {
	incompleteUsage bool // a stream accounting frame was missing or unreadable

	ID         string         `json:"id"`
	Type       string         `json:"type"` // message | error
	Model      string         `json:"model"`
	Role       string         `json:"role"`
	StopReason string         `json:"stop_reason"`
	Content    []ContentBlock `json:"content"`
	Usage      Usage          `json:"usage"`
	// Stream reports that the response was assembled from an event stream.
	Stream bool `json:"-"`
	// FinalUsage reports that the stream carried a message_delta with usage, the event whose output count is
	// the message's. A stream without one reported only message_start's placeholder output (R29).
	FinalUsage bool `json:"-"`
	// ErrorAnswer reports a stream whose first event was an error (an overloaded_error on a 200, before any
	// message_start): no message began, and nothing was spent (R29).
	ErrorAnswer bool `json:"-"`
}

// ContentBlock is one block of a response. Input keeps the tool_use arguments as the exact wire bytes:
// input_hash is taken over them, never over a re-marshaling (R31).
type ContentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text,omitempty"`
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
}

// StreamEvent is one `data:` payload of the event stream, decoded far enough to route it.
type StreamEvent struct {
	Type  string          `json:"type"`
	Index int             `json:"index"`
	Delta json.RawMessage `json:"delta,omitempty"`
	Usage *Usage          `json:"usage,omitempty"`
	// Message is message_start's message object.
	Message json.RawMessage `json:"message,omitempty"`
	// ContentBlock is content_block_start's opening block.
	ContentBlock json.RawMessage `json:"content_block,omitempty"`
	// Error is an error event's body.
	Error json.RawMessage `json:"error,omitempty"`
}
