// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"encoding/json/jsontext"
	"fmt"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ParserVersion is stamped on every ssl_response this parser produces (R32, I6). It is bumped whenever the wire
// shape the parser depends on changes.
const ParserVersion = "openai-2026-11-1"

// Provider is the models[] provider name this parser claims (R25).
const Provider = "openai"

// The endpoints whose answers state usage, as OpenAI's API reference names them (ADR 0037, amended 2026-11-26 lists the pages read).
const (
	ChatCompletionsPath = "/v1/chat/completions"
	ResponsesPath       = "/v1/responses"
)

// EventResponseCompleted is the Responses API stream event that carries the finished response, usage included.
const EventResponseCompleted = "response.completed"

// MaxBody is the largest response body this parser reads. The forwarder keeps at most its own cap (8 MiB) of a
// body; a body past this one is read by no one, and is an answer whose spend cannot be read (fail closed), so a
// caller that hands it more can neither make the decode run away nor have a prefix of it counted as the whole.
const MaxBody = 32 << 20

// ErrSchema is this parser's structural sentinel; it wraps derive.ErrSchema, so a Dispatcher maps it to decision:
// unparsed why=schema (R29).
var ErrSchema = fmt.Errorf("openai: %w", derive.ErrSchema)

// ErrEncoding is the sentinel for bytes that never became text: a Content-Encoding capture could not undo.
var ErrEncoding = fmt.Errorf("openai: %w", derive.ErrEncoding)

// errStreamNoUsage is a streamed chat completion that ended without a usage chunk: the client did not ask the API for
// one (stream_options.include_usage). It is a schema error whose note (derive.UnmeteredNoter) tells a person what
// to change.
type errStreamNoUsage struct{}

func (errStreamNoUsage) Error() string {
	return "openai: streamed chat completion without usage (the client did not ask for it)"
}
func (errStreamNoUsage) Is(target error) bool  { return target == derive.ErrSchema }
func (errStreamNoUsage) UnmeteredNote() string { return derive.NoteStreamWithoutUsage }

// errCutOff is an answer a closed connection or a capture cap cut short: a schema error whose note says so, and not that
// the client should ask for usage.
type errCutOff struct{ route string }

func (e errCutOff) Error() string {
	return "openai: " + e.route + " answer was cut short before its end"
}
func (errCutOff) Is(target error) bool  { return target == derive.ErrSchema }
func (errCutOff) UnmeteredNote() string { return derive.NoteAnswerCutOff }

// chatUsage is the Chat Completions usage object (CompletionUsage): prompt_tokens, completion_tokens and
// prompt_tokens_details.cached_tokens are read; total_tokens and every other detail are not (completion_tokens
// already includes reasoning tokens, and prompt_tokens the cached ones).
type chatUsage struct {
	Prompt     *int `json:"prompt_tokens"`
	Completion *int `json:"completion_tokens"`
	Details    *struct {
		Cached *int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

func (u *chatUsage) record() (record.Usage, error) {
	var cached *int
	if u.Details != nil {
		cached = u.Details.Cached
	}
	return counts("chat completion usage", "prompt_tokens", "completion_tokens", u.Prompt, u.Completion, cached)
}

// respUsage is the Responses API usage object (ResponseUsage): input_tokens, output_tokens and
// input_tokens_details.cached_tokens are read.
type respUsage struct {
	Input   *int `json:"input_tokens"`
	Output  *int `json:"output_tokens"`
	Details *struct {
		Cached *int `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

func (u *respUsage) record() (record.Usage, error) {
	var cached *int
	if u.Details != nil {
		cached = u.Details.Cached
	}
	return counts("response usage", "input_tokens", "output_tokens", u.Input, u.Output, cached)
}

// counts maps an OpenAI-style usage onto the ledger's counters, the way ADR 0037, amended 2026-11-26 states: the budget counts input plus
// output tokens with cache tokens excluded (docs/site/budgets.md), and OpenAI reports its prompt count with the cached
// tokens inside it, so Input is the prompt minus the cached part, CacheRead the cached part and Output the whole
// completion count (reasoning tokens are billed as output and are inside it). Both counters must be stated: a usage
// object missing one is spend no one can read, never zero. A negative count, or more cached tokens than the prompt
// holds, is a body the API does not produce and is refused rather than clamped.
func counts(what, inName, outName string, in, out, cached *int) (record.Usage, error) {
	if in == nil || out == nil {
		return record.Usage{}, fmt.Errorf("%w: %s requires %s and %s", ErrSchema, what, inName, outName)
	}
	c := 0
	if cached != nil {
		c = *cached
	}
	switch {
	case *in < 0 || *out < 0 || c < 0:
		return record.Usage{}, fmt.Errorf("%w: %s is negative", ErrSchema, what)
	case c > *in:
		return record.Usage{}, fmt.Errorf("%w: %s says %d cached tokens of a %d token prompt", ErrSchema, what, c, *in)
	}
	return record.Usage{Input: *in - c, Output: *out, CacheRead: c}, nil
}

// chatBody is as much of a chat completion, or of one of its stream's chunks, as the budgets need.
type chatBody struct {
	ID    string     `json:"id"`
	Model string     `json:"model"`
	Usage *chatUsage `json:"usage"`
}

// respBody is as much of a Responses API response as the budgets need.
type respBody struct {
	ID    string     `json:"id"`
	Model string     `json:"model"`
	Usage *respUsage `json:"usage"`
}

// respEvent is a Responses API stream event, decoded far enough to route it; the response is decoded only when the
// event is the completed one.
type respEvent struct {
	Type     string         `json:"type"`
	Response jsontext.Value `json:"response"`
}
