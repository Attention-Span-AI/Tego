// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"encoding/json"
	"fmt"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// ErrSchema is this parser's structural sentinel: a JSON syntax error, a missing required field, an
// unknown stream event, a delta for a block that never opened, a body a capture cap cut short. It wraps
// derive.ErrSchema, so a Dispatcher maps it to decision: unparsed why=schema (R29).
var ErrSchema = fmt.Errorf("anthropic: %w", derive.ErrSchema)

// ErrEncoding is the sentinel for bytes that never became text: a Content-Encoding capture could not
// undo. It wraps derive.ErrEncoding (R29).
var ErrEncoding = fmt.Errorf("anthropic: %w", derive.ErrEncoding)

// requestShape is the part of a request validateRequest checks: the same fields and types as Request, without
// the RawMessage fields, so decoding it copies none of the conversation, the system prompt or the tool schemas.
type requestShape struct {
	Model    string `json:"model"`
	Messages []struct {
		Role string `json:"role"`
	} `json:"messages"`
	Tools []struct {
		Name string `json:"name"`
	} `json:"tools"`
	Stream bool `json:"stream"`
}

// validateRequest reads a Messages API request body and keeps nothing: the whole body is valid JSON, each
// field has its type, and a model is named, since a body without one is not a model call this parser can
// attribute (R28). Parse only needs to know whether the request half is readable, and a request is up to
// megabytes on a long agent session. encoding/json folds key case, so where a charge depends on a key (the
// model a response without one is priced by, the max_tokens a cut stream is bounded by) Parse reads it again
// exactly as written (requestModel, RequestMaxTokens), and only there.
func validateRequest(body []byte) error {
	if len(body) == 0 {
		return fmt.Errorf("%w: empty request body", ErrSchema)
	}
	var req requestShape
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("%w: request body: %w", ErrSchema, err)
	}
	if req.Model == "" {
		return fmt.Errorf("%w: request without a model", ErrSchema)
	}
	return nil
}

// ParseResponse reads a non-streaming Messages API response body. An error body (type "error", the shape
// a 4xx or 5xx carries) parses successfully with no content and no usage: the status code is the fact,
// and a rate-limit answer is not an unreadable body.
func ParseResponse(status int, body []byte) (*Response, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty response body (status %d)", ErrSchema, status)
	}
	var resp Response
	// Names are read as written (keys.go): encoding/json v1 folded case, so {"usage":…,"USAGE":…} was charged
	// whichever came last (R29).
	if err := unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("%w: response body (status %d): %w", ErrSchema, status, err)
	}
	if resp.Type == "error" {
		return &Response{Type: "error"}, nil
	}
	if resp.ID == "" && resp.Model == "" && len(resp.Content) == 0 {
		return nil, fmt.Errorf("%w: response is neither a message nor an error (status %d)", ErrSchema, status)
	}
	if !resp.Usage.present {
		// A message that reports no usage object spent what nothing here can read: counting it as zero let
		// a budget pass it unseen (limits-check-doctor-cli.md R1 (a)). It is unparsed, and the Dispatcher
		// reports a successful one unmetered.
		return nil, fmt.Errorf("%w: message response carries no usage (status %d)", ErrSchema, status)
	}
	if !resp.Usage.hasOutput {
		// A usage object with no output_tokens is the same unreadable spend: it was charged zero output, so a
		// token or cost ceiling never saw it. The stream path already refuses it as a final count (hasOutput).
		return nil, fmt.Errorf("%w: message usage carries no output_tokens (status %d)", ErrSchema, status)
	}
	if !resp.Usage.hasInput {
		return nil, fmt.Errorf("%w: message usage carries no input_tokens (status %d)", ErrSchema, status)
	}
	if err := resp.Usage.validate(); err != nil {
		return nil, err
	}
	resp.incompleteUsage = resp.Usage.unboundedIterations
	for i, b := range resp.Content {
		if b.Type == BlockToolUse && len(b.Input) > 0 && !json.Valid(b.Input) {
			return nil, fmt.Errorf("%w: content[%d].input is not valid JSON", ErrSchema, i)
		}
	}
	return &resp, nil
}
