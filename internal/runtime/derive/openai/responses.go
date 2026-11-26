// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// responsesWhole reads a non-streamed Responses API response: its id, model and usage (ResponseUsage, optional or
// null in the reference: nil when it states none).
func responsesWhole(body []byte) (id, model string, usage *record.Usage, err error) {
	var b respBody
	if err := unmarshal(body, &b, respShape); err != nil {
		return "", "", nil, fmt.Errorf("%w: response body: %w", ErrSchema, err)
	}
	if b.Usage == nil {
		return b.ID, b.Model, nil, nil
	}
	u, err := b.Usage.record()
	if err != nil {
		return "", "", nil, err
	}
	return b.ID, b.Model, &u, nil
}

// responsesStream reads a streamed Responses API answer: the usage is the one the response.completed event's response
// states. Every other event is passed over (their response objects carry usage null while the answer is
// being made). A stream that ends without that event (a response.incomplete or response.failed one included, whose
// payload this parser does not read) states no usage, and so an answer whose spend cannot be read; a second
// response.completed is refused as a repeated usage report.
func responsesStream(body []byte, wireSSE bool) (id, model string, usage *record.Usage, err error) {
	err = scanSSE(body, wireSSE, func(f frame) error {
		data, skip, err := payload(f.data)
		if skip || err != nil {
			return err
		}
		var ev respEvent
		if err := unmarshal(data, &ev, eventShape); err != nil {
			return fmt.Errorf("%w: response stream event: %w", ErrSchema, err)
		}
		if ev.Type == "" {
			ev.Type = f.name
		}
		if ev.Type != EventResponseCompleted {
			return nil
		}
		if usage != nil {
			return fmt.Errorf("%w: response stream repeated %s", ErrSchema, EventResponseCompleted)
		}
		if len(ev.Response) == 0 {
			return fmt.Errorf("%w: %s without a response", ErrSchema, EventResponseCompleted)
		}
		var b respBody
		if err := unmarshal(ev.Response, &b, respShape); err != nil {
			return fmt.Errorf("%w: %s response: %w", ErrSchema, EventResponseCompleted, err)
		}
		id, model = b.ID, b.Model
		if b.Usage == nil {
			return fmt.Errorf("%w: %s response states no usage", ErrSchema, EventResponseCompleted)
		}
		u, err := b.Usage.record()
		if err != nil {
			return err
		}
		usage = &u
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	return id, model, usage, nil
}
