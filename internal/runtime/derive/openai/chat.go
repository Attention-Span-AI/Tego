// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// chatWhole reads a non-streamed chat completion: its id, model and usage object (nil when it states none).
func chatWhole(body []byte) (id, model string, usage *record.Usage, err error) {
	var b chatBody
	if err := unmarshal(body, &b, chatShape); err != nil {
		return "", "", nil, fmt.Errorf("%w: chat completion body: %w", ErrSchema, err)
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

// chatStream reads a streamed chat completion. Usage is in one chunk, the last before [DONE] with an empty choices
// array, and only when the client asked for it (stream_options.include_usage); every other chunk carries
// "usage": null. Usage-only final chunks still belong to the response named by earlier chunks: conflicting identities
// cannot be priced as one exchange, and the API's one usage report is never replaced by a second one, which a
// cumulative-usage server would send every chunk and a hostile stream could use to hide the real total. Any frame
// that cannot be read is an error: a usage the stream may have stated after it is not known to be absent.
func chatStream(body []byte, wireSSE bool) (id, model string, usage *record.Usage, err error) {
	err = scanSSE(body, wireSSE, func(f frame) error {
		data, skip, err := payload(f.data)
		if skip || err != nil {
			return err
		}
		var chunk chatBody
		if err := unmarshal(data, &chunk, chatShape); err != nil {
			return fmt.Errorf("%w: chat completion stream chunk: %w", ErrSchema, err)
		}
		if chunk.Model != "" {
			if model != "" && model != chunk.Model {
				return fmt.Errorf("%w: chat completion stream changed model", ErrSchema)
			}
			model = chunk.Model
		}
		if chunk.ID != "" {
			if id != "" && id != chunk.ID {
				return fmt.Errorf("%w: chat completion stream changed response id", ErrSchema)
			}
			id = chunk.ID
		}
		if chunk.Usage != nil {
			if usage != nil {
				return fmt.Errorf("%w: chat completion stream repeated usage", ErrSchema)
			}
			u, err := chunk.Usage.record()
			if err != nil {
				return err
			}
			usage = &u
		}
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	return id, model, usage, nil
}
