// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"slices"
)

type accountingShape uint8

const (
	messageAccounting accountingShape = iota
	eventAccounting
	usageAccounting
	cacheAccounting
	iterationAccounting
	chatAccounting
	chatUsageAccounting
	chatCacheAccounting
)

var accountingNames = [...][]string{
	messageAccounting:   {"id", "type", "model", "role", "stop_reason", "content", "usage"},
	eventAccounting:     {"type", "index", "delta", "usage", "message", "content_block", "error"},
	usageAccounting:     {"input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens", "cache_creation", "server_tool_use", "speed", "service_tier", "inference_geo", "iterations"},
	cacheAccounting:     {"ephemeral_5m_input_tokens", "ephemeral_1h_input_tokens"},
	iterationAccounting: {"type"},
	chatAccounting:      {"id", "model", "usage"},
	chatUsageAccounting: {"prompt_tokens", "completion_tokens", "prompt_tokens_details"},
	chatCacheAccounting: {"cached_tokens"},
}

// uniqueAccounting refuses an ambiguous field used for attribution, event routing or billing. The lenient
// decoder still accepts duplicate names in unrelated extensions and tool inputs. Only the few known names
// in each accounting object are tracked, in a fixed bitset; skipped values alias data through bytes.Buffer,
// so checking a large text/tool block makes no second copy of it or map of its members.
func uniqueAccounting(data []byte, shape accountingShape) error {
	d := jsontext.NewDecoder(bytes.NewBuffer(data), asWritten)
	tok, err := d.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != '{' {
		return nil // the ordinary unmarshal checks the field's required type
	}
	var seen uint16
	for d.PeekKind() != '}' {
		key, err := d.ReadToken()
		if err != nil {
			return err
		}
		name := key.String()
		if i := slices.Index(accountingNames[shape], name); i >= 0 {
			bit := uint16(1) << i
			if seen&bit != 0 {
				return fmt.Errorf("duplicate accounting key %q", name)
			}
			seen |= bit
		}
		value, err := d.ReadValue()
		if err != nil {
			return err
		}
		switch {
		case shape == eventAccounting && name == "message":
			err = uniqueAccounting(value, messageAccounting)
		case shape == usageAccounting && name == "cache_creation":
			err = uniqueAccounting(value, cacheAccounting)
		case shape == chatUsageAccounting && name == "prompt_tokens_details":
			err = uniqueAccounting(value, chatCacheAccounting)
		}
		if err != nil {
			return err
		}
	}
	_, err = d.ReadToken()
	return err
}
