// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// MaxToolResults bounds the tool results one request is read for; a message reporting more is not read.
const MaxToolResults = 256

// MaxToolUseIDLen bounds one tool_use id; a longer one makes the message unread. The API's own ids are about 30 bytes.
const MaxToolUseIDLen = 256

// ToolResults reads the tool_use ids a Messages API turn's last message reports results for (derive.RequestReader,
// capture-derive R42). Only a POST to the Messages endpoint whose body capture kept whole, and decoded when it was
// coded, is read; every other request is not read and says so.
func (p *Parser) ToolResults(req *derive.Message) ([]string, bool) {
	if req == nil || req.Method != http.MethodPost || req.Truncated ||
		(req.ContentEncoding != "" && !req.Decoded) || classifyPathOn(req.Method, req.Path, p.declared) != pathMessages {
		return nil, false
	}
	return RequestToolResults(req.Body)
}

// RequestToolResults reads the tool_use ids whose results a Messages API request body reports in its last message,
// in wire order. The API requires the results of a reply's tool_use blocks in the user message that follows the
// reply, so a request continuing a conversation reports the results of its previous reply there; the results of
// earlier replies, which every request repeats, are not read again.
//
// ok is false when the body cannot be read with certainty: not one JSON object, no messages array or an empty one,
// a last message or one of its blocks that is not an object, a key the reading uses (messages; the last message's
// role and content; a block's type and tool_use_id) written twice or in another case (servers keep the first, keep
// the last or fold the case differently), a tool_result block without a string tool_use_id, more than
// MaxToolResults results or an id longer than MaxToolUseIDLen. A last message that is not the user's (an assistant prefill) or whose content is text
// reports no result, which is read: ok with no ids. The whole body is scanned once; only the last message is kept.
func RequestToolResults(body []byte) ([]string, bool) {
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, false
	}
	var (
		last []byte
		seen bool
	)
	for dec.PeekKind() != '}' {
		name, err := dec.ReadToken()
		if err != nil {
			return nil, false
		}
		key := name.String()
		if key != "messages" {
			if strings.EqualFold(key, "messages") {
				return nil, false
			}
			if err := dec.SkipValue(); err != nil {
				return nil, false
			}
			continue
		}
		if seen {
			return nil, false
		}
		seen = true
		if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '[' {
			return nil, false
		}
		for dec.PeekKind() != ']' {
			v, err := dec.ReadValue()
			if err != nil {
				return nil, false
			}
			last = append(last[:0], v...)
		}
		if _, err := dec.ReadToken(); err != nil {
			return nil, false
		}
	}
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	if _, err := dec.ReadToken(); err == nil || len(last) == 0 {
		return nil, false // trailing data after the object, or no message
	}
	return lastMessageResults(last)
}

// lastMessageResults reads the tool_result ids of one message, decoded as written: each name the reading uses must
// appear once and exactly as named, and one written twice or in another case (strings.EqualFold, the Unicode fold
// a server may apply) makes the message unread, as "messages" does in RequestToolResults.
func lastMessageResults(raw []byte) ([]string, bool) {
	role, content, ok := members(jsontext.NewDecoder(bytes.NewReader(raw)), "role", "content")
	if !ok {
		return nil, false
	}
	var who string
	if role != nil && jsonv2.Unmarshal(role, &who) != nil {
		return nil, false
	}
	if who != "user" || len(content) == 0 || content.Kind() != '[' {
		return nil, true
	}
	dec := jsontext.NewDecoder(bytes.NewReader(content))
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	var ids []string
	for dec.PeekKind() != ']' {
		typ, toolUseID, ok := members(dec, "type", "tool_use_id")
		if !ok {
			return nil, false
		}
		var kind string
		if typ != nil && jsonv2.Unmarshal(typ, &kind) != nil {
			return nil, false
		}
		if kind != "tool_result" {
			continue
		}
		var id string
		if len(toolUseID) == 0 || toolUseID.Kind() != '"' || jsonv2.Unmarshal(toolUseID, &id) != nil ||
			id == "" || len(id) > MaxToolUseIDLen || len(ids) == MaxToolResults {
			return nil, false
		}
		ids = append(ids, id)
	}
	if _, err := dec.ReadToken(); err != nil {
		return nil, false
	}
	return ids, true
}

// members reads the next value of dec, which must be an object, keeping the values of the members named a and b
// (nil when absent). ok is false when it is not an object or names a or b twice or in another case.
func members(dec *jsontext.Decoder, a, b string) (va, vb jsontext.Value, ok bool) {
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return nil, nil, false
	}
	for dec.PeekKind() != '}' {
		name, err := dec.ReadToken()
		if err != nil {
			return nil, nil, false
		}
		key := name.String() // the token is valid only until the next read
		v, err := dec.ReadValue()
		if err != nil {
			return nil, nil, false
		}
		switch {
		case key == a && va == nil:
			va = v.Clone()
		case key == b && vb == nil:
			vb = v.Clone()
		case strings.EqualFold(key, a) || strings.EqualFold(key, b):
			return nil, nil, false
		}
	}
	if _, err := dec.ReadToken(); err != nil {
		return nil, nil, false
	}
	return va, vb, true
}
