// SPDX-License-Identifier: Apache-2.0

package anthropic

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

// Exact-case reading of the keys the budgets are metered by (R29).
//
// encoding/json (v1) matches an object key to a struct field case-insensitively, with Unicode folding (so
// "max_tokenſ" is max_tokens), and lets the last of several matches win. The API reads keys as written. A
// request {"max_tokens":64000,...,"MAX_TOKENS":1} was therefore bounded by 1 while the model could write 64000,
// and a response {"usage":{...},"USAGE":{...}} was charged whichever came last. The bodies a charge is read
// from are therefore decoded with encoding/json/v2, whose names match case-sensitively: a key is read only when
// spelled exactly so, as the API spells it, and another spelling is an unknown member, ignored as the API
// ignores it. The decode is the same single pass v1 made (v1 is v2 underneath), so reading keys as written
// costs nothing.
//
// Where a request's key sets a charge, a second reading also fails closed: max_tokens is read by
// MaxTokensScanner (maxtokens.go), for which a case variant or a second exact key is no bound, and the model is
// read with duplicate names refused.

// asWritten decodes a response or a stream event: names case-sensitive, and otherwise as lenient as v1 was, so a
// repeated name (in a tool_use input, say) or a byte of invalid UTF-8 in a text block does not void the usage
// beside it.
var asWritten = jsonv2.JoinOptions(jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))

// unmarshal decodes data into v, reading each name only as written. Routing/accounting envelopes have one
// reading of each known field; unrelated repeated tool-input or extension names remain lenient.
func unmarshal(data []byte, v any) error {
	var err error
	switch v.(type) {
	case *Response:
		err = uniqueAccounting(data, messageAccounting)
	case *chatBody:
		err = uniqueAccounting(data, chatAccounting)
	case *StreamEvent:
		// Most stream frames contain only text/tool deltas. Accounting candidates use the same cheap
		// classifier as StreamUsageScanner; a possibly escaped key/type is checked conservatively too.
		if bytes.Contains(data, scanMessageStart) || bytes.Contains(data, scanMessageDelta) ||
			bytes.Contains(data, []byte(`"usage"`)) || bytes.Contains(data, scanError) || bytes.Contains(data, scanEscape) {
			err = uniqueAccounting(data, eventAccounting)
		}
	case *usageEvent:
		err = uniqueAccounting(data, eventAccounting)
	}
	if err != nil {
		return err
	}
	return jsonv2.Unmarshal(data, v, asWritten)
}

// requestModel is the request's model as written: the top-level key spelled exactly model, a non-empty string.
// A body naming any key twice has no model, since which one the API took is not known; neither has one whose
// JSON is not strict (v2's defaults). It is read only where the model prices an exchange whose response names
// none, so a whole request is decoded a second time only then.
func requestModel(body []byte) (string, bool) {
	var req struct {
		Model string `json:"model"`
	}
	if jsonv2.Unmarshal(body, &req) != nil || req.Model == "" {
		return "", false
	}
	return req.Model, true
}
