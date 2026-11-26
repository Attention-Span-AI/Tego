// SPDX-License-Identifier: Apache-2.0

package openai

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"slices"
)

// Exact-case reading of the keys the budgets are metered by, as the Anthropic parser reads its own (R29): names
// match case-sensitively and only as written, so "USAGE" or "Prompt_Tokens" is an unknown member and never the usage
// charged, and a name that sets a charge and is written twice is refused, since which one the API meant is not known.
// Unrelated repeated names (a tool call's arguments, an extension) stay lenient: a count's neighbour does not void it.
var asWritten = jsonv2.JoinOptions(jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))

// shape is the accounting names of one object and the nested objects whose names are tracked too.
type shape struct {
	names  []string
	nested map[string]*shape
}

var (
	chatCache = &shape{names: []string{"cached_tokens"}}
	chatUse   = &shape{names: []string{"prompt_tokens", "completion_tokens", "prompt_tokens_details"},
		nested: map[string]*shape{"prompt_tokens_details": chatCache}}
	chatShape = &shape{names: []string{"id", "model", "usage"}, nested: map[string]*shape{"usage": chatUse}}

	respCache = &shape{names: []string{"cached_tokens"}}
	respUse   = &shape{names: []string{"input_tokens", "output_tokens", "input_tokens_details"},
		nested: map[string]*shape{"input_tokens_details": respCache}}
	respShape  = &shape{names: []string{"id", "model", "usage"}, nested: map[string]*shape{"usage": respUse}}
	eventShape = &shape{names: []string{"type", "response"}}

	requestShape = &shape{names: []string{"model"}}
)

// unique refuses an object that writes one of its accounting names twice (also when one is spelled with a JSON
// escape: the decoder resolves escapes before comparing), at any depth sh tracks. A value that is not an object is
// left to the ordinary decode, which checks its type.
func unique(data []byte, sh *shape) error {
	d := jsontext.NewDecoder(bytes.NewBuffer(data), asWritten)
	tok, err := d.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != '{' {
		return nil
	}
	var seen uint16
	for d.PeekKind() != '}' {
		key, err := d.ReadToken()
		if err != nil {
			return err
		}
		name := key.String()
		i := slices.Index(sh.names, name)
		if i >= 0 {
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
		if inner := sh.nested[name]; inner != nil {
			if err := unique(value, inner); err != nil {
				return err
			}
		}
	}
	_, err = d.ReadToken()
	return err
}

// unmarshal decodes data into v, reading each accounting name once and only as written.
func unmarshal(data []byte, v any, sh *shape) error {
	if err := unique(data, sh); err != nil {
		return err
	}
	return jsonv2.Unmarshal(data, v, asWritten)
}

// requestModel is the request's model as written: the top-level key spelled exactly model, a non-empty string,
// written once. It names the model of an answer that names none.
func requestModel(body []byte) (string, bool) {
	if len(body) == 0 || unique(body, requestShape) != nil {
		return "", false
	}
	var req struct {
		Model string `json:"model"`
	}
	if jsonv2.Unmarshal(body, &req) != nil || req.Model == "" {
		return "", false
	}
	return req.Model, true
}
