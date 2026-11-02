// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"encoding/json"
	"unicode"
)

// ambiguousKeys reports whether a client message names one key twice, in the message or in its params, where two
// keys are the same when encoding/json would match them to one field: equal under Unicode simple case folding.
// The relay decides on the method and the tool name as Go's decoder reads them (the last of equal keys, matched
// case-insensitively), while the server is another program with its own parser: a CPython server reads
// {"name":"delete_file","Name":"read_file"} as delete_file, the call the relay decided as read_file. Such a message
// is one the relay cannot read the way the server will, so it is refused as unreadable, never passed (review of the
// relay's parser differential). A message that is not an object reads as not ambiguous: the
// envelope decode has refused it already.
func ambiguousKeys(msg []byte) bool {
	dup, params := objectKeys(msg, "params")
	if dup {
		return true
	}
	if len(params) > 0 {
		dup, _ = objectKeys(params, "")
	}
	return dup
}

// objectKeys reads one JSON object's keys and reports a key repeated under folding; want names a key whose value it
// returns (the last one read).
func objectKeys(b []byte, want string) (dup bool, value json.RawMessage) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false, nil
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false, nil
		}
		key, _ := tok.(string)
		k := foldKey(key)
		if seen[k] {
			return true, nil
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return false, nil
		}
		if want != "" && k == foldKey(want) {
			value = v
		}
	}
	return false, value
}

// foldKey maps every rune to the least rune of its simple-fold orbit, so keys encoding/json matches as one field
// ("name", "NAME", "Name"; "kind" and "\u212aind" with the Kelvin sign) map to one string.
func foldKey(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		m := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < m {
				m = f
			}
		}
		out = append(out, m)
	}
	return string(out)
}
