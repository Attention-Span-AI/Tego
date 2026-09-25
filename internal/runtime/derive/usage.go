// SPDX-License-Identifier: Apache-2.0

package derive

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
)

// The Messages API usage object reports two things a cost budget must charge at rates of their own, which the
// four token counters leave out (R29): the cache writes made with the 1-hour lifetime
// (cache_creation.ephemeral_1h_input_tokens, billed above the 5-minute kind) and the server-side tool requests
// billed per request (server_tool_use, e.g. web_search_requests). derive's Anthropic parser and the forwarder's
// wire usage scanner both read them through the two types here, so the two can never read a response
// differently.

// CacheCreation is the Messages API usage.cache_creation object: the cache writes of a response by lifetime.
type CacheCreation struct {
	Ephemeral5m int `json:"ephemeral_5m_input_tokens"`
	Ephemeral1h int `json:"ephemeral_1h_input_tokens"`
}

// ServerToolOther is the ServerToolUse key the counts of names past maxServerTools, or of names that are not a
// plain lower-case identifier, are summed under. A price table that names no fee for it leaves a response that
// reports one unpriced, which is the fail-closed reading of a count it cannot name.
const ServerToolOther = "other_requests"

// maxServerTools is how many server-tool names a response keeps by name. The names come from the upstream's
// reply, and a map with a key per name would grow the record without bound.
const maxServerTools = 8

// maxServerToolName is the longest name kept by name.
const maxServerToolName = 64

// ServerToolUse is the Messages API usage.server_tool_use object read as per-request counts, keyed by the name the
// response reports each under. Non-numeric metadata and zero counts are not kept; a negative count is kept,
// for the caller's validation to reject. A numeric value that cannot be represented as an integer is an error,
// since dropping an overflowing count would turn unknown spend into zero.
type ServerToolUse map[string]int

// UnmarshalJSON reads the object, keeping at most maxServerTools names, in name order, and summing the rest under
// ServerToolOther.
func (s *ServerToolUse) UnmarshalJSON(b []byte) error {
	raw, err := serverToolMembers(b)
	if err != nil {
		return err
	}
	var out ServerToolUse
	named := 0 // names kept by name; the ServerToolOther bucket does not count against the cap
	for _, name := range slices.Sorted(maps.Keys(raw)) {
		var n int
		if err := json.Unmarshal(raw[name], &n); err != nil {
			value := bytes.TrimSpace(raw[name])
			if len(value) > 0 && (value[0] == '-' || value[0] >= '0' && value[0] <= '9') {
				return fmt.Errorf("server_tool_use.%s is not a representable integer count: %w", name, err)
			}
			continue // non-numeric metadata is not a count
		}
		if n == 0 {
			continue
		}
		if out == nil {
			out = make(ServerToolUse, min(len(raw), maxServerTools+1))
		}
		if !plainName(name) || (named >= maxServerTools && out[name] == 0) {
			name = ServerToolOther
		}
		if _, seen := out[name]; !seen && name != ServerToolOther {
			named++
		}
		out[name] = addCounts(out[name], n)
	}
	*s = out
	return nil
}

// serverToolMembers reads each counter name once, without rejecting duplicate keys inside unrelated
// metadata objects. The decoder reads directly from b; the retained raw values are copied as json.Unmarshal
// copied them before. Duplicate counter names, including escaped spellings, have no certain count.
func serverToolMembers(b []byte) (map[string]json.RawMessage, error) {
	d := jsontext.NewDecoder(bytes.NewBuffer(b), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	first, err := d.ReadToken()
	if err != nil {
		return nil, err
	}
	if first.Kind() == 'n' {
		if _, err := d.ReadToken(); err != io.EOF {
			if err == nil {
				err = fmt.Errorf("trailing data after server_tool_use")
			}
			return nil, err
		}
		return nil, nil
	}
	if first.Kind() != '{' {
		return nil, fmt.Errorf("server_tool_use is not an object")
	}
	raw := make(map[string]json.RawMessage)
	for d.PeekKind() != '}' {
		key, err := d.ReadToken()
		if err != nil {
			return nil, err
		}
		name := key.String()
		if _, exists := raw[name]; exists {
			return nil, fmt.Errorf("duplicate server_tool_use key %q", name)
		}
		value, err := d.ReadValue()
		if err != nil {
			return nil, err
		}
		raw[name] = bytes.Clone(value)
	}
	if _, err := d.ReadToken(); err != nil {
		return nil, err
	}
	if _, err := d.ReadToken(); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("trailing data after server_tool_use")
		}
		return nil, err
	}
	return raw, nil
}

// Merge folds a later report into s and returns the result: each count the larger of the two, since the Messages
// API reports totals, not increments, ServerToolOther's among them. If the two together name more than
// maxServerTools names, the ones past the first maxServerTools in name order are then summed into ServerToolOther,
// as UnmarshalJSON sums a report's own: folded one at a time by the larger of the two, a later report's names past
// the cap took the bucket's max rather than its sum, and a cost budget charged fewer requests than were reported.
// A name one report kept by name and the other folded is then counted in both places, which may charge more than
// was spent but never less.
func (s ServerToolUse) Merge(n ServerToolUse) ServerToolUse {
	for name, v := range n {
		if s == nil {
			s = make(ServerToolUse, len(n))
		}
		if cur, ok := s[name]; ok {
			s[name] = max(cur, v)
		} else {
			s[name] = v
		}
	}
	names := make([]string, 0, len(s))
	for name := range s {
		if name != ServerToolOther {
			names = append(names, name)
		}
	}
	if len(names) <= maxServerTools {
		return s
	}
	slices.Sort(names)
	for _, name := range names[maxServerTools:] {
		s[ServerToolOther] = addCounts(s[ServerToolOther], s[name])
		delete(s, name)
	}
	return s
}

// Negative reports a negative count, the name it is under, and whether there is one.
func (s ServerToolUse) Negative() (string, int, bool) {
	for name, v := range s {
		if v < 0 {
			return name, v, true
		}
	}
	return "", 0, false
}

// plainName reports whether name is a short lower-case identifier, as every name the API reports is.
func plainName(name string) bool {
	if name == "" || len(name) > maxServerToolName {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// addCounts adds two counts, saturating rather than wrapping. A negative operand is kept negative, so a sum over
// one is still rejected.
func addCounts(a, b int) int {
	if a < 0 || b < 0 {
		return min(a, b)
	}
	if a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}
