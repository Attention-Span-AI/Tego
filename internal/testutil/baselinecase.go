// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// BaselineCase is a raw evidence mutation with the fixture's commitments unchanged.
type BaselineCase struct {
	Name, Fact string
	Event      *record.Event
	Line       []byte
}

// BaselineCases mutates every required member, including nested rule origins.
// Only already-null source bytes/digests are excluded from null mutations.
// The corpus is independent of the validator, so weakening it cannot hide a case.
// Hashes deliberately remain stale: these tests exercise views that do not require
// chain verification before displaying a claim.
func BaselineCases(line []byte) ([]BaselineCase, error) {
	event, err := record.Decode(line)
	if err != nil {
		return nil, err
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(event.Payload, &payload); err != nil {
		return nil, err
	}
	var cases []BaselineCase
	emit := func(name, fact string, raw []byte) error {
		q := *event
		q.Payload = raw
		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(line, &envelope); err != nil {
			return err
		}
		for k := range payload {
			delete(envelope, k)
		}
		head, err := json.Marshal(envelope)
		if err != nil {
			return err
		}
		full := append(append(append(head[:len(head)-1], ','), raw[1:len(raw)-1]...), '}')
		cases = append(cases, BaselineCase{Name: name, Fact: fact, Event: &q, Line: full})
		return nil
	}
	var walk func(json.RawMessage, string, func(string, string, []byte) error) error
	walk = func(raw json.RawMessage, at string, output func(string, string, []byte) error) error {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		for key, value := range obj {
			fact := at + "." + key
			for _, mutation := range []string{"omitted", "null", "wrong-type", "duplicate"} {
				if mutation == "null" && strings.HasPrefix(at, "baseline.sources.") && (key == "bytes" || key == "sha256") && bytes.Equal(value, []byte("null")) {
					continue
				}
				copy := make(map[string]json.RawMessage, len(obj))
				for k, v := range obj {
					copy[k] = v
				}
				switch mutation {
				case "omitted":
					delete(copy, key)
				case "null":
					copy[key] = json.RawMessage("null")
				case "wrong-type":
					copy[key] = json.RawMessage(`{"wrong":true}`)
				}
				changed, err := json.Marshal(copy)
				if err != nil {
					return err
				}
				if mutation == "duplicate" {
					pair, err := json.Marshal(key)
					if err != nil {
						return err
					}
					changed = append(changed[:len(changed)-1], ',')
					changed = append(changed, pair...)
					changed = append(changed, ':')
					changed = append(changed, value...)
					changed = append(changed, '}')
				}
				if err := output(fact+"/"+mutation, fact, changed); err != nil {
					return err
				}
			}
			// Keep the invalid byte raw: JSON's typed decoder would repair it.
			if (bytes.Contains(value, []byte{'"'}) || bytes.Equal(value, []byte("[]")) || bytes.Equal(value, []byte("null")) && strings.HasPrefix(at, "baseline.sources.") && (key == "sha256" || key == "bytes")) && key != "sources" && key != "rules" {
				tokens := regexp.MustCompile(`"(?:\\.|[^"\\])*"`)
				if bytes.Equal(value, []byte("[]")) {
					value = json.RawMessage(`[""]`)
				}
				if bytes.Equal(value, []byte("null")) {
					value = json.RawMessage(`""`)
				}
				var loc []int
				for _, candidate := range tokens.FindAllIndex(value, -1) {
					rest := bytes.TrimSpace(value[candidate[1]:])
					if len(rest) > 0 && rest[0] == ':' {
						continue
					} // an object key, not a string value
					loc = candidate
					break
				}
				if loc != nil {
					invalid := append([]byte{}, value[:loc[0]+1]...)
					invalid = append(invalid, 0xff)
					invalid = append(invalid, value[loc[0]+1:]...)
					copy := make(map[string]json.RawMessage, len(obj))
					for k, v := range obj {
						copy[k] = v
					}
					copy[key] = json.RawMessage(`"__baseline_utf8__"`)
					changed, err := json.Marshal(copy)
					if err != nil {
						return err
					}
					changed = bytes.Replace(changed, []byte(`"__baseline_utf8__"`), invalid, 1)
					if err := output(fact+"/invalid-utf8", fact, changed); err != nil {
						return err
					}
				}
			}
			if key != "sources" && key != "rules" {
				continue
			}
			var rows []json.RawMessage
			if err := json.Unmarshal(value, &rows); err != nil {
				return err
			}
			if len(rows) == 0 {
				return fmt.Errorf("%s needs a representative row", fact)
			}
			for index := range rows {
				if err := walk(rows[index], fmt.Sprintf("%s.%d", fact, index), func(name, leaf string, changed []byte) error {
					next := append([]json.RawMessage{}, rows...)
					next[index] = changed
					encoded, err := json.Marshal(next)
					if err != nil {
						return err
					}
					copy := make(map[string]json.RawMessage, len(obj))
					for k, v := range obj {
						copy[k] = v
					}
					copy[key] = encoded
					encoded, err = json.Marshal(copy)
					if err != nil {
						return err
					}
					return output(name, leaf, encoded)
				}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(payload["baseline"], "baseline", func(name, fact string, changed []byte) error {
		copy := make(map[string]json.RawMessage, len(payload))
		for k, v := range payload {
			copy[k] = v
		}
		copy["baseline"] = changed
		encoded, err := json.Marshal(copy)
		if err != nil {
			return err
		}
		return emit(name, fact, encoded)
	}); err != nil {
		return nil, err
	}
	// The enclosing required members are required too, before typed decoding.
	for _, key := range []string{"baseline", "effective_hash", "contract_hash"} {
		for _, mutation := range []string{"omitted", "null", "wrong-type", "duplicate"} {
			copy := make(map[string]json.RawMessage, len(payload))
			for k, v := range payload {
				copy[k] = v
			}
			switch mutation {
			case "omitted":
				delete(copy, key)
			case "null":
				copy[key] = json.RawMessage("null")
			case "wrong-type":
				copy[key] = json.RawMessage(`[]`)
			}
			raw, err := json.Marshal(copy)
			if err != nil {
				return nil, err
			}
			if mutation == "duplicate" {
				pair, err := json.Marshal(key)
				if err != nil {
					return nil, err
				}
				raw = append(raw[:len(raw)-1], ',')
				raw = append(raw, pair...)
				raw = append(raw, ':')
				raw = append(raw, payload[key]...)
				raw = append(raw, '}')
			}
			if err := emit(key+"/"+mutation, key, raw); err != nil {
				return nil, err
			}
		}
	}
	for _, minor := range []int{36, 38, record.Minor + 1} {
		copy := make(map[string]json.RawMessage, len(payload))
		for k, v := range payload {
			copy[k] = v
		}
		copy["record_minor"] = json.RawMessage(fmt.Sprint(minor))
		for _, withEvidence := range []bool{true, false} {
			if !withEvidence {
				delete(copy, "baseline")
				delete(copy, "effective_hash")
			}
			raw, err := json.Marshal(copy)
			if err != nil {
				return nil, err
			}
			if err := emit(fmt.Sprintf("unsupported-%d/evidence-%t", minor, withEvidence), "record_minor", raw); err != nil {
				return nil, err
			}
		}
	}
	for _, key := range []string{"effective_hash", "contract_hash"} {
		copy := make(map[string]json.RawMessage, len(payload))
		for k, v := range payload {
			copy[k] = v
		}
		copy[key] = json.RawMessage(`"__baseline_utf8__"`)
		changed, err := json.Marshal(copy)
		if err != nil {
			return nil, err
		}
		invalid := []byte{'"', 0xff, '"'}
		changed = bytes.Replace(changed, []byte(`"__baseline_utf8__"`), invalid, 1)
		if err := emit(key+"/invalid-utf8", key, changed); err != nil {
			return nil, err
		}
	}
	var p record.RunStartPayload
	if err := event.DecodePayload(&p); err != nil {
		return nil, err
	}
	p.Baseline.Home += "/\ufffd"
	if err := p.Baseline.SealEvidence(); err != nil {
		return nil, err
	}
	committed, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	malformed := bytes.Replace(committed, []byte("\ufffd"), []byte{0xff}, 1)
	if bytes.Equal(committed, malformed) {
		return nil, fmt.Errorf("UTF-8 substitution did not fire")
	}
	if err := emit("baseline.home/utf8-substitution", "baseline.home", malformed); err != nil {
		return nil, err
	}
	return cases, nil
}
