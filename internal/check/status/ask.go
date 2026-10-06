// SPDX-License-Identifier: Apache-2.0

package status

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The current broker permits at most 64 simultaneous asks. Never grow a
// history-sized map from a long ledger or invent readiness from malformed
// records. Optional payload additions remain compatible with older readers.
type pendingApprovals map[string]struct{}

func (p *pendingApprovals) add(e *record.Event) error {
	if e.Kind != record.KindAsk && e.Kind != record.KindAnswer {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(e.Payload))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return errors.New("approval payload must be an object")
	}
	seen := map[string]bool{}
	var id, hold string
	for d.More() {
		t, err = d.Token()
		key, ok := t.(string)
		if err != nil || !ok || seen[key] {
			return errors.New("approval payload has duplicate or malformed fields")
		}
		seen[key] = true
		if len(seen) > 128 {
			return errors.New("approval payload exceeds 128 fields")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
		switch key {
		case "ask_id":
			if err = json.Unmarshal(value, &id); err != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return errors.New("approval ask_id must be a string")
			}
		case "hold":
			if e.Kind == record.KindAsk {
				if err = json.Unmarshal(value, &hold); err != nil {
					return errors.New("approval hold must be a string")
				}
			}
		case "approved":
			if e.Kind == record.KindAnswer && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return errors.New("approval answer approved cannot be null")
			}
		}
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return errors.New("approval payload is malformed")
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("approval payload has trailing data")
	}
	// Earlier v1 records do not prescribe the broker's q-hex spelling.
	if id == "" || len(id) > 128 || !utf8.ValidString(id) || strings.ContainsFunc(id, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return errors.New("approval ask_id is invalid")
	}
	if e.Kind == record.KindAnswer {
		var answer struct {
			record.AnswerPayload
			Approved *bool `json:"approved,omitempty"`
		}
		if err := json.Unmarshal(e.Payload, &answer); err != nil || answer.By == "" || answer.AfterS < 0 || math.IsNaN(answer.AfterS) || math.IsInf(answer.AfterS, 0) {
			return errors.New("approval answer is malformed")
		}
		delete(*p, id)
		return nil
	}
	// "open" is a held file open's (added within v1 2026-10-05, ask-4; such asks said "connect" before), "mutation" a
	// held fs mutation's in an fs.ask scope (ADR 0047, record_minor 13).
	if hold != "connect" && hold != "first_write" && hold != "request" && hold != "open" && hold != "mutation" {
		return errors.New("approval hold is unsupported")
	}
	if *p == nil {
		*p = make(pendingApprovals)
	}
	if _, exists := (*p)[id]; !exists && len(*p) >= 64 {
		return fmt.Errorf("approval pending state exceeds 64")
	}
	(*p)[id] = struct{}{}
	return nil
}
