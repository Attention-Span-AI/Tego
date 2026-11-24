// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestRunStartLearnHistory(t *testing.T) {
	const src = `{"path":"/agent.yaml","learn":{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://203.0.113.9:443"]}}`
	var p RunStartPayload
	if err := json.Unmarshal([]byte(`{"record_minor":31,"contract_source":`+src+`}`), &p); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"learn"`) {
		t.Fatal("record drops contract learn history")
	}
	if err := p.ValidateFields(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"run":"bad","withheld":["tcp://203.0.113.9:443"]}`,
		`{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":[]}`,
		`{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://example.com:443"]}`,
		`{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://203.0.113.9:0"]}`,
		`{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://203.0.113.9:443","tcp://203.0.113.9:443"]}`,
		`{"run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["udp://203.0.113.9:443","tcp://203.0.113.9:443"]}`,
		`{"Run":"r-12345678-0aaaaaaaaaaaa-abcdef","withheld":["tcp://203.0.113.9:443"]}`,
		`null`,
	} {
		e := base(KindRunStart, `{"record_minor":31,"contract_source":{"path":"/agent.yaml","learn":`+bad+`}}`)
		if err := e.ValidateAt(31); err == nil {
			t.Errorf("record reader accepted malformed history %s", bad)
		}
	}
	p.RecordMinor = 30
	if got := FieldCode(p.ValidateFields()); got != "below-minor" {
		t.Fatalf("learn history below its revision: %q", got)
	}
}

// Strict decoding also applies to contract_source in ledgers written before learn
// history existed. Unknown members still follow the v1 forward-reading rule.
func TestContractSourceStrictAtOlderMinors(t *testing.T) {
	for _, minor := range []int{0, MinorContractSource - 1, MinorContractSource, MinorLearn - 1} {
		t.Run(fmt.Sprintf("minor-%d", minor), func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				extra string
				code  string
			}{
				{"absent", "", ""},
				{"plain source", `,"contract_source":{"path":"/agent.yaml"}`, ""},
				{"unknown member", `,"contract_source":{"path":"/agent.yaml","later":{"value":1}}`, ""},
				{"source path case ignored", `,"contract_source":{"Path":"/agent.yaml"}`, ""},
				{"raw UTF-8 repaired", ",\"contract_source\":{\"path\":\"/agent\xff.yaml\"}", ""},
				{"null source", `,"contract_source":null`, "learn"},
				{"null path", `,"contract_source":{"path":null}`, "learn"},
				{"wrong path type", `,"contract_source":{"path":13}`, "learn"},
				{"odd source case", `,"Contract_Source":{"path":"/agent.yaml"}`, "field-case"},
				{"odd learn case", `,"contract_source":{"path":"/agent.yaml","Learn":{}}`, "field-case"},
				{"duplicate member", `,"contract_source":{"path":"/agent.yaml","path":"/other.yaml"}`, "learn"},
				{"unpaired surrogate", `,"contract_source":{"path":"/agent\ud800.yaml"}`, "learn"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					e := base(KindRunStart, fmt.Sprintf(`{"record_minor":%d%s}`, minor, tc.extra))
					err := e.ValidateAt(minor)
					if got := FieldCode(err); got != tc.code || tc.code == "" && err != nil {
						t.Fatalf("ValidateAt(%d) = %v [%s], want [%s]", minor, err, got, tc.code)
					}
					if err != nil && !errors.Is(err, ErrInvalidEvent) {
						t.Fatalf("refusal %v is not ErrInvalidEvent", err)
					}
				})
			}
		})
	}
}
