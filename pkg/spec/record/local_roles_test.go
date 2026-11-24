// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalRolesRecordFixtures(t *testing.T) {
	const base = "../../../spec/record/v1/fixtures/local-roles"
	for _, group := range []string{"valid", "invalid"} {
		paths, err := filepath.Glob(base + "/" + group + "/*.json")
		if err != nil || len(paths) == 0 {
			t.Fatal(paths, err)
		}
		for _, path := range paths {
			t.Run(group+"/"+filepath.Base(path), func(t *testing.T) {
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var doc struct {
					Kind    Kind            `json:"kind"`
					Minor   int             `json:"minor"`
					Payload json.RawMessage `json:"payload"`
				}
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatal(err)
				}
				e := &Event{V: Version, Kind: doc.Kind, Source: SourceSupervisor, Run: "r-00000000-000000000000a-aaaaaa", Agent: "test", TS: time.Unix(10, 0), Payload: doc.Payload}
				err = e.ValidateAt(doc.Minor)
				if group == "valid" {
					if err != nil {
						t.Fatal(err)
					}
				} else {
					code, _, _ := strings.Cut(filepath.Base(path), ".")
					if FieldCode(err) != code {
						t.Fatalf("%v, want %s", err, code)
					}
				}
			})
		}
	}
}

func TestLocalRolesRevisionAndLegacyBytes(t *testing.T) {
	if MinorLocalRoles != 37 {
		t.Fatal("ADR 0154 reserved revision 37 for local roles")
	}
	if MinorPrincipal+1 != MinorLocalRoles {
		t.Fatal("local profile does not follow occupied team reservation")
	}
	e := &Event{V: Version, Kind: KindAnswer, Source: SourceSupervisor, Run: "r-00000000-000000000000a-aaaaaa", Agent: "test", TS: time.Unix(10, 0)}
	if err := e.SetPayload(AnswerPayload{AskID: "q-old", By: "uid:0 pid:42", AfterS: 2}); err != nil {
		t.Fatal(err)
	}
	a, err := e.MarshalLineAt(Minor)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.MarshalLineAt(MinorLocalRoles)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || strings.Contains(string(a), `"actor"`) || strings.Contains(string(a), `"system_cause"`) {
		t.Fatal("legacy record bytes changed or role inferred")
	}
}
