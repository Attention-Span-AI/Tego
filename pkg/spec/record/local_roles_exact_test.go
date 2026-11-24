// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func localRolesEvent(payload []byte) *Event {
	return &Event{V: Version, Kind: KindAnswer, Source: SourceSupervisor, Run: "r-00000000-000000000000a-aaaaaa", Agent: "test", TS: time.Unix(10, 0), Payload: payload}
}

func TestLocalRolesAuthorityProjectionMatchesValidation(t *testing.T) {
	authority := `{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
	valid := `{"record_minor":37,"local_approval_authority":` + authority + `}`
	for _, tc := range []struct {
		name, payload string
		want          bool
	}{
		{"valid", valid, true},
		{"below-minor", strings.Replace(valid, `:37`, `:31`, 1), false},
		{"folded-revision", strings.Replace(valid, `"record_minor"`, `"Record_minor"`, 1), false},
		{"folded-authority", strings.Replace(valid, `"local_approval_authority"`, `"Local_approval_authority"`, 1), false},
		{"folded-mode", strings.Replace(valid, `"mode"`, `"Mode"`, 1), false},
		{"unknown-member", strings.TrimSuffix(valid, "}}") + `,"extra":true}}`, false},
		{"duplicate-member", strings.TrimSuffix(valid, "}}") + `,"agent_uid":1001}}`, false},
		{"duplicate-authority", strings.TrimSuffix(valid, "}") + `,"local_approval_authority":` + authority + `}`, false},
		{"invalid-other-reserved-field", strings.TrimSuffix(valid, "}") + `,"deployment":{}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := localRolesEvent([]byte(tc.payload))
			e.Kind = KindRunStart
			if got := e.ValidateAt(MinorLocalRoles) == nil; got != tc.want {
				t.Fatalf("validation=%v want %v: %s", got, tc.want, tc.payload)
			}
			if got := ValidatedLocalApprovalAuthority(e.Payload) != nil; got != tc.want {
				t.Fatalf("projection=%v want %v: %s", got, tc.want, tc.payload)
			}
		})
	}
}

func TestLocalRolesDecisionFieldsExact(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixturesDir, "local-roles/valid/approve.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"approved", "by", "answer_reason", "alternate"} {
		base := string(doc.Payload)
		if key == "answer_reason" || key == "alternate" {
			base = strings.TrimSuffix(strings.TrimSpace(base), "}") + `,"` + key + `":""}`
		}
		for _, spelling := range []string{strings.ToUpper(key[:1]) + key[1:], strings.ToUpper(key)} {
			t.Run(key+"/"+spelling, func(t *testing.T) {
				mutated := strings.Replace(base, `"`+key+`"`, `"`+spelling+`"`, 1)
				if err := localRolesEvent([]byte(mutated)).ValidateAt(MinorLocalRoles); FieldCode(err) != "field-case" {
					t.Fatalf("got %v, want field-case", err)
				}
			})
		}
		value := `""`
		if key == "approved" {
			value = `false`
		}
		for _, spelling := range []string{key, strings.ToUpper(key[:1]) + key[1:]} {
			t.Run(key+"/duplicate/"+spelling, func(t *testing.T) {
				mutated := strings.TrimSuffix(strings.TrimSpace(base), "}") + `,"` + spelling + `":` + value + `}`
				if err := localRolesEvent([]byte(mutated)).ValidateAt(MinorLocalRoles); err == nil {
					t.Fatal("duplicate decision accepted")
				}
			})
		}
	}
}

func TestLocalRolesUnattributedDecisionFieldsExact(t *testing.T) {
	const base = `{"approved":true,"by":"terminal","answer_reason":"","alternate":""}`
	for _, key := range []string{"approved", "by", "answer_reason", "alternate"} {
		folded := strings.ToUpper(key[:1]) + key[1:]
		t.Run(key, func(t *testing.T) {
			mutated := strings.Replace(base, `"`+key+`"`, `"`+folded+`"`, 1)
			if err := localRolesEvent([]byte(mutated)).ValidateAt(MinorLocalRoles); FieldCode(err) != "field-case" {
				t.Fatalf("unattributed decision: got %v, want field-case", err)
			}
			if err := localRolesEvent([]byte(mutated)).ValidateAt(MinorLearn); err != nil {
				t.Fatalf("legacy decision spelling changed: %v", err)
			}
			value := `""`
			if key == "approved" {
				value = `false`
			}
			duplicate := strings.TrimSuffix(base, "}") + `,"` + folded + `":` + value + `}`
			if err := localRolesEvent([]byte(duplicate)).ValidateAt(MinorLocalRoles); FieldCode(err) != "field-case" {
				t.Fatalf("unattributed folded duplicate: got %v, want field-case", err)
			}
			if err := localRolesEvent([]byte(duplicate)).ValidateAt(MinorLearn); err != nil {
				t.Fatalf("legacy folded duplicate behavior changed: %v", err)
			}
		})
	}
	for _, payload := range []string{base, `{"approved":false,"by":"terminal","answer_reason":"ask-denied"}`, `{"by":"terminal"}`} {
		e := localRolesEvent([]byte(payload))
		if err := e.ValidateAt(MinorLocalRoles); err != nil {
			t.Fatal(err)
		}
		line, err := e.MarshalLineAt(MinorLocalRoles)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(line)
		if err != nil {
			t.Fatal(err)
		}
		if err := decoded.ValidateAt(MinorLocalRoles); err != nil {
			t.Fatalf("unattributed decision became invalid after canonical encoding: %v", err)
		}
	}
}

// Every accepted member-order, case, duplicate and value mutation of the shared
// corpus must remain valid after the writer sorts and canonicalizes its members.
func TestLocalRolesAcceptedPayloadCanonicalProperty(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(fixturesDir, "local-roles/*/*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal(paths, err)
	}
	accepted := 0
	for _, path := range paths {
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
		mutations := [][]byte{doc.Payload}
		if doc.Kind == KindAnswer && strings.Contains(string(doc.Payload), `"approved": true`) {
			mutated := strings.Replace(string(doc.Payload), `"approved": true`, `"approved": false`, 1)
			mutations = append(mutations, []byte(strings.TrimSuffix(strings.TrimSpace(mutated), "}")+`,"Approved":true}`))
		}
		fields, err := objectFields(doc.Payload)
		if err != nil {
			t.Fatal(err)
		}
		// Reorder every member, then replace each one independently as well as
		// adding duplicate variants. This exercises accepted mutations too: a
		// corpus of duplicate-only mutations would mostly test refusals.
		render := func(replace int, key string, value []byte, reverse bool) []byte {
			var b strings.Builder
			b.WriteByte('{')
			for i := range fields {
				at := i
				if reverse {
					at = len(fields) - 1 - i
				}
				name, val := fields[at].key, fields[at].val
				if at == replace {
					name, val = key, value
				}
				if i > 0 {
					b.WriteByte(',')
				}
				nameJSON, err := json.Marshal(name)
				if err != nil {
					t.Fatal(err)
				}
				b.Write(nameJSON)
				b.WriteByte(':')
				b.Write(val)
			}
			b.WriteByte('}')
			return []byte(b.String())
		}
		mutations = append(mutations, render(-1, "", nil, false), render(-1, "", nil, true))
		for at, f := range fields {
			for _, key := range []string{f.key, strings.ToUpper(f.key[:1]) + f.key[1:]} {
				for _, value := range [][]byte{f.val, []byte(`true`), []byte(`false`), []byte(`""`), []byte(`null`), []byte(`1`), []byte(`[]`)} {
					// Both orders matter: encoding/json used to take the final
					// folded key, while canonical output sorts the original names.
					end := strings.TrimSuffix(strings.TrimSpace(string(doc.Payload)), "}") + `,"` + key + `":` + string(value) + `}`
					begin := `{"` + key + `":` + string(value) + `,` + strings.TrimPrefix(strings.TrimSpace(string(doc.Payload)), "{")
					mutations = append(mutations, []byte(end), []byte(begin), render(at, key, value, false), render(at, key, value, true))
				}
			}
		}
		for i, payload := range mutations {
			e := localRolesEvent(payload)
			e.Kind = doc.Kind
			if e.ValidateAt(doc.Minor) != nil {
				continue
			}
			accepted++
			line, err := e.MarshalLineAt(doc.Minor)
			if err != nil {
				t.Fatalf("%s mutation %d accepted but cannot encode: %v", path, i, err)
			}
			decoded, err := Decode(line)
			if err != nil {
				t.Fatal(err)
			}
			if err := decoded.ValidateAt(doc.Minor); err != nil {
				t.Fatalf("%s mutation %d became invalid after canonical encoding: %v; %s", path, i, err, line)
			}
			canonical, err := decoded.MarshalLineAt(doc.Minor)
			if err != nil || string(canonical) != string(line) {
				t.Fatalf("%s mutation %d canonical encoding is unstable: %v", path, i, err)
			}
		}
	}
	if accepted < 7 {
		t.Fatalf("only %d accepted payloads exercised", accepted)
	}
	t.Logf("%d accepted fixture payloads and mutations preserve validation and canonical bytes", accepted)
}

func TestLocalRolesSharedChainFixture(t *testing.T) {
	events := readFixture(t, "local-roles.jsonl")
	if len(events) != 5 {
		t.Fatal(len(events))
	}
	for _, e := range events {
		if err := e.ValidateAt(MinorLocalRoles); err != nil {
			t.Fatalf("line %d: %v", e.Seq, err)
		}
	}
	var answer struct {
		AnswerAuthority
		Approved bool `json:"approved"`
	}
	if events[2].DecodePayload(&answer) != nil || !answer.Approved || answer.Actor == nil || events[3].Verdict != VerdictRefused || events[3].Reason != ReasonAskUnavailable {
		t.Fatal("fixture lost recorded selection followed by refused effect")
	}
}

// The local approval fields have a minimum revision, not an exact one: a ledger written at a later supported revision,
// which declares a superset of 37, carries and validates them the same way (the writer never drops to 37 for them).
func TestLocalRolesFieldsAreValidFromRevision37OnwardWhereSupported(t *testing.T) {
	authority := `{"mode":"owner_only","sha256":"` + strings.Repeat("ab", 32) + `","agent_uid":1001}`
	actor := `{"uid":0,"pid":42,"start_boot_ns":10000000,"user_namespace":4026531837,"source":"kernel-local-uid","role":"owner"}`
	answer := json.RawMessage(`{"ask_id":"q-0123456789abcdef0123456789abcdef","by":"uid:0 pid:42","after_s":1,"approved":true,"actor":` + actor + `}`)
	for _, minor := range []int{MinorLocalRoles, MinorAppliedLimits} {
		start := json.RawMessage(`{"record_minor":` + strconv.Itoa(minor) + `,"local_approval_authority":` + authority + `}`)
		if ValidatedLocalApprovalAuthority(start) == nil {
			t.Errorf("revision %d: the authority block is not valid", minor)
		}
		if ValidatedAnswerAuthority(answer, minor).Actor == nil {
			t.Errorf("revision %d: the actor is not attributed", minor)
		}
	}
	if ValidatedAnswerAuthority(answer, MinorLearn).Actor != nil || ValidatedAnswerAuthority(answer, MinorStoppedBy).Actor != nil {
		t.Error("an actor was attributed below revision 37")
	}
}
