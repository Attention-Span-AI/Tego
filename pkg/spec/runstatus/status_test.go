// SPDX-License-Identifier: Apache-2.0

package runstatus

import (
	"encoding/json"
	"strings"
	"testing"
)

func validStatus() Status {
	return Status{Schema: Schema, Run: "r-00000000-000000000000a-aaaaaa", Scope: "/sys/fs/cgroup/tego.slice/run-a.scope", CgroupID: "123", Removed: true}
}

func TestStatusCodec(t *testing.T) {
	for _, s := range []Status{validStatus(), {Schema: Schema, Run: validStatus().Run}, {Schema: Schema, Run: validStatus().Run, Scope: validStatus().Scope, CgroupID: "123", Deferred: true}} {
		b, err := Encode(s)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(b)
		if err != nil || got != s {
			t.Fatalf("round trip = %+v, %v; want %+v", got, err, s)
		}
	}
}

func TestStatusRejectsEveryMissingAndWrongField(t *testing.T) {
	b, err := json.Marshal(validStatus())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			original := fields[key]
			delete(fields, key)
			missing, _ := json.Marshal(fields)
			if _, err := Decode(missing); err == nil {
				t.Fatal("accepted missing field")
			}
			for _, wrong := range []json.RawMessage{[]byte("null"), []byte("[]"), []byte("{}"), []byte("7")} {
				fields[key] = wrong
				bad, _ := json.Marshal(fields)
				if _, err := Decode(bad); err == nil {
					t.Fatalf("accepted wrong field %s", bad)
				}
			}
			fields[key] = original
		})
	}
}

func TestStatusRejectsMalformedInput(t *testing.T) {
	b, _ := Encode(validStatus())
	for _, bad := range []string{
		strings.Replace(string(b), `"schema":`, `"schema":"tego.run-status/1","schema":`, 1),
		strings.Replace(string(b), `"schema":`, `"extra":false,"schema":`, 1),
		string(b) + " {}", "[]", "null", string(b[:len(b)-3]), strings.Repeat(" ", MaxBytes+1),
	} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatalf("accepted malformed input %q", bad)
		}
	}
}

func TestStatusRejectsInvalidClaims(t *testing.T) {
	for _, change := range []func(*Status){
		func(s *Status) { s.Schema = "tego.run-status/2" }, func(s *Status) { s.Run = "r-1" },
		func(s *Status) { s.Scope = "relative" }, func(s *Status) { s.Scope = "/a/../b" },
		func(s *Status) { s.Scope = "/" }, func(s *Status) { s.Scope = "" },
		func(s *Status) { s.CgroupID = "" }, func(s *Status) { s.CgroupID = "0" },
		func(s *Status) { s.CgroupID = "01" }, func(s *Status) { s.CgroupID = "-1" },
		func(s *Status) { s.CgroupID = "18446744073709551616" }, func(s *Status) { s.Deferred = true },
	} {
		s := validStatus()
		change(&s)
		if _, err := Encode(s); err == nil {
			t.Fatalf("accepted invalid status %+v", s)
		}
	}
}
