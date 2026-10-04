// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"testing"
)

func TestHTTPRequestFieldsRemainAdditiveInV1(t *testing.T) {
	e := action(KindNet, "")
	e.Source, e.Authority, e.Rule, e.Verdict, e.Reason = SourceForwarder, AuthorityRule, "unmatched", VerdictRefused, ReasonNetHTTP
	p := NetPayload{Op: "http_request", Proto: "http", Dst: "api.example.com:8443", HTTPAuthority: "api.example.com:8443", Host: "api.example.com", Method: "POST", Path: "/v1/messages"}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	d, err := Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	var got NetPayload
	if err := json.Unmarshal(d.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != p.Op || got.HTTPAuthority != p.HTTPAuthority || got.Method != p.Method || got.Path != p.Path || d.Authority != AuthorityRule {
		t.Fatalf("HTTP upstream identity overwrote envelope: %+v %+v", d, got)
	}
	// The historical socket form has no HTTP meaning added by decoding.
	legacy := perKind(t)[KindNet]
	line, err = legacy.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	d, err = Decode(line)
	if err != nil {
		t.Fatal(err)
	}
	got = NetPayload{}
	if err := json.Unmarshal(d.Payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != "" || got.HTTPAuthority != "" || got.Method != "" || got.Path != "" {
		t.Fatal("legacy socket action invented HTTP fields")
	}
}
