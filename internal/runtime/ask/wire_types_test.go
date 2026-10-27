// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// TestBrokerTypesMatchWire: the broker's Request, Summary and Decision carry exactly askproto's wire fields, in the
// same order with the same types and tags, besides the fields that never leave the run (json:"-"), so the
// conversions in socket.go lose nothing and a field added to one side and not the other fails here.
func TestBrokerTypesMatchWire(t *testing.T) {
	for _, c := range []struct{ broker, wire reflect.Type }{
		{reflect.TypeOf(Request{}), reflect.TypeOf(askproto.Request{})},
		{reflect.TypeOf(Decision{}), reflect.TypeOf(askproto.Decision{})},
	} {
		var fields []reflect.StructField
		for i := 0; i < c.broker.NumField(); i++ {
			if f := c.broker.Field(i); f.Tag.Get("json") != "-" {
				fields = append(fields, f)
			}
		}
		if len(fields) != c.wire.NumField() {
			t.Fatalf("%s has %d wire fields, askproto.%s %d", c.broker, len(fields), c.wire.Name(), c.wire.NumField())
		}
		for i, f := range fields {
			w := c.wire.Field(i)
			if f.Name != w.Name || f.Type != w.Type || f.Tag != w.Tag {
				t.Errorf("%s field %d is %s %s %q, askproto's %s %s %q", c.broker, i, f.Name, f.Type, f.Tag, w.Name, w.Type, w.Tag)
			}
		}
	}
	s, w := reflect.TypeOf(Summary{}), reflect.TypeOf(askproto.Summary{})
	if s.NumField() != w.NumField() || !s.Field(0).Anonymous || !w.Field(0).Anonymous {
		t.Fatalf("Summary is not askproto.Summary's shape: %v / %v", s, w)
	}
	for i := 1; i < s.NumField(); i++ {
		if f, g := s.Field(i), w.Field(i); f.Name != g.Name || f.Tag != g.Tag || f.Type != g.Type {
			t.Errorf("Summary field %d is %s %s %q, askproto's %s %s %q", i, f.Name, f.Type, f.Tag, g.Name, g.Type, g.Tag)
		}
	}
	score := 3
	req := Request{Score: &score, GateRule: "g", AskID: "q-1", Op: "o", Target: "t", Target2: "t2", Rule: "r", Hold: "h", PID: 1, TID: 2,
		Alternates: NewAlternateCheck(func(*AlternateFile) (string, error) { return "", nil })}
	back := requestOf(req.wire())
	back.Alternates = req.Alternates
	if !reflect.DeepEqual(back, req) {
		t.Fatalf("a request through the wire: %+v, want %+v", back, req)
	}
	d := Decision{AskID: "q-1", Approved: true, By: "b", Reason: "r", AfterS: 1.5, Always: true, Alternate: "/a", AlternateDev: 7, AlternateIno: 9}
	if got := decisionOf(d.wire()); !reflect.DeepEqual(got, d) {
		t.Fatalf("a decision through the wire: %+v, want %+v", got, d)
	}
	sum := Summary{Request: req, TargetTruncated: true, RuleTruncated: true}
	gotSum := summaryOf(sum.wire())
	gotSum.Alternates = req.Alternates
	if !reflect.DeepEqual(gotSum, sum) {
		t.Fatalf("a summary through the wire: %+v, want %+v", gotSum, sum)
	}
}
