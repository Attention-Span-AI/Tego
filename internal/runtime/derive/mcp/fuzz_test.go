// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"unicode/utf8"
)

func seedMessages(f *testing.F) {
	for _, l := range bytes.Split(fixture(f, "stdio-client.jsonl"), []byte("\n")) {
		f.Add(l)
	}
	f.Add([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},7]`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"x","params":{"name":"a","name":1}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","Method":"tools/call","params":{"name":"rm_rf"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"METHOD":"tools/call","params":{"name":"rm_rf"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","Name":"rm_rf"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"q"}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte("\xff{"))
}

// FuzzRead: every reader of bytes the governed run controls gets a fuzz target (capture-derive.md §9). The
// properties: Read never panics; an item comes only from valid JSON; a value that is not valid JSON is exactly one
// unreadable message; a tool name is bounded and is valid UTF-8 whenever the wire's was; reading is deterministic.
func FuzzRead(f *testing.F) {
	seedMessages(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		items, bad := Read(raw)
		if bad < 0 {
			t.Fatalf("negative bad count %d", bad)
		}
		if !json.Valid(raw) && (len(items) != 0 || bad != 1) {
			t.Fatalf("invalid JSON read as %+v, %d bad", items, bad)
		}
		for _, it := range items {
			if it.Kind != KindInitialize && it.Kind != KindToolCall {
				t.Fatalf("an item of kind %d", it.Kind)
			}
			if len(it.Tool) > MaxTool || it.Kind == KindInitialize && it.Tool != "" {
				t.Fatalf("item %+v", it)
			}
			if utf8.Valid(raw) && !utf8.ValidString(it.Tool) {
				t.Fatalf("a tool name %q that is not UTF-8 from UTF-8 input", it.Tool)
			}
			if it.Kind == KindToolCall && it.Tool == "" {
				t.Fatalf("a call with no tool from %q", raw)
			}
		}
		// A call read from one object is the call a Go server decoding it with encoding/json, which folds key case
		// and keeps the last of two keys, reads too (R41).
		if len(items) == 1 && items[0].Kind == KindToolCall && bytes.HasPrefix(trimSpace(raw), []byte("{")) {
			var g struct {
				Method string `json:"method"`
				Params struct {
					Name string `json:"name"`
				} `json:"params"`
			}
			if err := json.Unmarshal(raw, &g); err != nil || g.Method != methodToolsCall || cut(g.Params.Name) != items[0].Tool {
				t.Fatalf("read call %q from %q, encoding/json reads method %q tool %q (%v)", items[0].Tool, raw, g.Method, g.Params.Name, err)
			}
		}
		again, bad2 := Read(raw)
		if !reflect.DeepEqual(items, again) || bad != bad2 {
			t.Fatal("two readings of one value differ")
		}
	})
}

// FuzzStdio: a stream read in two pieces split anywhere reads as it does whole, and no input panics.
func FuzzStdio(f *testing.F) {
	f.Add(fixture(f, "stdio-client.jsonl"), 17)
	f.Add([]byte("{\"jsonrpc\":\"2.0\"\n\n\r\n[]\nx"), 3)
	f.Fuzz(func(t *testing.T, wire []byte, at int) {
		var whole Stdio
		a, aEnd := whole.Write(wire), whole.Close()
		if at < 0 {
			at = -at
		}
		at %= len(wire) + 1
		var split Stdio
		b1, b2, bEnd := split.Write(wire[:at]), split.Write(wire[at:]), split.Close()
		items := append(append([]Item(nil), b1.Items...), b2.Items...)
		if !reflect.DeepEqual(a.Items, items) && (len(a.Items) != 0 || len(items) != 0) ||
			a.Malformed+aEnd.Malformed != b1.Malformed+b2.Malformed+bEnd.Malformed || a.Oversize != b1.Oversize+b2.Oversize {
			t.Fatalf("split at %d: %+v %+v %+v, whole %+v %+v", at, b1, b2, bEnd, a, aEnd)
		}
	})
}

// FuzzReadHTTPRequest: a POST body is items, an unreadable error, or nothing; never another error, never a panic.
func FuzzReadHTTPRequest(f *testing.F) {
	seedMessages(f)
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ReadHTTPRequest("POST", body, false)
		if err != nil {
			if !errors.Is(err, ErrUnreadable) || len(r.Items) != 0 {
				t.Fatalf("%v with %+v", err, r)
			}
			return
		}
		if len(r.Items) == 0 && r.Malformed != 0 {
			t.Fatalf("nothing read and %d malformed, yet no error", r.Malformed)
		}
	})
}
