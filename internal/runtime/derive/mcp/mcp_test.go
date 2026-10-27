// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// recorded is what every fixture's client did (testdata/README.md): initialize, tools/list, two calls.
var recorded = []Item{{Kind: KindInitialize}, {Kind: KindToolCall, Tool: "db_query"}, {Kind: KindToolCall, Tool: "echo"}}

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestStdioRecordedSession reads the bytes a real client wrote to its server's stdin, whole and cut into pieces of
// every size from one byte up: where a write splits a line must never change what is read.
func TestStdioRecordedSession(t *testing.T) {
	wire := fixture(t, "stdio-client.jsonl")
	for size := 1; size <= len(wire); size++ {
		var s Stdio
		var got Result
		for p := wire; len(p) > 0; {
			n := min(size, len(p))
			r := s.Write(p[:n])
			got.Items, got.Malformed, got.Oversize = append(got.Items, r.Items...), got.Malformed+r.Malformed, got.Oversize+r.Oversize
			p = p[n:]
		}
		end := s.Close()
		if !reflect.DeepEqual(got.Items, recorded) || got.Malformed+end.Malformed != 0 || got.Oversize != 0 {
			t.Fatalf("pieces of %d bytes: read %+v, want %+v and nothing malformed", size, got, recorded)
		}
	}
}

type exchange struct {
	Request struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
	} `json:"request"`
	Status int `json:"status"`
}

// TestHTTPRecordedExchanges reads the POST bodies of both HTTP transports as a real client sent them.
func TestHTTPRecordedExchanges(t *testing.T) {
	for _, name := range []string{"streamable-sse.jsonl", "streamable-json.jsonl", "http-sse-legacy.jsonl"} {
		t.Run(name, func(t *testing.T) {
			sc := bufio.NewScanner(bytes.NewReader(fixture(t, name)))
			sc.Buffer(nil, 1<<20)
			var got []Item
			for sc.Scan() {
				var x exchange
				if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
					t.Fatal(err)
				}
				r, err := ReadHTTPRequest(x.Request.Method, []byte(x.Request.Body), false)
				if err != nil || r.Malformed != 0 {
					t.Fatalf("%s %s: %v, %d malformed", x.Request.Method, x.Request.Path, err, r.Malformed)
				}
				got = append(got, r.Items...)
			}
			if !reflect.DeepEqual(got, recorded) {
				t.Fatalf("read %+v, want %+v", got, recorded)
			}
		})
	}
}

// TestReadAsAServerReads pins the reading every server's own JSON parser agrees on: JSON-RPC 2.0's shape and
// tools/call's. Where parsers disagree it reads nothing and counts the message bad (R41): a key the reader uses
// spelled in another case (Go's encoding/json folds it onto the field, a JavaScript or Python server does not), the
// same key twice (the last wins in most parsers, serde refuses it), a request with no id (a notification, which the
// SDKs drop for these methods), and a null or empty tool name (no SDK's schema takes one).
func TestReadAsAServerReads(t *testing.T) {
	call := func(tool string) []Item { return []Item{{Kind: KindToolCall, Tool: tool}} }
	for _, c := range []struct {
		name  string
		in    string
		items []Item
		bad   int
	}{
		{"call", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q","arguments":{}}}`, call("q"), 0},
		{"string id", `{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"q"}}`, call("q"), 0},
		{"notification-shaped call", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"notification-shaped initialize", `{"jsonrpc":"2.0","method":"initialize","params":{}}`, nil, 1},
		{"duplicate method", `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"q"}}`, nil, 1},
		{"duplicate method, other way", `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"duplicate name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`, nil, 1},
		{"duplicate id", `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"duplicate params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}}`, nil, 1},
		{"an unused key twice is read", `{"jsonrpc":"2.0","id":1,"method":"tools/call","x":1,"x":2,"params":{"name":"q","_meta":{},"_meta":{}}}`, call("q"), 0},
		{"Method alone", `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"Name alone", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"Name":"q"}}`, nil, 1},
		// A Go server decoding into a tagged struct folds key case and keeps the last: it reads tools/call rm_rf.
		{"Method beside method", `{"jsonrpc":"2.0","id":1,"method":"ping","Method":"tools/call","params":{"name":"rm_rf"}}`, nil, 1},
		{"METHOD beside method", `{"jsonrpc":"2.0","id":1,"method":"ping","METHOD":"tools/call","params":{"name":"rm_rf"}}`, nil, 1},
		{"METHOD alone", `{"jsonrpc":"2.0","id":1,"METHOD":"tools/call","params":{"name":"rm_rf"}}`, nil, 1},
		{"Name beside name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","Name":"rm_rf"}}`, nil, 1},
		{"Arguments beside arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q","arguments":{},"Arguments":[]}}`, nil, 1},
		{"Params beside params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"},"Params":{"name":"rm_rf"}}`, nil, 1},
		{"Id", `{"jsonrpc":"2.0","Id":1,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"JSONRPC", `{"JSONRPC":"2.0","jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"Result in a response", `{"jsonrpc":"2.0","id":1,"result":{},"Result":{}}`, nil, 1},
		// Go's fold also maps U+212A KELVIN SIGN onto k and U+017F LONG S onto s.
		{"long s in params", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"},"paramſ":{"name":"rm_rf"}}`, nil, 1},
		{"kelvin in a key the reader does not use", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"q\"},\"\u212aey\":1}", call("q"), 0},
		{"null name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`, nil, 1},
		{"empty name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`, nil, 1},
		{"initialize", `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}`, []Item{{Kind: KindInitialize}}, 0},
		{"other request", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil, 0},
		{"response", `{"jsonrpc":"2.0","id":1,"result":{}}`, nil, 0},
		{"error response", `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, nil, 0},
		{"response with both", `{"jsonrpc":"2.0","id":1,"result":{},"error":{}}`, nil, 1},
		{"no jsonrpc", `{"id":1,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"jsonrpc 1.0", `{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"object id", `{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"no params", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, nil, 1},
		{"params array", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["q"]}`, nil, 1},
		{"numeric name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":7}}`, nil, 1},
		{"array arguments", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q","arguments":[]}}`, nil, 1},
		{"method not a string", `{"jsonrpc":"2.0","id":1,"method":1}`, nil, 1},
		{"not json", `{"jsonrpc":"2.0",`, nil, 1},
		{"two values", `{"jsonrpc":"2.0","id":1,"result":{}} {}`, nil, 1},
		{"scalar", `"tools/call"`, nil, 1},
		{"U+00A0 is not JSON whitespace", "\u00a0" + `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`, nil, 1},
		{"empty batch", `[]`, nil, 1},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"b"}}]`,
			[]Item{{Kind: KindToolCall, Tool: "a"}, {Kind: KindToolCall, Tool: "b"}}, 0},
		{"batch with a bad member", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a"}},7,{"id":2}]`, call("a"), 2},
	} {
		items, bad := Read([]byte(c.in))
		if !reflect.DeepEqual(items, c.items) || bad != c.bad {
			t.Errorf("%s: read %+v with %d bad, want %+v with %d", c.name, items, bad, c.items, c.bad)
		}
	}
}

// TestToolNameBounded: a name past MaxTool is cut on a rune boundary and marked.
func TestToolNameBounded(t *testing.T) {
	long := strings.Repeat("é", MaxTool)
	items, _ := Read([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + long + `"}}`))
	if len(items) != 1 || len(items[0].Tool) > MaxTool || !strings.HasSuffix(items[0].Tool, "...") ||
		!strings.HasPrefix(long, strings.TrimSuffix(items[0].Tool, "...")) {
		t.Fatalf("a long name read as %q", items)
	}
}

// TestStdioBounds: an oversize line is counted and skipped to its newline, the next line is read, CRLF and blank
// lines are tolerated, and a last line the stream ended inside is malformed, never read.
func TestStdioBounds(t *testing.T) {
	var s Stdio
	callLine := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`
	big := bytes.Repeat([]byte("x"), MaxMessage/4)
	var r Result
	for range 5 { // 5/4 of the bound, written with no newline
		w := s.Write(big)
		r.Oversize += w.Oversize
	}
	if r.Oversize != 1 || len(s.line) != 0 {
		t.Fatalf("an oversize line counted %d times, %d bytes held", r.Oversize, len(s.line))
	}
	w := s.Write([]byte("tail of the big line\n\r\n\n" + callLine + "\r\n" + callLine[:10]))
	if !reflect.DeepEqual(w.Items, []Item{{Kind: KindToolCall, Tool: "q"}}) || w.Malformed != 0 || w.Oversize != 0 {
		t.Fatalf("after the oversize line: %+v", w)
	}
	if end := s.Close(); end.Malformed != 1 {
		t.Fatalf("a cut last line: %+v", end)
	}
	// A line that crosses the bound only once its newline arrives.
	var s2 Stdio
	s2.Write(bytes.Repeat([]byte(" "), MaxMessage-1))
	if w := s2.Write([]byte("xx\n" + callLine + "\n")); w.Oversize != 1 || len(w.Items) != 1 {
		t.Fatalf("a line ending past the bound: %+v", w)
	}
	// A line of exactly MaxMessage bytes is read.
	var s3 Stdio
	exact := append([]byte(callLine), bytes.Repeat([]byte(" "), MaxMessage-len(callLine))...)
	if w := s3.Write(append(exact, '\n')); w.Oversize != 0 || len(w.Items) != 1 {
		t.Fatalf("a line of exactly the bound: %+v", w)
	}
}

// TestReadHTTPRequest: only a POST body carries client messages; an unreadable or cut one is an error, a batch
// with some readable members names them.
func TestReadHTTPRequest(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"q"}}`
	if r, err := ReadHTTPRequest("GET", []byte(call), false); err != nil || len(r.Items) != 0 {
		t.Fatalf("a GET read as %+v, %v", r, err)
	}
	if r, err := ReadHTTPRequest("POST", nil, false); err != nil || len(r.Items) != 0 {
		t.Fatalf("an empty POST read as %+v, %v", r, err)
	}
	for _, c := range []struct {
		body      string
		truncated bool
	}{{call, true}, {"", true}, {"not json", false}, {`[1,2]`, false}} {
		if _, err := ReadHTTPRequest("POST", []byte(c.body), c.truncated); !errors.Is(err, ErrUnreadable) {
			t.Fatalf("%q truncated=%v: %v, want ErrUnreadable", c.body, c.truncated, err)
		}
	}
	r, err := ReadHTTPRequest("POST", []byte("["+call+",1]"), false)
	if err != nil || len(r.Items) != 1 || r.Malformed != 1 {
		t.Fatalf("a half-readable batch: %+v, %v", r, err)
	}
}
