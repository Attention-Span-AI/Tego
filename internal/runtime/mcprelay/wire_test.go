// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// serverLines cuts b as the widest line reader a server may use does: Python's str.splitlines, whose breaks hold those
// of universal newlines and of Node's readline.
func serverLines(b []byte) []string {
	return strings.FieldsFunc(string(b), func(r rune) bool {
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			return true
		}
		return false
	})
}

// TestClientLineReachesTheServerAsOneLine: a denied call hidden between lone CRs in a line the relay reads as something
// else stays inside that message on every path that forwards one, so a server cannot frame it as a call of its own.
func TestClientLineReachesTheServerAsOneLine(t *testing.T) {
	hidden := "\r" + toolCall(9, "delete_file") + "\r"
	for _, c := range []struct {
		name string
		line string
	}{
		{"non-call", `{"jsonrpc":"2.0","id":2,"method":"ping","x":` + hidden + `}`},
		{"allowed call", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","x":` + hidden + `}}`},
		{"held call, approved", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","x":` + hidden + `}}`},
		{"batch", `[{"jsonrpc":"2.0","id":2,"method":"ping","x":` + hidden + `},` + toolCall(3, "read_file") + `]`},
		{"line separators in a string", "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"x\":\"a\u2028b\u2029c\u0085d\"}"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _, _ := start(t, nil, filesServer())
			s.ConfigureMCPAsk(func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{Approved: true}, nil })
			sh, _ := dial(t, s, "files", filesCmd)
			sh.client(c.line)
			f := sh.read()
			if f.ToServer == nil {
				t.Fatalf("not passed: %s", f.ToClient)
			}
			if lines := serverLines(f.ToServer); len(lines) != 1 {
				t.Fatalf("a server reads %d lines from %q, want 1", len(lines), f.ToServer)
			}
			sent, _, ok := readCalls(f.ToServer)
			decided, _, _ := readCalls([]byte(c.line))
			if !ok || !reflect.DeepEqual(sent, decided) {
				t.Fatalf("the server gets %+v, the relay decided %+v", sent, decided)
			}
		})
	}
}

// TestDressedDeniedCallStaysRefused: a denied call does not pass by being wrapped in a CR, alone or in a batch.
func TestDressedDeniedCallStaysRefused(t *testing.T) {
	for _, line := range []string{
		"\r" + toolCall(2, "delete_file") + "\r",
		"[\r" + toolCall(2, "delete_file") + "\r]",
	} {
		s, sk, _ := start(t, nil, filesServer())
		sh, _ := dial(t, s, "files", filesCmd)
		sh.client(line)
		if f := sh.read(); f.ToServer != nil || !strings.Contains(string(f.ToClient), `"code":-32001`) {
			t.Fatalf("%q: frame %+v", line, f)
		}
		if l := sk.of(record.KindMCP); len(l) != 1 || l[0].Rule != "mcp[files].tools.deny[delete_file]" {
			t.Fatalf("%q: mcp lines %+v", line, l)
		}
	}
}

// TestClientLineNotUTF8Refused: a line with a byte that is not UTF-8 is unreadable, however it would read to the relay.
// "delete_file\xff" is on no deny list as Go decodes it, and is delete_file to a reader that drops the byte.
func TestClientLineNotUTF8Refused(t *testing.T) {
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file` + "\xff" + `"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping","x":"` + "\xc0\x8d" + `"}`,
	} {
		s, _, _ := start(t, nil, filesServer())
		sh, _ := dial(t, s, "files", filesCmd)
		sh.client(line)
		if f := sh.read(); f.ToServer != nil || !strings.Contains(string(f.ToClient), `"code":-32700`) {
			t.Fatalf("%q: frame %+v", line, f)
		}
	}
}

// TestWireFormStaysInItsBound: escapes make a line longer, and the shim cannot read a frame past maxFrame: it would
// take that for a lost relay and kill the server. A line whose wire form is past the bound is answered, and the
// connection stays.
func TestWireFormStaysInItsBound(t *testing.T) {
	s, _, _ := start(t, nil, filesServer())
	sh, _ := dial(t, s, "files", filesCmd)
	sh.client(`{"jsonrpc":"2.0","id":2,"method":"ping","x":"` + strings.Repeat("\u0085", MaxLine/3) + `"}`)
	if f := sh.read(); f.ToServer != nil || !strings.Contains(string(f.ToClient), `"code":-32700`) {
		t.Fatalf("frame with %d bytes to the server, %.80s to the client", len(f.ToServer), f.ToClient)
	}
	sh.client(toolCall(3, "read_file"))
	if f := sh.read(); string(f.ToServer) != toolCall(3, "read_file") {
		t.Fatalf("the next line: %+v", f)
	}
}

func TestWireLine(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		want string // "" when the line is refused
	}{
		{"compact line stands byte for byte", toolCall(1, "read_file"), toolCall(1, "read_file")},
		{"space between tokens goes", " { \"a\" : 1 ,\t\"b\" :\r\n[ 2 ,\r3 ] }\r ", `{"a":1,"b":[2,3]}`},
		{"a string's escapes and text stand", `{"a":" b\tc\r\nd \u2028 \/ <&> é 😀"}`, `{"a":" b\tc\r\nd \u2028 \/ <&> é 😀"}`},
		{"a number stands", `{"a":1.50e+2,"b":12345678901234567890}`, `{"a":1.50e+2,"b":12345678901234567890}`},
		{"a key's break goes as an escape", "{\"\u2028\":1}", `{"\u2028":1}`},
		{"a string's breaks go as escapes", "{\"a\":\"x\u2028y\u2029z\u0085w\"}", `{"a":"x\u2028y\u2029z\u0085w"}`},
		{"a break after an escaped backslash", "{\"a\":\"\\\\\u2028\"}", `{"a":"\\\u2028"}`},
		{"a value that is no object is still one value", "null\r", `null`},
		{"empty", "", ""},
		{"space only", " \r\t", ""},
		{"not JSON", "ping", ""},
		{"two values", `{"a":1}{"b":2}`, ""},
		{"two values split by a CR", "{\"a\":1}\r{\"b\":2}", ""},
		{"raw CR in a string", "{\"a\":\"x\ry\"}", ""},
		{"raw VT in a string", "{\"a\":\"x\vy\"}", ""},
		{"FF before the value is no JSON space", "\f{}", ""},
		{"NBSP before the value is no JSON space", "\u00a0{}", ""},
		{"not UTF-8", "{\"a\":\"\xff\"}", ""},
		{"an overlong CR", "{\"a\":\"\xc0\x8d\"}", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := wireLine([]byte(c.in))
			if ok != (c.want != "") || string(got) != c.want {
				t.Fatalf("wireLine(%q) = %q, %v; want %q", c.in, got, ok, c.want)
			}
		})
	}
}

// decoded is a JSON text's value, numbers as written.
func decoded(t *testing.T, b []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	return v
}

// FuzzWireLine: whatever is passed is one line to any reader, holds no raw control byte, and is the same JSON value the
// line was, so the relay never changes a message's meaning to fix its framing.
func FuzzWireLine(f *testing.F) {
	for _, s := range []string{
		toolCall(1, "read_file"),
		"{\"a\":\r{\"b\":\"\u2028\"}\r}",
		"[1,\r2]\r\n",
		`{"a":"\\","b":"\"","c":"\u0000"}`,
		"{\"\u0085\":\"\u2029\"}",
		"\"\xe2\x80\"",
		"null",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		wire, ok := wireLine(in)
		if !ok {
			return
		}
		if lines := serverLines(wire); len(lines) != 1 {
			t.Fatalf("%q reads as %d lines: %q", in, len(lines), wire)
		}
		if i := bytes.IndexFunc(wire, func(r rune) bool { return r < 0x20 }); i >= 0 {
			t.Fatalf("%q: a control byte at %d of %q", in, i, wire)
		}
		if a, b := decoded(t, in), decoded(t, wire); !reflect.DeepEqual(a, b) {
			t.Fatalf("%q reads as %#v, its wire form %q as %#v", in, a, wire, b)
		}
		if again, ok := wireLine(wire); !ok || !bytes.Equal(again, wire) {
			t.Fatalf("the wire form %q is not its own wire form: %q, %v", wire, again, ok)
		}
	})
}
