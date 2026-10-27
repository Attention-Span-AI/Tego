// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// Version is the parser_version of an exchange this package read (R32, I6), and the run_start.parsers["mcp"]
// token that names it.
const Version = "mcp/1"

// Kind is what one client message was, among the ones a record names.
type Kind uint8

const (
	// KindInitialize is the initialize request that opens a session: the client connected to the server.
	KindInitialize Kind = iota + 1
	// KindToolCall is a tools/call request; Item.Tool names the tool.
	KindToolCall
)

// Item is one client message a record names, in wire order.
type Item struct {
	Kind Kind
	// Tool is params.name of a tools/call, at most MaxTool bytes (cut ones end in "..."), "" otherwise.
	Tool string
}

// MaxTool bounds the tool name an Item carries. The protocol asks for names of 1 to 128 characters; a longer one is
// kept to this many bytes, cut on a rune boundary and marked, so one message cannot put an arbitrary string on
// every ledger line that names it.
const MaxTool = 256

// MaxMessage bounds one message: a stdio line or an HTTP body longer than this is not read (Stdio counts it as
// Result.Oversize). 8 MiB holds any tool call's arguments a model writes; the bound is what keeps one line from
// growing a run's recorder without limit.
const MaxMessage = 8 << 20

// Methods the record names (MCP 2025-06-18, Lifecycle and Tools).
const (
	methodInitialize = "initialize"
	methodToolsCall  = "tools/call"
)

// errMessage is a value that is not a JSON-RPC 2.0 message as a server would read one, or one servers' parsers
// would read differently.
var errMessage = errors.New("mcp: not a JSON-RPC 2.0 message")

// The members the reader uses: a message's, and a tools/call's params'.
var (
	messageKeys = []string{"jsonrpc", "id", "method", "params", "result", "error"}
	paramsKeys  = []string{"name", "arguments"}
)

// Read reads one JSON value a client sent — a message, or a batch of them (JSON-RPC 2.0 §6, which MCP's 2025-03-26
// revision admits) — and returns the items it names in wire order and how many messages could not be read. A value
// that is not JSON, not an object or an array, or an empty batch is one unreadable message; one bad member of a
// batch is one, and the others are still read. Messages that are neither an initialize nor a tools/call request
// (notifications, responses, other requests) name nothing.
func Read(raw []byte) (items []Item, bad int) {
	raw = trimSpace(raw)
	if !json.Valid(raw) {
		return nil, 1
	}
	switch raw[0] {
	case '{':
		it, ok, err := readMessage(raw)
		if err != nil {
			return nil, 1
		}
		if ok {
			items = append(items, it)
		}
		return items, 0
	case '[':
		dec := json.NewDecoder(bytes.NewReader(raw))
		if _, err := dec.Token(); err != nil { // '['
			return nil, 1
		}
		n := 0
		for dec.More() {
			var m json.RawMessage
			if err := dec.Decode(&m); err != nil {
				return items, bad + 1
			}
			n++
			it, ok, err := readMessage(m)
			switch {
			case err != nil:
				bad++
			case ok:
				items = append(items, it)
			}
		}
		if n == 0 {
			return nil, 1 // JSON-RPC 2.0 §6: an empty array is an invalid request
		}
		return items, bad
	default:
		return nil, 1
	}
}

// readMessage reads one object. ok is false for a well-formed message the record does not name.
func readMessage(raw []byte) (Item, bool, error) {
	f, err := fields(raw, messageKeys)
	if err != nil {
		return Item{}, false, err
	}
	var version string
	if v, ok := f["jsonrpc"]; !ok || json.Unmarshal(v, &version) != nil || version != "2.0" {
		return Item{}, false, errMessage
	}
	m, isCall := f["method"]
	if !isCall {
		// A response: it must carry an id and exactly one of result and error.
		_, hasResult := f["result"]
		_, hasError := f["error"]
		if _, hasID := f["id"]; !hasID || hasResult == hasError {
			return Item{}, false, errMessage
		}
		return Item{}, false, nil
	}
	var method string
	if json.Unmarshal(m, &method) != nil {
		return Item{}, false, errMessage
	}
	id, hasID := f["id"]
	if hasID && !validID(id) {
		return Item{}, false, errMessage
	}
	switch method {
	case methodInitialize, methodToolsCall:
		if !hasID {
			// A notification: the SDKs drop one of these methods unanswered (the TypeScript SDK's
			// _onnotification), and a server that ran it would answer nothing either; which one a server is the
			// reader cannot know, so it is unreadable rather than a call or nothing.
			return Item{}, false, errMessage
		}
	}
	switch method {
	case methodInitialize:
		return Item{Kind: KindInitialize}, true, nil
	case methodToolsCall:
		params, ok := f["params"]
		if !ok {
			return Item{}, false, errMessage
		}
		pf, err := fields(params, paramsKeys)
		if err != nil {
			return Item{}, false, errMessage
		}
		var name string
		// A JSON string, not null (which Unmarshal takes as no change), and not empty: no SDK's schema takes either.
		if n, ok := pf["name"]; !ok || !bytes.HasPrefix(n, []byte(`"`)) || json.Unmarshal(n, &name) != nil || name == "" {
			return Item{}, false, errMessage
		}
		if a, ok := pf["arguments"]; ok && !bytes.HasPrefix(a, []byte("{")) {
			return Item{}, false, errMessage // tools/call arguments is an object when present
		}
		return Item{Kind: KindToolCall, Tool: cut(name)}, true, nil
	}
	return Item{}, false, nil
}

// validID: a request id is a string or a number (JSON-RPC 2.0 §4; MCP forbids null).
func validID(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	switch c := raw[0]; {
	case c == '"':
		return true
	case c == '-' || c >= '0' && c <= '9':
		return true
	}
	return false
}

// fields reads one JSON object's members, each value its exact wire bytes. Servers' parsers read a member's key
// differently: a JavaScript or Python server compares it exactly and keeps the last of two equal keys, serde
// refuses the second, and Go's encoding/json folds its case (strings.EqualFold's folding, U+212A and U+017F
// included) onto a struct field and keeps the last. So where they could disagree on a key the reader uses (one of
// used), the object is unreadable rather than given one of their readings: a key that folds to a used one but is
// not spelled as it is, or a used key twice. Keys the reader does not use are kept and never compared.
func fields(raw []byte, used []string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	t, err := dec.Token()
	if err != nil {
		return nil, errMessage
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, errMessage
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errMessage
		}
		key, ok := t.(string)
		if !ok {
			return nil, errMessage
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errMessage
		}
		for _, u := range used {
			if !strings.EqualFold(key, u) {
				continue
			}
			if _, dup := out[u]; dup || key != u {
				return nil, errMessage
			}
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // '}'
		return nil, errMessage
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errMessage // trailing data after the object
	}
	return out, nil
}

// trimSpace trims JSON's own whitespace (RFC 8259 §2: space, tab, LF, CR) and nothing else: bytes.TrimSpace also
// trims Unicode spaces such as U+00A0, which no server's JSON parser takes for whitespace.
func trimSpace(b []byte) []byte { return bytes.Trim(b, " \t\n\r") }

// cut bounds a tool name at MaxTool bytes on a rune boundary.
func cut(s string) string {
	if len(s) <= MaxTool {
		return s
	}
	n := MaxTool - len("...")
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}
