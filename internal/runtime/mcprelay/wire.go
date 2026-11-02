// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// lineBreaks spells as JSON escapes the line breaks valid JSON can hold raw, all of them inside a string.
var lineBreaks = strings.NewReplacer("\u0085", `\u0085`, "\u2028", `\u2028`, "\u2029", `\u2029`)

// wireLine is a client line in the only form it goes to a stdio server: one JSON value, on one line under any server's
// line reader. ok is false for a line that is not exactly one JSON value in UTF-8.
//
// The shim and the relay end a line at LF; a server ends one where its own reader does. The official Python SDK's
// reader (universal newlines) and Node's readline also end one at a lone CR, which JSON allows between tokens. So
// {"method":"ping","x":<CR>{...a tools/call...}<CR>} was one ping to the relay and, forwarded as it came, a tools/call
// to the server: a denied tool ran with no ledger line, at any tier (review of the relay's line framing). The relay
// therefore never forwards the agent's bytes, and reads this form itself, so what it decides is what the server gets.
//
// Compact drops the space between tokens and JSON has no raw control character inside a string, so no CR, LF or other
// C0 break survives. What is left is the three breaks a string may hold, which Python's str.splitlines ends a line at:
// their escapes read as the same characters. Every byte of a string and a number otherwise stands as it came.
//
// UTF-8 is what MCP's stdio transport requires. A reader's way with a bad byte (replace it, drop it, fail) is one more
// reading of the name the relay decided: "delete_file\xff" is not on a deny list here and is delete_file to a reader
// that drops the byte. Such a line is unreadable, as ambiguousKeys's is.
//
// An escape is longer than its break, and a frame past maxFrame reads to the shim as a lost relay, which stops the
// server. So a wire form past MaxLine is unreadable too: that line is answered and the connection stays.
func wireLine(line []byte) (wire []byte, ok bool) {
	wire, ok = wireForm(line)
	return wire, ok && len(wire) <= MaxLine
}

// wireForm is line as one JSON value in UTF-8, compact, with the three breaks a string can hold as escapes. ok is false
// for anything else. An HTTP body takes this form with no line bound: no frame carries it.
func wireForm(line []byte) (wire []byte, ok bool) {
	var b bytes.Buffer
	if json.Compact(&b, line) != nil || !utf8.Valid(b.Bytes()) {
		return nil, false
	}
	return []byte(lineBreaks.Replace(b.String())), true
}
