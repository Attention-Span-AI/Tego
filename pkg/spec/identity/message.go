// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"strconv"
	"strings"
)

// FormatMessage renders one diagnostic line: "<file>:<line>[:<col>]: <what> [<code>]".
//
// The line is omitted when line <= 0 (then the column is omitted too), the column when col <= 0,
// the file prefix when file is empty, and the bracketed code when code is empty. what is written
// verbatim, so callers keep it to one sentence and never embed a reason code in the prose. Pure.
func FormatMessage(file string, line, col int, what, code string) string {
	var b strings.Builder
	b.Grow(len(file) + len(what) + len(code) + 16)
	if file != "" {
		b.WriteString(file)
		if line > 0 {
			b.WriteByte(':')
			b.WriteString(strconv.Itoa(line))
			if col > 0 {
				b.WriteByte(':')
				b.WriteString(strconv.Itoa(col))
			}
		}
		b.WriteString(": ")
	}
	b.WriteString(what)
	if code != "" {
		b.WriteString(" [")
		b.WriteString(code)
		b.WriteByte(']')
	}
	return b.String()
}

// Diagnostic is one finding in the shared message format, usable by any subcommand.
type Diagnostic struct {
	File     string
	Line     int
	Col      int
	Message  string
	Code     string
	Fix      string // one sentence, appended after the message when set
	Severity string // "error" | "warning"
}

// String renders the diagnostic through FormatMessage, followed by the fix when there is one.
func (d Diagnostic) String() string {
	s := FormatMessage(d.File, d.Line, d.Col, d.Message, d.Code)
	if d.Fix != "" {
		s += " " + d.Fix
	}
	return s
}
