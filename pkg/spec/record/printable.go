// SPDX-License-Identifier: Apache-2.0

package record

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Printable returns s safe to write to a terminal as one cell of a line. A ledger holds text the agent
// chose (file names, argv, hosts, header values), and the human-readable views print it: a control byte in
// it could move the cursor, clear a row or retitle the terminal, and a newline could forge a row. Every C0
// and C1 control, DEL, every invisible format character (Unicode category Cf: the bidirectional overrides,
// isolates and marks, zero-width characters), the line and paragraph separators (Zl, Zp) and the tag block
// (U+E0000-U+E007F) are written as Go escapes, and so is each byte of invalid UTF-8. Everything else, printable Unicode included,
// is left as it is. --json output is never passed through it: it is the byte-exact form.
func Printable(s string) string {
	if isPlain(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(`\x`)
			b.WriteString(strconv.FormatUint(uint64(s[i])|0x100, 16)[1:])
		case unsafeRune(r):
			q := strconv.QuoteRuneToASCII(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// isPlain is the fast path: printable ASCII only.
func isPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			return false
		}
	}
	return true
}

// unsafeRune reports a rune Printable escapes: a control, or an Invisible one.
func unsafeRune(r rune) bool {
	if r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f {
		return true
	}
	return Invisible(r)
}

// Invisible reports whether r is a character that does not show as itself, so a view of agent-chosen text must not
// print it as it is: a bidirectional override, embedding, isolate or mark reorders the text after it (a file named
// "a\u202etxt.exe" reads as "aexe.txt", and the view's own words after it run backwards), and a zero-width or tag
// character hides in a name. It is every format character (Unicode category Cf), the line and paragraph separators
// (Zl, Zp) and the tag block (U+E0000-U+E007F). The bidi controls are named by their code points as well as by
// category, so they are caught whatever Unicode tables a build has. Printable escapes each one for a terminal, and the
// dashboard writes each as a visible literal (internal/control/web, visibleText).
func Invisible(r rune) bool {
	switch {
	case r < 0x80:
		return false
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0x061c:
		return true
	}
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r >= 0xe0000 && r <= 0xe007f
}
