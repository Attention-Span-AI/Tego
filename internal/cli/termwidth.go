// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// A summary or a receipt is written for a person at a terminal as well as for a script: its sentences are long, and a
// terminal that breaks them anywhere cuts a path or a rule name in half. When tego's own standard output or error is a
// terminal, fitTerminal breaks each long line at a word of its own, at a clause ("·") where it can, and indents what
// follows; to a pipe, a file or a test's buffer the bytes are what they always were, so a script that reads the first
// line of the summary or greps the receipt reads the same text.

// minWrapWidth is the narrowest width a line is broken to: a terminal this narrow or narrower is broken at this one, so
// the continuation lines have room for their words.
const minWrapWidth = 40

// terminalWidthOf is the width in columns of the terminal w writes to, 0 when w is not tego's own standard output or
// error on a terminal, or the terminal does not say. Tests replace it.
var terminalWidthOf = func(w io.Writer) int {
	ow, ok := w.(*outputWriter)
	if !ok {
		return 0
	}
	f, ok := ow.dst.(*os.File)
	if !ok || (f != os.Stdout && f != os.Stderr) {
		return 0
	}
	width := 0
	_ = sys.FileDo(f, func(fd int) error {
		if ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ); err == nil {
			width = int(ws.Col) // 0 from a terminal that does not know its size, and an error from anything that is no terminal
		}
		return nil
	})
	return width
}

// fitTerminal is text broken to the width of the terminal w writes to, or text itself when w is no terminal.
func fitTerminal(w io.Writer, text string) string {
	if width := terminalWidthOf(w); width > 0 {
		return wrapLines(text, max(width, minWrapWidth))
	}
	return text
}

// wrapLines breaks each line of s longer than width columns (runes) into lines of at most width, at spaces: at the last
// " · " clause break that fits when there is one, else at the last space that fits. A continuation line is indented two
// columns past the line's own indentation. A word longer than width stays whole on a line of its own (a path is never
// cut), so only such a line is wider than width. A line that fits, and every line break of s, are kept as they are.
func wrapLines(s string, width int) string {
	var b strings.Builder
	for i, line := range strings.Split(s, "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(wrapLine(line, width))
	}
	return b.String()
}

func wrapLine(line string, width int) string {
	if utf8.RuneCountInString(line) <= width {
		return line
	}
	indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
	cont := indent + "  "
	var out []string
	cur := line
	for utf8.RuneCountInString(cur) > width {
		head, rest, ok := breakAt(cur, width)
		if !ok {
			break // one word wider than the line: it stays whole
		}
		out = append(out, head)
		cur = cont + rest
	}
	out = append(out, cur)
	return strings.Join(out, "\n")
}

// breakAt splits line into the longest head of at most limit runes that ends at a word (preferring the end of a " · "
// clause) and the rest, which starts at the next word. When no word end fits, the head is the line's first word, whole,
// and ok is false only when the line is that one word.
func breakAt(line string, limit int) (head, rest string, ok bool) {
	runes := []rune(line)
	if len(runes) <= limit {
		return line, "", true
	}
	start := len(line) - len(strings.TrimLeft(line, " ")) // never break inside the indentation
	clause, space := -1, -1
	for i := range limit + 1 { // a space at index limit ends a head of limit runes
		if i >= len(runes) || runes[i] != ' ' || i <= start {
			continue
		}
		space = i
		if i >= 2 && i+2 < len(runes) && runes[i-1] != ' ' && string(runes[i+1:i+3]) == "· " {
			clause = i // the head ends before " · "; the clause mark starts the next line
		}
	}
	cut := space
	if clause >= 0 && clause >= limit/2 {
		cut = clause
	}
	if cut < 0 {
		// No word ends within the width: the first word is wider than the line. It stays whole, and the line breaks
		// after it, where its next word starts.
		for i := max(limit+1, start+1); i < len(runes); i++ {
			if runes[i] == ' ' {
				cut = i
				break
			}
		}
		if cut < 0 {
			return "", "", false
		}
	}
	return strings.TrimRight(string(runes[:cut]), " "), strings.TrimLeft(string(runes[cut:]), " "), true
}
