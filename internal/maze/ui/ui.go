// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Maze's accent, #E8692C, and the 256-color index closest to it for terminals without 24-bit color.
const (
	accentR, accentG, accentB = 0xE8, 0x69, 0x2C
	accent256                 = 208
)

// defaultWidth and defaultHeight are used when the terminal's size cannot be read (a pipe, a file). Scripted
// terminals in tests get scriptedHeight, tall enough that nothing scrolls.
const (
	defaultWidth   = 80
	defaultHeight  = 24
	scriptedHeight = 500
)

// ErrQuit is returned by a prompt when the person chose to stop.
var ErrQuit = errors.New("stopped at the prompt")

// Term is one command's view of the person running it.
type Term struct {
	in        *bufio.Reader
	out       io.Writer
	color     bool
	truecolor bool     // 24-bit color
	tty       bool     // stdin and stdout are both terminals: prompts may wait
	inF       *os.File // stdin when it is a terminal, nil otherwise
	outF      *os.File // stdout when it is a terminal, nil otherwise: its size is read again on Refresh
	inScreen  bool     // Enter switched to the alternate screen and Leave hasn't switched back
	width     int
	height    int
	lines     int            // lines printed since the last Clear
	pump      chan inByte    // every byte read from the person (input.go)
	resized   chan os.Signal // SIGWINCH while keys are read
	inDone    bool           // the input ended (EOF)
}

// Options decide how a Term behaves when they cannot be read from the streams (tests) or the user overrides
// them (--no-color).
type Options struct {
	// NoColor turns color and the banner off whatever the terminal supports.
	NoColor bool
}

// New returns a Term over in and out. Color, prompts and width come from whether in and out are terminals
// and from the environment; anything that is not an *os.File is treated as a pipe.
func New(in io.Reader, out io.Writer, o Options) *Term {
	outTTY, width, height := isTerminal(out)
	inTTY, _, _ := isTerminal(in)
	color := outTTY && !o.NoColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	var inF, outF *os.File
	if f, ok := in.(*os.File); ok && inTTY {
		inF = f
	}
	if f, ok := out.(*os.File); ok && outTTY {
		outF = f
	}
	return &Term{
		inF:       inF,
		outF:      outF,
		in:        bufio.NewReader(in),
		out:       out,
		color:     color,
		truecolor: ct == "truecolor" || ct == "24bit" || os.Getenv("TERM_PROGRAM") == "iTerm.app" || os.Getenv("TERM_PROGRAM") == "vscode",
		tty:       outTTY && inTTY,
		width:     width,
		height:    height,
	}
}

// NewPlain returns a Term that never colors and never waits, for tests and for --json.
func NewPlain(in io.Reader, out io.Writer, width int) *Term {
	if width <= 0 {
		width = defaultWidth
	}
	return &Term{in: bufio.NewReader(in), out: out, width: width, height: defaultHeight}
}

// Interactive reports whether a person can answer prompts: stdin and stdout are both terminals.
func (t *Term) Interactive() bool { return t.tty }

// Width is the terminal's width in columns, or 80 when it cannot be read.
func (t *Term) Width() int { return t.width }

// Height is the terminal's height in rows, or 24 when it cannot be read.
func (t *Term) Height() int { return t.height }

// Room is how many rows are left below what this page has printed so far.
func (t *Term) Room() int { return t.height - t.lines }

// Println writes a line. On the full screen a line wider than the terminal is cut to fit: a wrapped line
// would push the page past the screen's height and break every redraw.
func (t *Term) Println(a ...any) {
	t.lines++
	line := strings.TrimSuffix(fmt.Sprintln(a...), "\n")
	switch {
	case t.inScreen:
		// Cleared first: a page redrawn in place must not keep the end of a longer line from before.
		fmt.Fprintln(t.out, "\x1b[2K"+t.fit(line))
	case t.tty && t.outF != nil && t.width > 0 && visibleLen(line) >= t.width:
		// On the normal screen the terminal would break the line mid-word: break it between words instead,
		// under its own indent.
		for i, l := range wrap(line, t.width-1) {
			if i > 0 {
				t.lines++
			}
			fmt.Fprintln(t.out, l)
		}
	default:
		fmt.Fprintln(t.out, line)
	}
}

// wrap breaks s between words into lines of at most width columns; continuation lines get s's leading
// indent plus two spaces. Color codes are kept with their words and don't count.
func wrap(s string, width int) []string {
	indent := s[:len(s)-len(strings.TrimLeft(s, " "))]
	more := indent + "  "
	var out []string
	cur, curW := indent, len(indent)
	for _, w := range strings.Fields(s) {
		ww := visibleLen(w)
		if curW > len(indent) && curW+1+ww > width && (len(out) > 0 || curW > len(indent)) {
			out = append(out, cur)
			cur, curW = more, len(more)
		}
		if curW > len(indent) && cur != more {
			cur += " "
			curW++
		}
		cur += w
		curW += ww
	}
	return append(out, cur)
}

// Para prints s wrapped between words to the terminal's width, on any screen, so a long line reads in full
// instead of being cut; continuation lines are indented two spaces more than s.
func (t *Term) Para(s string) {
	if t.width <= 0 {
		t.Println(s)
		return
	}
	for _, line := range wrap(s, t.width-1) {
		t.Println(line)
	}
}

// fit cuts s to the terminal's width, ending it with "…" when something was cut. Color codes are kept and
// don't count; wide characters (emoji, CJK) count two columns.
func (t *Term) fit(s string) string {
	if t.width <= 0 || visibleLen(s) < t.width {
		return s
	}
	var b strings.Builder
	cols, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			b.WriteRune(r)
			esc = r != 'm'
			continue
		case r == '\x1b':
			b.WriteRune(r)
			esc = true
			continue
		}
		w := runeWidth(r)
		if cols+w > t.width-2 { // one column for "…", one so the cursor never wraps
			b.WriteString("…")
			if t.color {
				b.WriteString("\x1b[0m")
			}
			return b.String()
		}
		cols += w
		b.WriteRune(r)
	}
	return b.String()
}

// runeWidth is how many columns r takes in a terminal: two for emoji and East Asian wide characters.
func runeWidth(r rune) int {
	switch {
	case r >= 0x1F300 && r <= 0x1FAFF, r >= 0x2E80 && r <= 0xA4CF, r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF, r >= 0xFF00 && r <= 0xFF60:
		return 2
	}
	return 1
}

// Printf writes formatted text.
func (t *Term) Printf(format string, a ...any) {
	out := fmt.Sprintf(format, a...)
	t.lines += strings.Count(out, "\n")
	fmt.Fprint(t.out, out)
}

// isTerminal reports whether s is a character device, and its width and height when it is.
func isTerminal(s any) (bool, int, int) {
	f, ok := s.(*os.File)
	if !ok {
		return false, defaultWidth, defaultHeight
	}
	fi, err := f.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false, defaultWidth, defaultHeight
	}
	ws, err := winsize(f)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return true, defaultWidth, defaultHeight
	}
	return true, int(ws.Col), int(ws.Row)
}

// onFile runs fn with f's descriptor under the standard library's lease, the Control of f's SyscallConn, which
// holds the descriptor open for the call and fails once f is closed: (*os.File).Fd hands out a number with no
// lease, which the File's own cleanup may close under the caller (ADR 0023 A4). fn must not keep the number.
func onFile(f *os.File, fn func(fd int) error) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

// winsize reads the size of the terminal f is.
func winsize(f *os.File) (ws *unix.Winsize, err error) {
	err = onFile(f, func(fd int) error {
		ws, err = unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		return err
	})
	return ws, err
}

// style wraps s in an SGR sequence when color is on.
func (t *Term) style(code, s string) string {
	if !t.color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Accent colors s in Maze's orange.
func (t *Term) Accent(s string) string {
	if t.truecolor {
		return t.style(fmt.Sprintf("38;2;%d;%d;%d", accentR, accentG, accentB), s)
	}
	return t.style(fmt.Sprintf("38;5;%d", accent256), s)
}

// Bold makes s bold.
func (t *Term) Bold(s string) string { return t.style("1", s) }

// Dim makes s quiet, for hints, reasons and things that are not built yet: a muted gray-blue from Maze's
// navy that reads on dark and light backgrounds alike.
func (t *Term) Dim(s string) string { return t.fg(muted, s) }

// VisibleLen is how many columns s takes on screen: color codes don't count, wide characters count two.
func VisibleLen(s string) int { return visibleLen(s) }

// Color reports whether this Term shows color.
func (t *Term) Color() bool { return t.color }

// Good colors s green, for what was found or is allowed: a soft green that sits with Maze's palette.
func (t *Term) Good(s string) string { return t.fg(green, s) }

// Bad colors s red, for what is blocked or missing: a warm red kept clearly apart from the orange accent.
func (t *Term) Bad(s string) string { return t.fg(red, s) }

// Rule prints a section heading across the terminal: "── title ─────".
func (t *Term) Rule(title string) {
	w := min(t.width, 72)
	head := "── " + title + " "
	fill := w - utf8.RuneCountInString(head)
	if fill < 3 {
		fill = 3
	}
	t.Println(t.Accent(head + strings.Repeat("─", fill)))
}

// List prints items after label, wrapped to the terminal so a long list never breaks inside a word: the first
// line starts with label, later lines line up under the first item. At most limitN items are named; the rest are
// counted ("+3 more"). indent is the number of spaces before label.
func (t *Term) List(indent int, label string, items []string, limitN int) {
	if len(items) == 0 {
		return
	}
	shown := items
	more := 0
	if limitN > 0 && len(items) > limitN {
		shown, more = items[:limitN], len(items)-limitN
	}
	words := append([]string{}, shown...)
	if more > 0 {
		words = append(words, t.Dim(fmt.Sprintf("+%d more", more)))
	}
	pad := strings.Repeat(" ", indent)
	start := pad + label
	col := visibleLen(start)
	hang := strings.Repeat(" ", col)
	limit := min(t.width, 100)
	var b strings.Builder
	b.WriteString(start)
	line := col
	for i, w := range words {
		vis := visibleLen(w)
		sep := "  "
		if i == 0 {
			sep = ""
		}
		if i > 0 && line+len(sep)+vis > limit {
			b.WriteString("\n" + hang)
			line = col
			sep = ""
		}
		b.WriteString(sep + w)
		line += len(sep) + vis
	}
	t.Println(b.String())
}

// visibleLen is the number of columns s takes, not counting color sequences.
func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case esc:
			if r == 'm' {
				esc = false
			}
		case r == '\x1b':
			esc = true
		default:
			n += runeWidth(r)
		}
	}
	return n
}

// Continue waits for Enter. q stops (ErrQuit). It returns at once when nobody can answer.
func (t *Term) Continue(ctx context.Context) error {
	if !t.tty {
		return nil
	}
	t.Printf("%s", t.Dim("   Enter to continue · q to quit "))
	line, err := t.readLine(ctx)
	if errors.Is(err, ErrBack) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.EqualFold(line, "q") {
		return ErrQuit
	}
	t.Println()
	return nil
}

// Ask prints question and returns the line the person types, trimmed. It returns ErrQuit without asking when
// nobody can answer.
func (t *Term) Ask(ctx context.Context, question string) (string, error) {
	if !t.tty {
		return "", ErrQuit
	}
	t.Printf("%s ", t.Bold(question))
	line, err := t.readLine(ctx)
	if errors.Is(err, ErrBack) {
		return "", nil // Esc: the caller treats an empty answer as going back
	}
	return strings.TrimSpace(line), err
}

// Confirm asks a yes-or-no question whose default is yes. It returns false without asking when nobody can
// answer, so a script never says yes by accident.
func (t *Term) Confirm(ctx context.Context, question string) (bool, error) {
	return t.ConfirmDefault(ctx, question, true)
}

// ConfirmDefault asks a yes-or-no question; Enter alone answers def. Like Confirm, it returns false without
// asking when nobody can answer.
func (t *Term) ConfirmDefault(ctx context.Context, question string, def bool) (bool, error) {
	if !t.tty {
		return false, nil
	}
	hint := "[Y/n]"
	if !def {
		hint = "[y/N]"
	}
	t.Printf("%s %s ", t.Bold(question), t.Dim(hint))
	line, err := t.readLine(ctx)
	if errors.Is(err, ErrBack) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// NewScripted returns a Term that answers prompts from in as if a person typed it, with no color and a width
// of 80: for tests of guided flows.
func NewScripted(in io.Reader, out io.Writer) *Term {
	return &Term{in: bufio.NewReader(in), out: out, tty: true, width: defaultWidth, height: scriptedHeight}
}

// keysHint is long, or short when long wouldn't fit on one line.
func (t *Term) keysHint(long, short string) string {
	if t.width > 0 && visibleLen(long)+3 > t.width {
		return short
	}
	return long
}
