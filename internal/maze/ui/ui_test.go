// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPlainHasNoColor(t *testing.T) {
	var out bytes.Buffer
	term := New(strings.NewReader(""), &out, Options{})
	term.Banner()
	term.Println(term.Accent("a"), term.Bold("b"), term.Dim("c"))
	if strings.Contains(out.String(), "\x1b[") {
		t.Errorf("a buffer got color codes: %q", out.String())
	}
	if term.Interactive() {
		t.Error("a buffer counts as a person at a terminal")
	}
}

func TestColor(t *testing.T) {
	term := &Term{color: true, truecolor: true}
	if got := term.Accent("x"); got != "\x1b[38;2;232;105;44mx\x1b[0m" {
		t.Errorf("Accent in 24-bit = %q", got)
	}
	term.truecolor = false
	if got := term.Accent("x"); got != "\x1b[38;5;208mx\x1b[0m" {
		t.Errorf("Accent in 256 colors = %q", got)
	}
	if got := term.Accent(""); got != "" {
		t.Errorf("Accent of nothing = %q, want nothing", got)
	}
}

func TestBannerRowsLineUp(t *testing.T) {
	want := utf8.RuneCountInString(bannerGlyphs[0])
	for i, row := range bannerGlyphs {
		if n := utf8.RuneCountInString(row); n != want {
			t.Errorf("banner row %d is %d columns, row 0 is %d", i, n, want)
		}
		if len(bannerFG[i]) != want || len(bannerBG[i]) != want {
			t.Errorf("banner row %d: %d glyphs but %d foreground and %d background colors", i, want, len(bannerFG[i]), len(bannerBG[i]))
		}
		for _, c := range bannerFG[i] + strings.ReplaceAll(bannerBG[i], ".", "") {
			if _, ok := bannerPalette[byte(c)]; !ok {
				t.Errorf("banner row %d uses color %q, which the palette lacks", i, c)
			}
		}
	}
}

func TestBannerColored(t *testing.T) {
	var out bytes.Buffer
	term := &Term{out: &out, color: true, truecolor: true, width: 80, height: 50}
	term.Banner()
	s := out.String()
	if !strings.Contains(s, "38;2;232;105;44") || !strings.Contains(s, Tagline) {
		t.Errorf("a color terminal's banner lacks the accent or the tagline:\n%q", s)
	}
	out.Reset()
	(&Term{out: &out, color: true, width: 20, height: 50}).Banner()
	if strings.Contains(out.String(), "▐") {
		t.Error("a 20-column terminal got the full banner")
	}
}

func TestListWraps(t *testing.T) {
	var out bytes.Buffer
	term := NewPlain(strings.NewReader(""), &out, 40)
	items := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.git-credentials", "~/.config/gh", "~/.docker/config.json"}
	term.List(2, "never reads  ", items, 0)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("a long list did not wrap at 40 columns:\n%s", out.String())
	}
	for _, l := range lines {
		if n := utf8.RuneCountInString(l); n > 40 {
			t.Errorf("line is %d columns, over 40: %q", n, l)
		}
	}
	indent := strings.Repeat(" ", utf8.RuneCountInString("  never reads  "))
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, indent) {
			t.Errorf("wrapped line does not line up under the first item: %q", l)
		}
	}
	for _, item := range items {
		if !strings.Contains(out.String(), item) {
			t.Errorf("item %q was split or lost", item)
		}
	}
}

func TestListCounts(t *testing.T) {
	var out bytes.Buffer
	term := NewPlain(strings.NewReader(""), &out, 80)
	term.List(0, "x ", []string{"a", "b", "c", "d"}, 2)
	if got := out.String(); !strings.Contains(got, "a  b  +2 more") {
		t.Errorf("List with a limit = %q", got)
	}
	out.Reset()
	term.List(0, "x ", nil, 2)
	if out.Len() != 0 {
		t.Errorf("an empty list printed %q", out.String())
	}
}

func TestPrompts(t *testing.T) {
	tests := []struct {
		input string
		want  bool
		err   error
	}{
		{"\n", true, nil},
		{"y\n", true, nil},
		{"YES\n", true, nil},
		{"n\n", false, nil},
		{"no\n", false, nil},
		{"", false, ErrQuit},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		got, err := NewScripted(strings.NewReader(tt.input), &out).Confirm(context.Background(), "go?")
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("Confirm(%q) = %v, %v; want %v, %v", tt.input, got, err, tt.want, tt.err)
		}
	}
	var out bytes.Buffer
	if err := NewScripted(strings.NewReader("q\n"), &out).Continue(context.Background()); !errors.Is(err, ErrQuit) {
		t.Errorf("Continue(q) = %v, want ErrQuit", err)
	}
	if ok, err := NewPlain(strings.NewReader("y\n"), &out, 80).Confirm(context.Background(), "go?"); ok || err != nil {
		t.Errorf("Confirm with nobody at the terminal = %v, %v; want false, nil", ok, err)
	}
}

func TestPromptCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _ := blockingReader()
	var out bytes.Buffer
	if err := NewScripted(r, &out).Continue(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Continue after Ctrl+C = %v, want context.Canceled", err)
	}
}

// blockingReader returns a reader whose Read never returns until the writer is closed.
func blockingReader() (*blockReader, func()) {
	b := &blockReader{done: make(chan struct{})}
	return b, func() { close(b.done) }
}

type blockReader struct{ done chan struct{} }

func (b *blockReader) Read(p []byte) (int, error) {
	<-b.done
	return 0, errors.New("closed")
}

func TestListWrapsWithColor(t *testing.T) {
	var out bytes.Buffer
	term := &Term{out: &out, color: true, width: 40}
	items := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.git-credentials", "~/.config/gh"}
	term.List(3, term.Bad("✗")+" never reads  ", items, 0)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("did not wrap: %q", out.String())
	}
	want := visibleLen("   ✗ never reads  ")
	for _, l := range lines[1:] {
		if got := len(l) - len(strings.TrimLeft(l, " ")); got != want {
			t.Errorf("wrapped line starts at column %d, the first item at %d: %q", got, want, l)
		}
	}
}

func TestSelect(t *testing.T) {
	choices := []Choice{{Label: "a"}, {Label: "b", Soon: true}, {Label: "c"}}
	tests := []struct {
		keys string
		want int
		err  error
	}{
		{"\r", 0, nil},
		{"\x1b[B\r", 2, nil},
		{"j\r", 2, nil},
		{"\x1b[B\x1b[B\r", 2, nil}, // stops at the last choice
		{"\x1b[A\r", 0, nil},       // stops at the first
		{"k\r", 0, nil},
		{"xyz\r", 0, nil},
		{"q", 0, ErrQuit},
		{"", 0, ErrQuit},
	}
	for _, tt := range tests {
		var out bytes.Buffer
		got, err := NewScripted(strings.NewReader(tt.keys), &out).Select(context.Background(), choices)
		if got != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("Select(%q) = %d, %v; want %d, %v", tt.keys, got, err, tt.want, tt.err)
		}
	}
	var out bytes.Buffer
	if _, err := NewScripted(strings.NewReader("\r"), &out).Select(context.Background(), []Choice{{Label: "x", Soon: true}}); err == nil {
		t.Error("a menu of only soon choices returned no error")
	}
}

func TestConfirmDefaultNo(t *testing.T) {
	var out bytes.Buffer
	ok, err := NewScripted(strings.NewReader("\n"), &out).ConfirmDefault(context.Background(), "here?", false)
	if ok || err != nil || !strings.Contains(out.String(), "[y/N]") {
		t.Errorf("ConfirmDefault(no) with Enter = %v, %v, %q", ok, err, out.String())
	}
}

// The art is Maze's face: it shows at any height, so it never comes and goes as the window changes.
func TestBannerAtAnyHeight(t *testing.T) {
	for _, h := range []int{12, 20, 24, 40} {
		var out bytes.Buffer
		(&Term{out: &out, color: true, width: 80, height: h}).Banner()
		if !strings.Contains(out.String(), "▐█▄") {
			t.Errorf("a %d-row terminal got no art", h)
		}
	}
}

func TestScroll(t *testing.T) {
	// Three sections of ten rows each: 33 lines.
	var lines []line
	for _, g := range []string{"A", "B", "C"} {
		lines = append(lines, line{text: g, heading: g, isHead: true})
		for i := 0; i < 10; i++ {
			lines = append(lines, line{text: fmt.Sprintf("%s%d", g, i), heading: g})
		}
	}
	id := func(s string) string { return s }
	if got, _ := scroll(lines[:5], 2, 10, 0, id); len(got) != 5 {
		t.Errorf("a list that fits was cut: %d lines", len(got))
	}
	for cur := 0; cur < len(lines); cur++ {
		if lines[cur].isHead {
			continue
		}
		got, top := scroll(lines, cur, 12, 0, id)
		joined := strings.Join(got, "\n")
		if len(got) > 12 {
			t.Errorf("cur %d: %d lines in 12 rows", cur, len(got))
		}
		if !strings.Contains(joined, lines[cur].text) {
			t.Errorf("cur %d is not in view: %q", cur, got)
		}
		// The first line after any "↑ N more" is always the heading of the first row in view.
		h := 0
		if strings.HasPrefix(strings.TrimSpace(got[0]), "↑") {
			h = 1
		}
		if got[h] != lines[top].heading {
			t.Errorf("cur %d: heading %q, want %q", cur, got[h], lines[top].heading)
		}
		// Counts are rules: shown + above + below = 30.
		shown := 0
		for _, l := range got {
			if len(l) == 2 && (l[0] == 'A' || l[0] == 'B' || l[0] == 'C') {
				shown++
			}
		}
		above, below := 0, 0
		fmt.Sscanf(strings.TrimSpace(got[0]), "↑ %d more", &above)
		fmt.Sscanf(strings.TrimSpace(got[len(got)-1]), "↓ %d more", &below)
		if shown+above+below != 30 {
			t.Errorf("cur %d: %d shown + %d above + %d below != 30: %q", cur, shown, above, below, got)
		}
		// A heading never sits last with nothing under it.
		last := got[len(got)-1]
		if strings.HasPrefix(strings.TrimSpace(last), "↓") {
			last = got[len(got)-2]
		}
		if last == "A" || last == "B" || last == "C" {
			t.Errorf("cur %d: view ends on a bare heading: %q", cur, got)
		}
	}
	// On an action (cur -1) the view stays where it was.
	_, top := scroll(lines, 20, 12, 0, id)
	if _, again := scroll(lines, -1, 12, top, id); again != top {
		t.Errorf("moving to an action scrolled the list: %d, then %d", top, again)
	}
}

func TestRuleList(t *testing.T) {
	newRows := func() []Row {
		return []Row{
			{Group: "Files", Label: "read a", Allow: true, Was: true},
			{Group: "Files", Label: "change locked", Allow: false, Locked: true},
			{Group: "Programs", Label: "run c", Allow: false},
		}
	}
	actions := []string{"Start", "Back"}
	tests := []struct {
		keys  string
		want  int
		allow []bool
	}{
		{"\x1b[B\x1b[B\r", 0, []bool{true, false, false}},               // starts on row a; down past c to Start
		{"\x1b[B\x1b[B\x1b[B\r", 1, []bool{true, false, false}},         // the second action
		{"\x1b[B\x1b[B\x1b[B\x1b[B\r", 1, []bool{true, false, false}},   // stops at the last action, no wrap
		{" \x1b[B\x1b[B\r", 0, []bool{false, false, false}},             // Space switches the row under the cursor
		{"\x1b[B \x1b[B\r", 0, []bool{true, false, true}},               // down to row c (the fixed row is skipped)
		{"\r\x1b[B\x1b[B\r", 0, []bool{true, false, false}},             // Enter on a row changes nothing
		{"\x1b[A\x1b[A \x1b[B\x1b[B\r", 0, []bool{false, false, false}}, // stops at the top row
		{"\x1b[B\x1b[B \x1b[B\r", 1, []bool{true, false, false}},        // Space on an action changes nothing
		{"q", -1, []bool{true, false, false}},
	}
	for _, tt := range tests {
		rows := newRows()
		var out bytes.Buffer
		got, err := NewScripted(strings.NewReader(tt.keys), &out).RuleList(context.Background(), List{Header: func() {}, Rows: rows, Actions: actions, Footer: "keys"})
		if err != nil || got != tt.want {
			t.Errorf("RuleList(%q) = %d, %v; want %d", tt.keys, got, err, tt.want)
		}
		for i, want := range tt.allow {
			if rows[i].Allow != want {
				t.Errorf("RuleList(%q): row %d allow = %v, want %v", tt.keys, i, rows[i].Allow, want)
			}
		}
		for _, want := range []string{"FILES", "PROGRAMS", "✓ can", "✗ can't", "Start"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("RuleList(%q) output lacks %q:\n%s", tt.keys, want, out.String())
			}
		}
	}
	// A switched row shows it in its mark alone: no extra words, no line under the list.
	rows := newRows()
	var out bytes.Buffer
	if _, err := NewScripted(strings.NewReader(" "), &out).RuleList(context.Background(), List{Header: func() {}, Rows: rows, Actions: actions, Footer: "keys"}); err != nil {
		t.Fatal(err)
	}
	if rows[0].Allow || !strings.Contains(out.String(), "✗ can't  read a") || strings.Contains(out.String(), "was on") || strings.Contains(out.String(), "Space turns") {
		t.Errorf("a switched row should show only its new mark:\n%s", out.String())
	}
}

// With Always set, the list is a checklist of the rows that can change, and the fixed rows show only as the
// summary under ALWAYS, wrapped rather than cut.
func TestRuleListAlways(t *testing.T) {
	rows := []Row{
		{Group: "Files", Label: "read a", Allow: true, Was: true},
		{Group: "Files", Label: "change locked", Allow: false, Locked: true},
		{Group: "Programs", Label: "run c", Allow: false},
	}
	long := "read " + strings.Repeat("some/long/path, ", 10) + "the end"
	var out bytes.Buffer
	term := NewScripted(strings.NewReader("q"), &out)
	term.width = 60
	always := func(rows []Row) []Fixed { return []Fixed{{Allow: false, Text: long}} }
	if _, err := term.RuleList(context.Background(), List{Header: func() {}, Rows: rows, Actions: []string{"Save"}, Footer: "keys", Always: always}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"[✓]  read a", "[ ]  run c", "ALWAYS", "the end"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "change locked") || strings.Contains(got, "fixed") || strings.Contains(got, "…") {
		t.Errorf("a fixed row is in the checklist, or a line was cut:\n%s", got)
	}
}

func TestRuleListScrolls(t *testing.T) {
	var rows []Row
	for i := 0; i < 40; i++ {
		rows = append(rows, Row{Group: "Files", Label: fmt.Sprintf("read file%d", i), Allow: true, Was: true})
	}
	var out bytes.Buffer
	term := NewScripted(strings.NewReader("q"), &out)
	term.height = 24
	if _, err := term.RuleList(context.Background(), List{Header: func() {}, Rows: rows, Actions: []string{"Start", "Back"}, Footer: "keys"}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "\n"); n > 24 {
		t.Errorf("a 40-row list on a 24-row screen printed %d rows", n)
	}
	if !strings.Contains(out.String(), "↓") || !strings.Contains(out.String(), "Start") {
		t.Errorf("no ↓ count or the actions were pushed off:\n%s", out.String())
	}
}

func TestWrap(t *testing.T) {
	got := wrap("  ! Not active yet. Claude Code still runs without Maze until maze run ships.", 40)
	for _, l := range got {
		if visibleLen(l) > 40 {
			t.Errorf("line longer than 40: %q", l)
		}
	}
	if len(got) < 2 || !strings.HasPrefix(got[1], "    ") || strings.Contains(strings.Join(got, "|"), "ru|n") {
		t.Errorf("wrap = %q", got)
	}
}

func TestLineEditor(t *testing.T) {
	for _, tt := range []struct{ keys, want string }{
		{"mke\x1b[D\x1b[Da\x1b[Fx\r", "makex"},    // ← ← a, End x: fixes a typo in the middle
		{"mkae\x1b[D\x1b[D\x7f\x1b[Ck\r", "make"}, //nolint:misspell // a deliberate typo the editor fixes: ← ← Backspace → k swaps two letters
		{"abc\x01X\x05Y\r", "XabcY"},              // Ctrl+A and Ctrl+E
		{"abc\x1b[D\x1b[3~\r", "ab"},              // Delete under the cursor
		{"abc\x1b[A\x1b[B\r", "abc"},              // ↑ and ↓ are ignored, not typed
		{"héllo\x7f\r", "héll"},                   // a character in several bytes
		{"abc\x15xy\r", "xy"},                     // Ctrl+U clears
	} {
		var out bytes.Buffer
		got, err := NewScripted(strings.NewReader(tt.keys), &out).Ask(context.Background(), "Program:")
		if err != nil || got != tt.want {
			t.Errorf("Ask(%q) = %q, %v; want %q", tt.keys, got, err, tt.want)
		}
	}
	var out bytes.Buffer
	if got, err := NewScripted(strings.NewReader("abc\x1b"), &out).Ask(context.Background(), "Program:"); got != "" || err != nil {
		t.Errorf("Esc = %q, %v; want back", got, err)
	}
}

// Home, End, Page Up and Page Down move over the list; Esc chooses EscAction when one is set (Back), else leaves.
func TestRuleListKeys(t *testing.T) {
	rows := []Row{{Group: "A", Label: "a", Allow: true, Was: true}, {Group: "A", Label: "b", Allow: true, Was: true}}
	actions := []string{"Save", "Add", "Back", "Cancel"}
	tests := []struct {
		keys string
		esc  int
		want int
	}{
		{"\x1b[F\r", 0, 3},               // End: the last action
		{"\x1b[4~\x1b[H \x1b[F\r", 0, 3}, // End, Home (back to row a), End again
		{"\x1b[6~\r", 0, 3},              // Page Down stops at the last action
		{"\x1b[6~\x1b[5~\r", 0, -1},      // Page Up back to the top row: Enter on a row does nothing, input ends
		{"\x1b", 3, 2},                   // Esc with EscAction 3: Back
		{"\x1b", 0, -1},                  // Esc without: leave
	}
	for _, tt := range tests {
		var out bytes.Buffer
		got, err := NewScripted(strings.NewReader(tt.keys), &out).RuleList(context.Background(),
			List{Header: func() {}, Rows: append([]Row(nil), rows...), Actions: actions, Footer: "keys", EscAction: tt.esc})
		if err != nil || got != tt.want {
			t.Errorf("RuleList(%q, esc %d) = %d, %v; want %d", tt.keys, tt.esc, got, err, tt.want)
		}
	}
}
