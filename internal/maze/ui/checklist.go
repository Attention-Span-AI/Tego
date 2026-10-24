// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"fmt"
	"strings"
)

// Row is one rule in a rule list: under a heading, something the agent can or can't do.
type Row struct {
	// Group is the heading the row sits under (FILES, PROGRAMS, …); a heading prints when it changes.
	Group string
	// Note is a few quiet words printed next to the group's heading, taken from its first row.
	Note string
	// Label is what the agent does, as a phrase that follows "can" or "can't": "read files in shop".
	Label string
	// Hint is a few quiet words after the label.
	Hint string
	// Allow is the rule's effect: true shows "✓ can", false "✗ can't".
	Allow bool
	// Was is the effect the row started with; a row switched away from it shows Changed instead of Hint.
	Was bool
	// Changed is what a switched row says when switching it breaks something ("can't commit or pull"); the box
	// alone shows the switch otherwise.
	Changed string
	// Locked rows are enforced whatever the person chooses: the cursor skips them, and they are drawn in grey
	// with "fixed" after them.
	Locked bool
	// Focus puts the cursor on this row when the list opens (a rule just added), instead of the first action.
	Focus bool
	// Diff marks a row of a change list the way git and terraform do: "+" added, "-" removed, "~" switched. Such a
	// row says "can" or "can't" in plain words (never a green tick: a new permission is not good news by
	// default) and wraps instead of being cut, since the value is what the person is judging.
	Diff string
}

// List is what RuleList shows.
type List struct {
	// Header draws what sits above the rows (the step bar, the title).
	Header func()
	Rows   []Row
	// Actions are the buttons below the rows ("Save rules", "Cancel").
	Actions []string
	Footer  string
	// Update, when set, runs before every draw, so a row's hint can follow other rows (a row that needs git
	// says so once git is switched off).
	Update func(rows []Row)
	// ReadOnly lists rows to read, not switch: Space does nothing and no row is drawn as fixed.
	ReadOnly bool
	// FocusAction, when set (1 for the first action), puts the cursor on that action when the list opens.
	FocusAction int
	// ActionHelp says what each action does, on the line under the list while the cursor is on it.
	ActionHelp []string
	// Status is shown on the line under the list until the first key ("Added: can run make").
	Status string
	// EscAction, when set (1 for the first action), is the action Esc chooses, so Esc means Back as it does on
	// every other page; without it Esc leaves like q.
	EscAction int
	// AlwaysShort is the ALWAYS summary in one line, shown instead of the full lines when they would push the
	// checklist off a short screen.
	AlwaysShort string
	// Always, when set, turns the list into a checklist of the rows that can change, with the fixed rows left
	// out of it: instead, the lines it returns are shown under ALWAYS below the checklist, a short summary of
	// what Maze enforces whatever is chosen. It runs before every draw, so a summary can follow the rows.
	Always func(rows []Row) []Fixed
}

// Fixed is one line of the ALWAYS summary: what the agent always can (Allow) or never can do.
type Fixed struct {
	Allow bool
	Text  string
}

// RuleList shows rows grouped under headings, each starting "✓ can" or "✗ can't", with the actions below them
// and, under those, one line about where the cursor is: what Space will do to this row, or what the action does.
// The whole page is drawn again after every key, at the terminal's current size, so nothing is left cut off
// after a resize or a scroll.
//
// It works like the checkbox lists of gum, huh and inquirer: the cursor moves only over rows that can change (a
// fixed row is grey, says "fixed", and is skipped, as those tools skip a disabled choice), so Space always does
// something where the cursor is. ↑/↓ (or k/j) move, stopping at the ends; Space switches a row between can and
// can't; Enter on an action returns its index, and Enter on a row only says how to switch and save, so a stray
// Enter never changes a rule. q or Esc returns -1. Rows taller than the screen scroll, with "↑ N more" and
// "↓ N more" counting rules. It changes the rows in place. The cursor starts on the row marked Focus, else the
// first row that can change, else the first action.
func (t *Term) RuleList(ctx context.Context, l List) (int, error) {
	rows := l.Rows
	var stops []int // rows that can change, then actions (as len(rows)+i)
	for i := range rows {
		if l.ReadOnly || !rows[i].Locked {
			stops = append(stops, i)
		}
	}
	firstAction := len(stops)
	for i := range l.Actions {
		stops = append(stops, len(rows)+i)
	}
	if len(stops) == 0 {
		return -1, fmt.Errorf("a rule list with nothing to choose")
	}
	cur := 0
	if l.ReadOnly && len(l.Actions) > 0 {
		cur = firstAction
	}
	for i, at := range stops[:firstAction] {
		if rows[at].Focus {
			cur = i
			break
		}
	}
	if l.FocusAction > 0 && l.FocusAction <= len(l.Actions) {
		cur = firstAction + l.FocusAction - 1
	}
	restore := t.keyMode()
	defer restore()
	defer t.watchResize()()
	t.Printf("\x1b[?25l")
	defer t.Printf("\x1b[?25h")

	top, lastW, lastH := 0, t.width, t.height
	status, loud := l.Status, l.Status != "" // loud: said because of a key, so it stands out
	draw := func() {
		t.Refresh()
		if t.width != lastW || t.height != lastH {
			// A resize leaves the old page's characters where the new one doesn't reach: start clean.
			t.Printf("\x1b[2J")
			lastW, lastH = t.width, t.height
		}
		if l.Update != nil {
			l.Update(rows)
		}
		t.Repaint()
		l.Header()
		// One row is kept free: a newline on the screen's last row would scroll the header away.
		say := status
		if say == "" {
			say = t.Dim(t.where(l, rows, stops[cur]))
		} else if loud {
			say = t.Accent(say)
		}
		top = t.drawRuleList(l, rows, stops[cur], cur == 0, say, max(t.Room()-1, 4), top)
		t.ClearBelow()
	}
	draw()
	for {
		k, err := t.readKey(ctx)
		if err != nil {
			if err == ErrQuit {
				return -1, nil
			}
			return -1, err
		}
		at := stops[cur]
		status, loud = "", false
		switch k {
		case keyUp:
			cur = max(cur-1, 0)
		case keyDown:
			cur = min(cur+1, len(stops)-1)
		case keyHome:
			cur = 0
		case keyEnd:
			cur = len(stops) - 1
		case keyPgUp:
			cur = max(cur-pageStep, 0)
		case keyPgDn:
			cur = min(cur+pageStep, len(stops)-1)
		case keySpace:
			switch {
			case at >= len(rows):
				status, loud = "Space switches a rule. Enter chooses "+l.Actions[at-len(rows)]+".", true
			case !l.ReadOnly:
				rows[at].Allow = !rows[at].Allow
			}
		case keyEnter:
			if at >= len(rows) {
				return at - len(rows), nil
			}
			if !l.ReadOnly {
				status, loud = "Space switches this rule. To save, go down to "+l.Actions[0]+".", true
			}
		case keyEsc:
			if l.EscAction > 0 && l.EscAction <= len(l.Actions) {
				return l.EscAction - 1, nil
			}
			return -1, nil
		case keyQuit:
			return -1, nil
		case keyResize:
		default:
			continue
		}
		draw()
	}
}

// where is the quiet line under the list: what Space would make the row say, or what the action does.
func (t *Term) where(l List, rows []Row, at int) string {
	if at >= len(rows) {
		if i := at - len(rows); i < len(l.ActionHelp) {
			return l.ActionHelp[i]
		}
		return ""
	}
	return "" // on a rule, its box already says everything
}

// pageStep is how many stops Page Up and Page Down move.
const pageStep = 8

// line is one printed line of the rule list: a heading or a row.
type line struct {
	text    string
	heading string // the heading this line sits under (itself for a heading)
	isHead  bool
	cont    bool // a blank line or the rest of a wrapped one: not a rule of its own
}

// drawRuleList prints the rows (scrolling within room), the actions, the status line and the footer, and returns
// the scroll position to keep for the next draw. at is the current row, or len(rows)+i for action i; first says
// the cursor is on the first stop, so the view starts at the top (the fixed rows above it show too).
func (t *Term) drawRuleList(l List, rows []Row, at int, first bool, status string, room, top int) int {
	actions, footer := l.Actions, l.Footer
	// The actions, status and footer stay below the scrolling rows: 1 blank + actions + 1 blank + status +
	// footer. On a short screen the blank lines and the key hints go first, so the page never grows past the
	// screen (a page taller than the screen scrolls, and every redraw would then stack on the last). The status
	// line wraps: it is a sentence the person reads before choosing.
	var statusLines []string // none on a rule: its box already says everything, and the room goes to the rules
	if VisibleLen(status) > 0 {
		statusLines = wrap("  "+status, max(t.width-1, 20))
	}
	compact := room < len(actions)+3+len(statusLines)+6
	fixed := len(actions) + 3 + len(statusLines)
	if compact {
		fixed = len(actions) + len(statusLines)
	}
	body := max(room-fixed, 3)

	checklist := l.Always != nil && !l.ReadOnly
	// The label column fits the labels of the rows shown. A very long name (a pasted path) mustn't push every
	// hint off the screen.
	labelW := 0
	for _, r := range rows {
		if !(checklist && r.Locked) {
			labelW = max(labelW, len([]rune(r.Label)))
		}
	}
	labelW = min(labelW, max(24, t.width-48)) // at 80 columns, 32: about 24 are left for the hint
	var lines []line
	curLine := -1
	group, head := "\x00", ""
	for i, r := range rows {
		if checklist && r.Locked {
			continue // summed up under ALWAYS
		}
		if r.Group != group {
			group = r.Group
			head = "  " + t.Accent(t.Bold(strings.ToUpper(r.Group)))
			if r.Note != "" {
				head += "  " + t.Dim(r.Note)
			}
			lines = append(lines, line{text: head, heading: head, isHead: true})
		}
		pointer := "  "
		tail := t.Dim(r.Hint)
		if r.Allow != r.Was && r.Changed != "" {
			// The box shows the switch; a note only when switching breaks something ("can't commit or pull").
			tail = t.Accent(r.Changed)
		}
		label := r.Label
		if i == at {
			pointer = t.Accent("▸ ")
			curLine = len(lines)
		}
		if r.Diff != "" {
			// A change to judge: the whole rule, wrapped, never cut, and what it would mean on the line under it.
			words := map[bool]string{true: "can  ", false: "can't"}[r.Allow]
			for j, part := range wrap("  "+pointer+t.Accent(r.Diff)+" "+words+"  "+label, max(t.width-1, 20)) {
				lines = append(lines, line{text: part, heading: head, cont: j > 0})
			}
			if r.Hint != "" {
				for _, part := range wrap("             "+r.Hint, max(t.width-1, 20)) {
					lines = append(lines, line{text: t.Dim(part), heading: head, cont: true})
				}
			}
			continue
		}
		if r.Hint != "" || (r.Allow != r.Was && r.Changed != "") {
			label = pad(cut(label, labelW), labelW)
		}
		if i == at {
			label = t.Bold(label)
		}
		if r.Locked && !l.ReadOnly {
			label = t.Dim(label)
		}
		mark := t.mark(r)
		if checklist {
			mark = t.box(r)
		}
		lines = append(lines, line{text: "  " + pointer + mark + "  " + label + "  " + tail, heading: head})
	}
	if checklist {
		if fixed := l.Always(rows); len(fixed) > 0 {
			always := []line{{heading: head, cont: true}}
			head = "  " + t.Accent(t.Bold("ALWAYS")) + "  " + t.Dim("you can't switch these")
			always = append(always, line{text: head, heading: head, isHead: true})
			for _, f := range fixed {
				mark := t.Good("✓ can  ")
				if !f.Allow {
					mark = t.Bad("✗ can't")
				}
				// Wrapped, never cut: these lines name paths, and a cut path says nothing.
				for j, part := range wrap(f.Text, max(t.width-17, 20)) {
					if j == 0 {
						always = append(always, line{text: "    " + mark + "  " + part, heading: head})
						continue
					}
					always = append(always, line{text: "             " + strings.TrimLeft(part, " "), heading: head, cont: true})
				}
			}
			// On a short screen the full block would push the person's own choices out of view: one line
			// instead, which names the worst of it and where the rest is.
			if len(lines)+len(always) > body && l.AlwaysShort != "" {
				always = always[:2]
				for j, part := range wrap(l.AlwaysShort, max(t.width-5, 20)) {
					always = append(always, line{text: "    " + t.Dim(strings.TrimLeft(part, " ")), heading: head, cont: j > 0})
				}
			}
			lines = append(lines, always...)
		}
	}
	switch {
	case first:
		curLine = 0 // the top of the list, fixed rows above the cursor included
	case at >= len(rows):
		curLine = len(lines) - 1 // on the actions, the end of the list shows: no row is left unseen below
	}
	var shown []string
	shown, top = scroll(lines, curLine, body, top, t.Dim)
	if !compact {
		shown = append(shown, "")
	}
	for i, a := range actions {
		if len(rows)+i == at {
			shown = append(shown, "  "+t.Accent("▸ "+a))
			continue
		}
		shown = append(shown, "    "+a)
	}
	if !compact {
		shown = append(shown, "")
	}
	shown = append(shown, statusLines...)
	if !compact {
		shown = append(shown, "  "+t.Dim(footer))
	}
	for _, l := range shown {
		t.Printf("\x1b[2K\r%s\n", t.fit(l))
	}
	return top
}

// scroll picks the lines to show in body rows. When all fit, all of them. Otherwise the view is: a "↑ N more"
// line, the heading of the first row in view (pinned, so rows never show without their section), then rows, then
// a "↓ N more" line. top, the first row in view, stays where it was unless the cursor's line (cur, or -1 when the
// cursor is on an action) would leave the view. A heading never ends the view with no row under it, and the
// counts are rules, not lines.
func scroll(lines []line, cur, body, top int, dim func(string) string) ([]string, int) {
	n := len(lines)
	if n <= body {
		out := make([]string, n)
		for i, l := range lines {
			out[i] = l.text
		}
		return out, 0
	}
	rowsIn := func(ls []line) int {
		c := 0
		for _, l := range ls {
			if !l.isHead && !l.cont {
				c++
			}
		}
		return c
	}
	view := max(body-3, 1) // less the counts above and below and the pinned heading
	start := top
	if cur >= 0 {
		if cur < start {
			start = cur
		}
		if cur >= start+view {
			start = cur - view + 1
		}
	}
	start = max(0, min(start, n-view))
	for start < n-1 && lines[start].isHead {
		start++ // the pinned slot shows the heading; the view starts at its first row
	}
	if rowsIn(lines[:start]) == 0 {
		view++ // at the top there's no "↑ N more" line: its row shows one more rule
	}
	end := min(start+view, n)
	if end < n && lines[end-1].isHead {
		end-- // never a heading with nothing under it at the bottom
	}
	var out []string
	if above := rowsIn(lines[:start]); above > 0 {
		out = append(out, "  "+dim(fmt.Sprintf("↑ %d more", above)))
	}
	out = append(out, lines[start].heading)
	for _, l := range lines[start:end] {
		out = append(out, l.text)
	}
	if below := rowsIn(lines[end:]); below > 0 {
		out = append(out, "  "+dim(fmt.Sprintf("↓ %d more", below)))
	}
	return out, start
}

// mark is a row's effect in words: "✓ can" in green or "✗ can't" in red.
func (t *Term) mark(r Row) string {
	if r.Allow {
		return t.Good("✓ can  ")
	}
	return t.Bad("✗ can't")
}

// box is a checklist row's state: "[✓]" when the agent can, "[ ]" when it can't.
func (t *Term) box(r Row) string {
	if r.Allow {
		return "[" + t.Good("✓") + "]"
	}
	return "[ ]"
}

// cut shortens s to n columns, ending it with "…" when something was cut.
func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 2 {
		return s
	}
	return string(r[:n-1]) + "…"
}

// pad pads s with spaces to n columns.
func pad(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}
