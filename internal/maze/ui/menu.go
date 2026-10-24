// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// Choice is one line of a menu.
type Choice struct {
	// Label is what the line says.
	Label string
	// Hint is shown faintly after the label, usually the command the choice runs.
	Hint string
	// Soon marks a choice that isn't built yet: it is shown dimmed and the cursor skips it.
	Soon bool
}

// Keys a menu understands.
const (
	keyUp = iota + 1
	keyDown
	keyEnter
	keyQuit
	keySpace
	keyEsc
	keyResize
	keyOther
)

// Select shows choices with a ▸ on the current one and returns the index picked with Enter. ↑/↓ (or k/j)
// move, skipping choices marked Soon; q or Esc returns ErrQuit; Ctrl+C cancels ctx. It needs a person at the
// terminal: the caller checks Interactive first. The ▸ starts on the first choice that isn't Soon.
func (t *Term) Select(ctx context.Context, choices []Choice) (int, error) {
	return t.SelectAt(ctx, choices, -1)
}

// SelectAt is Select with the ▸ starting on choice at, when at names a choice that isn't Soon.
func (t *Term) SelectAt(ctx context.Context, choices []Choice, at int) (int, error) {
	cur := -1
	if at >= 0 && at < len(choices) && !choices[at].Soon {
		cur = at
	}
	for i, c := range choices {
		if cur >= 0 {
			break
		}
		if !c.Soon {
			cur = i
		}
	}
	if cur < 0 {
		return 0, errors.New("a menu with nothing to choose")
	}
	restore := t.keyMode()
	defer restore()
	defer t.watchResize()()
	t.Printf("\x1b[?25l") // hide the cursor while the menu is up
	defer t.Printf("\x1b[?25h")

	lines := len(choices) + 2
	t.drawMenu(choices, cur, false)
	for {
		k, err := t.readKey(ctx)
		if err != nil {
			return 0, err
		}
		switch k {
		case keyUp:
			cur = step(choices, cur, -1)
		case keyDown:
			cur = step(choices, cur, +1)
		case keyEnter:
			t.Printf("\x1b[%dA", lines)
			t.drawMenu(choices, cur, true)
			return cur, nil
		case keyQuit, keyEsc:
			return 0, ErrQuit
		case keyResize:
			t.Refresh()
		default:
			continue
		}
		t.Printf("\x1b[%dA", lines)
		t.drawMenu(choices, cur, false)
	}
}

// step moves from cur by dir to the next choice that isn't Soon, stopping at the ends: one key too many never
// lands on the opposite choice (from "Decide later" to "Approve").
func step(choices []Choice, cur, dir int) int {
	for j := cur + dir; j >= 0 && j < len(choices); j += dir {
		if !choices[j].Soon {
			return j
		}
	}
	return cur
}

// drawMenu prints the menu and its key hints, each line cleared first so a redraw leaves nothing behind. done
// leaves only the picked line marked and replaces the hints with a blank line.
func (t *Term) drawMenu(choices []Choice, cur int, done bool) {
	width := 0
	for _, c := range choices {
		width = max(width, len(c.Label))
	}
	for i, c := range choices {
		label := c.Label + strings.Repeat(" ", width-len(c.Label))
		var line string
		switch {
		case c.Soon:
			line = "    " + t.Dim(label+"  "+c.Hint+"  · soon")
		case i == cur:
			line = "  " + t.Accent("▸ "+label) + "  " + t.Dim(c.Hint)
		default:
			line = "    " + label + "  " + t.Dim(c.Hint)
		}
		t.Printf("\x1b[2K\r%s\n", t.fit(line))
	}
	t.Printf("\x1b[2K\r\n")
	if done {
		t.Printf("\x1b[2K\r\n")
		return
	}
	t.Printf("\x1b[2K\r%s\n", t.fit("  "+t.Dim(t.keysHint("↑/↓ to move · Enter to choose · q to quit", "↑↓ · Enter · q"))))
}

// keyMode switches the terminal so each key press arrives at once and is not echoed, keeping Ctrl+C as a
// signal; the returned function puts the terminal back. On anything that isn't a terminal it does nothing.
func (t *Term) keyMode() func() {
	if t.inF == nil {
		return func() {}
	}
	var old *unix.Termios
	if err := onFile(t.inF, func(fd int) (err error) {
		old, err = unix.IoctlGetTermios(fd, ioctlGetTermios)
		return err
	}); err != nil {
		return func() {}
	}
	setTermios := func(to *unix.Termios) error {
		return onFile(t.inF, func(fd int) error { return unix.IoctlSetTermios(fd, ioctlSetTermios, to) })
	}
	raw := *old
	raw.Lflag &^= unix.ICANON | unix.ECHO
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := setTermios(&raw); err != nil {
		return func() {}
	}
	return func() {
		if err := setTermios(old); err != nil {
			fmt.Fprintln(t.out, "\nmaze: could not restore the terminal; run `reset` if typing looks wrong")
		}
	}
}
