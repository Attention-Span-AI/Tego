// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"time"
)

// Enter switches to the terminal's alternate screen, the way full-screen tools (vim, htop) do, so each step of
// a guided flow replaces the last instead of stacking below it. Leave switches back, leaving the terminal as it
// was before. Without a person at a real terminal neither does anything.
func (t *Term) Enter() {
	if t.inScreen || !t.tty || t.inF == nil {
		return
	}
	t.inScreen = true
	t.Printf("\x1b[?1049h\x1b[H\x1b[2J")
}

// Leave switches back from the alternate screen if Enter switched to it; calling it again does nothing. A
// command calls it before printing what should stay on the terminal afterwards.
func (t *Term) Leave() {
	if !t.inScreen {
		return
	}
	t.inScreen = false
	t.Printf("\x1b[?1049l")
}

// Clear starts a new page on the alternate screen: the cursor home, the screen cleared. Outside it (piped
// output, tests) it prints a blank line instead, so the pages read in order.
func (t *Term) Clear() {
	if !t.inScreen {
		t.Println()
		return
	}
	t.Printf("\x1b[H\x1b[2J")
	t.lines = 0
}

// Repaint starts drawing a page again over the one on screen: the cursor home, without clearing first, so a
// page redrawn after every key doesn't flicker. Lines that change must clear themselves (\x1b[2K), and
// ClearBelow clears what the old page left under the new one. Outside the alternate screen it prints a blank
// line, like Clear.
func (t *Term) Repaint() {
	if !t.inScreen {
		t.Println()
		return
	}
	t.Printf("\x1b[H")
	t.lines = 0
}

// ClearBelow clears the screen from the cursor down, on the alternate screen only.
func (t *Term) ClearBelow() {
	if t.inScreen {
		t.Printf("\x1b[J")
	}
}

// Pause waits d on a real terminal, so a summary can be read before the next page replaces it; elsewhere (tests,
// pipes) it returns at once. Ctrl+C ends it.
func (t *Term) Pause(ctx context.Context, d time.Duration) {
	if !t.inScreen {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Refresh reads the terminal's size again, so a page drawn after the window was resized fits it.
func (t *Term) Refresh() {
	if t.outF == nil {
		return
	}
	if ws, err := winsize(t.outF); err == nil && ws.Col > 0 && ws.Row > 0 {
		t.width, t.height = int(ws.Col), int(ws.Row)
	}
}
