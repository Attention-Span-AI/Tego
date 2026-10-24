// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unicode/utf8"
)

// All key presses and typed text come through one reader goroutine (the pump), so menus and text prompts never
// race for the same bytes. Text is read with a small line editor rather than the terminal's own: an arrow key or
// Esc typed at a prompt would otherwise arrive as raw escape codes and be saved into a rule name.

// inByte is one byte read from the person, or the error that ended reading.
type inByte struct {
	b   byte
	err error
}

// errResized is how next reports that the terminal changed size.
var errResized = errors.New("terminal resized")

// escWait is how long a lone Esc waits for the rest of an arrow key's sequence before it counts as Esc.
const escWait = 30 * time.Millisecond

// startPump starts the reader goroutine once. It lives as long as the command: a read can't be interrupted, and
// the process ends soon after the last prompt.
func (t *Term) startPump() {
	if t.pump != nil {
		return
	}
	t.pump = make(chan inByte, 256)
	go func() {
		for {
			b, err := t.in.ReadByte()
			t.pump <- inByte{b, err}
			if err != nil {
				return
			}
		}
	}()
}

// watchResize asks to be told when the terminal changes size, while keys are being read; the returned function
// stops it. Only a real terminal has a size to change.
func (t *Term) watchResize() func() {
	if t.inF == nil || t.outF == nil {
		return func() {}
	}
	t.resized = make(chan os.Signal, 1)
	signal.Notify(t.resized, syscall.SIGWINCH)
	return func() {
		signal.Stop(t.resized)
		t.resized = nil
	}
}

// next returns the next byte. wait > 0 gives up after wait with ok false; ctx ends it with ctx's error; a resize
// returns errResized.
func (t *Term) next(ctx context.Context, wait time.Duration) (b byte, ok bool, err error) {
	if t.inDone {
		return 0, false, ErrQuit // the input ended: every later read ends at once too
	}
	t.startPump()
	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-ctx.Done():
		return 0, false, ctx.Err()
	case <-t.resized:
		return 0, false, errResized
	case <-timeout:
		return 0, false, nil
	case in := <-t.pump:
		if in.err != nil {
			t.inDone = true
			return 0, false, ErrQuit
		}
		return in.b, true, nil
	}
}

// escapeKey reads the rest of an escape sequence after Esc and says which key it was: keyUp, keyDown, keyHome,
// keyEnd, keyPgUp, keyPgDn, keyEsc for a lone Esc, or keyOther for any other sequence (left, right, a function
// key), read to its end. Home and End come as ESC [ H / ESC [ F, ESC O H / ESC O F or ESC [ 1~ / 4~ (7~ / 8~ in
// rxvt); Page Up and Down as ESC [ 5~ and 6~.
func (t *Term) escapeKey(ctx context.Context) (int, error) {
	b1, ok, err := t.next(ctx, escWait)
	if errors.Is(err, ErrQuit) {
		return keyEsc, nil // Esc as the last key before the input ended
	}
	if err != nil || !ok {
		return keyEsc, err
	}
	if b1 != '[' && b1 != 'O' {
		return keyOther, nil
	}
	params := ""
	for {
		b, ok, err := t.next(ctx, escWait)
		if err != nil || !ok {
			return keyOther, err
		}
		if b >= 0x40 && b <= 0x7e { // the final byte of a control sequence
			switch b {
			case 'A':
				return keyUp, nil
			case 'B':
				return keyDown, nil
			case 'H':
				return keyHome, nil
			case 'F':
				return keyEnd, nil
			case '~':
				switch params {
				case "1", "7":
					return keyHome, nil
				case "4", "8":
					return keyEnd, nil
				case "5":
					return keyPgUp, nil
				case "6":
					return keyPgDn, nil
				}
			}
			return keyOther, nil
		}
		params += string(b)
	}
}

// readKey reads one key press. Ctrl+C cancels ctx; a resize returns keyResize.
func (t *Term) readKey(ctx context.Context) (int, error) {
	b, _, err := t.next(ctx, 0)
	if errors.Is(err, errResized) {
		return keyResize, nil
	}
	if err != nil {
		return 0, err
	}
	switch b {
	case '\r', '\n':
		return keyEnter, nil
	case 'q', 'Q':
		return keyQuit, nil
	case 'k':
		return keyUp, nil
	case 'j':
		return keyDown, nil
	case ' ':
		return keySpace, nil
	case 0x1b:
		return t.escapeKey(ctx)
	}
	return keyOther, nil
}

// InputEnded reports whether the input has ended (EOF): nothing more can be asked.
func (t *Term) InputEnded() bool { return t.inDone }

// ErrBack is returned by a text prompt when the person pressed Esc: go back, nothing typed is kept.
var ErrBack = errors.New("went back from the prompt")

// readLine reads a line of text with a small editor: typed and pasted characters are shown, ←/→ move along the
// line, Home/End (or Ctrl+A/Ctrl+E) jump to its ends, Backspace and Delete remove a character, Ctrl+U clears it,
// Enter ends it and Esc gives ErrBack. Up, Down and other special keys are ignored rather than typed. Ctrl+C
// cancels ctx.
func (t *Term) readLine(ctx context.Context) (string, error) {
	restore := t.keyMode()
	defer restore()
	var (
		line    []rune
		pos     int    // the cursor, in runes
		pending []byte // the start of a character typed in several bytes
	)
	// redraw prints the line from the cursor to its end, clears what was after it, and puts the cursor back.
	redraw := func() {
		rest := string(line[pos:])
		t.Printf("%s\x1b[K", rest)
		if n := len(line) - pos; n > 0 {
			t.Printf("\x1b[%dD", n)
		}
	}
	for {
		b, _, err := t.next(ctx, 0)
		if errors.Is(err, errResized) {
			continue
		}
		if errors.Is(err, ErrQuit) && len(line) > 0 {
			return string(line), nil
		}
		if err != nil {
			return "", err
		}
		switch {
		case len(pending) > 0 || b >= 0x80:
			pending = append(pending, b)
			if !utf8.FullRune(pending) {
				continue
			}
			r, _ := utf8.DecodeRune(pending)
			pending = pending[:0]
			line = append(line[:pos], append([]rune{r}, line[pos:]...)...)
			t.Printf("%s", string(r))
			pos++
			redraw()
		case b == '\r' || b == '\n':
			t.Printf("\n")
			return string(line), nil
		case b == 0x1b:
			key, err := t.lineEscape(ctx)
			if err != nil {
				return "", err
			}
			switch key {
			case keyEsc:
				t.Printf("\n")
				return "", ErrBack
			case keyLeft:
				if pos > 0 {
					pos--
					t.Printf("\x1b[D")
				}
			case keyRight:
				if pos < len(line) {
					pos++
					t.Printf("\x1b[C")
				}
			case keyHome:
				if pos > 0 {
					t.Printf("\x1b[%dD", pos)
					pos = 0
				}
			case keyEnd:
				if n := len(line) - pos; n > 0 {
					t.Printf("\x1b[%dC", n)
					pos = len(line)
				}
			case keyDelete:
				if pos < len(line) {
					line = append(line[:pos], line[pos+1:]...)
					redraw()
				}
			}
		case b == 0x7f || b == 0x08:
			if pos > 0 {
				line = append(line[:pos-1], line[pos:]...)
				pos--
				t.Printf("\x1b[D")
				redraw()
			}
		case b == 0x01: // Ctrl+A
			if pos > 0 {
				t.Printf("\x1b[%dD", pos)
				pos = 0
			}
		case b == 0x05: // Ctrl+E
			if n := len(line) - pos; n > 0 {
				t.Printf("\x1b[%dC", n)
				pos = len(line)
			}
		case b == 0x15: // Ctrl+U
			if pos > 0 {
				t.Printf("\x1b[%dD", pos)
			}
			line, pos = line[:0], 0
			redraw()
		case b < 0x20:
			// other control keys: ignored
		default:
			line = append(line[:pos], append([]rune{rune(b)}, line[pos:]...)...)
			t.Printf("%c", b)
			pos++
			redraw()
		}
	}
}

// Keys only the line editor uses.
const (
	keyLeft = iota + 100
	keyRight
	keyHome
	keyEnd
	keyDelete
	keyPgUp
	keyPgDn
)

// lineEscape reads the rest of an escape sequence at a text prompt: Esc alone, or ←, →, Home, End, Delete;
// anything else (↑, ↓, a function key) is read to its end and ignored.
func (t *Term) lineEscape(ctx context.Context) (int, error) {
	b1, ok, err := t.next(ctx, escWait)
	if errors.Is(err, ErrQuit) {
		return keyEsc, nil // Esc as the last key before the input ended
	}
	if err != nil || !ok {
		return keyEsc, err
	}
	if b1 != '[' && b1 != 'O' {
		return keyOther, nil
	}
	var param []byte
	for {
		b, ok, err := t.next(ctx, escWait)
		if err != nil || !ok {
			return keyOther, err
		}
		if b < 0x40 || b > 0x7e {
			param = append(param, b)
			continue
		}
		switch {
		case b == 'C':
			return keyRight, nil
		case b == 'D':
			return keyLeft, nil
		case b == 'H':
			return keyHome, nil
		case b == 'F':
			return keyEnd, nil
		case b == '~' && (string(param) == "1" || string(param) == "7"):
			return keyHome, nil
		case b == '~' && (string(param) == "4" || string(param) == "8"):
			return keyEnd, nil
		case b == '~' && string(param) == "3":
			return keyDelete, nil
		}
		return keyOther, nil
	}
}
