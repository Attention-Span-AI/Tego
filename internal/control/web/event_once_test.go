// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
)

// TestLinePageSaysEachFactOnce (C113): "Decided by" is on the line page once (the decision, not again as a field of
// Every field), and the target is written with the run's home as ~/ in the What happened panel as it is in the
// decision, with the full path in its title.
func TestLinePageSaysEachFactOnce(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	page := get(t, s, c, "/runs/"+pw3Enf+"/lines/1")
	if n := strings.Count(page, "Decided by"); n != 1 {
		t.Errorf("the line page says Decided by %d times, want once", n)
	}
	mustContain(t, "the target", page, `<span class="mono ev-wrap" title="/w/x/home/.ssh/id_rsa">~/.ssh/id_rsa</span>`)
}

// TestWatchedLinePageUsesPlainActionWords (C119): the panel on a watched run's line page is headed in plain words,
// and no page names it by its old label.
func TestWatchedLinePageUsesPlainActionWords(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	for _, run := range []string{pw3Watch, pw3Enf} {
		page := get(t, s, c, "/runs/"+run+"/lines/1")
		mustContain(t, run+" line page", page, `<h2 id="h-act">What to do about this</h2>`)
		if strings.Contains(page, "Act on this") {
			t.Errorf("%s line page still says Act on this", run)
		}
	}
}

// TestLongHostIdentityIsRecoverable (C112): a computer name too long for the header is cut there, and its whole
// name is one click away, visible and selectable as text; a short name has no such control.
func TestLongHostIdentityIsRecoverable(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	const long = "build-workstation-17.engineering.example-corp.internal"
	s.host = long
	page := get(t, s, c, "/")
	mustContain(t, "the header", page, `<details class="host-more"><summary>Whole name</summary>`, `translate="no" tabindex="0">`+long+`</code>`)
	s.host = "laptop"
	if page = get(t, s, c, "/"); strings.Contains(page, "host-more") {
		t.Error("a short name offers a whole-name control")
	}
}
