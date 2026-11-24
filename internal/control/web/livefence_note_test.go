// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLiftNoteOnTheForm: the lift's confirm form has one optional text input for a note, bounded in the browser; a
// confirmed lift with a note signs it inside the lift's MAC for a run whose launcher made the mark that it reads one, is
// refused in words (and writes nothing) for a run whose launcher did not, and a lift with no note needs no mark.
func TestLiftNoteOnTheForm(t *testing.T) {
	s, c, dir := liveFenceServer(t)
	target := "/runs/" + adjRun + "/lift"
	form, body := previewForm(t, s, c, target+"?kind=exec&value=/usr/bin/psql&for=1h")
	mustContain(t, "the preview", body, `name="note"`, `maxlength="200"`, "Note for the record (optional)")
	if strings.Count(body, `name="note"`) != 1 {
		t.Errorf("the form has %d note inputs, want one", strings.Count(body, `name="note"`))
	}
	form.Set("understand", "yes")
	form.Set("note", "ticket 4411")
	if b := follow(t, s, c, post(s, target, form, own, "", c)); !strings.Contains(b, "does not say it reads a note on a lift") ||
		!strings.Contains(b, "Lift again without a note") {
		t.Errorf("a note for a launcher with no mark: the page does not say so")
	}
	if ch := overlayChanges(t, dir); len(ch) != 0 {
		t.Fatalf("a refused note wrote %+v", ch)
	}
	if err := liveblock.MarkNote(dir); err != nil {
		t.Fatal(err)
	}
	form.Set("note", "  line one\nline two  ")
	if b := follow(t, s, c, post(s, target, form, own, "", c)); !strings.Contains(b, "not printable text") {
		t.Errorf("a note with a line break: the page does not say it is not printable text")
	}
	if ch := overlayChanges(t, dir); len(ch) != 0 {
		t.Fatalf("a refused note wrote %+v", ch)
	}
	form.Set("note", "  ticket 4411: <b>nightly</b> export  ")
	follow(t, s, c, post(s, target, form, own, "", c))
	ch := overlayChanges(t, dir)
	key, err := liveblock.ReadKey(dir)
	if err != nil || len(ch) != 1 || ch[0].Op != liveblock.OpLift || ch[0].Note != "ticket 4411: <b>nightly</b> export" || !liveblock.LiftMACOK(key, adjRun, ch[0]) {
		t.Fatalf("overlay changes %+v (%v): want one lift with the trimmed note, MAC'ed with it", ch, err)
	}
	// With no note a lift is as it was, mark or none.
	form2, _ := previewForm(t, s, c, target+"?kind=read&value=/srv/exports&for=1h")
	form2.Set("understand", "yes")
	form2.Set("note", "   ")
	follow(t, s, c, post(s, target, form2, own, "", c))
	if ch := overlayChanges(t, dir); len(ch) != 2 || ch[1].Note != "" || ch[1].MAC == "" {
		t.Fatalf("overlay changes %+v: want a second lift with no note", ch)
	}
}

// TestFenceRowShowsTheNote: the Rules page's fence row of a lifted entry shows the note its launcher's line carries,
// escaped as text and bounded and written as the terminal writes it (record.LiveNoteShown); a row refused again shows none.
func TestFenceRowShowsTheNote(t *testing.T) {
	for _, note := range []string{"ticket 4411: nightly export", "<script>alert(1)</script> & \"quotes\"", "tampered\x1b[2J\u202eline\nbreak",
		strings.Repeat("long ", 80)} {
		s, c, _ := liveFenceServerNote(t, note)
		w := do(s, "GET", "/rules?run="+url.QueryEscape(adjRun), "127.0.0.1:8484", c)
		body := w.Body.String()
		want := html.EscapeString(record.LiveNoteShown(note))
		if w.Code != 200 || !strings.Contains(body, "Note: "+want) {
			t.Errorf("note %q: the fence row does not show %q", note, want)
		}
		if strings.Contains(body, "<script>alert") || strings.ContainsAny(body, "\x1b\u202e") {
			t.Errorf("note %q: the page carries it unescaped", note)
		}
	}
	s, c, _ := liveFenceServer(t)
	if body := do(s, "GET", "/rules?run="+url.QueryEscape(adjRun), "127.0.0.1:8484", c).Body.String(); strings.Contains(body, "Note: ") {
		t.Error("a lift with no note shows a note")
	}
}
