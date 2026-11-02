// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// liveWord is the top bar's Live word while a run is live (layout.tmpl, r-top).
const liveWord = `<span class="live"><span class="dot" aria-hidden="true"></span>Live</span>`

// TestErrorPageChrome: an error page says what every page says while a run is live and an ask waits (the top bar's
// Live word, the Approvals count, the title's count and the banner with Allow once and Deny), never "Nothing
// running" beside a live run. It says it as of the answer: no signature, so live.js follows nothing on it, and no note
// about runs left out, since it lists none. The page of a run's missing tab keeps that run's own ask in the banner:
// it shows no ask card.
func TestErrorPageChrome(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, p := range []string{"/nope", "/runs/r-nope-0000-none", "/runs/" + harmRun + "/nope", "/runs/" + harmRun + "/lines/99"} {
		w := do(s, "GET", p, "127.0.0.1:8484", c)
		b := w.Body.String()
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, w.Code)
		}
		mustContain(t, p, b, liveWord, `id="ask-banner"`, "demo-harm is waiting for you", `name="ask" value="ask-7"`,
			`value="approve"`, `value="deny"`, `<title>(1) `, `<span class="count" aria-live="polite">1`)
		for _, bad := range []string{"Nothing running", "data-sig=", "Showing the newest"} {
			if strings.Contains(b, bad) {
				t.Errorf("%s: the error page has %q", p, bad)
			}
		}
	}

	// A cut snapshot's note belongs to the pages that list runs, not to an error page.
	was := ledgerview.MaxRuns
	ledgerview.MaxRuns = 1
	t.Cleanup(func() { ledgerview.MaxRuns = was })
	cut := newServer(t, fixture(t))
	cc := login(t, cut)
	if b := do(cut, "GET", "/runs", "127.0.0.1:8484", cc).Body.String(); !strings.Contains(b, "Showing the newest 1 of 2 runs.") {
		t.Fatal("the cut ledger's Runs page lacks its note: the test no longer cuts the snapshot")
	}
	if b := do(cut, "GET", "/nope", "127.0.0.1:8484", cc).Body.String(); strings.Contains(b, "Showing the newest") {
		t.Error("an error page carries the note about runs left out")
	}
}

// TestErrorPageUnreadableLedger: when the ledger cannot be read, the error page that says so has the bare chrome:
// nothing it could read says a run is live or an ask waits.
func TestErrorPageUnreadableLedger(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger")
	if err := os.WriteFile(root, []byte("not a folder"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/", "127.0.0.1:8484", c)
	b := w.Body.String()
	if w.Code != http.StatusInternalServerError || !strings.Contains(b, "The ledger could not be read") {
		t.Fatalf("an unreadable ledger: %d\n%s", w.Code, b)
	}
	mustContain(t, "the unreadable ledger's page", b, "Nothing running")
	for _, bad := range []string{liveWord, `id="ask-banner"`, "<title>(", `class="count"`, "data-sig="} {
		if strings.Contains(b, bad) {
			t.Errorf("the unreadable ledger's page has %q", bad)
		}
	}
}
