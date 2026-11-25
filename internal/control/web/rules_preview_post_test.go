// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// N124: sixteen entries of up to rules.MaxEntry bytes do not fit in an address. Serve's server reads at most 16 KiB of a
// request's header (the request line included), and past it the browser got a bare "431" page. The Several changes at
// once form therefore posts, and a refused Save does not send the person back to an address that long.

// longRows makes rules.MaxEdits folders, each reached through a chain of 100-byte names, and returns the rows that add
// a file in each: entries of about n bytes (the parent must exist, and a path is at most 4096 bytes).
func longRows(t *testing.T, proj string, n int) [][3]string {
	t.Helper()
	rows := make([][3]string, 0, rules.MaxEdits)
	for i := 0; i < rules.MaxEdits; i++ {
		e := "./more/c" + strconv.Itoa(1000+i)
		for len(e) < n-110 {
			e += "/" + strings.Repeat("d", 100)
		}
		if err := os.MkdirAll(filepath.Join(proj, e), 0o755); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, [3]string{"add", "fs.write", e + "/new.txt"})
	}
	return rows
}

// onTheWire is a dashboard served by Serve (the production server and its header limit) over a real connection.
func (f *changeFix) onTheWire(t *testing.T) (base string, cookie *http.Cookie, s *Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	m := &config.Machine{Home: f.home}
	s, err = New(Config{Ledger: f.root, Port: ln.Addr().(*net.TCPAddr).Port, Token: "tok123", Machine: m, Rules: f.svc})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = Serve(ctx, ln, s); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return "http://" + ln.Addr().String(), &http.Cookie{Name: s.cookie, Value: s.session}, s
}

func wire(t *testing.T, method, target string, form url.Values, c *http.Cookie, base string) (int, string, http.Header) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(c)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", base)
	}
	cl := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestSeveralLongEntriesPreviewByPost(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	base, c, s := f.onTheWire(t)
	rows := longRows(t, f.proj, 3500)
	q := severalQuery(ref, rows)
	// The cause: as an address the same preview is over the server's header limit.
	if code, _, _ := wire(t, "GET", base+"/rules/change/preview?"+q.Encode(), nil, c, base); code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("GET with %d bytes of address: %d, want 431", len(q.Encode()), code)
	}
	// The form posts them and gets the preview.
	q.Set("csrf", s.csrf)
	code, body, _ := wire(t, "POST", base+"/rules/change/preview", q, c, base)
	if code != http.StatusOK || strings.Count(body, `<input type="hidden" name="op"`) != rules.MaxEdits || !strings.Contains(body, "Check the change") {
		t.Fatalf("POST preview: %d, %d edits carried to Save\n%s", code, strings.Count(body, `<input type="hidden" name="op"`), problems(body))
	}
	if readText(t, f.source) != before || journalLen(t, f.root) != 0 {
		t.Fatal("a preview wrote")
	}
	// A token that is not the page's is refused like any form, and the form is a post only because of the length: the
	// Change rules page's Several form says so.
	bad := url.Values{"csrf": {"nope"}, "c": {ref.Ref}, "op": {"add"}, "key": {"fs.write"}, "v": {"./x/"}}
	if code, _, _ := wire(t, "POST", base+"/rules/change/preview", bad, c, base); code != http.StatusForbidden {
		t.Errorf("a preview post with a wrong token: %d, want 403", code)
	}
	_, page, _ := wire(t, "GET", base+"/rules/change?c="+url.QueryEscape(ref.Ref), nil, c, base)
	if !strings.Contains(page, `method="post" action="/rules/change/preview"`) {
		t.Error("the Several changes form does not post")
	}
}

// A Save refused because the file moved sends the person back to the preview of the same edits; with edits too long for
// an address the preview is the answer itself, with the same line above it.
func TestRefusedLongSavePlansAgainHere(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	base, c, s := f.onTheWire(t)
	// save previews rows, moves the file under the preview, then saves what the preview checked.
	save := func(rows [][3]string, moved string) (int, string, http.Header) {
		t.Helper()
		q := severalQuery(ref, rows)
		q.Set("csrf", s.csrf)
		code, prev, _ := wire(t, "POST", base+"/rules/change/preview", q, c, base)
		if code != http.StatusOK {
			t.Fatalf("preview: %d\n%s", code, problems(prev))
		}
		if err := os.WriteFile(f.source, []byte(readText(t, f.source)+moved), 0o600); err != nil {
			t.Fatal(err)
		}
		form := url.Values{"csrf": {s.csrf}, "c": {ref.Ref}, "base": {ref.Base}, "ack": {ackIn(t, prev)}}
		for _, r := range rows {
			form.Add("op", r[0])
			form.Add("key", r[1])
			form.Add("v", r[2])
		}
		return wire(t, "POST", base+"/rules/change", form, c, base)
	}
	code, body, h := save(longRows(t, f.proj, 3500), "\n# edited elsewhere\n")
	if code != http.StatusOK || h.Get("Location") != "" || !strings.Contains(body, "Check the change") || !strings.Contains(body, "contract changed since you looked") {
		t.Fatalf("a refused long Save: %d, Location %d bytes\n%.600s", code, len(h.Get("Location")), body)
	}
	if n := strings.Count(body, `<input type="hidden" name="op"`); n != rules.MaxEdits {
		t.Errorf("the preview it answers with carries %d edits to Save, want %d", n, rules.MaxEdits)
	}
	// A short one still goes back by address, as before.
	code, _, h = save([][3]string{{"add", "fs.write", "./more/"}}, "\n# edited again\n")
	if code != http.StatusSeeOther || !strings.HasPrefix(h.Get("Location"), "/rules/change/preview?") {
		t.Errorf("a refused short Save: %d to %q", code, h.Get("Location"))
	}
}

// problems is the page's own words about what is wrong, for a failure message.
func problems(body string) string {
	var out []string
	for _, m := range regexp.MustCompile(`<li><a class="link" href="#[^"]*">([^<]*)</a></li>`).FindAllStringSubmatch(body, 5) {
		out = append(out, regexp.MustCompile(`d{40,}`).ReplaceAllString(m[1], "d..."))
	}
	return strings.Join(out, "\n")
}

// A preview writes nothing, so the post of the Several form is open where the GET always was: to a peer inside a run,
// which sees the change without a Save, and while the machine baseline is unknown.
func TestSeveralPreviewPostKeepsTheGetsReach(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	q := func() url.Values {
		return severalQuery(ref, [][3]string{{"add", "fs.write", "./more/"}, {"add", "exec.allow", anyProgram}})
	}
	f.s.governed = func(*http.Request) error { return errors.New("governed run") }
	code, body := f.post(t, "/rules/change/preview", q())
	if code != http.StatusOK || !strings.Contains(body, "Saving is not available") || strings.Contains(body, `name="ack"`) || strings.Contains(body, `action="/rules/change"`) {
		t.Errorf("a governed peer's preview post: %d, read-only %v", code, strings.Contains(body, "Saving is not available"))
	}
	if code, _ := f.post(t, "/rules/change", url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add"}, "key": {"fs.write"}, "v": {"./more/"}}); code == http.StatusOK || code == http.StatusSeeOther {
		t.Errorf("a governed peer's save was answered %d", code)
	}
	f.s.governed = func(*http.Request) error { return nil }
	f.s.cfg.Machine = machineWithMode(t, 0o666) // untrusted, so unknown as root too: root reads a mode-000 file
	if code, body := f.post(t, "/rules/change/preview", q()); code != http.StatusOK {
		t.Errorf("a preview post with the baseline unknown: %d %.300s", code, body)
	}
	if code, _ := f.post(t, "/rules/change", url.Values{"c": {ref.Ref}, "op": {"add"}, "key": {"fs.write"}, "v": {"./more/"}}); code != http.StatusServiceUnavailable {
		t.Errorf("a save with the baseline unknown: %d, want 503", code)
	}
}
