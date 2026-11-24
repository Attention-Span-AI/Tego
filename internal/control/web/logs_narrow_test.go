// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestLogsRowsDoNotCarryTheSearch: a row's program and process buttons hold only their own term; the search is written
// once, as the hidden fields of one form, so a long query is not repeated twice in each of a page's rows.
func TestLogsRowsDoNotCarryTheSearch(t *testing.T) {
	root, _ := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	const where = "verdict:allow verdict:refused verdict:none verdict:observed kind:exec kind:net kind:fs kind:run -host:example.net -rule:zzz*"
	b := get(t, s, c, "/logs?where="+url.QueryEscape(where)+"&agent=codex")
	t.Logf("the page is %d bytes for %d rows", len(b), strings.Count(b, `<tr role="row"`))
	rows := b[strings.Index(b, `id="lq-rows"`):]
	rows = rows[:strings.Index(rows, "</tbody>")]
	if n := strings.Count(rows, `<tr role="row"`); n < 50 {
		t.Fatalf("the page has %d rows: the fixture proves nothing", n)
	}
	rows = rows[strings.Index(rows, ">")+1:] // the tbody's own data-rows address is the one copy the page's rows keep
	if n := strings.Count(rows, "verdict%3Aallow") + strings.Count(rows, "verdict:allow"); n != 0 {
		t.Errorf("the rows carry the search %d times", n)
	}
	if n := strings.Count(b, `name="where" value="`+where+`"`) + strings.Count(b, `name="narrow"`); n == 0 {
		t.Error("the page lacks its buttons")
	}
	if !strings.Contains(b, `<input type="hidden" name="where" value="`+where+`">`) || !strings.Contains(b, `<input type="hidden" name="agent" value="codex">`) {
		t.Error("the narrow form lacks the search's fields")
	}
}

// TestLogsNarrowButtonAddsAndRemovesATerm: pressing a row's button leads to the search with its term added, a second
// press (the term already in the query) takes it out, and anything but a program or process term is refused.
func TestLogsNarrowButtonAddsAndRemovesATerm(t *testing.T) {
	root, _ := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, c2 := range []struct{ from, to string }{
		{"/logs?narrow=prog%3Acurl", "/logs?where=prog%3Acurl"},
		{"/logs?where=kind%3Aexec&narrow=pid%3A10&agent=codex", "/logs?agent=codex&where=kind%3Aexec+pid%3A10"},
		{"/logs?where=prog%3Acurl&narrow=prog%3Acurl", "/logs"},
		{"/logs?where=prog%3Acurl+kind%3Aexec&narrow=prog%3Acurl", "/logs?where=kind%3Aexec"},
		{"/logs?narrow=prog%3A%22a+b%22", "/logs?where=prog%3A%22a+b%22"},
	} {
		w := do(s, "GET", c2.from, "127.0.0.1:8484", c)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != c2.to {
			t.Errorf("%s: %d to %q, want 303 to %q", c2.from, w.Code, w.Header().Get("Location"), c2.to)
		}
	}
	for _, bad := range []string{"/logs?narrow=", "/logs?narrow=kind%3Aexec", "/logs?narrow=-prog%3Acurl", "/logs?narrow=prog%3Aa&narrow=pid%3A1", "/logs?narrow=pid%3Aabc"} {
		if w := do(s, "GET", bad, "127.0.0.1:8484", c); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, w.Code)
		}
	}
}
