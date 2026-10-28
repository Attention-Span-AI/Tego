// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"strings"
	"testing"
)

// TestLogsRowsWordFollowsTheLiveTotal: the "row"/"rows" after the results total sits in its own span, and logs.js
// rewrites that word whenever a live update rewrites the total, so a page that grew from 1 row to 3 reads "3 rows"
// without a reload (found by the 16:00 release's demo-safety pass on the MCP segment's Logs search).
func TestLogsRowsWordFollowsTheLiveTotal(t *testing.T) {
	root, _ := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	b := do(s, "GET", "/logs?q=pypi.org", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(b, `<span class="lq-total">1</span> <span class="lq-rows-w">row</span> shown`) {
		t.Error(`the results head lacks the "row" word in its own span after the total`)
	}
	js, err := os.ReadFile("static/logs.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`document.querySelector('.lq-rows-w')`, `rowsW.textContent = Number(total) === 1 ? 'row' : 'rows'`} {
		if !strings.Contains(string(js), want) {
			t.Errorf("logs.js lacks %s", want)
		}
	}
}
