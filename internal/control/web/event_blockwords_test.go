// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var rawBlockKey = regexp.MustCompile(`(title="|Block )(exec|net|path|read|write)[: ]`)

// TestEventLiveBlockLabelsUseRuleWords (C139): the line page's live-block labels (the Block now button, and the
// titles of the blocks it placed) say Program, Destination, File or folder, as the run page does, never the raw key
// ("exec:/usr/bin/curl", "Block path").
func TestEventLiveBlockLabelsUseRuleWords(t *testing.T) {
	s, c, _, _ := askServer(t)
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	line := "/runs/" + actRun + "/lines/4"
	page := do(s, "GET", "/runs/"+actRun+"/lines/3?level=0", "127.0.0.1:8484", c).Body.String()
	preview := do(s, "GET", line+"?a=block&level=0", "127.0.0.1:8484", c).Body.String()
	saved := follow(t, s, c, post(s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"0"}, "base": {baseOf(t, preview)}, "now": {actRun}}, own, "", c))
	for name, body := range map[string]string{"line page": page, "saved panel": saved} {
		if m := rawBlockKey.FindString(body); m != "" {
			t.Errorf("%s shows the raw key %q", name, m)
		}
	}
	if !strings.Contains(page, "Block file or folder") && !strings.Contains(page, "Block program") && !strings.Contains(page, "Block destination") {
		t.Errorf("line page has no worded Block now button")
	}
	if !strings.Contains(saved, `title="Program `) {
		t.Errorf("saved panel's block has no worded title")
	}
}
