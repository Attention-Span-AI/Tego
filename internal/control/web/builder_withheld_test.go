// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

func TestBuilderLeakingRunRenderedFormSavesUnchanged(t *testing.T) {
	root := sysFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	home := t.TempDir()
	dir := filepath.Join(home, "project")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s.cfg.Setup = &rules.Service{Ledger: root, Home: home, Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
	q := url.Values{"mode": {"run"}, "from": {sysWatchRun}, "dir": {dir}, "name": {"learned"}, "to": {"project"}, "preview": {"1"}}
	body := get(t, s, c, "/rules/new?"+q.Encode())
	const sink = "127.0.0.1:48802"
	if !strings.Contains(body, "leaked to "+sink+"</strong>") || !strings.Contains(body, "Left out: ") {
		t.Fatal("fixture preview did not withhold the leaking destination")
	}
	form := builderRenderedSaveForm(t, body)
	if form.Get("draft") == "" || form.Get("base") == "" {
		t.Fatal("rendered Save form has no authenticated draft or review binding")
	}
	if strings.Contains(form.Get("text"), `- "tcp://`+sink+`"`) {
		t.Fatal("reviewed proposal still allows the leaking destination")
	}
	w := post(s, "/rules/new", form, own, "", c)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("unchanged rendered Save was refused: HTTP %d", w.Code)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(saved) != form.Get("text") {
		t.Fatal("Save did not publish the exact reviewed proposal")
	}
}
