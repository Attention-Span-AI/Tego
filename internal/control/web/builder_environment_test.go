// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestBuilderPresetGeneratedEnvironmentHTTPJourney(t *testing.T) {
	for _, destination := range []string{"project", "registry"} {
		t.Run(destination, func(t *testing.T) { builderPresetEnvironmentJourney(t, destination) })
	}
}

func builderPresetEnvironmentJourney(t *testing.T, destination string) {
	f := newChangeFix(t)
	observed := &builderReadPlans{Service: f.svc}
	f.s.cfg.Setup = observed
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	dir := filepath.Join(filepath.Dir(f.proj), "generated-environment")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"mode": {"presets"}, "dir": {dir}, "name": {"generated-environment"}, "preset": {"no-secrets", "repo-only-writes"}, "writes": {"./out/"}, "cmd": {"/bin/sh"}, "to": {destination}, "preview": {"1"}}
	code, body := f.get(t, "/rules/new?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("source preview: %d", code)
	}
	checkHidden := func(body string) {
		t.Helper()
		for _, hidden := range []string{agent.ProjectDirToken + "/.tego/tmp", "literal-attack-value"} {
			if strings.Contains(body, hidden) {
				t.Fatal("a hidden assignment value appeared in the response")
			}
		}
	}
	checkHidden(body)
	if !strings.Contains(body, "TMPDIR") || !strings.Contains(body, "(value hidden)") {
		if p := observed.newPlan; p != nil {
			t.Fatalf("fixture did not create a redacted generated assignment: problems %v; diagnostics %v", p.Problems, p.Diagnostics)
		}
		t.Fatal("fixture did not create a redacted generated assignment: no plan")
	}
	original := builderRenderedEditForm(t, body)
	if original.Get("draft") == "" {
		t.Fatal("no authenticated draft token")
	}
	// Check twice and move through both views using the actual rendered draft.
	for _, view := range []string{"simple", "simple", "full", "simple", "full"} {
		form := builderRenderedEditForm(t, body)
		form.Set("step", "preview")
		form.Set("view", view)
		w := post(f.s, "/rules/new", form, own, "", f.c)
		body = w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(body, `id="builder-save"`) || !strings.Contains(body, `type="submit">`+saveLabel(destination)) {
			t.Fatalf("%s Check/view lost saveable generated draft: %d %s", view, w.Code, body)
		}
		checkHidden(body)
	}
	// A literal supplied in place of the redacted assignment is refused without
	// reflecting that value in either the editor, diagnostics or the error.
	tampered := builderRenderedEditForm(t, body)
	tampered.Set("text", strings.ReplaceAll(tampered.Get("text"), "(value hidden)", "literal-attack-value"))
	tampered.Set("step", "preview")
	w := post(f.s, "/rules/new", tampered, own, "", f.c)
	checkHidden(w.Body.String())
	if strings.Contains(w.Body.String(), `type="submit">`+saveLabel(destination)) {
		t.Fatal("client-supplied generated assignment remained saveable")
	}
	// The same service must refuse the opaque draft under another authenticated
	// session and under another draft's destination.
	foreign, err := New(f.s.cfg)
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(foreign)
	foreignCookie := login(t, foreign)
	crossSession := builderRenderedEditForm(t, body)
	crossSession.Set("csrf", foreign.csrf)
	crossSession.Set("step", "preview")
	w = post(foreign, "/rules/new", crossSession, own, "", foreignCookie)
	checkHidden(w.Body.String())
	if strings.Contains(w.Body.String(), `type="submit">`+saveLabel(destination)) {
		t.Fatal("another session restored generated assignments")
	}
	crossDraft := builderRenderedEditForm(t, body)
	crossDraft.Set("name", "different-draft")
	crossDraft.Set("step", "preview")
	w = post(f.s, "/rules/new", crossDraft, own, "", f.c)
	checkHidden(w.Body.String())
	if strings.Contains(w.Body.String(), `type="submit">`+saveLabel(destination)) {
		t.Fatal("draft token restored assignments into another draft")
	}
	form := builderRenderedSaveForm(t, body)
	w = post(f.s, "/rules/new", form, own, "", f.c)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("preset Save: %d %s", w.Code, w.Body.String())
	}
	savedPath := filepath.Join(dir, "agent.yaml")
	if destination == "registry" {
		savedPath = filepath.Join(f.svc.Machine.Registry.Value, "agents", "generated-environment.yaml")
	}
	saved, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), agent.ProjectDirToken+"/.tego/tmp") || strings.Contains(string(saved), "(value hidden)") {
		t.Fatal("saved contract lost the original generated assignment")
	}
	for _, path := range []string{"out", ".tego/tmp"} {
		if st, err := os.Stat(filepath.Join(dir, path)); err != nil || !st.IsDir() {
			t.Errorf("generated setup metadata did not create %s: %v", path, err)
		}
	}
	checkHidden(follow(t, f.s, f.c, w))
}

func builderRenderedEditForm(t *testing.T, body string) url.Values {
	t.Helper()
	_, part, ok := strings.Cut(body, `id="builder-edit"`)
	if !ok {
		t.Fatal("no edit form")
	}
	part, _, ok = strings.Cut(part, "</form>")
	if !ok {
		t.Fatal("unclosed edit form")
	}
	form := make(url.Values)
	for _, field := range regexp.MustCompile(`<input\b[^>]*>`).FindAllString(part, -1) {
		attrs := make(map[string]string)
		for _, a := range regexp.MustCompile(`([a-z-]+)="([^"]*)"`).FindAllStringSubmatch(field, -1) {
			attrs[a[1]] = html.UnescapeString(a[2])
		}
		if (attrs["type"] == "radio" || attrs["type"] == "checkbox") && !strings.Contains(field, " checked") {
			continue
		}
		if attrs["name"] != "" {
			form.Add(attrs["name"], attrs["value"])
		}
	}
	for _, field := range regexp.MustCompile(`(?s)<textarea\b([^>]*)>(.*?)</textarea>`).FindAllStringSubmatch(part, -1) {
		name := regexp.MustCompile(`name="([^"]+)"`).FindStringSubmatch(field[1])
		if name != nil {
			form.Add(name[1], html.UnescapeString(field[2]))
		}
	}
	return form
}

func saveLabel(destination string) string {
	if destination == "registry" {
		return "Save generated-environment"
	}
	return "Create agent.yaml"
}

func TestBuilderEmptyFullSaveNeverRecomposesSource(t *testing.T) {
	for _, dropToken := range []bool{false, true} {
		t.Run(map[bool]string{false: "with-token", true: "missing-token"}[dropToken], func(t *testing.T) {
			f := newRulesFix(t)
			f.withRegistry(t)
			dir := filepath.Join(filepath.Dir(f.proj), "empty-full")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			q := url.Values{"mode": {"presets"}, "dir": {dir}, "name": {"empty-full"}, "preset": {"no-secrets"}, "cmd": {"/bin/sh"}, "to": {"project"}, "preview": {"1"}}
			_, body := f.get(t, "/rules/new?"+q.Encode())
			form := builderRenderedSaveForm(t, body)
			form.Set("text", "")
			if dropToken {
				form.Del("draft")
			}
			w := post(f.s, "/rules/new", form, own, "", f.c)
			if w.Code != http.StatusConflict {
				t.Fatalf("empty Full Save: %d", w.Code)
			}
			if _, err := os.Lstat(filepath.Join(dir, "agent.yaml")); !os.IsNotExist(err) {
				t.Fatalf("empty editor published original source: %v", err)
			}
		})
	}
}

type busyBuilderSetup struct{ SetupService }

func (b busyBuilderSetup) PlanNew(context.Context, rules.NewReq) (*rules.NewPlan, error) {
	return &rules.NewPlan{Problems: []string{"busy, try again"}}, nil
}

func TestBuilderBusyPreviewRetainsDraft(t *testing.T) {
	f := newRulesFix(t)
	f.withRegistry(t)
	dir := filepath.Join(filepath.Dir(f.proj), "busy-preview")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"mode": {"presets"}, "dir": {dir}, "name": {"busy-preview"}, "preset": {"no-secrets"}, "cmd": {"/bin/sh"}, "to": {"project"}, "preview": {"1"}, "view": {"full"}}
	_, body := f.get(t, "/rules/new?"+q.Encode())
	form := builderRenderedEditForm(t, body)
	text, token := form.Get("text"), form.Get("draft")
	if text == "" || token == "" {
		t.Fatal("fixture has no authenticated draft")
	}
	f.s.cfg.Setup = busyBuilderSetup{f.s.cfg.Setup}
	form.Set("step", "preview")
	w := post(f.s, "/rules/new", form, own, "", f.c)
	got := builderRenderedEditForm(t, w.Body.String())
	if got.Get("text") != text || got.Get("draft") != token {
		t.Fatal("busy preflight lost the posted draft or its restoration handle")
	}
	if !strings.Contains(w.Body.String(), "busy, try again") || strings.Contains(w.Body.String(), `type="submit">Create agent.yaml`) {
		t.Fatal("busy preview lost its refusal or enabled Save")
	}
}
