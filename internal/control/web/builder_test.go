// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"gopkg.in/yaml.v3"
)

func TestBuilderFormsRetainFullDraft(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "builder")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	original := "# a deliberate edit\nversion: 0\nname: builder\ncommand: [sh]\nexec:\n  allow: [sh, git]\nnet:\n  allow: []\n"
	form := url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "dir": {dir}, "name": {"builder"}, "mode": {"blank"}, "view": {"simple"}, "current-view": {"full"}, "text": {original}}
	w := post(f.s, "/rules/new", form, own, "", f.c)
	if w.Code != 200 || !strings.Contains(w.Body.String(), html.EscapeString(original)) {
		t.Fatalf("switch lost draft: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "May run git") {
		t.Fatal("no Simple decision")
	}
	form.Set("view", "full")
	form.Set("current-view", "simple")
	w = post(f.s, "/rules/new", form, own, "", f.c)
	if !strings.Contains(w.Body.String(), html.EscapeString(original)) {
		t.Fatal("switch invented or lost a rule")
	}
}

func TestBuilderSecurityBoundaries(t *testing.T) {
	f := newRulesFix(t)
	reg := f.withRegistry(t)
	dir := filepath.Join(filepath.Dir(f.proj), "builder-sec")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"mode": {"blank"}, "dir": {dir}, "name": {"builder-sec"}, "to": {"registry"}, "preview": {"1"}}
	_, body := f.get(t, "/rules/new?"+q.Encode())
	w := post(f.s, "/rules/new", builderRenderedSourceForm(t, body), own, "", f.c)
	if w.Code != http.StatusOK {
		t.Fatalf("guarded preview: %d", w.Code)
	}
	form := builderRenderedSaveForm(t, w.Body.String())
	for _, origin := range []string{"https://attacker.example", "null"} {
		form.Set("csrf", f.s.csrf)
		w := post(f.s, "/rules/new", form, origin, "", f.c)
		if w.Code != http.StatusForbidden {
			t.Fatalf("origin %s: %d", origin, w.Code)
		}
	}
	form.Del("csrf")
	if w := post(f.s, "/rules/new", form, own, "", f.c); w.Code != http.StatusForbidden {
		t.Fatal("missing CSRF accepted")
	}
	form.Set("csrf", f.s.csrf)
	for _, name := range []string{"../escape", "<script>alert(1)</script>", "a/../../escape"} {
		t.Run("hostile-name-"+name, func(t *testing.T) {
			before := builderDestinationFiles(t, filepath.Dir(f.proj), f.home)
			form.Set("name", name)
			w := post(f.s, "/rules/new", form, own, "", f.c)
			if w.Code != http.StatusConflict {
				t.Errorf("bad name %q was not refused: %d", name, w.Code)
			}
			// Inspect both the literal destination and each location a path join
			// could escape to. The full fixture snapshots also catch a different name.
			for _, path := range []string{
				filepath.Join(reg, "agents", name+".yaml"),
				filepath.Join(reg, name+".yaml"),
				filepath.Join(dir, name+".yaml"),
				filepath.Join(dir, "agent.yaml"),
			} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Errorf("hostile name %q attempted destination %s exists or cannot be checked: %v", name, path, err)
				}
			}
			if after := builderDestinationFiles(t, filepath.Dir(f.proj), f.home); !reflect.DeepEqual(before, after) {
				t.Errorf("hostile name %q changed a destination file set or digest", name)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(reg, "agents", "builder-sec.yaml")); !os.IsNotExist(err) {
		t.Fatal("hostile request wrote a file")
	}
	form.Set("name", "builder-sec")
	// A symlink out of agents/ must not publish outside the reviewed destination.
	if err := os.MkdirAll(reg, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(f.proj), "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	// Planning may have prepared an empty agents directory; substitute that
	// same reviewed destination rather than relying on it not existing yet.
	if err := os.Remove(filepath.Join(reg, "agents")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(reg, "agents")); err != nil {
		t.Fatal(err)
	}
	post(f.s, "/rules/new", form, own, "", f.c)
	if _, err := os.Stat(filepath.Join(outside, "builder-sec.yaml")); !os.IsNotExist(err) {
		t.Fatal("followed agents symlink")
	}
}

func TestBuilderUsesCompilerAndRefusesConcurrentEdit(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.source)
	cur, _ := f.svc.Current(c.Ref)
	text := string(cur.Editor) + "\nkeyring: true\n"
	p, err := f.svc.PlanRaw(t.Context(), rules.RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text)})
	if err != nil || p.Err != "" || len(p.NewlyAllows) == 0 {
		t.Fatalf("comparison: %+v %v", p, err)
	}
	// Review through the rendered form so Save names this session's held proposal.
	_, body := f.get(t, "/rules/change?c="+c.Ref+"&view=full")
	form := builderRenderedEditForm(t, body)
	form.Set("step", "check")
	form.Set("view", "full")
	form.Set("text", text)
	w := post(f.s, "/rules/change", form, own, "", f.c)
	ack := ackField.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || ack == nil || !strings.Contains(w.Body.String(), "It compiles.") {
		t.Fatalf("rendered review: %d", w.Code)
	}
	form = builderRenderedEditForm(t, w.Body.String())
	form.Set("ack", ack[1])
	form.Set("step", "save")
	form.Set("view", "full")
	// A concurrent edit keeps the first viewer's base stale, including after a Check.
	if err := os.WriteFile(c.Path, []byte(readText(t, c.Path)+"\n# concurrent\n"), 0600); err != nil {
		t.Fatal(err)
	}
	w = post(f.s, "/rules/change", form, own, "", f.c)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "changed since") {
		t.Fatalf("stale: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(readText(t, c.Path), "# concurrent") {
		t.Fatal("overwrote concurrent edit")
	}
	// Real compiler rejects a malformed field and locates it.
	form.Set("step", "check")
	form.Set("text", "version: 0\nname: bad\ncommand: [sh]\nnet:\n  allow: ['api.example.com:443/v1']\n")
	w = post(f.s, "/rules/change", form, own, "", f.c)
	if !strings.Contains(w.Body.String(), "cannot be saved") || !regexp.MustCompile(`line [0-9]|\.yaml:[0-9]`).MatchString(w.Body.String()) {
		t.Fatalf("no located compiler error: %s", w.Body.String())
	}
}

func TestBuilderRealRunHasDecisions(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	appendLine(t, f.root, rulesRunA, line(rulesRunA, "rules-demo", 4, time.Now(), "fs", `"verdict":"allow","op":"open","path":"`+f.proj+`/out/file.txt","flags":65`))
	p, err := f.svc.PlanNew(t.Context(), rules.NewReq{Dir: f.proj, Name: "builder-run", FromRun: rulesRunA, Registry: true, Reads: true})
	if err != nil || len(p.Decisions) == 0 {
		t.Fatalf("run has no decisions: %+v %v", p, err)
	}
}

func TestBuilderCannotNameAnUnloadedContract(t *testing.T) {
	f := newChangeFix(t)
	for _, ref := range []string{f.other, "../agent.yaml", "..%2fagent.yaml", strings.Repeat("f", 16)} {
		form := url.Values{"csrf": {f.s.csrf}, "mode": {"raw"}, "step": {"save"}, "c": {ref}, "base": {strings.Repeat("0", 64)}, "text": {"version: 0\nname: hostile\ncommand: [sh]\n"}}
		w := post(f.s, "/rules/change", form, own, "", f.c)
		if w.Code != 404 {
			t.Errorf("unloaded %q: %d", ref, w.Code)
		}
	}
}

func TestBuilderFieldErrorsAndViewerPreference(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.source)
	w := do(f.s, "GET", "/rules/change/preview?"+url.Values{"c": {c.Ref}, "op": {"add"}, "key": {"net.allow"}, "v": {"bad host/443"}}.Encode(), "127.0.0.1:8484", f.c)
	if w.Code != 422 || !strings.Contains(w.Body.String(), `role="alert"`) || !strings.Contains(w.Body.String(), `id="add-net.allow" name="v" value="bad host/443" aria-invalid="true"`) {
		t.Fatalf("no linked field error: %d %s", w.Code, w.Body.String())
	}
	_, body := f.get(t, "/rules/change?c="+c.Ref+"&view=full")
	if !strings.Contains(body, `id="yaml-text"`) {
		t.Fatal("Full editor absent")
	}
	req := httptest.NewRequest("GET", "/rules/change?c="+c.Ref, nil)
	req.Host = "127.0.0.1:8484"
	req.AddCookie(f.c)
	req.AddCookie(&http.Cookie{Name: "tego-builder-view", Value: "full"})
	out := httptest.NewRecorder()
	f.s.ServeHTTP(out, req)
	if !strings.Contains(out.Body.String(), `id="yaml-text"`) {
		t.Fatal("viewer preference lost")
	}
}

func TestBuilderSaveFromGovernedPeerIsRefused(t *testing.T) {
	f := newRulesFix(t)
	f.withRegistry(t)
	f.s.governed = func(*http.Request) error { return fmt.Errorf("request came from inside governed run %s", rulesRunA) }
	form := url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "step": {"save"}, "mode": {"blank"}, "dir": {f.proj}, "name": {"hostile"}, "to": {"registry"}, "base": {strings.Repeat("0", 64)}}
	w := post(f.s, "/rules/new", form, own, "", f.c)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "governed run") {
		t.Fatalf("governed save: %d %s", w.Code, w.Body.String())
	}
}

func TestBuilderConfirmationBindsCompiledProfiles(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.other)
	profileDir := filepath.Join(f.home, "profiles")
	if err := os.Mkdir(profileDir, 0700); err != nil {
		t.Fatal(err)
	}
	f.svc.Machine.Profiles.Value = profileDir
	profile := filepath.Join(profileDir, "builder-profile.yaml")
	if err := os.WriteFile(profile, []byte("version: 0\nnet:\n  allow: ['203.0.113.24:443']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	text := readText(t, c.Path) + "\nextends: builder-profile\n"
	req := rules.RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(text)}
	p, err := f.svc.PlanRaw(t.Context(), req)
	if err != nil || p.Err != "" {
		t.Fatalf("profile preview: %+v %v", p, err)
	}
	if err := os.WriteFile(profile, []byte("version: 0\nnet:\n  allow: ['203.0.113.24:443', '198.51.100.9:443']\n"), 0600); err != nil {
		t.Fatal(err)
	}
	req.Ack = p.Ack
	if _, err := f.svc.ApplyRaw(t.Context(), req); !errors.Is(err, rules.ErrAckMismatch) {
		t.Fatalf("changed compiled profile accepted: %v", err)
	}
	if readText(t, c.Path) == text {
		t.Fatal("unreviewed effective rules written")
	}
}

func TestBuilderSwitchesSetOnlyExplicitRules(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	req := rules.NewReq{Dir: f.proj, Name: "explicit", Registry: true, PrepareDirectories: true, Blank: true, Command: "/bin/sh", Switches: true, Wall: "2h", WantAsk: true, AskHosts: []string{"api.example.com:443"}}
	p, err := f.svc.PlanNew(t.Context(), req)
	if err != nil || !p.OK {
		t.Fatalf("switches do not compile: %+v %v", p, err)
	}
	if !strings.Contains(string(p.Text), "wall: 2h") || !strings.Contains(string(p.Text), "api.example.com:443") || strings.Contains(string(p.Text), "reads: on") {
		t.Fatalf("unexpected defaults: %s", p.Text)
	}
	req.Text = p.Text
	req.Wall = ""
	req.RemoveWall = true
	req.DropAsk = true
	req.AskHosts = nil
	req.WantAsk = false
	p, err = f.svc.PlanNew(t.Context(), req)
	if err != nil || !p.OK || strings.Contains(string(p.Text), "wall: 2h") || strings.Contains(string(p.Text), "api.example.com") {
		t.Fatalf("explicit switch-off failed: %s %v", p.Text, err)
	}
}

func TestBuilderDoesNotCallARestrictionANewPermission(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.other)
	req := rules.RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(readText(t, c.Path) + "\nnet:\n  allow: ['203.0.113.24:443']\n")}
	p, err := f.svc.PlanRaw(t.Context(), req)
	if err != nil || p.Err != "" {
		t.Fatalf("restriction: %+v %v", p, err)
	}
	if len(p.NewlyAllows) != 0 {
		t.Fatalf("already allowed destination listed as new: %v", p.NewlyAllows)
	}
}

func TestBuilderCanRepairAContractThatNoLongerCompiles(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.other)
	good := readText(t, c.Path)
	if err := os.WriteFile(c.Path, []byte("version: [broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cur, err := f.svc.Current(c.Ref)
	if err != nil {
		t.Fatal(err)
	}
	req := rules.RawReq{Ref: c.Ref, Base: cur.Base, Text: []byte(good)}
	p, err := f.svc.PlanRaw(t.Context(), req)
	if err != nil || p.Err != "" || len(p.NewlyAllows) == 0 {
		t.Fatalf("repair preview refused: %+v %v", p, err)
	}
	if _, err := f.svc.ApplyRaw(t.Context(), req); !errors.Is(err, rules.ErrNeedsAck) {
		t.Fatalf("unconfirmed repair: %v", err)
	}
	req.Ack = p.Ack
	if _, err := f.svc.ApplyRaw(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if readText(t, c.Path) != good {
		t.Fatal("repair did not write the checked bytes")
	}
}

// Keep the Full guide complete when the contract gains a field, including nested MCP and route entries.
func TestBuilderFieldGuideCoversContract(t *testing.T) {
	fields := make(map[string]string)
	for _, f := range builderFields {
		fields[f.Key] = f.Meaning
	}
	var walk func(reflect.Type, string)
	walk = func(typ reflect.Type, prefix string) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ == reflect.TypeFor[yaml.Node]() {
			return
		}
		if typ.Kind() == reflect.Slice {
			typ = typ.Elem()
			if typ.Kind() != reflect.Struct {
				return
			}
			prefix += "[]"
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if key == "" || key == "-" {
				continue
			}
			if prefix != "" {
				key = prefix + "." + key
			}
			if meaning := fields[key]; meaning == "" || strings.HasPrefix(meaning, "Configure ") {
				t.Errorf("no useful definition for %s", key)
			}
			walk(f.Type, key)
		}
	}
	walk(reflect.TypeFor[agent.Contract](), "")
}

func TestBuilderSimpleErrorsPointToTheirFields(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	f.s.cfg.Setup = f.svc
	q := url.Values{"dir": {f.proj}, "name": {"field-errors"}, "mode": {"blank"}, "to": {"registry"}, "cmd": {"/bin/sh"}, "hosts": {"bad host/443"}, "preview": {"1"}}
	w := do(f.s, "GET", "/rules/new?"+q.Encode(), "127.0.0.1:8484", f.c)
	if !strings.Contains(w.Body.String(), `id="builder-hosts" name="hosts" aria-invalid="true"`) {
		t.Errorf("no host field error: %s", w.Body.String())
	}
	text := "version: 0\nname: field-errors\ncommand: [/bin/sh]\nnet:\n  allow: []\n"
	form := url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "step": {"preview"}, "mode": {"blank"}, "dir": {f.proj}, "name": {"field-errors"}, "to": {"registry"}, "text": {text}, "view": {"simple"}, "current-view": {"simple"}, "wall-choice": {"1"}, "wall": {"nonsense"}}
	w = post(f.s, "/rules/new", form, own, "", f.c)
	if !strings.Contains(w.Body.String(), `id="builder-wall" name="wall" aria-invalid="true"`) {
		t.Fatalf("no time-limit field error: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `value="nonsense"`) {
		t.Fatal("time limit edit lost")
	}
}

func TestBuilderPreferenceSurvivesBrowserRestart(t *testing.T) {
	f := newRulesFix(t)
	w := do(f.s, "GET", "/rules/new?view=full", "127.0.0.1:8484", f.c)
	for _, c := range w.Result().Cookies() {
		if c.Name == "tego-builder-view" {
			if c.Value != "full" || c.MaxAge <= 0 || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("preference is not persistent and scoped: %+v", c)
			}
			return
		}
	}
	t.Fatal("no viewer preference cookie")
}

func TestBuilderRejectedSaveKeepsEditedDraft(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	f.s.cfg.Setup = f.svc
	text := "# retain this exact edit\nversion: 0\nname: kept-edit\ncommand: [/bin/sh]\nnet:\n  allow: []\n"
	q := url.Values{"mode": {"blank"}, "dir": {f.proj}, "name": {"kept-edit"}, "to": {"registry"}, "view": {"full"}, "preview": {"1"}}
	_, body := f.get(t, "/rules/new?"+q.Encode())
	preview := post(f.s, "/rules/new", builderRenderedSourceForm(t, body), own, "", f.c)
	if preview.Code != http.StatusOK {
		t.Fatalf("source preview: %d", preview.Code)
	}
	edit := builderRenderedEditForm(t, preview.Body.String())
	edit.Set("text", text)
	edit.Set("step", "preview")
	edit.Set("view", "full")
	preview = post(f.s, "/rules/new", edit, own, "", f.c)
	if preview.Code != http.StatusOK {
		t.Fatalf("edited preview: %d", preview.Code)
	}
	form := builderRenderedSaveForm(t, preview.Body.String())
	file := filepath.Join(f.svc.Machine.Registry.Value, "agents", "kept-edit.yaml")
	existing := "# concurrent owner file\n" + text
	if err := os.WriteFile(file, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}
	w := post(f.s, "/rules/new", form, own, "", f.c)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), html.EscapeString(text)) {
		t.Fatalf("rejected save lost the edited draft: HTTP %d", w.Code)
	}
	if retry := builderRenderedEditForm(t, w.Body.String()); retry.Get("draft") == "" || retry.Get("draft") != form.Get("draft") {
		t.Fatal("rejected Save lost its authenticated composition handle")
	}
	if got := readText(t, file); got != existing {
		t.Fatal("rejected save changed the concurrent file")
	}
}

func TestBuilderRunSourceErrorsStayWithTheRunChoice(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	observed := &builderReadPlans{Service: f.svc}
	f.s.cfg.Setup = observed
	for _, id := range []string{"", "not-a-run"} {
		q := url.Values{"mode": {"run"}, "preview": {"1"}, "dir": {f.proj}, "name": {"choose-run"}, "to": {"registry"}, "from": {id}}
		w := do(f.s, "GET", "/rules/new?"+q.Encode(), "127.0.0.1:8484", f.c)
		if !strings.Contains(w.Body.String(), `id="builder-run" name="from" aria-invalid="true"`) {
			if p := observed.newPlan; p != nil {
				t.Errorf("run %q has no field error: HTTP %d; problems %v; diagnostics %v", id, w.Code, p.Problems, p.Diagnostics)
			} else {
				t.Errorf("run %q has no field error: HTTP %d; no plan", id, w.Code)
			}
		}
		if strings.Contains(w.Body.String(), `href="/runs/"`) || strings.Contains(w.Body.String(), `href="/runs/not-a-run"`) {
			t.Errorf("run %q has an unusable recorded-run link", id)
		}
	}
}

func TestBuilderPresetProblemBelongsToPresetChoices(t *testing.T) {
	f := newChangeFix(t)
	f.svc.Machine.Registry.Value = filepath.Join(f.home, ".config", "tego")
	f.s.cfg.Setup = f.svc
	q := url.Values{"mode": {"presets"}, "preview": {"1"}, "dir": {f.proj}, "name": {"choose-preset"}, "to": {"registry"}}
	w := do(f.s, "GET", "/rules/new?"+q.Encode(), "127.0.0.1:8484", f.c)
	if !strings.Contains(w.Body.String(), `id="builder-presets" aria-invalid="true"`) {
		t.Fatal("no field-level error on the required preset group")
	}
}

// Keep evidence for every file under both roots, including attempts that invent
// a destination name instead of writing the legitimate contract under test.
func builderDestinationFiles(t *testing.T, roots ...string) map[string][sha256.Size]byte {
	t.Helper()
	out := make(map[string][sha256.Size]byte)
	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			text, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out[path] = sha256.Sum256(text)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return out
}
