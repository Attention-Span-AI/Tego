// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	htmlnode "golang.org/x/net/html"
)

// A restart loses authenticated reviews, and concurrent edits invalidate them.
// Native Save forms must refuse without calling any proposal planner, even when
// the posted source could still compile.
func TestBuilderLostReviewRefusesWithoutPlanning(t *testing.T) {
	for _, kind := range []string{"new", "raw", "structured"} {
		for _, condition := range []string{"lost", "changed"} {
			t.Run(kind+"/"+condition, func(t *testing.T) {
				f := newChangeFix(t)
				f.s.cfg.Setup = f.svc
				var form url.Values
				var editFile string
				target := "/rules/change"
				switch kind {
				case "new":
					target = "/rules/new"
					dir := filepath.Join(f.proj, "lost-new")
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					q := url.Values{"mode": {"blank"}, "dir": {dir}, "name": {"lost-new"}, "to": {"project"}, "cmd": {"/bin/sh"}, "preview": {"1"}}
					code, body := f.get(t, target+"?"+q.Encode())
					if code != http.StatusOK {
						t.Fatalf("Preview: %d", code)
					}
					form = builderRenderedSaveForm(t, body)
					if form.Get("base") == "" || form.Get("text") == "" {
						t.Fatal("Preview did not offer a reviewed new contract")
					}
				case "raw":
					c := f.ref(t, f.other)
					editFile = c.Path
					_, body := f.get(t, target+"?c="+c.Ref+"&view=full")
					form = builderRenderedEditForm(t, body)
					form.Set("text", form.Get("text")+"\nkeyring: true\n")
					form.Set("step", "check")
					form.Set("view", "full")
					preview := post(f.s, target, form, own, "", f.c)
					ack := ackField.FindStringSubmatch(preview.Body.String())
					if preview.Code != http.StatusOK || ack == nil || !strings.Contains(preview.Body.String(), "It compiles.") {
						t.Fatalf("Preview did not offer a reviewed raw edit: %d", preview.Code)
					}
					form = builderRenderedEditForm(t, preview.Body.String())
					form.Set("ack", ack[1])
					form.Set("step", "save")
					form.Set("view", "full")
				case "structured":
					c := f.ref(t, f.other)
					editFile = c.Path
					q := url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}
					code, body := f.get(t, target+"/preview?"+q.Encode())
					if code != http.StatusOK {
						t.Fatalf("Preview: %d", code)
					}
					form = builderLostStructuredForm(t, body)
				}
				service := f.svc
				if condition == "lost" {
					// Keep the dashboard session, but replace the rule service as after
					// a restart. No retained review or composition survives.
					service = &rules.Service{Ledger: f.root, Home: f.home, Machine: f.svc.Machine, Now: f.svc.Now}
				} else {
					if kind == "new" {
						editFile = filepath.Join(form.Get("dir"), "agent.yaml")
						if err := os.WriteFile(editFile, []byte("# concurrent destination\n"), 0600); err != nil {
							t.Fatal(err)
						}
					} else if err := os.WriteFile(editFile, []byte(readText(t, editFile)+"\n# concurrent source\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				observed := &builderLostPlans{builderReadPlans: &builderReadPlans{Service: service}}
				f.s.cfg.Rules, f.s.cfg.Setup = observed, observed
				before := builderDiskSnapshot(t, f.home, f.proj, f.root)
				w := post(f.s, target, form, own, "", f.c)
				if condition == "changed" && kind == "structured" {
					if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/rules/change/preview?") {
						t.Fatalf("changed source did not redirect to review: %d %s", w.Code, w.Header().Get("Location"))
					}
				} else if w.Code != http.StatusConflict {
					t.Fatalf("refused review: %d %s", w.Code, w.Body.String())
				}
				if condition == "lost" && strings.Count(w.Body.String(), rules.ErrReviewGone.Error()) != 1 {
					t.Fatalf("lost review has no single plain review-again sentence: %s", w.Body.String())
				}
				if observed.calls != 0 || observed.newPlan != nil || observed.changePlan != nil {
					t.Fatal("refused Save called a proposal planner")
				}
				if after := builderDiskSnapshot(t, f.home, f.proj, f.root); !reflect.DeepEqual(before, after) {
					t.Fatal("lost-review Save changed disk")
				}
			})
		}
	}
}

type builderLostPlans struct {
	*builderReadPlans
	calls int
}

func (s *builderLostPlans) PlanNew(context.Context, rules.NewReq) (*rules.NewPlan, error) {
	s.calls++
	return nil, errors.New("Save must not plan a proposal")
}

func (s *builderLostPlans) PlanChange(context.Context, rules.ChangeReq) (*rules.ChangePlan, error) {
	s.calls++
	return nil, errors.New("Save must not plan a proposal")
}

func (s *builderLostPlans) PlanRaw(context.Context, rules.RawReq) (*rules.ChangePlan, error) {
	s.calls++
	return nil, errors.New("Save must not plan a proposal")
}

func builderLostStructuredForm(t *testing.T, body string) url.Values {
	t.Helper()
	var form url.Values
	walk(parseHTML(t, "structured review", body), func(n *htmlnode.Node) {
		class, _ := attr(n, "class")
		if n.Data != "form" || !strings.Contains(class, "rc-confirm") {
			return
		}
		form = url.Values{}
		walk(n, func(input *htmlnode.Node) {
			if input.Data == "input" {
				name, _ := attr(input, "name")
				value, _ := attr(input, "value")
				kind, _ := attr(input, "type")
				if kind == "checkbox" || kind == "radio" {
					if _, checked := attr(input, "checked"); !checked && name != "ack" {
						return
					}
				}
				// The person ticks the acknowledgement after reviewing. Other
				// unchecked controls, including Also apply now, stay unsubmitted.
				if name != "" {
					form.Add(name, value)
				}
			}
		})
	})
	if form.Get("base") == "" || form.Get("ack") == "" {
		t.Fatal("Preview did not offer a reviewed structured edit")
	}
	return form
}
