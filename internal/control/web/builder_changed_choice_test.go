// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Simple choices changed after Check must not save the previous hidden text.
// The response asks for another Check without building a proposal on Save.
func TestBuilderRawSimpleChangedChoiceRequiresCheck(t *testing.T) {
	f := newChangeFix(t)
	c := f.ref(t, f.other)
	_, body := f.get(t, "/rules/change?c="+c.Ref+"&view=simple")
	form := builderRenderedEditForm(t, body)
	form.Set("text", strings.Replace(form.Get("text"), "allow: [sh]", "allow: [sh, /bin/echo]", 1))
	form.Set("step", "check")
	form.Set("view", "simple")
	preview := post(f.s, "/rules/change", form, own, "", f.c)
	ack := ackField.FindStringSubmatch(preview.Body.String())
	if preview.Code != http.StatusOK || ack == nil || !strings.Contains(preview.Body.String(), "It compiles.") {
		t.Fatalf("no valid reviewed Simple edit: %d", preview.Code)
	}
	form = builderRenderedEditForm(t, preview.Body.String())
	if form.Get("current-view") != "simple" {
		t.Fatal("review did not retain the Simple form")
	}
	changed := false
	for name, values := range form {
		if strings.HasPrefix(name, "choice-") && len(values) == 1 && values[0] == "keep" {
			form.Set(name, "drop")
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("reviewed edit has no remaining choice to change")
	}
	form.Set("ack", ack[1])
	form.Set("step", "save")
	form.Set("view", "simple")
	observed := &builderLostPlans{builderReadPlans: &builderReadPlans{Service: f.svc}}
	f.s.cfg.Rules = observed
	before := builderDiskSnapshot(t, f.home, f.proj, f.root)
	w := post(f.s, "/rules/change", form, own, "", f.c)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "check the contract again before saving") {
		t.Fatalf("changed Simple choice Save: %d %s", w.Code, w.Body.String())
	}
	if observed.calls != 0 {
		t.Fatal("changed-choice Save called a proposal planner")
	}
	if after := builderDiskSnapshot(t, f.home, f.proj, f.root); !reflect.DeepEqual(before, after) {
		t.Fatal("changed-choice Save wrote the previously reviewed proposal")
	}
}
