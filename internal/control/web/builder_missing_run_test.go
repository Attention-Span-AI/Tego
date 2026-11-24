// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

func TestBuilderMissingRunErrorWithCancelledPreflight(t *testing.T) {
	for _, view := range []string{"simple", "full"} {
		t.Run(view, func(t *testing.T) {
			f := newChangeFix(t)
			observed := &builderReadPlans{Service: f.svc}
			f.s.cfg.Setup = observed
			before := builderDestinationFiles(t, filepath.Dir(f.proj))
			q := url.Values{"mode": {"run"}, "preview": {"1"}, "dir": {f.proj}, "name": {"choose-run"}, "to": {"project"}, "from": {""}, "view": {view}}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			r := httptest.NewRequest(http.MethodGet, "/rules/new?"+q.Encode(), nil).WithContext(ctx)
			r.Host = "127.0.0.1:8484"
			r.AddCookie(f.c)
			w := httptest.NewRecorder()
			f.s.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("cancelled preview: HTTP %d", w.Code)
			}
			if p := observed.newPlan; p == nil || p.OK || len(p.Text) != 0 || len(p.Problems) != 1 || p.Problems[0] != context.Canceled.Error() {
				t.Fatalf("real preflight did not preserve its cancellation refusal: %+v", p)
			}
			body := w.Body.String()
			if !strings.Contains(body, `id="builder-run" name="from" aria-invalid="true"`) {
				t.Error("cancelled preflight hid the empty required run choice")
			}
			if !strings.Contains(body, context.Canceled.Error()) {
				t.Error("run-choice error hid the original preflight refusal")
			}
			if strings.Contains(body, `id="builder-save"`) || strings.Contains(body, `name="step" value="save"`) {
				t.Error("cancelled preflight offered Save")
			}
			if after := builderDestinationFiles(t, filepath.Dir(f.proj)); !reflect.DeepEqual(before, after) {
				t.Error("cancelled preview changed the fixture files")
			}
		})
	}
}

func TestBuilderMissingRunErrorsDoNotDependOnPreflight(t *testing.T) {
	cases := []struct {
		name     string
		problems []string
	}{
		{"busy", []string{"busy, try again"}},
		{"deadline", []string{context.DeadlineExceeded.Error()}},
		{"folder", []string{"The project folder could not be checked."}},
		{"preset", []string{"Pick at least one preset: no-secrets."}},
		{"busy-and-preset", []string{"busy, try again", "Pick at least one preset: no-secrets."}},
	}
	for _, view := range []string{"simple", "full"} {
		for _, tc := range cases {
			t.Run(view+"/"+tc.name, func(t *testing.T) {
				p := &rules.NewPlan{Problems: tc.problems}
				errors := newBuilderErrors(p, view, "run")
				runErrors := 0
				for _, e := range errors {
					if e.Field == "builder-run" {
						runErrors++
					}
				}
				if runErrors != 1 || builderErrorText(errors, "builder-run") != "Choose a finished run first." {
					t.Errorf("empty required run errors = %+v, want one instruction on the run choice", errors)
				}
				for _, problem := range tc.problems {
					if strings.Contains(problem, "preset") {
						continue
					}
					found := false
					for _, e := range errors {
						found = found || e.Message == problem
					}
					if !found {
						t.Errorf("run instruction lost preflight refusal %q", problem)
					}
				}
			})
		}
	}
}
