// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Separate authenticated preset drafts can be edited to identical final YAML.
// Their retained setup actions still have to be the ones the person reviewed.
func TestBuilderReviewBindsRetainedSetupMetadata(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "setup-review")
	text := []byte("version: 0\nname: setup-review\ncommand: [sh]\n")
	req := NewReq{Dir: dir, Name: "setup-review", Text: text, Session: "viewer"}
	context := &NewPlan{Dir: dir, Name: req.Name}
	first := &setup.Result{Contract: text, MakeDirs: []string{filepath.Join(dir, "first")}, Ignore: []string{"first/"}}
	req.Draft = f.s.keepDraft(req.Session, first, context)
	p, err := f.s.PlanNew(t.Context(), req)
	if err != nil || !p.OK {
		t.Fatalf("first preview: %v %v", err, p.Problems)
	}
	second := &setup.Result{Contract: text, MakeDirs: []string{filepath.Join(dir, "second")}, Ignore: []string{"second/"}}
	req.Draft = f.s.keepDraft(req.Session, second, context)
	next, err := f.s.PlanNew(t.Context(), req)
	if err != nil || !next.OK {
		t.Fatalf("second preview: %v %v", err, next.Problems)
	}
	if next.Base == p.Base {
		t.Error("different retained setup actions share a review binding")
	}
	if _, err := f.s.CreateNew(t.Context(), req, p.Base); !errors.Is(err, ErrStale) {
		t.Fatalf("substituted setup metadata: %v", err)
	}
	for _, name := range []string{"first", "second", NewFile} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("unreviewed setup created %s: %v", name, err)
		}
	}
	if _, err := f.s.CreateNew(t.Context(), req, next.Base); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, "second")); err != nil || !st.IsDir() {
		t.Fatalf("reviewed setup not created: %v", err)
	}
}

// A server-held learned draft must retain the registry's independent own-write
// refusal after Check, even when a test compiler accepts the candidate.
func TestBuilderDraftRetainsRegistryWriteGuard(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "learned-writes")
	writes := filepath.Join(dir, "out")
	registry := filepath.Join(writes, "registry")
	f.s.Machine = config.Builtin()
	f.s.Machine.Home = f.s.Home
	f.s.Machine.Registry.Value = registry
	text := []byte("version: 0\nname: learned-writes\ncommand: [sh]\nfs: {write: ['./out/']}\n")
	req := NewReq{Dir: dir, Name: "learned-writes", Registry: true, Text: text, Session: "viewer"}
	retained := &NewPlan{Dir: dir, Name: req.Name, Registry: true, writeDirs: []string{writes}}
	req.Draft = f.s.keepDraft(req.Session, &setup.Result{Contract: text}, retained)
	p, err := f.s.PlanNew(t.Context(), req)
	if err != nil {
		t.Fatalf("fixture preview: %v %v", err, p.Problems)
	}
	if p.OK || !strings.Contains(strings.Join(p.Problems, " "), "own write entry") {
		t.Error("restored draft lost the preview's registry own-write refusal")
	}
	if _, err := f.s.CreateNew(t.Context(), req, p.Base); err == nil {
		t.Fatal("restored draft lost registry own-write refusal")
	}
	if _, err := os.Lstat(filepath.Join(registry, "agents", req.Name+".yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("own-writable registry file created: %v", err)
	}
}

// The withheld destinations belong to the authenticated server draft. Restoring
// must neither trust a replacement request list nor share mutable plan slices.
func TestBuilderDraftRetainsServerWithheldDestinations(t *testing.T) {
	f := newFixture(t)
	text := []byte("version: 0\nname: learned\ncommand: [sh]\n")
	p := &NewPlan{Dir: f.newProject(t, "withheld"), Name: "learned", Withheld: []string{"127.0.0.1:48802"}}
	req := NewReq{Dir: p.Dir, Name: p.Name, Text: text, Session: "viewer", Withhold: []string{"client.example:443"}}
	req.Draft = f.s.keepDraft(req.Session, &setup.Result{Contract: text}, p)
	p.Withheld[0] = "changed-after-keep"
	for i := 0; i < 2; i++ {
		restored := &NewPlan{Dir: req.Dir, Name: req.Name}
		if _, err := f.s.restoreDraft(req, restored); err != nil {
			t.Fatal(err)
		}
		if len(restored.Withheld) != 1 || restored.Withheld[0] != "127.0.0.1:48802" {
			t.Fatalf("restored withheld destinations: %v", restored.Withheld)
		}
		restored.Withheld[0] = "changed-after-restore"
	}
}
