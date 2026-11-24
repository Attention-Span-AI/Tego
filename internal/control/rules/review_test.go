// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestBuilderReviewBindsDestination(t *testing.T) {
	f := newFixture(t)
	a := f.newProject(t, "review-a")
	b := f.newProject(t, "review-b")
	req := NewReq{Dir: a, Name: "review", Text: []byte("version: 0\nname: review\ncommand: [sh]\n")}
	p, _ := f.s.PlanNew(context.Background(), req)
	req.Dir = b
	if got, err := f.s.CreateNew(context.Background(), req, p.Base); err == nil {
		t.Fatalf("changed destination saved: %+v", got)
	}
	for _, dir := range []string{a, b} {
		if _, err := os.Lstat(filepath.Join(dir, NewFile)); !os.IsNotExist(err) {
			t.Fatalf("file created at %s: %v", dir, err)
		}
	}
}

func TestBuilderReviewBindsDirectoryIdentity(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "link"}[link], func(t *testing.T) {
			f := newFixture(t)
			dir := f.newProject(t, "review-dir")
			req := NewReq{Dir: dir, Name: "review", Text: []byte("version: 0\nname: review\ncommand: [sh]\n")}
			p, _ := f.s.PlanNew(context.Background(), req)
			if err := os.Rename(dir, dir+"-old"); err != nil {
				t.Fatal(err)
			}
			if link {
				target := f.newProject(t, "redirect")
				if err := os.Symlink(target, dir); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.CreateNew(context.Background(), req, p.Base); err == nil {
				t.Fatal("saved beneath another directory inode")
			}
			if _, err := os.Lstat(filepath.Join(dir, NewFile)); !os.IsNotExist(err) {
				t.Fatal("published at replacement")
			}
		})
	}
}

func TestBuilderNewReviewBindsDependencyBytes(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "review-deps")
	profiles := f.newProject(t, "profiles")
	profile := filepath.Join(profiles, "base.yaml")
	writeFile(t, profile, "# first review\nnet:\n  allow: []\n")
	f.s.Compile = nil
	f.s.Check = nil
	f.s.Machine = config.Builtin()
	f.s.Machine.Home = f.s.Home
	f.s.Machine.Profiles.Value = profiles
	req := NewReq{Dir: dir, Name: "review", Text: []byte("version: 0\nname: review\nextends: base\ncommand: [sh]\n")}
	p, _ := f.s.PlanNew(context.Background(), req)
	if !p.OK {
		t.Fatalf("preview: %v %v", p.Problems, p.Diagnostics)
	}
	// Only a comment differs: the dependency snapshot, not just the merged result, must bind it.
	writeFile(t, profile, "# edited after review\nnet:\n  allow: []\n")
	if _, err := f.s.CreateNew(context.Background(), req, p.Base); err == nil {
		t.Fatal("saved with changed dependency bytes")
	}
	next, _ := f.s.PlanNew(context.Background(), req)
	if !next.OK || next.Base == p.Base {
		t.Fatalf("new preview not acknowledged separately: %v %v", next.Problems, next.Diagnostics)
	}
}

func TestBuilderNewReviewBindsConfigLayer(t *testing.T) {
	f := newFixture(t)
	if err := os.Chmod(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	dir := f.newProject(t, "review-config")
	layer := filepath.Join(f.dir, "machine.yaml")
	writeFile(t, layer, "version: 0\n")
	m, _, err := config.LoadSources(config.Sources{EnvFile: layer}, f.s.Home, os.Geteuid(), config.TrustAbort)
	if err != nil {
		t.Fatal(err)
	}
	f.s.Compile = nil
	f.s.Check = nil
	f.s.Machine = m
	req := NewReq{Dir: dir, Name: "review", Text: []byte("version: 0\nname: review\ncommand: [sh]\n")}
	p, _ := f.s.PlanNew(context.Background(), req)
	if !p.OK {
		t.Fatalf("preview %v %v", p.Problems, p.Diagnostics)
	}
	writeFile(t, layer, "version: 0\n# changed layer\n")
	if _, err := f.s.CreateNew(context.Background(), req, p.Base); err == nil {
		t.Fatal("saved with changed config layer")
	}
	next, _ := f.s.PlanNew(context.Background(), req)
	if !next.OK || next.Base == p.Base {
		t.Fatalf("new config preview %v %v", next.Problems, next.Diagnostics)
	}
	if strings.Contains(strings.Join(next.Diagnostics, " "), "private-value") {
		t.Fatal("diagnostic leaked value")
	}
}

func TestBuilderNewCompilationHonoursCancellation(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "cancel-draft")
	f.s.Compile = nil
	f.s.Check = nil
	f.s.Machine = config.Builtin()
	f.s.Machine.Home = f.s.Home
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := f.s.PlanNew(ctx, NewReq{Dir: dir, Name: "cancel-draft", Text: []byte("version: 0\nname: cancel-draft\ncommand: [sh]\nnet:\n  allow: [one.example:443,two.example:443]\n")})
	if err == nil && p.OK {
		t.Fatal("cancelled draft compiled to an enabled Save")
	}
}

// applyReviewed carries the server's hidden review value for a narrowing; explicit
// widening acknowledgement tests call ApplyChange themselves.
func (f *fixture) applyReviewed(t *testing.T, ctx context.Context, req ChangeReq) (*Applied, error) {
	t.Helper()
	req.Ack = changeAck(t, f.s, req)
	return f.s.ApplyChange(ctx, req)
}

func TestBuilderNarrowingBindsReview(t *testing.T) {
	f := newFixture(t)
	c := f.ref(t, f.contract)
	req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}
	p, err := f.s.PlanChange(t.Context(), req)
	if err != nil || p.Err != "" || p.NeedsAck {
		t.Fatalf("narrowing: %+v %v", p, err)
	}
	if _, err := f.s.ApplyChange(t.Context(), req); err == nil {
		t.Fatal("unreviewed narrowing saved")
	}
	req.Ack = p.Ack
	old := f.proj + "-old"
	if err := os.Rename(f.proj, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(f.proj, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, f.contract, baseText)
	if _, err := f.s.ApplyChange(t.Context(), req); err == nil {
		t.Fatal("narrowing saved beneath a different directory inode")
	}
	if got := f.text(t); got != baseText {
		t.Fatal("stale narrowing published")
	}
}

func TestBuilderExistingReviewBindsDependencyBytes(t *testing.T) {
	f := newFixture(t)
	profiles := f.newProject(t, "existing-profiles")
	profile := filepath.Join(profiles, "base.yaml")
	writeFile(t, profile, "# first review\nnet: {allow: []}\n")
	f.s.Compile = nil
	f.s.Check = nil
	f.s.Machine = config.Builtin()
	f.s.Machine.Home = f.s.Home
	f.s.Machine.Profiles.Value = profiles
	head := "version: 0\nname: tester\nextends: base\ncommand: [sh]\n"
	writeFile(t, f.contract, head)
	c := f.ref(t, f.contract)
	req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(head + "limits: {wall: 2h}\n")}
	p, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || p.Err != "" {
		t.Fatalf("preview: %+v %v", p, err)
	}
	req.Ack = p.Ack
	writeFile(t, profile, "# changed after review\nnet: {allow: []}\n")
	if _, err := f.s.ApplyRaw(t.Context(), req); err == nil {
		t.Fatal("saved with changed inherited bytes")
	}
	next, err := f.s.PlanRaw(t.Context(), req)
	if err != nil || next.Err != "" || next.Ack == p.Ack {
		t.Fatalf("fresh inherited preview: %+v %v", next, err)
	}
	if got := f.text(t); got != head {
		t.Fatal("stale replacement published")
	}
}

func TestBuilderReviewedRealEditsSave(t *testing.T) {
	for _, mode := range []string{"structured", "full"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.s.Compile = nil
			f.s.Check = nil
			f.s.Machine = config.Builtin()
			f.s.Machine.Home = f.s.Home
			head := "version: 0\nname: tester\ncommand: [sh]\nexec: {allow: [sh, cat]}\n"
			writeFile(t, f.contract, head)
			c := f.ref(t, f.contract)
			if mode == "structured" {
				req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}
				p, err := f.s.PlanChange(t.Context(), req)
				if err != nil || p.Err != "" {
					t.Fatalf("preview: %+v %v", p, err)
				}
				req.Ack = p.Ack
				if _, err := f.s.ApplyChange(t.Context(), req); err != nil {
					t.Fatal(err)
				}
			} else {
				req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(head + "limits: {wall: 2h}\n")}
				p, err := f.s.PlanRaw(t.Context(), req)
				if err != nil || p.Err != "" {
					t.Fatalf("preview: %+v %v", p, err)
				}
				req.Ack = p.Ack
				if _, err := f.s.ApplyRaw(t.Context(), req); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestBuilderEmptyAuthenticatedDraftIsRefused(t *testing.T) {
	f := newFixture(t)
	dir := f.newProject(t, "empty-draft")
	req := NewReq{Dir: dir, Name: "empty-draft", Presets: []string{"no-secrets"}, Command: "sh", Session: "session"}
	p, err := f.s.PlanNew(t.Context(), req)
	if err != nil || !p.OK {
		t.Fatalf("source preview: %+v %v", p, err)
	}
	req.Draft = p.Draft
	req.Text = []byte{}
	next, err := f.s.PlanNew(t.Context(), req)
	if err != nil || next.OK || len(next.Problems) == 0 {
		t.Fatalf("empty posted draft silently recomposed: %+v %v", next, err)
	}
	if _, err := f.s.CreateNew(t.Context(), req, p.Base); err == nil {
		t.Fatal("empty editor saved the original source")
	}
}
