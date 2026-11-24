// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Every proposal source uses held bytes at Save; the seam counts construction,
// while the unchanged compiler still revalidates the held candidate.
func TestBuilderSaveNeverBuildsProposalAgain(t *testing.T) {
	for _, mode := range []string{"blank", "raw-new", "preset", "run", "raw-edit", "structured", "blank-registry", "raw-new-registry", "preset-registry", "run-registry"} {
		t.Run(mode, func(t *testing.T) {
			registry := strings.HasSuffix(mode, "-registry")
			mode = strings.TrimSuffix(mode, "-registry")
			f := newFixture(t)
			if registry {
				f.s.Machine = config.Builtin()
				f.s.Machine.Home = f.s.Home
				f.s.Machine.Registry.Value = filepath.Join(f.s.Home, ".config", "tego")
			}
			built := 0
			f.s.proposalBuilt = func(string) { built++ }
			var save func() error
			var path string
			var want []byte
			if mode == "raw-edit" || mode == "structured" {
				c := f.ref(t, f.contract)
				path = c.Path
				if mode == "raw-edit" {
					req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# retained\n")}
					p, err := f.s.PlanRaw(t.Context(), req)
					if err != nil || p.Err != "" {
						t.Fatalf("Preview: %+v %v", p, err)
					}
					req.Ack = p.Ack
					want = bytes.Clone(p.text)
					save = func() error { _, err := f.s.ApplyRaw(t.Context(), req); return err }
				} else {
					req := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}}
					p, err := f.s.PlanChange(t.Context(), req)
					if err != nil || p.Err != "" {
						t.Fatalf("Preview: %+v %v", p, err)
					}
					req.Ack = p.Ack
					want = bytes.Clone(p.text)
					save = func() error { _, err := f.s.ApplyChange(t.Context(), req); return err }
				}
			} else {
				req := NewReq{Dir: f.newProject(t, "retained"), Name: "retained", Command: "sh", Registry: registry, PrepareDirectories: registry}
				switch mode {
				case "blank":
					req.Blank = true
				case "raw-new":
					req.Text = []byte("version: 0\nname: retained\ncommand: [sh]\n")
				case "preset":
					req.Presets = []string{"no-secrets"}
				case "run":
					req.FromRun = "r-aaaaaaaa-0000000000001-learnx"
					f.writeRun(t, req.FromRun, f.contract, 9)
				}
				p, err := f.s.PlanNew(t.Context(), req)
				if err != nil || !p.OK {
					t.Fatalf("Preview: %+v %v", p, err)
				}
				path = p.File
				want = bytes.Clone(p.Text)
				save = func() error { _, err := f.s.CreateNew(t.Context(), req, p.Base); return err }
			}
			previewCalls := built
			if previewCalls != 1 {
				t.Fatalf("Preview built %d proposals", previewCalls)
			}
			saveErr := save()
			if built != previewCalls {
				t.Fatalf("Save rebuilt proposal: before %d after %d", previewCalls, built)
			}
			if saveErr != nil {
				t.Fatalf("Save: %v", saveErr)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("Save changed reviewed bytes: %v", err)
			}
		})
	}
}

func TestBuilderLostReviewedDraftRefuses(t *testing.T) {
	for _, mode := range []string{"new", "raw", "structured"} {
		for _, loss := range []string{"restart", "expiry", "session"} {
			t.Run(mode+"/"+loss, func(t *testing.T) {
				f := newFixture(t)
				now := time.Now()
				f.s.Now = func() time.Time { return now }
				c := f.ref(t, f.contract)
				nr := NewReq{Dir: f.newProject(t, "lost"), Name: "lost", Blank: true, Session: "one"}
				rr := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# edit\n"), Session: "one"}
				cr := ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []Edit{{"remove", "exec.allow", "cat"}}, Session: "one"}
				var ack string
				switch mode {
				case "new":
					p, _ := f.s.PlanNew(t.Context(), nr)
					if !p.OK {
						t.Fatal(p.Problems)
					}
					ack = p.Base
				case "raw":
					p, _ := f.s.PlanRaw(t.Context(), rr)
					if p.Err != "" {
						t.Fatal(p.Err)
					}
					rr.Ack = p.Ack
				case "structured":
					p, _ := f.s.PlanChange(t.Context(), cr)
					if p.Err != "" {
						t.Fatal(p.Err)
					}
					cr.Ack = p.Ack
				}
				switch loss {
				case "restart":
					f.s.drafts.entries = nil
				case "expiry":
					now = now.Add(draftTTL)
				case "session":
					nr.Session = "two"
					rr.Session = "two"
					cr.Session = "two"
				}
				built := 0
				f.s.proposalBuilt = func(string) { built++ }
				var err error
				switch mode {
				case "new":
					_, err = f.s.CreateNew(t.Context(), nr, ack)
				case "raw":
					_, err = f.s.ApplyRaw(t.Context(), rr)
				case "structured":
					_, err = f.s.ApplyChange(t.Context(), cr)
				}
				if !errors.Is(err, ErrReviewGone) || err.Error() != ErrReviewGone.Error() {
					t.Fatalf("lost draft: %v", err)
				}
				if built != 0 {
					t.Fatal("lost draft rebuilt")
				}
				if f.text(t) != baseText {
					t.Fatal("lost draft wrote")
				}
				if _, err := os.Stat(nr.Dir + "/agent.yaml"); !os.IsNotExist(err) {
					t.Fatal("lost new draft wrote")
				}
			})
		}
	}
}

func TestBuilderReviewedDraftBoundsAndCopies(t *testing.T) {
	f := newFixture(t)
	now := time.Now()
	f.s.Now = func() time.Time { return now }
	req := NewReq{Dir: f.newProject(t, "bounded"), Name: "bounded", Blank: true}
	p, _ := f.s.PlanNew(t.Context(), req)
	if !p.OK {
		t.Fatal(p.Problems)
	}
	ack := p.Base
	p.Text[0] = '!'
	r, err := f.s.reviewedDraft("", ack)
	if err != nil || r.New.Text[0] == '!' {
		t.Fatal("review shares caller bytes")
	}
	r.New.Text[0] = '?'
	r, err = f.s.reviewedDraft("", ack)
	if err != nil || r.New.Text[0] == '?' {
		t.Fatal("restores share bytes")
	}
	for i := 0; i < maxDrafts+1; i++ {
		now = now.Add(time.Second)
		f.s.drafts.Lock()
		f.s.drafts.put(strings.Repeat("x", i+1), draftState{payload: []byte("bounded"), at: now})
		f.s.drafts.Unlock()
	}
	if len(f.s.drafts.entries) > maxDrafts {
		t.Fatal("count exceeded")
	}
	if _, err := f.s.reviewedDraft("", ack); !errors.Is(err, ErrReviewGone) {
		t.Fatal("oldest review not evicted")
	}
	f.s.drafts.entries = nil
	for i := 0; i < 10; i++ {
		f.s.drafts.put(strings.Repeat("y", i+1), draftState{payload: make([]byte, maxDraftBytes), at: now})
	}
	total := 0
	for _, v := range f.s.drafts.entries {
		total += v.size
	}
	if total > maxDraftStoreBytes {
		t.Fatal("total byte bound exceeded")
	}
	tooBig := reviewedDraft{Binding: reviewedWrite{ReviewID: newDraftID()}, Input: make([]byte, maxDraftBytes)}
	if err := f.s.keepReview("", f.s.reviewAck(tooBig.Binding), tooBig); !errors.Is(err, ErrReviewGone) {
		t.Fatal("oversize review accepted")
	}
	now = now.Add(draftTTL)
	f.s.drafts.expire(now)
	if len(f.s.drafts.entries) != 0 {
		t.Fatal("expired entries retained")
	}
}

// Retention does not turn compilation into a preview-only guard.
func TestBuilderHeldBytesStillCompileAtSave(t *testing.T) {
	f := newFixture(t)
	req := NewReq{Dir: f.newProject(t, "recompile"), Name: "recompile", Blank: true}
	p, _ := f.s.PlanNew(t.Context(), req)
	if !p.OK {
		t.Fatal(p.Problems)
	}
	f.s.Compile = nil
	f.s.Check = nil
	f.s.Machine = config.Builtin()
	f.s.Machine.Home = f.s.Home
	f.s.Machine.Registry.Value = "/changed-compiled-context"
	if _, err := f.s.CreateNew(t.Context(), req, p.Base); err == nil {
		t.Fatal("changed compiled context saved")
	}
}

// Repeated previews with identical bytes are separate retained drafts. A later
// review must not replace the proposal selected by an earlier native Save form.
func TestBuilderRepeatedReviewKeepsEarlierProposal(t *testing.T) {
	f := newFixture(t)
	req := NewReq{Dir: f.newProject(t, "repeated"), Name: "repeated", Text: []byte("version: 0\nname: repeated\ncommand: [sh]\n"), Session: "viewer"}
	first, err := f.s.PlanNew(t.Context(), req)
	if err != nil || !first.OK {
		t.Fatalf("first Preview: %v %+v", err, first)
	}
	next, err := f.s.PlanNew(t.Context(), req)
	if err != nil || !next.OK {
		t.Fatalf("next Preview: %v %+v", err, next)
	}
	if first.Base == next.Base || first.ReviewID == next.ReviewID || len(first.ReviewID) != 48 || first.ReviewID == first.Draft {
		t.Fatal("equal new Previews did not mint independent review identities")
	}
	if _, ok := f.s.drafts.entries[first.ReviewID]; !ok {
		t.Fatal("review not stored under its identity")
	}
	req.Draft = first.Draft
	if _, err := f.s.CreateNew(t.Context(), req, first.Base); err != nil {
		t.Fatalf("later review invalidated earlier reviewed proposal: %v", err)
	}
	got, err := os.ReadFile(first.File)
	if err != nil || !bytes.Equal(got, first.Text) {
		t.Fatalf("earlier reviewed bytes changed: %v", err)
	}
}
