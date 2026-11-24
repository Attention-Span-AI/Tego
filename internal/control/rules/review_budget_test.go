// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/draftcompile"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

type delayedPublication struct{ localWriter }

func publicationDelay(ctx context.Context) error {
	time.Sleep(draftcompile.Budget + 25*time.Millisecond)
	return ctx.Err()
}
func (w delayedPublication) Create(ctx context.Context, path string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	if err := publicationDelay(ctx); err != nil {
		return nil, err
	}
	return w.localWriter.Create(ctx, path, text, c)
}
func (w delayedPublication) Replace(ctx context.Context, path, base string, text []byte, c rulefile.Change) (*rulefile.Entry, error) {
	if err := publicationDelay(ctx); err != nil {
		return nil, err
	}
	return w.localWriter.Replace(ctx, path, base, text, c)
}

func TestBuilderCompilationBudgetExcludesPublication(t *testing.T) {
	for _, mode := range []string{"new", "existing"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.s.Writer = delayedPublication{localWriter{f.s.guard()}}
			if mode == "new" {
				req := NewReq{Dir: f.newProject(t, "slow-publication"), Name: "slow-publication", Blank: true}
				p, err := f.s.PlanNew(t.Context(), req)
				if err != nil || !p.OK {
					t.Fatalf("preview: %+v %v", p, err)
				}
				if _, err := f.s.CreateNew(t.Context(), req, p.Base); err != nil {
					t.Fatalf("publication consumed compilation budget: %v", err)
				}
			} else {
				c := f.ref(t, f.contract)
				req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(f.text(t) + "\n# reviewed edit\n")}
				p, err := f.s.PlanRaw(t.Context(), req)
				if err != nil || p.Err != "" {
					t.Fatalf("preview: %+v %v", p, err)
				}
				req.Ack = p.Ack
				if _, err := f.s.ApplyRaw(t.Context(), req); err != nil {
					t.Fatalf("publication consumed compilation budget: %v", err)
				}
			}
		})
	}
}
