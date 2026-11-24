// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Separate request sessions must retain independent, single-use reviews in the
// serving process even though each path operation reconstructs its helper service.
func TestRemoteBuilderReviewAcrossRequests(t *testing.T) {
	f := newFixture(t)
	m := config.Builtin()
	m.Home = f.s.Home
	s := &Service{Ledger: f.s.Ledger, Home: f.s.Home, Machine: m, PATH: "/usr/bin:/bin"}
	if !s.remote() {
		t.Fatal("fixture bypasses production transport")
	}
	dir := f.newProject(t, "remote-review")
	req := NewReq{Dir: dir, Name: "remote-review", Text: []byte("version: 0\nname: remote-review\ncommand: [sh]\n"), Session: "browser"}
	preview := func(req NewReq) *NewPlan {
		t.Helper()
		ctx, closeSession := contracts.WithHelperSession(context.Background())
		defer closeSession()
		p, err := s.PlanNew(ctx, req)
		if err != nil || p == nil || !p.OK {
			t.Fatalf("preview: %+v %v", p, err)
		}
		return p
	}
	first, second := preview(req), preview(req)
	if first.Base == second.Base || first.ReviewID == "" {
		t.Fatal("equal previews lost independent identities")
	}
	readonly := req
	readonly.PreviewOnly = true
	read := preview(readonly)
	if read.Base != "" || read.ReviewID != "" || read.Draft != "" {
		t.Fatal("read-only preview retained credentials")
	}
	ctx, closeSession := contracts.WithHelperSession(context.Background())
	created, err := s.CreateNew(ctx, req, first.Base)
	closeSession()
	if err != nil || created == nil {
		t.Fatalf("save across requests: %+v %v", created, err)
	}
	if _, err := os.Stat(filepath.Join(dir, NewFile)); err != nil {
		t.Fatal(err)
	}
	ctx, closeSession = contracts.WithHelperSession(context.Background())
	_, err = s.CreateNew(ctx, req, first.Base)
	closeSession()
	if !errors.Is(err, ErrReviewGone) {
		t.Fatalf("consumed review replay: %v", err)
	}
}
