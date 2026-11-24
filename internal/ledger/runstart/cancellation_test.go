// SPDX-License-Identifier: Apache-2.0

package runstart

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

type cancellingRepository struct {
	reader *ledger.Reader
	cancel context.CancelFunc
	lists  int
	opens  int
}

func (r *cancellingRepository) List(context.Context) ([]record.RunRef, error) {
	r.lists++
	return []record.RunRef{{ID: "r-fixture"}}, nil
}

func (r *cancellingRepository) Open(context.Context, string) (*ledger.Reader, error) {
	r.opens++
	r.cancel()
	return r.reader, nil
}

func TestLoadCancellationBeforeList(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repo := &cancellingRepository{cancel: cancel}
	s, problems := loadFrom(ctx, "fixture", repo, 10, 4096)
	if repo.lists != 0 || repo.opens != 0 {
		t.Errorf("cancelled discovery opened another stage: lists %d opens %d", repo.lists, repo.opens)
	}
	if len(s.Runs) != 0 || len(problems) != 1 || problems[0] != context.Canceled {
		t.Fatalf("cancelled discovery: snapshot %+v, problems %v", s, problems)
	}
}

func TestLoadCancellationAfterOpen(t *testing.T) {
	dir := t.TempDir()
	// If load begins Iter after Open returns past cancellation, this invalid
	// record produces a parse error instead of the cancellation finding.
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() }) // also closes it if an assertion fails before discovery owns it
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repo := &cancellingRepository{reader: reader, cancel: cancel}
	s, problems := loadFrom(ctx, dir, repo, 10, 4096)
	if repo.lists != 1 || repo.opens != 1 {
		t.Errorf("wrong stand-in stage counts: lists %d opens %d", repo.lists, repo.opens)
	}
	if len(s.Runs) != 0 || len(problems) != 1 || problems[0] != context.Canceled {
		t.Fatalf("read began after cancellation: snapshot %+v, problems %v", s, problems)
	}
}
