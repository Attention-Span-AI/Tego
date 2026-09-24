// SPDX-License-Identifier: Apache-2.0

package viewtest

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/drift"
	"github.com/attention-span-ai/tego/internal/check/events"
	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/check/status"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func FuzzViews(f *testing.F) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	for _, l := range bytes.SplitAfter(data, []byte("\n")) {
		if len(l) > 0 {
			f.Add(l)
		}
	}
	f.Add(data)
	f.Fuzz(func(t *testing.T, b []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		open := func() *ledger.Reader {
			r, err := ledger.OpenReader(dir)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		r := open()
		_, _ = status.Derive(r, true, time.Now(), 0)
		r.Close()
		r = open()
		_, _ = measure.ComputeAt(t.Context(), r, nil, 1<<62)
		r.Close()
		r = open()
		_, _ = drift.ComputeCtx(t.Context(), r, &agent.RuleTable{})
		r.Close()
		r = open()
		_, _ = events.TableOf(t.Context(), io.Discard, r, r.Entries(), events.Filter{})
		r.Close()
		r = open()
		_, _ = events.JSONOf(t.Context(), io.Discard, r, r.Entries(), events.Filter{})
		r.Close()
	})
}
