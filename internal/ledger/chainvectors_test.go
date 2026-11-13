// SPDX-License-Identifier: Apache-2.0

package ledger_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
	chainvectors "github.com/attention-span-ai/tego/spec/record/v1/vectors/chain"
)

// TestSharedChainVectorsOnDisk runs VerifyRunDirChain, the reader over real files, on every shared vector
// (spec/record/v1/vectors/chain) written into a run directory, so the file side agrees with the pure check
// (chaincheck.Check) the vectors also hold.
func TestSharedChainVectorsOnDisk(t *testing.T) {
	vs, err := chainvectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "runs", v.Dir)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			events, has, err := v.Events()
			if err != nil {
				t.Fatal(err)
			}
			if has {
				if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), events, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			anchorBytes, given, absent, err := v.Anchor()
			if err != nil {
				t.Fatal(err)
			}
			var anchor ledger.ChainAnchor
			if given {
				path := filepath.Join(root, "chain.log")
				if !absent {
					if err := os.WriteFile(path, anchorBytes, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				anchor = ledger.NewFileChainAnchor(path)
			}
			rep, verr := ledger.VerifyRunDirChain(context.Background(), dir, anchor)
			verdict, reason := chaincheck.Reason(rep, verr, func(err error) bool { return errors.Is(err, os.ErrNotExist) })
			got := chainvectors.Result{Verdict: verdict, Reason: reason, AtLine: rep.AtLine, Line: rep.BrokenLine,
				Lines: rep.Lines, Head: rep.Head, Anchored: rep.Anchored, TornBytes: rep.TornBytes, Newer: rep.Newer}
			for _, d := range v.Judge(v.GoExpect(), got) {
				t.Errorf("%s (%s): %s; err %v", v.File, v.Rule, d, verr)
			}
		})
	}
}
