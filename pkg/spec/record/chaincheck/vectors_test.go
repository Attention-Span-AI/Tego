// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
	chainvectors "github.com/attention-span-ai/tego/spec/record/v1/vectors/chain"
)

// TestSharedChainVectors runs Check, the pure chain check in its integrity scope, over every shared vector
// (spec/record/v1/vectors/chain) and holds it to the vector's handwritten expectation. rust/tego-record runs the same
// files.
func TestSharedChainVectors(t *testing.T) {
	vs, err := chainvectors.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) < 30 {
		t.Fatalf("%d vectors, want 30 or more", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			events, hasEvents, err := v.Events()
			if err != nil {
				t.Fatal(err)
			}
			anchor, given, absent, err := v.Anchor()
			if err != nil {
				t.Fatal(err)
			}
			rep, cerr := chaincheck.Check(chaincheck.Input{Dir: v.Dir, Events: events, NoEvents: !hasEvents,
				AnchorGiven: given, Anchor: anchor, NoAnchorFile: absent})
			if v.Finding != nil {
				t.Logf("%s: known finding %s: %s", v.File, v.Finding.Label, v.Finding.Why)
			}
			for _, d := range v.Judge(v.GoExpect(), Result(rep, cerr, nil)) {
				t.Errorf("%s (%s): %s; err %v", v.File, v.Rule, d, cerr)
			}
		})
	}
}

// Result is a check's answer in the vectors' terms.
func Result(rep chaincheck.Report, err error, notExist func(error) bool) chainvectors.Result {
	verdict, reason := chaincheck.Reason(rep, err, notExist)
	return chainvectors.Result{Verdict: verdict, Reason: reason, AtLine: rep.AtLine, Line: rep.BrokenLine,
		Lines: rep.Lines, Head: rep.Head, Anchored: rep.Anchored, TornBytes: rep.TornBytes, Newer: rep.Newer}
}
