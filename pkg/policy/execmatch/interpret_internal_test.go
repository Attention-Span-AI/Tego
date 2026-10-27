// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"strconv"
	"testing"
)

// TestBuilderOverflowFailsClosed is the invariant of the interpretation bound (ADR 0048 (2)): the builder keeps at
// most maxInterpretations invocations, and it overflows exactly when a distinct one past the bound was not kept. A
// duplicate past the bound is no overflow (nothing was lost), and an empty tool is never an invocation.
func TestBuilderOverflowFailsClosed(t *testing.T) {
	for n := 0; n <= maxInterpretations+3; n++ {
		var b builder
		for i := 0; i < n; i++ {
			b.add("t"+strconv.Itoa(i), nil, ViaName, nil)
		}
		b.add("", nil, ViaName, nil)
		if n > 0 {
			b.add("t0", nil, ViaImage, nil) // a duplicate of a kept one
		}
		if len(b.out) > maxInterpretations {
			t.Fatalf("%d adds kept %d invocations, past the bound %d", n, len(b.out), maxInterpretations)
		}
		if want := n > maxInterpretations; b.overflow != want {
			t.Errorf("%d distinct adds: overflow %v, want %v (kept %d)", n, b.overflow, want, len(b.out))
		}
	}
}

// TestInterpretationsOverflowSentinel: an exec whose reading yields more distinct interpretations than the bound (here
// a #! chain of 40 stages, each named differently, which Facts allows though the kernel stops at five) ends with the
// ViaOverflow sentinel, and Decide refuses it command-unresolved via overflow, even with a ruled tool among the
// stages past the bound, which a silently dropped interpretation read as unmatched. A loaded program whose own
// reading overflows passes the sentinel on (the loader re-adds the program's interpretations).
func TestInterpretationsOverflowSentinel(t *testing.T) {
	rm := &Row{Tool: "rm", Root: &Level{Opts: []Opt{{Name: "recursive", Short: "rR", Long: []string{"recursive"}}}, Syntax: Syntax{Clusters: true, LongEquals: true}}}
	bb := &Row{Tool: "busybox", Multicall: true, Root: &Level{}}
	rows := NewRows(rm, bb)
	deny, err := Parse("rm -r", ListDeny, rows)
	if err != nil {
		t.Fatal(err)
	}
	ix := NewIndex(rows, []*Pattern{deny}, IndexOptions{})
	f := Facts{Requested: "s", Image: "s", Argv0: "s", Path: "/w/s", Argv: []string{"s", "x"}, ArgvComplete: true, Form: FormScript}
	for i := 0; i < 40; i++ {
		f.Interp = append(f.Interp, Stage{Path: "/w/t" + strconv.Itoa(i)})
	}
	f.Interp = append(f.Interp, Stage{Path: "/usr/bin/rm", Arg: "-rf"})
	invs := ix.Interpretations(&f)
	if len(invs) == 0 || invs[len(invs)-1].Via != ViaOverflow {
		t.Fatalf("40 stages: no overflow sentinel among %d interpretations", len(invs))
	}
	if len(invs) > maxInterpretations+1 {
		t.Errorf("%d interpretations, past the bound and its one sentinel", len(invs))
	}
	r := ix.Decide(&f)
	if r.Outcome != OutcomeRefused || !r.Overflow || r.Rule() != RuleCommandUnresolved || r.Via != ViaOverflow {
		t.Errorf("40 stages then #!/usr/bin/rm -rf: %s %q via %s, want refused %s via overflow", r.Outcome, r.Rule(), r.Via, RuleCommandUnresolved)
	}

	// A directly-invoked loader's program is read by a nested Interpretations, whose own bound can overflow: busybox
	// nested past maxDispatch under the loader. Its sentinel names no tool, so re-adding it as one of the loader's
	// invocations dropped it; it is kept now, and the exec fails closed even where the outer pass, which re-dispatches
	// the program's invocations from depth 0, would have resolved the chain.
	argv := []string{"/bin/busybox"}
	for i := 0; i < maxDispatch+2; i++ {
		argv = append(argv, "busybox")
	}
	argv = append(argv, "true")
	lf := Facts{Requested: "ld-linux-x86-64.so.2", Image: "ld-linux-x86-64.so.2", Argv0: "ld", Argv: append([]string{"ld"}, argv...),
		ArgvComplete: true, Loaded: &Loaded{Path: "/bin/busybox", Image: "busybox", Argv: argv}}
	if inner := lf.loadedFacts(); !hasSentinel(ix.Interpretations(&inner)) {
		t.Fatalf("the loaded program's own reading did not overflow: the case proves nothing")
	}
	if !hasSentinel(ix.Interpretations(&lf)) {
		t.Errorf("a loaded program's overflow sentinel was dropped by the loader's pass")
	}
	if r := ix.Decide(&lf); r.Outcome != OutcomeRefused || r.Rule() != RuleCommandUnresolved {
		t.Errorf("ld busybox x%d true: %s %q, want refused %s", maxDispatch+3, r.Outcome, r.Rule(), RuleCommandUnresolved)
	}
}

// hasSentinel reports whether interpretations end in the ViaOverflow sentinel.
func hasSentinel(invs []Invocation) bool {
	return len(invs) > 0 && invs[len(invs)-1].Via == ViaOverflow
}
