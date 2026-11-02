// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// withFDBudget gives every Prepare of the test the budget b.
func withFDBudget(t *testing.T, b FDBudget) {
	t.Helper()
	prev := readFDBudget
	readFDBudget = func() (FDBudget, error) { return b, nil }
	t.Cleanup(func() { readFDBudget = prev })
}

// TestPrepareHoldsThePlanToTheFDBudget is enforce-landlock E11 at the cap (enforce-plane §2.4 condition 7): a
// deny_read target among many siblings holds every sibling, and a plan that needs more descriptors than the
// launcher's budget is refused naming the cap and the count, never with EMFILE; the same table under a budget it
// fits is built. Nothing is left open either way.
func TestPrepareHoldsThePlanToTheFDBudget(t *testing.T) {
	root := tempDir(t)
	names := make([]string, 0, 41)
	for i := range 40 {
		names = append(names, filepath.Join("d", "s"+strconv.Itoa(i)))
	}
	mkTree(t, root, append(names, "d/secret")...)
	rt := &agent.RuleTable{FS: []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(root, "d", "secret"))}}
	before := openFDs(t)

	withFDBudget(t, FDBudget{Limit: 1000, InUse: 900, Reserve: 80}) // a cap of 20
	err := prepareErr(t, 7, rt, nil)
	var capErr *FDCapError
	if !errors.As(err, &capErr) || !errors.Is(err, ErrFDExhausted) || errors.Is(err, unix.EMFILE) {
		t.Fatalf("a plan over its budget: %v, want FDCapError", err)
	}
	if capErr.Held != 20 || capErr.Budget.Cap() != 20 || !strings.Contains(err.Error(), "holds 20 descriptors, its cap") {
		t.Errorf("refusal %v (held %d), want the cap of 20 named", err, capErr.Held)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak after the refusal: %d -> %d", before, after)
	}

	withFDBudget(t, FDBudget{Limit: 1 << 20, InUse: 100, Reserve: 80})
	h, _ := prepare(t, 7, rt)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak after Close: %d -> %d", before, after)
	}
}

// TestLeftOutDenyReadTargetsHoldNoDescriptor is R4 against E11's budget: a deny_read target beneath a write entry is
// left out of the ruleset, so the plan holds no descriptor for it for the run; its name is still read from an opened
// descriptor (closed at once) for the containment plan. Forty nested .env files under a cap 20 above the rest of the
// plan are built, each
// reported unenforced, where every one held a descriptor before and the plan met the cap (a project of thousands of
// them, which ADR 0043 D6 compacts out of the plane's rows, was refused at every tier). A target the plan enforces is
// still held.
func TestLeftOutDenyReadTargetsHoldNoDescriptor(t *testing.T) {
	root := tempDir(t)
	work := filepath.Join(root, "work")
	rules := []agent.FSRule{fsRule(agent.FSWrite, work)}
	var paths []string
	for i := range 40 {
		p := filepath.Join("work", "s"+strconv.Itoa(i), ".env")
		paths = append(paths, p)
		rules = append(rules, agent.FSRule{Path: filepath.Join(root, p), Kind: agent.FSDenyRead, Unenforced: true})
	}
	mkTree(t, root, append(paths, "plain/secret", "plain/other")...)
	enforced := filepath.Join(root, "plain", "secret")
	rules = append(rules, fsRule(agent.FSDenyRead, enforced))
	rt := &agent.RuleTable{Contract: contractWith(true, true), FS: rules}
	before := openFDs(t)

	// The cap is what the plan holds without the nested targets (the write entry, the enforced target's siblings and
	// ancestors from /), and 20 more: less than the 40 the nested targets held.
	withFDBudget(t, FDBudget{Limit: 1 << 20, InUse: 100, Reserve: 80})
	base, _ := prepare(t, 7, &agent.RuleTable{Contract: contractWith(true, true), FS: []agent.FSRule{rules[0], rules[len(rules)-1]}})
	need := len(base.fds.open)
	if err := base.Close(); err != nil {
		t.Fatal(err)
	}
	withFDBudget(t, FDBudget{Limit: need + 20 + 100 + 80, InUse: 100, Reserve: 80})
	h, _ := prepare(t, 7, rt)
	if got := len(h.unenforced); got != 40 {
		t.Errorf("%d targets reported unenforced, want the 40 beneath the write entry", got)
	}
	for _, p := range paths {
		if _, held := h.entry(filepath.Join(root, p)); held {
			t.Errorf("%s is held for the run, though the ruleset leaves it out (R4)", p)
		}
	}
	if e, held := h.entry(enforced); !held || e.Kind != kindDenyTarget {
		t.Errorf("the enforced target: held %v (%+v), want it held as the deny node", held, e)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("fd leak after Close: %d -> %d", before, after)
	}
}

// nofileChildEnv makes this test binary, re-run by TestReadFDBudgetLeavesTheChildsLimit under a low soft limit, stand in
// for a launcher: it takes its budget and reports the soft limit a child it starts inherits.
const nofileChildEnv = "TEGO_TEST_NOFILE_CHILD"

// TestReadFDBudgetLeavesTheChildsLimit: the launcher's raise is its own. The agent keeps the soft RLIMIT_NOFILE the
// launcher was started with: under `ulimit -Sn 1024` every agent ran with the hard limit, which a program built on
// select(2), or one that closes every descriptor up to the limit, does not survive. tego's own comment said so; the
// raise took the limit to the hard one, past the mark Go's runtime restores it from.
func TestReadFDBudgetLeavesTheChildsLimit(t *testing.T) {
	if os.Getenv(nofileChildEnv) != "" {
		if _, err := ReadFDBudget(); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("/bin/sh", "-c", "ulimit -Sn").Output()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("child soft limit: %s", out)
		return
	}
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max <= 256 {
		t.Fatalf("hard RLIMIT_NOFILE %d leaves no room for the low soft limit this test sets", lim.Max)
	}
	cmd := exec.Command("/bin/sh", "-c", `ulimit -Sn 256 && exec "$0" -test.run='^TestReadFDBudgetLeavesTheChildsLimit$' -test.v`, os.Args[0])
	cmd.Env = append(os.Environ(), nofileChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	if !strings.Contains(string(out), "child soft limit: 256\n") {
		t.Errorf("a child under a launcher started at soft 256:\n%s", out)
	}
}

// TestReadFDBudget: the budget is the soft limit less what is held and the reserve, with the soft limit raised to
// one under the hard one, the mark Go's runtime leaves, where it was lower.
func TestReadFDBudget(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim) })
	if lim.Max > 64 {
		low := unix.Rlimit{Cur: lim.Max / 2, Max: lim.Max}
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &low); err != nil {
			t.Skipf("setrlimit: %v", err)
		}
	}
	b, err := ReadFDBudget()
	if err != nil {
		t.Fatal(err)
	}
	if want := int(min(lim.Max-1, uint64(1)<<30)); b.Limit != want {
		t.Errorf("limit %d, want one under the hard limit, %d", b.Limit, want)
	}
	if held := openFDs(t); b.InUse < 3 || b.InUse > held {
		t.Errorf("in use %d, %d open now", b.InUse, held)
	}
	if b.Reserve != fdReserveFor(b.Limit) || b.Cap() != b.Limit-b.InUse-b.Reserve {
		t.Errorf("budget %+v", b)
	}
	for limit, reserve := range map[int]int{256: 64, 1024: 64, 2048: 128, 4096: 256, 1 << 20: 256} {
		if got := fdReserveFor(limit); got != reserve {
			t.Errorf("reserve under %d: %d, want %d", limit, got, reserve)
		}
	}
}
