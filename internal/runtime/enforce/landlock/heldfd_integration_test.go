// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// runFinalizers runs a GC and waits for a marker finalizer and a marker cleanup it queued, three times
// over. The finalizer goroutine drains one snapshot of its queue before it takes the next, but runs a
// snapshot's entries in no fixed order, so a marker says only that its own snapshot was taken; a
// finalizer queued before the first cycle shares a snapshot with the third cycle's marker only if the
// goroutine took no snapshot through two whole cycles. Both kinds are waited for because an *os.File's
// close is registered as one or the other depending on the Go release.
func runFinalizers(t *testing.T) {
	t.Helper()
	for range 3 {
		fin, clean := make(chan struct{}), make(chan struct{})
		marker := new([64]byte)
		runtime.SetFinalizer(marker, func(*[64]byte) { close(fin) })
		other := new([64]byte)
		runtime.AddCleanup(other, func(ch chan struct{}) { close(ch) }, clean)
		// marker and other are not used again, so the compiler's liveness already leaves them
		// unreachable for the collection below; no assignment is needed to drop them.
		runtime.GC()
		for _, ch := range []chan struct{}{fin, clean} {
			select {
			case <-ch:
			case <-time.After(10 * time.Second):
				t.Fatal("the GC's finalizers and cleanups did not run")
			}
		}
	}
}

// TestRunHelperLeavesTheRulesetFDToItsHandle pins the fix for a ruleset fd closed twice. runHelper wrapped the Handle's ruleset
// fd in an *os.File for cmd.ExtraFiles and dropped it; the File's finalizer closed that number whenever
// the GC next ran, while the Handle still owned it or after Close had freed it and a later test's Prepare
// had been handed it for a deny_read sibling. Here the finalizers run twice at known points: first while
// the Handle still owns the number, where a second closer makes Close fail, and then after Close, with an
// unrelated file standing at the number, which must stay open.
func TestRunHelperLeavesTheRulesetFDToItsHandle(t *testing.T) {
	root := tempDir(t)
	h := realPrepare(t, integrationTable(t, root))
	fd, _ := h.LandlockRuleset()
	runHelper(t, "restrict", fd, helperRoot+"="+root)
	runFinalizers(t)
	if err := h.Close(); err != nil {
		t.Fatalf("Handle.Close after runHelper: %v: something else closed the ruleset fd %d the Handle owns", err, fd)
	}
	sfd, sid := sentinel(t)
	standAt(t, sfd, fd)
	runFinalizers(t)
	stillNames(t, fd, sid, "the finalizers of whatever runHelper left behind")
}

// hookSyscalls runs before once, when the ruleset is created: after every path is held and listed, and
// before the first landlock_add_rule.
type hookSyscalls struct {
	landlockSyscalls
	before func()
}

func (s *hookSyscalls) CreateRuleset(attr *unix.LandlockRulesetAttr, flags int) (int, error) {
	if attr != nil && s.before != nil {
		s.before()
		s.before = nil
	}
	return s.landlockSyscalls.CreateRuleset(attr, flags)
}

func kernelABI(t *testing.T) int {
	t.Helper()
	abi, err := ProbeABI()
	if err != nil {
		t.Skipf("no Landlock: %v", err)
	}
	return abi
}

// TestSiblingUnlinkedBeforeItsRuleIsHarmless is E28's later window on the real kernel: a directory and a
// file enumerated as siblings are removed after the builder has opened them and before their rules go in
// (the shape of the double close, where the sibling was another test's directory, being deleted). The held O_PATH fd
// keeps each unlinked inode, the kernel takes the rule on it, and the held-number check still recognises
// it, so Prepare succeeds; the rule reaches nothing, since no path leads to that inode any more. A name
// gone before its open is the earlier window, skipped (TestSiblingVanishedMidWalk).
func TestSiblingUnlinkedBeforeItsRuleIsHarmless(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secret/key", "public/", "note")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS:       []agent.FSRule{fsRule(agent.FSDenyRead, filepath.Join(root, "secret"))},
	}
	public, note := filepath.Join(root, "public"), filepath.Join(root, "note")
	sc := &hookSyscalls{landlockSyscalls: realSyscalls{}, before: func() {
		for _, p := range []string{public, note} {
			if err := os.Remove(p); err != nil {
				t.Errorf("remove %s: %v", p, err)
			}
		}
	}}
	h, err := New(Options{ABI: kernelABI(t), syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatalf("Prepare with siblings unlinked before their rules: %v", err)
	}
	for _, p := range []string{public, note} {
		if e, ok := h.entry(p); !ok || e.Access == 0 {
			t.Errorf("%s: entry %+v held=%v, want a sibling rule on the unlinked inode", p, e, ok)
		}
	}
	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestRuleOnAReusedNumberFailsOnTheKernel is the consequence on the real kernel: the sibling's number
// is closed by another owner and reopened on the deny_read target itself just before its rule goes in.
// Landlock takes that rule without complaint, and it grants the sibling's read set on the secret; only the
// held-number check stands between that ruleset and the agent.
func TestRuleOnAReusedNumberFailsOnTheKernel(t *testing.T) {
	root := tempDir(t)
	mkTree(t, root, "secret/key", "public/")
	secret, public := filepath.Join(root, "secret"), filepath.Join(root, "public")
	rt := &agent.RuleTable{
		Contract: contractWith(true, true),
		FS:       []agent.FSRule{fsRule(agent.FSDenyRead, secret)},
	}
	var number int
	sc := &thievingSyscalls{landlockSyscalls: realSyscalls{}, victim: identityOf(t, public)}
	sc.steal = func(_ int, attr *unix.LandlockPathBeneathAttr) error {
		other, err := unix.Open(secret, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %s: %v", secret, err)
		}
		number = int(attr.Parent_fd)
		standAt(t, other, number)
		_ = unix.Close(other)
		return nil
	}
	h, err := New(Options{ABI: kernelABI(t), syscalls: sc}).Prepare(context.Background(), rt, Run{})
	if err == nil {
		_ = h.Close()
		t.Fatal("Prepare returned a ruleset whose sibling rule went in through a number reopened on the deny_read target")
	}
	if !sc.stolen {
		t.Fatal("no rule went in for the sibling: the test did not exercise the reuse")
	}
	if !errors.Is(err, ErrRulesetBuild) || !strings.Contains(err.Error(), public) {
		t.Errorf("error %v, want ErrRulesetBuild naming %q", err, public)
	}
	stillNames(t, number, identityOf(t, secret), "Prepare's cleanup")
}

// TestProbeRulesetAnswersOnTheKernel pins the kernel's side of rulesetStill: an empty
// landlock_add_rule answers ENOMSG for a live ruleset, EBADFD for an open file that is not one and was
// not opened O_PATH, and EBADF for a number that is not open or names an O_PATH file (the kernel's fdget
// lookup does not see those). The ruleset number is closed on a failed build or at Close only on ENOMSG.
func TestProbeRulesetAnswersOnTheKernel(t *testing.T) {
	sc := realSyscalls{}
	attr := unix.LandlockRulesetAttr{Handled_access_fs: uint64(profileFor(kernelABI(t)).FS)}
	fd, err := sc.CreateRuleset(&attr, 0)
	if err != nil {
		t.Fatalf("landlock_create_ruleset: %v", err)
	}
	defer func() { _ = unix.Close(fd) }()
	checkProbeAnswers(t, sc, fd)
}

// TestRulesetNumberReopenedBeforeAnAddOnTheKernel is the reviewer's reproduction of the ruleset's half of
// The ruleset number is closed by another owner and reopened just before a sibling's rule, on a
// pipe, for which the kernel answers the add EBADFD, and on an O_PATH file, the kind of open that took a
// freed number in the original trace, for which it answers EBADF, as for a closed number. Prepare's cleanup
// must leave either file at the number.
func TestRulesetNumberReopenedBeforeAnAddOnTheKernel(t *testing.T) {
	for _, s := range standIns {
		t.Run(s.name, func(t *testing.T) {
			rt, root := heldTable(t)
			sfd, sid := s.open(t)
			var number int
			sc := &thievingSyscalls{landlockSyscalls: realSyscalls{}, victim: identityOf(t, filepath.Join(root, "public"))}
			sc.steal = func(rulesetFD int, _ *unix.LandlockPathBeneathAttr) error {
				number = rulesetFD
				standAt(t, sfd, number)
				return nil // the kernel looks the number up itself
			}
			h, err := New(Options{ABI: kernelABI(t), syscalls: sc}).Prepare(context.Background(), rt, Run{})
			if err == nil {
				_ = h.Close()
			}
			if !sc.stolen {
				t.Fatal("no rule went in for the sibling: the test did not exercise the reuse")
			}
			rulesetLeftOpen(t, err, s, number, sid, "Prepare's cleanup")
		})
	}
}

// TestCloseLeavesAReopenedRulesetNumberOpenOnTheKernel is the first shape the closer took (a
// finalizer closing the ruleset number the Handle still owned), with the number reused before Close, by a
// pipe and by an O_PATH open.
func TestCloseLeavesAReopenedRulesetNumberOpenOnTheKernel(t *testing.T) {
	for _, s := range standIns {
		t.Run(s.name, func(t *testing.T) {
			rt, _ := heldTable(t)
			h, err := New(Options{ABI: kernelABI(t)}).Prepare(context.Background(), rt, Run{})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			number, _ := h.LandlockRuleset()
			sfd, sid := s.open(t)
			standAt(t, sfd, number)
			rulesetLeftOpen(t, h.Close(), s, number, sid, "Close")
		})
	}
}
