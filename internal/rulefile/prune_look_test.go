// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The lstat and runAs seams a Prune's lookers call are set once, here, and never written again: a looker a Prune gave
// up on may still be on its way to a look when the test that started it ends, and a seam a test wrote back then would
// be a write beside that looker's read. A test plays a stale mount (staleMount) or watches the looks' credentials
// (watchLooks) through lookPlay instead, under lookMu.
var (
	lookMu   sync.Mutex
	lookPlay struct {
		stale *stale
		// asked records the credentials each looker took; fail, when set, is what each one's runAs answers instead.
		asked *[]sys.TaskCreds
		fail  error
	}
)

// stale is a mount whose files hangs names never answer until the test that plays it ends.
type stale struct {
	hangs   func(name string) bool
	release chan struct{}
	stuck   sync.WaitGroup
}

func init() {
	lstat = func(name string) (os.FileInfo, error) {
		lookMu.Lock()
		s := lookPlay.stale
		hang := s != nil && s.hangs(name)
		if hang {
			s.stuck.Add(1)
		}
		lookMu.Unlock()
		if hang {
			defer s.stuck.Done()
			<-s.release
		}
		return os.Lstat(name)
	}
	runAs = func(c sys.TaskCreds, fn func()) error {
		lookMu.Lock()
		if lookPlay.asked != nil {
			*lookPlay.asked = append(*lookPlay.asked, c)
		}
		fail := lookPlay.fail
		lookMu.Unlock()
		if fail != nil {
			return fail
		}
		return sys.RunAs(c, fn)
	}
}

// staleMount makes the files hangs names never answer a look until the test ends, and sets lookWait to wait (0 leaves
// it as it is). hangs runs under lookMu, at most once per look.
func staleMount(t *testing.T, wait time.Duration, hangs func(name string) bool) {
	t.Helper()
	s := &stale{hangs: hangs, release: make(chan struct{})}
	lookMu.Lock()
	lookPlay.stale = s
	lookMu.Unlock()
	prevWait := lookWait
	if wait > 0 {
		lookWait = wait
	}
	t.Cleanup(func() {
		lookMu.Lock()
		lookPlay.stale = nil
		close(s.release) // the mount answers once the test is over
		lookMu.Unlock()
		s.stuck.Wait()
		lookWait = prevWait
	})
}

// watchLooks records the credentials each looker of the test's Prunes takes, and with fail set has each one's runAs
// answer fail instead of looking.
func watchLooks(t *testing.T, fail error) *[]sys.TaskCreds {
	t.Helper()
	asked := &[]sys.TaskCreds{}
	lookMu.Lock()
	lookPlay.asked, lookPlay.fail = asked, fail
	lookMu.Unlock()
	t.Cleanup(func() {
		lookMu.Lock()
		lookPlay.asked, lookPlay.fail = nil, nil
		lookMu.Unlock()
	})
	return asked
}

// lookedAt reads what watchLooks recorded.
func lookedAt(asked *[]sys.TaskCreds) []sys.TaskCreds {
	lookMu.Lock()
	defer lookMu.Unlock()
	return slices.Clone(*asked)
}

// twoGone journals two old changes of each of two contracts in folders of their own, first and then second, and removes
// both files, so that every line of both goes once a Prune sees each file gone.
func twoGone(t *testing.T) (g Guard, first, second string) {
	t.Helper()
	g, first = fixture(t)
	second = filepath.Join(filepath.Dir(filepath.Dir(first)), "proj2", "agent.yaml")
	if err := os.Mkdir(filepath.Dir(second), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte(textA), 0o600); err != nil {
		t.Fatal(err)
	}
	clock(t, time.Now().Add(-60*day))
	for _, p := range []string{first, second} {
		write(t, g, p, textA, textB)
		write(t, g, p, textB, textC)
	}
	now = time.Now
	for _, p := range []string{first, second} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	return g, first, second
}

// contractsLeft is the contracts root's journal still has a line of, in the journal's order.
func contractsLeft(t *testing.T, root string) []string {
	t.Helper()
	es, err := ReadJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		if !slices.Contains(out, e.Contract) {
			out = append(out, e.Contract)
		}
	}
	return out
}

// TestPruneLooksPastAFileThatDoesNotAnswer: the contracts' files are looked at a few at once, so a file on a stale
// mount holds up its own look and no other: the other file, gone, is seen gone and its lines go. Looked at one after
// the other, every file after the stale one in the journal was never looked at, counted as there and kept its lines,
// on every pass while the mount stayed stale.
func TestPruneLooksPastAFileThatDoesNotAnswer(t *testing.T) {
	g, first, second := twoGone(t)
	staleMount(t, time.Second, func(name string) bool { return name == first })
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if !errors.Is(err, ErrNotLooked) || !strings.Contains(err.Error(), first) || strings.Contains(err.Error(), second) {
		t.Errorf("Prune: %v; want ErrNotLooked naming %s alone", err, first)
	}
	if left := contractsLeft(t, g.LedgerRoot); p.Lines != 2 || !slices.Equal(left, []string{first}) {
		t.Errorf("pruned %+v, lines of %v left; want the 2 lines of %s, whose file is seen gone, pruned and those of %s "+
			"kept", p, left, second, first)
	}
}

// TestPrunePrunesInTheBudgetALookLeft: a run start's pass gives the prune what is left of its 2 s, and a file that never
// answers costs at most half of what is left when the files are looked at: the prune goes on in the other half, and the
// file that did answer gone has its lines pruned. A wait of lookWait (3 s) spent a run start's budget whole, the prune
// then stopped at its deadline, and no pass pruned anything while the mount stayed stale.
func TestPrunePrunesInTheBudgetALookLeft(t *testing.T) {
	const budget = 2 * time.Second // a run start's (internal/cli retentionBudget)
	g, first, second := twoGone(t)
	staleMount(t, 0, func(name string) bool { return name == first })
	if lookWait <= budget {
		t.Fatalf("lookWait is %s: this test needs it longer than its budget", lookWait)
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	start := time.Now()
	p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if !errors.Is(err, ErrNotLooked) || errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Prune: %v; want ErrNotLooked, the prune done in its budget", err)
	}
	if left := contractsLeft(t, g.LedgerRoot); p.Lines != 2 || !slices.Equal(left, []string{first}) {
		t.Errorf("pruned %+v, lines of %v left; want those of %s pruned in the budget", p, left, second)
	}
	if took := time.Since(start); took >= budget {
		t.Errorf("Prune took %s of a %s budget", took, budget)
	}
}

// TestPruneLooksAsItsCaller: every look at a contract's file is made with the credentials of the thread that called
// Prune, on a thread that takes them (sys.RunAs). A root pass calls Prune on a thread holding the user's ids, and its
// looks ran on goroutines of their own, which run on any thread of the process: one of root's, with every capability.
func TestPruneLooksAsItsCaller(t *testing.T) {
	g, _, _ := twoGone(t)
	asked := watchLooks(t, nil)
	// Prune is called on a thread of its own, as a root pass's is, so the credentials read are the ones it runs with.
	runtime.LockOSThread()
	caller, err := sys.ThreadCreds()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	runtime.UnlockOSThread()
	if err != nil || p.Lines != 4 {
		t.Fatalf("pruned %+v, %v; want both files seen gone and their 4 lines pruned", p, err)
	}
	got := lookedAt(asked)
	if len(got) == 0 {
		t.Fatal("no look took its caller's credentials")
	}
	for _, c := range got {
		if !c.Equal(caller) {
			t.Errorf("a look took %+v, its caller held %+v", c, caller)
		}
	}
}

// TestPruneSaysWhenNoLookCouldBeMade: a looker that cannot take its caller's credentials looks at nothing. Its files
// count as there, so their lines stay, and the Prune says why without waiting out lookWait.
func TestPruneSaysWhenNoLookCouldBeMade(t *testing.T) {
	g, first, second := twoGone(t)
	watchLooks(t, sys.ErrCredentials)
	start := time.Now()
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if !errors.Is(err, ErrNotLooked) || !errors.Is(err, sys.ErrCredentials) || p.Lines != 0 {
		t.Errorf("pruned %+v, %v; want nothing pruned and ErrNotLooked saying no credentials were taken", p, err)
	}
	if left := contractsLeft(t, g.LedgerRoot); !slices.Equal(left, []string{first, second}) {
		t.Errorf("lines of %v left, want both files'", left)
	}
	if took := time.Since(start); took >= lookWait {
		t.Errorf("Prune took %s, waiting out lookWait for lookers that had ended", took)
	}
}
