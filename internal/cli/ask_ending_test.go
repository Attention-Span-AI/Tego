// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/askclient"
	"github.com/attention-span-ai/tego/internal/runlock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// A run in the window at the end of its life (its broker has closed its socket, its launcher still holds the lock) is
// named when `tego ask` skips it, with why and where to read what it did. Exit codes and standard output are what they
// were; the words go to standard error with the notes that were already there.

const (
	endingServing = "r-3f9c2a1b-0dllq06ts7610-k7m2pa"
	endingPlain   = "r-3f9c2a1b-0dllq06ts7611-k7m2pb"
	endingLeft    = "r-3f9c2a1b-0dllq06ts7612-k7m2pc"
	endingHolder  = "r-3f9c2a1b-0dllq06ts7613-k7m2pd"
	someAskID     = "q-0123456789abcdef0123456789abcdef"
)

// leftLauncherRun is a run that looks live to the probe (its lock is held) whose launcher is gone when it is looked at
// for the exchange: the verified-launcher look says no broker, as it does for a launcher that left in between.
func leftLauncherRun(t *testing.T, root, id string) {
	t.Helper()
	newCLIRunServing(t, root, id, true)
	was := askLauncher
	t.Cleanup(func() { askLauncher = was })
	askLauncher = func(dir string) (*runlock.StopTarget, error) {
		if filepath.Base(dir) == id {
			return nil, fmt.Errorf("%w: its launcher left", askclient.ErrNoBroker)
		}
		return was(dir)
	}
}

func hasAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

// `tego ask <run>` of a run whose socket is gone says the run has ended or is ending and where its record is, with the
// exit code and the empty standard output it always had.
func TestAskOfARunWhoseSocketIsGoneSaysItEndedAndWhereToRead(t *testing.T) {
	id, dir, _ := goneRun(t, true, askLine(t, goneAsk))
	for _, tc := range []struct {
		name string
		id   string
		json bool
		exit int
		code string
	}{
		{"list", "", false, identity.ExitFinding, "[not-found]"},
		{"list as json", "", true, identity.ExitFinding, "[not-found]"},
		{"one request", goneAsk, false, identity.ExitError, "[io]"},
	} {
		var out, errs strings.Builder
		code := askAt(t.Context(), "ask", id, dir, tc.id, false, false, tc.json, "", &out, &errs)
		if code != tc.exit || out.Len() != 0 || !hasAll(errs.String(), id, "ask socket is not there now", "the run has ended or is ending", "tego events "+id+" shows what it did", tc.code) {
			t.Errorf("%s: exit %d stdout %q stderr %q, want exit %d, nothing on stdout, the run named, the ending and %q", tc.name, code, out.String(), errs.String(), tc.exit, "tego events "+id)
		}
	}
}

// `tego ask` with no run names each run it skipped, the one whose launcher left while the list was made and the one whose
// broker closed under it, and leaves a run with no ask rule out. The listing, its exit code and the empty list on
// standard output are unchanged: the broker's reset is still the failure (125) it was.
func TestAskListNamesTheRunsItSkippedAndWhy(t *testing.T) {
	root := gcRoot(t)
	newCLIRunServing(t, root, endingPlain, false)
	newCLIRunServing(t, root, endingServing, true) // its socket is gone
	leftLauncherRun(t, root, endingLeft)

	code, out, errs := run(t, "ask")
	if code != identity.ExitOK || out != "no pending approvals: no running run under "+root+" takes approvals\n" {
		t.Errorf("tego ask: exit %d stdout %q stderr %q", code, out, errs)
	}
	for _, want := range []string{
		endingServing + " takes approvals, but its ask socket is not there now, so nothing can be answered: the run has ended or is ending (tego events " + endingServing + " shows what it did); it is not in this list",
		endingLeft + " ended while the list was made; nothing waits for an answer in it (tego events " + endingLeft + " shows what it did)",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("tego ask: stderr lacks %q: %q", want, errs)
		}
	}
	if strings.Contains(errs, endingPlain) {
		t.Errorf("a run with no ask rule is not named: %q", errs)
	}

	// A broker that closes the connection under the list: said in words, the exit code is the one it was.
	root = gcRoot(t)
	dir := newCLIRunServing(t, root, endingHolder, true)
	resettingBroker(t, dir, false, nil)
	code, out, errs = run(t, "ask")
	if code != identity.ExitError || out != "no pending approvals: no running run under "+root+" takes approvals\n" {
		t.Errorf("a broker that went away: exit %d stdout %q stderr %q, want exit %d and the list as before", code, out, errs, identity.ExitError)
	}
	if !hasAll(errs, "tego ask: "+endingHolder+"'s broker went away while the list was made", "its requests are not in this list", "tego events "+endingHolder+" shows what it did", "[io]") ||
		strings.Contains(errs, "connection reset") {
		t.Errorf("a broker that went away: stderr %q", errs)
	}
}

// `tego ask <ask_id>` and `tego approve <ask_id>` pick the run that holds the id. When none does, a run that could not be
// asked because it is ending is named, so "no run holds it" is not read as "none could"; a run with no ask rule is not
// named, and a found id says nothing of the others. Exit codes and standard output are unchanged.
func TestAskByIDNamesTheRunsItSkipped(t *testing.T) {
	root := gcRoot(t)
	newCLIRunServing(t, root, endingPlain, false)
	newCLIRunServing(t, root, endingServing, true)
	leftLauncherRun(t, root, endingLeft)
	for _, name := range []string{"ask", "approve", "deny"} {
		code, out, errs := run(t, name, someAskID)
		if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "no running run under "+root+" holds ask "+someAskID) || !strings.Contains(errs, "[not-found]") {
			t.Errorf("%s: exit %d stdout %q stderr %q", name, code, out, errs)
		}
		if !hasAll(errs, "note: tego "+name+": "+endingServing+" was skipped while "+someAskID+" was looked for: it is ending (its ask socket is gone)", "tego events "+endingServing+" shows what it did", "[not-found]") ||
			!hasAll(errs, "note: tego "+name+": "+endingLeft+" ended while "+someAskID+" was looked for, so it was skipped", "tego events "+endingLeft+" shows what it did", "[not-running]") {
			t.Errorf("%s: the runs it skipped are not named: %q", name, errs)
		}
		if strings.Contains(errs, endingPlain) {
			t.Errorf("%s: a run with no ask rule is not named: %q", name, errs)
		}
	}

	// The id is found in another run: the answer is that run's, and nothing is said of the runs on the way.
	dirHeld, broker := newCLIBrokerIn(t, root, endingHolder, func(ask.Event) error { return nil })
	decision := make(chan ask.Decision, 1)
	go func() {
		d, _ := broker.Request(t.Context(), ask.Request{Op: "open", Target: "/d/file", Rule: "fs.ask", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
		decision <- d
	}()
	held := pendingAskID(t, endingHolder, dirHeld)
	if code, out, errs := run(t, "approve", held); code != identity.ExitOK || out != held+": approved\n" || errs != "" {
		t.Errorf("an id a run holds: exit %d stdout %q stderr %q", code, out, errs)
	}
	<-decision
}
