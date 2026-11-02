// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestAskByIDAcrossRunningRuns: with two running runs each holding one request and one ended run under the
// ledger root, `tego ask` lists both requests led by their run ids, `tego approve <ask_id>` and `tego deny <ask_id>`
// answer the run that holds each id and no other, an id no running run holds is a finding [not-found], and an
// answer to the ended run says it has ended [not-running], exit 1, not 125.
func TestAskByIDAcrossRunningRuns(t *testing.T) {
	root := gcRoot(t)
	const idA, idB, idEnded = "r-3f9c2a1b-0dllq06ts7400-k7m2pa", "r-3f9c2a1b-0dllq06ts7401-k7m2pb", "r-3f9c2a1b-0dllq06ts7300-k7m2pc"
	noop := func(ask.Event) error { return nil }
	dirA, brokerA := newCLIBrokerIn(t, root, idA, noop)
	dirB, brokerB := newCLIBrokerIn(t, root, idB, noop)
	if err := os.Mkdir(filepath.Join(root, idEnded), 0o700); err != nil { // no lock file: no launcher holds it
		t.Fatal(err)
	}
	hold := func(b *ask.Broker, target string) chan ask.Decision {
		c := make(chan ask.Decision, 1)
		go func() {
			d, _ := b.Request(t.Context(), ask.Request{Op: "open", Target: target, Rule: "fs.ask", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
			c <- d
		}()
		return c
	}
	decisionA, decisionB := hold(brokerA, "/a/file"), hold(brokerB, "/b/file")
	askA, askB := pendingAskID(t, idA, dirA), pendingAskID(t, idB, dirB)

	// The whole command, through the machine config's ledger root.
	code, out, errs := run(t, "ask")
	for _, want := range []string{idA + " " + askA + " ", " open /a/file\n", idB + " " + askB + " ", " open /b/file\n",
		"answer one with: tego approve <ask_id>, or tego deny <ask_id>\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("tego ask lacks %q: exit %d\nstdout %s\nstderr %s", want, code, out, errs)
		}
	}
	if code != identity.ExitOK || strings.Contains(out, idEnded) {
		t.Errorf("tego ask: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var listed struct {
		Root string       `json:"root"`
		Runs []askPending `json:"runs"`
	}
	if code, out, errs := run(t, "ask", "--json"); code != identity.ExitOK || json.Unmarshal([]byte(out), &listed) != nil ||
		listed.Root != root || len(listed.Runs) != 2 || listed.Runs[0].Run != idB || listed.Runs[1].Run != idA {
		t.Errorf("tego ask --json: exit %d %+v\nstdout %s\nstderr %s", code, listed, out, errs)
	}
	if code, out, errs := run(t, "ask", askA); code != identity.ExitOK || !strings.HasPrefix(out, askA+" ") || !strings.Contains(out, "/a/file") {
		t.Errorf("tego ask <ask_id>: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}

	if code, out, errs := run(t, "approve", askB); code != identity.ExitOK || out != askB+": approved\n" {
		t.Fatalf("tego approve <ask_id>: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if d := <-decisionB; !d.Approved || d.AskID != askB {
		t.Fatalf("run B's decision %+v", d)
	}
	select {
	case d := <-decisionA:
		t.Fatalf("approving B's ask answered A's: %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if code, out, errs := run(t, "deny", askA); code != identity.ExitOK || out != askA+": denied\n" {
		t.Fatalf("tego deny <ask_id>: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if d := <-decisionA; d.Approved || d.AskID != askA {
		t.Fatalf("run A's decision %+v", d)
	}

	// Answered, the id is held by no running run any more.
	if code, out, errs := run(t, "approve", askA); code != identity.ExitFinding || out != "" ||
		!strings.Contains(errs, "no running run under "+root+" holds ask "+askA) || !strings.Contains(errs, "[not-found]") {
		t.Errorf("an answered ask id: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if code, out, errs := run(t, "ask"); code != identity.ExitOK || out != "no pending approvals in the 2 running run(s) under "+root+" that take approvals\n" {
		t.Errorf("nothing pending: exit %d\nstdout %q\nstderr %s", code, out, errs)
	}

	// An ended run: its requests ended with it.
	for _, args := range [][]string{{"ask", idEnded}, {"approve", idEnded, askA}} {
		code, out, errs := run(t, args...)
		if code != identity.ExitFinding || out != "" || !strings.Contains(errs, idEnded+" has ended; nothing waits for an answer") ||
			!strings.Contains(errs, "[not-running]") {
			t.Errorf("%v: exit %d\nstdout %s\nstderr %s", args, code, out, errs)
		}
	}
	// A run id that names no run gets the command that lists them.
	if code, _, errs := run(t, "approve", "r-3f9c2a1b-0dllq06ts7402-k7m2pd", askA); code != identity.ExitUsage ||
		!strings.Contains(errs, "no such run under "+root+"; tego status --all lists the runs") {
		t.Errorf("unknown run: exit %d stderr %s", code, errs)
	}
}

// TestAnAbbreviatedRunIsTheRunAnswered (H08): ask, approve, deny and status given the end or the start of a running
// run's id reach that run's broker and no other, as the whole id does; a start that two running runs share answers
// nothing and names both.
func TestAnAbbreviatedRunIsTheRunAnswered(t *testing.T) {
	root := gcRoot(t)
	const idA, idB = "r-3f9c2a1b-0dllq06ts7400-k7m2pa", "r-3f9c2a1b-0dllq06ts7401-k7m2pb"
	noop := func(ask.Event) error { return nil }
	dirA, brokerA := newCLIBrokerIn(t, root, idA, noop)
	dirB, brokerB := newCLIBrokerIn(t, root, idB, noop)
	hold := func(b *ask.Broker, target string) chan ask.Decision {
		c := make(chan ask.Decision, 1)
		go func() {
			d, _ := b.Request(t.Context(), ask.Request{Op: "open", Target: target, Rule: "fs.ask", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
			c <- d
		}()
		return c
	}
	decisionA, decisionB := hold(brokerA, "/a/file"), hold(brokerB, "/b/file")
	askA, askB := pendingAskID(t, idA, dirA), pendingAskID(t, idB, dirB)

	if code, out, errs := run(t, "ask", "k7m2pa"); code != identity.ExitOK || !strings.HasPrefix(out, askA+" ") || strings.Contains(out, askB) {
		t.Errorf("ask k7m2pa: exit %d, want run A's request alone\nstdout %s\nstderr %s", code, out, errs)
	}
	if code, out, errs := run(t, "status", "k7m2pb", "--json"); code != identity.ExitOK || !strings.Contains(out, `"run":"`+idB+`"`) {
		t.Errorf("status k7m2pb --json: exit %d, want run B\nstdout %s\nstderr %s", code, out, errs)
	}
	// The first four after r-3f9c2a1b- are both runs': nothing is answered.
	want := "tego approve: r-3f9c2a1b-0dll names more than one run under " + root + ": " + idB + ", " + idA + "; give more of its id [usage]"
	if code, out, errs := run(t, "approve", "r-3f9c2a1b-0dll", askA); code != identity.ExitUsage || out != "" || !strings.Contains(errs, want) {
		t.Errorf("approve r-3f9c2a1b-0dll: exit %d, want 2: %q\nstdout %s\nstderr %s", code, want, out, errs)
	}
	if code, out, errs := run(t, "approve", "k7m2pb", askB); code != identity.ExitOK || out != askB+": approved\n" {
		t.Fatalf("approve k7m2pb: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if d := <-decisionB; !d.Approved || d.AskID != askB {
		t.Fatalf("run B's decision %+v", d)
	}
	select {
	case d := <-decisionA:
		t.Fatalf("approving B's ask, or the ambiguous approve, answered A's: %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if code, out, errs := run(t, "deny", "r-3f9c2a1b-0dllq06ts7400", askA); code != identity.ExitOK || out != askA+": denied\n" {
		t.Fatalf("deny r-3f9c2a1b-0dllq06ts7400: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if d := <-decisionA; d.Approved || d.AskID != askA {
		t.Fatalf("run A's decision %+v", d)
	}
}

// TestAskByIDArguments: one argument to approve, deny or alternate must be an ask id; a bad one says the format and
// where to list them. None of these read account state.
func TestAskByIDArguments(t *testing.T) {
	for _, tc := range []struct {
		command Command
		args    []string
		want    string
	}{
		{cmdApprove(), []string{"q-bad"}, "an ask id (q- and 32 hex digits)"},
		{cmdDeny(), nil, "tego ask lists the pending ones"},
		{cmdAlternate(), []string{"q-0123456789abcdef0123456789abcdef"}, "and --file"},
		{cmdAsk(), []string{"a", "b", "c"}, "at most a run id and an ask id"},
		{cmdApprove(), []string{"r-3f9c2a1b-0dllq06ts7400-k7m2pq", "q-bad"}, `"q-bad" is not an ask id (q- and 32 hex digits); tego ask r-3f9c2a1b-0dllq06ts7400-k7m2pq lists`},
	} {
		f := flag.NewFlagSet(tc.command.Name, flag.ContinueOnError)
		tc.command.Flags(f)
		_ = f.Parse(tc.args)
		var out, errs bytes.Buffer
		if code := tc.command.Run(t.Context(), f, &out, &errs); code != identity.ExitUsage || out.Len() != 0 || !strings.Contains(errs.String(), tc.want) {
			t.Errorf("%s %v: exit %d out %q err %q, want 2 and %q", tc.command.Name, tc.args, code, &out, &errs, tc.want)
		}
	}
}

// TestAskAcrossARunWithNoAskSocket: a running run whose contract has no ask rule, or a watched run, serves no ask
// socket. Beside one that holds a request, `tego ask` lists that request and exits 0, `--json` likewise, and
// `tego approve <ask_id>` still finds it; alone, `tego ask` says no running run takes approvals, exit 0, and
// `tego ask <run>` says it takes no approvals (QG-11; it said "no pending approvals"), exit 0, and `tego approve <run>
// <ask_id>` says the same, exit 1.
// Before, the dial's ENOENT made `tego ask` print an [io] error and exit 125.
func TestAskAcrossARunWithNoAskSocket(t *testing.T) {
	root := gcRoot(t)
	const idPlain, idAsk = "r-3f9c2a1b-0dllq06ts7500-k7m2pa", "r-3f9c2a1b-0dllq06ts7501-k7m2pb"
	newCLIRunIn(t, root, idPlain)

	if code, out, errs := run(t, "ask"); code != identity.ExitOK || errs != "" ||
		out != "no pending approvals: no running run under "+root+" takes approvals\n" {
		t.Errorf("only a run with no ask socket: exit %d\nstdout %q\nstderr %s", code, out, errs)
	}
	if code, out, errs := run(t, "ask", idPlain); code != identity.ExitOK || errs != "" || out != idPlain+" takes no approvals: its contract has no ask rule\n" {
		t.Errorf("tego ask <run> with no ask socket: exit %d\nstdout %q\nstderr %s", code, out, errs)
	}
	const someAsk = "q-0123456789abcdef0123456789abcdef"
	if code, out, errs := run(t, "approve", idPlain, someAsk); code != identity.ExitFinding || out != "" ||
		!strings.Contains(errs, idPlain+" takes no approvals") || !strings.Contains(errs, "[not-found]") {
		t.Errorf("tego approve <run> <ask_id> with no ask socket: exit %d\nstdout %q\nstderr %s", code, out, errs)
	}

	dirAsk, broker := newCLIBrokerIn(t, root, idAsk, func(ask.Event) error { return nil })
	decision := make(chan ask.Decision, 1)
	go func() {
		d, _ := broker.Request(t.Context(), ask.Request{Op: "open", Target: "/c/file", Rule: "fs.ask", Hold: ask.HoldOpen, PID: os.Getpid(), TID: os.Getpid()})
		decision <- d
	}()
	askID := pendingAskID(t, idAsk, dirAsk)

	if code, out, errs := run(t, "ask"); code != identity.ExitOK || errs != "" || !strings.Contains(out, idAsk+" "+askID+" ") ||
		strings.Contains(out, idPlain) {
		t.Errorf("mixed runs: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	var listed struct {
		Runs []askPending `json:"runs"`
	}
	if code, out, errs := run(t, "ask", "--json"); code != identity.ExitOK || errs != "" || json.Unmarshal([]byte(out), &listed) != nil ||
		len(listed.Runs) != 1 || listed.Runs[0].Run != idAsk {
		t.Errorf("mixed runs --json: exit %d %+v\nstdout %s\nstderr %s", code, listed, out, errs)
	}
	if code, out, errs := run(t, "approve", askID); code != identity.ExitOK || out != askID+": approved\n" {
		t.Fatalf("tego approve <ask_id> beside a run with no ask socket: exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
	if d := <-decision; !d.Approved {
		t.Fatalf("decision %+v", d)
	}
	if code, out, errs := run(t, "ask"); code != identity.ExitOK || out != "no pending approvals in the 1 running run(s) under "+root+" that take approvals\n" {
		t.Errorf("mixed runs, nothing pending: exit %d\nstdout %q\nstderr %s", code, out, errs)
	}
}
