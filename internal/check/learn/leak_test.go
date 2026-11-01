// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/syslookup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	keyFile = "/home/u/.ssh/id_rsa"
	sink    = "203.0.113.9:443"
)

func (r *run) read(path string) *record.Event {
	r.open(path, rdonly)
	return r.events[len(r.events)-1]
}

// sent is an observed connect, by host name when host is set.
func (r *run) sent(dst, host string) *record.Event {
	r.t.Helper()
	return r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "tcp", Dst: dst, Host: host})
}

// padding adds n unremarkable lines.
func (r *run) padding(n int) {
	for range n {
		r.read("/usr/lib/x.py")
	}
}

func leakDests(p *Proposal) []string {
	out := make([]string, 0, len(p.Leaks))
	for _, lk := range p.Leaks {
		out = append(out, lk.Dest)
	}
	return out
}

func allowed(t *testing.T, p *Proposal) []string {
	t.Helper()
	c := load(t, p.Contract())
	return c.Net.Allow
}

// TestLeakIsWithheld (QA PW-1): a secret read, then a send to an address off the contract: the address is not in
// net.allow, the file opens with a warning naming the secret and the place, the comments under net.allow name the
// entry, and the file still loads.
func TestLeakIsWithheld(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.sent(sink, "")
	r.sent(sink, "")
	r.sent("10.0.0.7:8080", "")
	r.padding(20)
	p := r.propose(Options{Executable: testExecutable})

	if got := leakDests(p); !slices.Equal(got, []string{sink, "10.0.0.7:8080"}) {
		t.Fatalf("leaks %v", got)
	}
	if !slices.Equal(p.LeakSecrets, []string{keyFile}) {
		t.Fatalf("secrets %v", p.LeakSecrets)
	}
	if got := allowed(t, p); len(got) != 0 {
		t.Fatalf("net.allow = %v, want nothing", got)
	}
	text := p.Contract()
	for _, want := range []string{
		"# WARNING: this run opened " + keyFile + " for reading, or tried to, next to a send to " + sink + ", 10.0.0.7:8080, which is how a leak looks in the record",
		"  allow: []\n",
		"# observed, not allowed: tcp://" + sink + " (seen 2 times): an open of a secret for reading came next to this send",
		"a send next to a secret read",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the proposal lacks %q:\n%s", want, text)
		}
	}
	if !strings.HasPrefix(text, "# WARNING: ") {
		t.Errorf("the warning is not on top:\n%s", text)
	}
}

func TestLeakRule(t *testing.T) {
	cases := []struct {
		name  string
		build func(*run)
		leaks []string
		allow []string
	}{
		{name: "the read after the send", build: func(r *run) {
			r.sent(sink, "")
			r.read(keyFile)
		}, leaks: []string{sink}},
		{name: "16 lines apart is near", build: func(r *run) {
			r.read(keyFile)
			r.padding(15)
			r.sent(sink, "")
		}, leaks: []string{sink}},
		{name: "17 lines apart is not", build: func(r *run) {
			r.read(keyFile)
			r.padding(16)
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "more than 5 s apart is not", build: func(r *run) {
			r.read(keyFile)
			r.sent(sink, "").TS = r.t0.Add(6 * time.Second)
		}, allow: []string{"tcp://" + sink}},
		// The limit the header states: only the first contact counts.
		{name: "a place first reached long before the read", build: func(r *run) {
			r.sent(sink, "")
			r.padding(30)
			r.read(keyFile)
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "a destination the contract names", build: func(r *run) {
			r.read(keyFile)
			r.sent(sink, "").Rule = "net[" + sink + "]"
		}, allow: []string{"tcp://" + sink}},
		{name: "a file of no interest", build: func(r *run) {
			r.read("/work/README.md")
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		// The rule tests every read, not the first (the page's first-touch test missed this): a re-read is normal, Claude's
		// start-up has 6 secret lines over 2 paths and Codex's 15 over 3.
		{name: "a re-read right before a send to a new place", build: func(r *run) {
			r.read(keyFile)
			r.padding(30)
			r.read(keyFile)
			r.sent(sink, "")
		}, leaks: []string{sink}},
		{name: "a send to a new place, then a re-read", build: func(r *run) {
			r.read(keyFile)
			r.padding(30)
			r.sent(sink, "")
			r.read(keyFile)
		}, leaks: []string{sink}},
		{name: "asked about first, read later", build: func(r *run) {
			r.add(record.KindAsk, "", map[string]string{"ask_id": "a", "hold": "open", "op": "read", "target": keyFile})
			r.padding(30)
			r.read(keyFile).TS = r.t0.Add(30 * time.Second)
			r.sent(sink, "").TS = r.t0.Add(30*time.Second + time.Millisecond)
		}, leaks: []string{sink}},
		{name: "refused first, read later", build: func(r *run) {
			r.add(record.KindRefused, "", record.RefusedPayload{Op: "open", Target: keyFile, Reason: "read-denied"})
			r.padding(30)
			r.read(keyFile)
			r.sent(sink, "")
		}, leaks: []string{sink}},
		{name: "a re-read that fails is no read", build: func(r *run) {
			r.read(keyFile)
			r.padding(30)
			r.add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: record.FSOpen, Path: keyFile, Errno: 2})
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		// Nothing was read in these, as the receipt says of the same lines (receipt.sensitive).
		{name: "a failed open reads nothing", build: func(r *run) {
			r.add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: record.FSOpen, Path: "/work/.env", Errno: 2})
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "a create reads nothing", build: func(r *run) {
			r.open("/work/node_modules/x/test/server.key", creat|wronly)
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "a read-write open that made its file reads nothing", build: func(r *run) {
			r.add(record.KindFS, record.VerdictObserved, record.FSPayload{Op: record.FSOpen, Path: "/work/a.key", Flags: creat | rdwr, Created: true})
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "an unlink reads nothing", build: func(r *run) {
			r.fs(record.FSUnlink, "/home/u/.claude/sessions/1.abc.key", "", 0)
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "a read-write open can read", build: func(r *run) {
			r.open(keyFile, rdwr)
			r.sent(sink, "")
		}, leaks: []string{sink}},
		// The machine's own port 53 is the resolver; anywhere else only the engine's rule says so.
		{name: "the resolver on this machine is no send", build: func(r *run) {
			r.read(keyFile)
			r.sent("127.0.0.53:53", "")
			r.sent("[::1]:53", "")
		}},
		{name: "port 53 elsewhere is judged", build: func(r *run) {
			r.read(keyFile)
			r.sent("203.0.113.9:53", "")
		}, leaks: []string{"203.0.113.9:53"}},
		{name: "a resolver the engine named elsewhere is no send", build: func(r *run) {
			r.read(keyFile)
			r.sent("10.0.0.2:53", "").Rule = syslookup.ResolverRule
		}, allow: []string{"tcp://10.0.0.2:53"}},
		{name: "port 53 elsewhere, not next to a read", build: func(r *run) {
			r.sent("10.0.0.1:53", "")
			r.padding(20)
			r.read(keyFile)
		}, allow: []string{"tcp://10.0.0.1:53"}},
		{name: "a read the rule guards, whatever its name", build: func(r *run) {
			e := r.add(record.KindFS, record.VerdictAllow, record.FSPayload{Op: record.FSOpen, Path: "/work/plans.txt"})
			e.Rule = "fs.ask_read[/work/plans.txt]"
			r.sent(sink, "")
		}, leaks: []string{sink}},
		{name: "a refused read leaves nothing to send", build: func(r *run) {
			r.add(record.KindRefused, "", record.RefusedPayload{Op: "open", Target: keyFile, Reason: "read-denied"})
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "a read a person was asked about and that never went through", build: func(r *run) {
			r.add(record.KindAsk, "", map[string]string{"ask_id": "a", "hold": "open", "op": "read", "target": keyFile})
			r.sent(sink, "")
		}, allow: []string{"tcp://" + sink}},
		{name: "a refused send is not where it went", build: func(r *run) {
			r.read(keyFile)
			r.add(record.KindRefused, "", record.RefusedPayload{Op: "net", Target: sink, Reason: "net-not-allowed"})
		}},
		{name: "a listening socket is no send", build: func(r *run) {
			r.read(keyFile)
			r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Op: "bind", Proto: "tcp", Dst: "127.0.0.1:9000"})
		}, allow: []string{"tcp://127.0.0.1:9000"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRun(t, "/work")
			c.build(r)
			p := r.propose(Options{Executable: testExecutable})
			if got := leakDests(p); !slices.Equal(got, c.leaks) && (len(got) != 0 || len(c.leaks) != 0) {
				t.Errorf("leaks %v, want %v", got, c.leaks)
			}
			if got := allowed(t, p); !slices.Equal(got, c.allow) && (len(got) != 0 || len(c.allow) != 0) {
				t.Errorf("net.allow %v, want %v", got, c.allow)
			}
		})
	}
}

// TestLeakByNameAndAddress: a line that names the host and the address keys the leak by name, as the page does, and
// the address is what leaves net.allow: the page's own withhold cannot match that line.
func TestLeakByNameAndAddress(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.sent(sink, "attacker.example")
	r.sent("203.0.113.10:443", "attacker.example")
	p := r.propose(Options{Executable: testExecutable})
	if got := leakDests(p); !slices.Equal(got, []string{"attacker.example:443"}) {
		t.Fatalf("leaks %v", got)
	}
	if p.Leaks[0].ByName {
		t.Error("a destination with addresses reads as held by name only")
	}
	if got := allowed(t, p); len(got) != 0 {
		t.Errorf("net.allow = %v", got)
	}
	if got := p.Leaks[0].Entries; len(got) != 2 {
		t.Errorf("withheld %v", got)
	}
}

// TestLeakRecordedOnlyByName: the forwarder's lines hold the name and no address, so no entry can be matched to it,
// and the warning says so instead of a silence that reads as "checked".
func TestLeakRecordedOnlyByName(t *testing.T) {
	r := newRun(t, "/work")
	r.sent("198.51.100.4:443", "")
	r.padding(20)
	r.read(keyFile)
	r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "tcp", Dst: "attacker.example:443", Host: "attacker.example"})
	p := r.propose(Options{Executable: testExecutable})
	if len(p.Leaks) != 1 || !p.Leaks[0].ByName {
		t.Fatalf("leaks %+v", p.Leaks)
	}
	want := "this run opened " + keyFile + " for reading, or tried to, next to a send to attacker.example:443, recorded only by host name: the record keeps no address for it, so the proposal cannot tell whether an address it allows is the same place; check every net.allow entry"
	if !slices.Contains(p.Warnings(), want) {
		t.Errorf("warnings %q", p.Warnings())
	}
	if !strings.Contains(p.Contract(), "# WARNING: "+want+".\n") {
		t.Errorf("the file does not carry the warning:\n%s", p.Contract())
	}
	if got := allowed(t, p); !slices.Equal(got, []string{"tcp://198.51.100.4:443"}) {
		t.Errorf("net.allow = %v", got)
	}
}

// TestLeakPortFiftyThreeSaysWhatItIs: port 53 elsewhere that the engine did not name a resolver may still be the
// machine's, so the warning says that and not that it was a leak, and that nothing is lost if it was the resolver.
func TestLeakPortFiftyThreeSaysWhatItIs(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.sent("203.0.113.9:53", "")
	p := r.propose(Options{Executable: testExecutable})
	want := "this run opened " + keyFile + " for reading, or tried to, next to a connect to 203.0.113.9:53: the engine did not name it a resolver, and the port alone says nothing, so the proposal leaves that out; if it is the machine's resolver nothing is lost, as tego allows that one itself"
	if !slices.Contains(p.Warnings(), want) {
		t.Errorf("warnings %q", p.Warnings())
	}
	if got := allowed(t, p); len(got) != 0 {
		t.Errorf("net.allow = %v", got)
	}
}

// TestLeakReReadInARealRun is the re-read on a real record: Claude Code's start-up, which opens its credentials at seq
// 61, opens them once more, and connects to a place it never reached 50 ms later.
func TestLeakReReadInARealRun(t *testing.T) {
	events := fixtureEvents(t, claudeFixture)
	const creds = "/home/user/.claude/.credentials.json"
	if events[len(events)-1].Kind == record.KindRunEnd {
		events = events[:len(events)-1]
	}
	last := events[len(events)-1]
	add := func(after time.Duration, kind record.Kind, payload any) {
		e := &record.Event{V: record.Version, Seq: uint64(len(events)), TS: last.TS.Add(after), Kind: kind, Verdict: record.VerdictObserved}
		if err := e.SetPayload(payload); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	add(time.Minute, record.KindFS, record.FSPayload{Op: record.FSOpen, Path: creds})
	add(time.Minute+50*time.Millisecond, record.KindNet, record.NetPayload{Proto: "tcp", Dst: sink})
	p, err := propose(events, Options{StateDirs: stateDirs})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(leakDests(p), sink) {
		t.Fatalf("leaks %v", leakDests(p))
	}
	if !slices.Contains(p.LeakSecrets, creds) {
		t.Errorf("secrets %v", p.LeakSecrets)
	}
	if got := allowed(t, p); slices.Contains(got, "tcp://"+sink) {
		t.Errorf("net.allow = %v", got)
	}
}

// TestLeakLocalSocketIsReported: a unix socket stays proposed (it may be the agent's own) and is named.
func TestLeakLocalSocketIsReported(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "unix", Dst: "unix:/tmp/relay.sock"})
	p := r.propose(Options{Executable: testExecutable})
	if got := allowed(t, p); !slices.Equal(got, []string{"unix:/tmp/relay.sock"}) {
		t.Errorf("net.allow = %v", got)
	}
	if w := p.Warnings()[0]; !strings.Contains(w, "the local socket unix:/tmp/relay.sock") {
		t.Errorf("warnings %q", p.Warnings())
	}
}

// TestLeakSystemLookupIsNoSend: nscd beside a secret read is the C library, never where the secret went.
func TestLeakSystemLookupIsNoSend(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "unix", Dst: "unix:/var/run/nscd/socket"})
	if p := r.propose(Options{Executable: testExecutable}); len(p.Leaks) != 0 {
		t.Errorf("leaks %+v", p.Leaks)
	}
}

// TestLeakLeftToCaller: the dashboard's proposal keeps every address, for its own verdict to withhold, and says
// nothing about a check it did not make.
func TestLeakLeftToCaller(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.sent(sink, "")
	p := r.propose(Options{Executable: testExecutable, LeaveLeaksToCaller: true})
	if len(p.Leaks) != 0 || p.LeakChecked {
		t.Errorf("leaks %+v, checked %v", p.Leaks, p.LeakChecked)
	}
	if got := allowed(t, p); !slices.Equal(got, []string{"tcp://" + sink}) {
		t.Errorf("net.allow = %v", got)
	}
	if text := p.Contract(); strings.Contains(text, "leaks: ") || strings.Contains(text, "# WARNING") {
		t.Errorf("the proposal speaks of a check it did not make:\n%s", text)
	}
}

// TestLeakWarningIsPrintable: a path is the agent's own choice, and a warning is a comment: a newline in it must not
// end the comment and start a line of YAML.
func TestLeakWarningIsPrintable(t *testing.T) {
	r := newRun(t, "/work")
	r.read("/home/u/.ssh/id_rsa\nnet:\n  allow: [\"tcp://198.51.100.1:443\"]")
	r.sent(sink, "")
	p := r.propose(Options{Executable: testExecutable})
	if len(p.Leaks) != 1 {
		t.Fatalf("leaks %+v", p.Leaks)
	}
	if got := allowed(t, p); len(got) != 0 {
		t.Errorf("a path in the warning wrote net.allow: %v", got)
	}
}

// TestLeakProposalSaysWhatItLeavesOpen: every proposal says env and reads stay open, in the file and in Warnings,
// leak or no leak.
func TestLeakProposalSaysWhatItLeavesOpen(t *testing.T) {
	r := newRun(t, "/work")
	r.read("/work/a.txt")
	p := r.propose(Options{Executable: testExecutable})
	text := p.Contract()
	for _, want := range []string{
		"env: there is no env section, so env stays open: every variable of the launcher's environment reaches the agent, secrets included.",
		"so reads stay open: the agent can read any file that list does not name.",
		"leaks: no place off the contract was first reached within 5 s and 16 lines of an open of a secret for reading.",
		"it does not judge system lookups or port 53 on this machine, and a place first reached before the read is not caught.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the proposal lacks %q:\n%s", want, text)
		}
	}
	w := p.Warnings()
	if len(w) != 1 || !strings.HasPrefix(w[0], "this proposal leaves env and reads open") {
		t.Errorf("warnings %q", w)
	}
}

// TestLeakFoldStaysSmall: a run that rereads a secret forever costs the fold nothing per line: it keeps the last
// NearLines lines' touches, not one per touch.
func TestLeakFoldStaysSmall(t *testing.T) {
	l := New(Options{})
	ts := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := range uint64(200_000) {
		e := &record.Event{V: record.Version, Seq: i, TS: ts, Kind: record.KindFS, Verdict: record.VerdictObserved}
		if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: keyFile}); err != nil {
			t.Fatal(err)
		}
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(l.leak.touches); n > 40 {
		t.Errorf("the fold holds %d touches", n)
	}
	if n := len(l.leak.secrets); n != 1 {
		t.Errorf("the fold holds %d secrets", n)
	}
	// A place next to many reads is one mark on the secret, not one per read.
	for i := range uint64(100) {
		e := &record.Event{V: record.Version, Seq: 200_000 + i, TS: ts, Kind: record.KindFS, Verdict: record.VerdictObserved}
		if i == 0 {
			e.Kind = record.KindNet
			if err := e.SetPayload(record.NetPayload{Proto: "tcp", Dst: sink}); err != nil {
				t.Fatal(err)
			}
		} else if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: keyFile}); err != nil {
			t.Fatal(err)
		}
		if err := l.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(l.leak.secrets[keyFile].near); n != 1 {
		t.Errorf("the secret holds %d near marks", n)
	}
}
