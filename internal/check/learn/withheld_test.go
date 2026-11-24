// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestLearnWritesWithheldHistory(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	r.sent(sink, "")
	r.sent(sink, "")
	r.add(record.KindNet, record.VerdictObserved, record.NetPayload{Proto: "udp", Dst: "203.0.113.7:8443"})
	p := r.propose(Options{Executable: testExecutable})
	text := p.Contract()
	if !strings.Contains(text, "learn:\n") || !strings.Contains(text, "withheld:") || !strings.Contains(text, `"tcp://`+sink+`"`) {
		t.Fatalf("withholding exists only in comments: %s", text)
	}
	c := load(t, text)
	canonical, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(canonical), "udp://203.0.113.7:8443") {
		t.Fatalf("lost the withheld UDP endpoint: %s", canonical)
	}
	if strings.Count(string(canonical), "tcp://203.0.113.9:443") != 1 {
		t.Fatalf("history repeats an endpoint: %s", canonical)
	}
	if !strings.Contains(string(canonical), "learn:") {
		t.Fatal("canonical contract lost withholding")
	}
	if len(c.Net.Allow) != 0 {
		t.Fatalf("history allowed the destination: %v", c.Net.Allow)
	}
	clean := newRun(t, "/work")
	clean.sent(sink, "")
	if strings.Contains(clean.propose(Options{Executable: testExecutable}).Contract(), "\nlearn:") {
		t.Fatal("a different watched run inherited withholding")
	}
}

func TestLearnContractTextTwiceOverOneRecordAgrees(t *testing.T) {
	r := newRun(t, "/work")
	r.read(keyFile)
	// Both a name and an address identify the same withheld place. Repeated
	// proposals must agree even when their internal maps iterate differently.
	r.sent(sink, "service.example")
	r.sent(sink, "")
	r.sent("203.0.113.7:8443", "other.example")
	r.sent("203.0.113.7:8443", "")
	r.net("udp", "[2001:db8::1]:8443")
	r.net("tcp", "[::ffff:203.0.113.9]:443")
	r.end(64*mib, 2, 0)
	want := r.propose(Options{}).Contract()
	c := load(t, want)
	if c.Learn == nil || len(c.Learn.Withheld) != 3 || len(c.Net.Allow) != 0 {
		t.Fatalf("fixture must withhold three distinct TCP/UDP endpoints: %+v", c)
	}
	for i := range 200 {
		if got := r.propose(Options{}).Contract(); got != want {
			t.Fatalf("proposal %d over the same record changed bytes:\nfirst:\n%s\nnext:\n%s", i+2, want, got)
		}
	}
}
