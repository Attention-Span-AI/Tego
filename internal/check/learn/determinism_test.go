// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// manyAddressesRecord is a run that reads several secrets and reaches many destinations around them, by address and by
// name, over TCP and UDP, IPv4 and IPv6, with repeats: the shape of an agent that fetches a site answering from several
// addresses (acceptance 3, 2026-11-11, stumble 3: which addresses learn withheld changed from one recording to the next).
func manyAddressesRecord(t *testing.T) *run {
	t.Helper()
	r := newRun(t, "/work", "python3", "agent.py")
	for i := range 6 {
		r.sent(fmt.Sprintf("198.51.100.%d:443", i+1), "")
		r.sent(fmt.Sprintf("[2001:db8::%x]:443", i+1), "")
	}
	r.read("/home/u/.ssh/id_ed25519")
	for i := range 6 {
		r.sent(fmt.Sprintf("203.0.113.%d:443", i+1), "")
		r.sent(fmt.Sprintf("203.0.113.%d:443", i+1), "cdn.example.com")
		r.net("udp", fmt.Sprintf("[2001:db8:1::%x]:443", i+1))
	}
	r.read("/home/u/.aws/credentials")
	for i := range 6 {
		r.sent(fmt.Sprintf("192.0.2.%d:8443", i+1), "")
		r.sent(fmt.Sprintf("[2001:db8:2::%x]:443", i+1), "api.example.org")
	}
	r.padding(40)
	r.read("/home/u/.netrc")
	r.sent("203.0.113.200:443", "")
	r.net("udp", "10.0.0.1:53")
	r.net("tcp", "unix:/run/user/1000/bus")
	r.padding(5)
	r.sent("198.51.100.77:443", "")
	return r
}

// TestLearnTwiceOverOneRecordAgrees: `tego learn` over the same record gives the same proposal every time, the
// warnings and counts about the addresses it withholds included. Go randomises map iteration, and the leak rule, the net proposal and the render
// each fold the record through maps, so any order that leaked into the output shows within a few runs. The set of
// withheld addresses that differed between two recordings of one agent (acceptance 3, stumble 3) is the record's:
// each recording holds other addresses, in another order, at other times (TestWhichAddressesAreWithheldIsTheRecords).
func TestLearnTwiceOverOneRecordAgrees(t *testing.T) {
	r := manyAddressesRecord(t)
	type answer struct {
		contract, leaks, secrets, addrs string
		suggest                         bool
	}
	one := func() answer {
		p, err := propose(r.events, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return answer{p.Contract(), fmt.Sprint(leakDests(p)), fmt.Sprint(p.LeakSecrets), fmt.Sprint(p.AddressEntries()), p.SuggestHosts()}
	}
	first := one()
	if first.leaks == "[]" {
		t.Fatalf("the record withholds nothing, so the test holds nothing:\n%s", first.contract)
	}
	for i := range 200 {
		if got := one(); got != first {
			t.Fatalf("run %d differs from the first:\nfirst:\n%s\n%v\nthis:\n%s\n%v", i, first.contract, first, got.contract, got)
		}
	}
}

// TestWhichAddressesAreWithheldIsTheRecords: two recordings of one agent that reached the same site's two addresses, in
// another order and at another time, leave other addresses out. This is the leak rule working on what each recording
// holds (a send within 16 lines and 5 s of a secret read), not an order inside Tego: learn over each record gives the
// same answer every time (TestLearnTwiceOverOneRecordAgrees). The warning says so, so a person who records twice and
// sees two sets is not left to wonder (acceptance 3, 2026-11-11, stumble 3).
func TestWhichAddressesAreWithheldIsTheRecords(t *testing.T) {
	const v4, v6 = "104.20.23.154:443", "[2606:4700:10::6814:179a]:443"
	record := func(order ...string) *run {
		r := newRun(t, "/work", "python3", "agent.py")
		for _, dst := range order[:1] {
			r.sent(dst, "")
		}
		r.padding(20) // far from the read: more than 16 lines
		r.read("/home/u/.ssh/id_ed25519")
		for _, dst := range order[1:] {
			r.sent(dst, "")
		}
		return r
	}
	first := record(v4, v6)  // v4 was reached long before the read, v6 right after it
	second := record(v6, v4) // the other way round
	withheld := func(r *run) string {
		p, err := propose(r.events, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(p.Withheld())
	}
	if a, b := withheld(first), withheld(second); a == b || a != "["+v6+"]" || b != "["+v4+"]" {
		t.Errorf("recording 1 withholds %s, recording 2 withholds %s: want the address reached next to the read each time", a, b)
	}
	p, err := propose(first.events, Options{})
	if err != nil {
		t.Fatal(err)
	}
	warned := strings.Join(p.Warnings(), "\n")
	const says = "Which addresses are left out depends on this recording alone"
	if !strings.Contains(warned, says) {
		t.Errorf("the warning does not say the set comes from this recording:\n%s", warned)
	}
}

// TestTheExcludedEntrySetDoesNotDependOnWhichLeakOwnsIt: what the map order changed was which leak owns an exclusion
// (leakRule.held), so the warnings, the labels and the counts; the net.allow entries the proposal keeps and the ones it
// leaves out were the same set before the fix, and are the same after it. A review caught an earlier
// claim here that the set itself differed. The test compares the two sets over 200 runs of one record; it passes on the
// base too (checked with go test -overlay), which is the evidence for that.
func TestTheExcludedEntrySetDoesNotDependOnWhichLeakOwnsIt(t *testing.T) {
	r := manyAddressesRecord(t)
	sets := func() string {
		p, err := propose(r.events, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var kept, left []string
		for _, it := range p.Net {
			kept = append(kept, it.Value)
		}
		for _, ex := range p.Left {
			if ex.Section == "net" {
				left = append(left, ex.What)
			}
		}
		slices.Sort(kept)
		slices.Sort(left)
		return fmt.Sprint(kept, "|", left)
	}
	first := sets()
	if !strings.Contains(first, "|[") || strings.HasSuffix(first, "|[]") {
		t.Fatalf("the record leaves nothing out, so the test holds nothing: %s", first)
	}
	for i := range 200 {
		if got := sets(); got != first {
			t.Fatalf("run %d: kept and left-out entries differ:\n%s\n%s", i, first, got)
		}
	}
}
