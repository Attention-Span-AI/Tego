// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"testing"
	"time"
)

// TestSignalOutboundOrderPutsSecretNeighboursFirst: a destination next to a secret leads the Outbound list (never one
// the contract allows: that is where the agent is meant to talk), then the other non-background refusals by count,
// then the rest (not in the contract before in it); OutHead and OutTail cut that order.
func TestSignalOutboundOrderPutsSecretNeighboursFirst(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0003-orderx"
	t0 := time.Date(2026, 10, 25, 23, 40, 0, 0, time.UTC)
	seq := 0
	add := func(dt time.Duration, kind, extra string) string {
		seq++
		return line(id, "supply-chain", seq, t0.Add(dt), kind, extra)
	}
	ls := []string{add(0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`)}
	refuse := func(dt time.Duration, target string) {
		ls = append(ls, add(dt, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"`+target+`"`))
	}
	refuse(time.Second, "203.0.113.8:443")
	for i := 0; i < 3; i++ { // more early refusals to a far host: leads the plain refusals
		refuse(time.Second, "203.0.113.7:443")
	}
	ls = append(ls,
		add(time.Second, "net", `"rule":"unmatched","verdict":"observed","dst":"198.51.100.9:443","proto":"tcp"`),
		add(time.Second, "net", `"rule":"net[tcp://api.example:443]","verdict":"allow","dst":"192.0.2.1:443","host":"api.example","proto":"tcp"`))
	for i := 0; i < 40; i++ { // the attack comes later, the lines in between put it out of reach of the early ones
		ls = append(ls, add(time.Minute, "net", `"rule":"net[tcp://api.example:443]","verdict":"allow","dst":"192.0.2.1:443","host":"api.example","proto":"tcp"`))
	}
	ls = append(ls,
		add(2*time.Minute, "fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`),
		add(2*time.Minute, "net", `"rule":"net[127.0.0.1:8803]","verdict":"allow","dst":"127.0.0.1:8803","host":"127.0.0.1","proto":"tcp"`))
	refuse(2*time.Minute, "127.0.0.1:8802")
	ls = append(ls, add(3*time.Minute, "run_end", `"reason":"exit","exit_code":0`))
	writeRun(t, root, id, ls...)
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	s := Signal(r, Sensitive{Cwd: r.Cwd})
	var got []string
	for _, d := range s.Outbound {
		got = append(got, d.Key)
	}
	want := []string{"127.0.0.1:8802", "203.0.113.7:443", "203.0.113.8:443", "198.51.100.9:443", "api.example:443", "127.0.0.1:8803"}
	if !slices.Equal(got, want) {
		t.Fatalf("outbound order %v, want %v", got, want)
	}
	if s.Outbound[5].NearSecret || !s.Outbound[5].InContract {
		t.Fatalf("the allowed 127.0.0.1:8803 %+v is marked next to a secret", s.Outbound[5])
	}
	if h, tl := s.OutHead(2), s.OutTail(2); len(h) != 2 || h[0].Key != "127.0.0.1:8802" || len(tl) != 4 {
		t.Fatalf("head %v tail %d: the secret neighbour belongs above the fold", h, len(tl))
	}
}
