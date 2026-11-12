// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"testing"
	"time"
)

// TestReceiptAndVerdictAgreeOnPlaces: the dashboard's verdict and the receipt (tego receipt, tego watch's "seen:")
// read one record and must name the same places. glibc's connect(AF_UNSPEC) resets and its netlink socket name none
// (syslookup.NoPlace): the verdict has no destination for them and the receipt counts them in RoutineSockets. A unix
// socket, an address and any other family (a vsock, family 40) are places on both; nscd is routine on both.
func TestReceiptAndVerdictAgreeOnPlaces(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	const id = "r-plcs-0001-watchx"
	seq := 0
	var ls []string
	add := func(kind, extra string) {
		ls = append(ls, line(id, "svc", seq, t0.Add(time.Duration(seq)*time.Millisecond), kind, extra))
		seq++
	}
	add("run_start", `"tier":"observe","command":["python3","fetch.py"],"cwd":"/w/proj"`)
	for range 6 {
		add("net", `"rule":"net.unspec","verdict":"observed","dst":"unspec","proto":"udp"`)
	}
	add("net", `"rule":"route-query","verdict":"allow","dst":"family(16)","proto":"raw"`)
	add("net", `"rule":"unmatched","verdict":"observed","dst":"unix:/var/run/nscd/socket","proto":"unix"`)
	for range 3 {
		add("net", `"rule":"unmatched","verdict":"observed","dst":"151.101.0.223:443","proto":"tcp"`)
	}
	add("net", `"rule":"unmatched","verdict":"observed","dst":"unix:/tmp/agent.sock","proto":"unix"`)
	add("net", `"rule":"unmatched","verdict":"observed","dst":"family(40)","proto":"raw"`)
	add("run_end", `"reason":"exit","exit_code":0`)
	writeRun(t, root, id, ls...)

	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	run := s.Find(id)
	if run == nil {
		t.Fatal("run not loaded")
	}
	var verdict []string
	for _, d := range Signal(run, Sensitive{Cwd: run.Cwd}).Outbound {
		if !d.Background {
			verdict = append(verdict, d.Key)
		}
	}
	rc, err := LoadReceipt(t.Context(), root, id)
	if err != nil {
		t.Fatal(err)
	}
	var places []string
	for _, c := range rc.Connections {
		places = append(places, c.Destination)
	}
	slices.Sort(verdict)
	slices.Sort(places)
	want := []string{"151.101.0.223:443", "family(40)", "unix:/tmp/agent.sock"}
	if !slices.Equal(verdict, want) || !slices.Equal(places, want) {
		t.Errorf("places: verdict %q, receipt %q; want %q on both", verdict, places, want)
	}
	if rc.RoutineSockets != 7 || rc.SystemLookups != 1 {
		t.Errorf("receipt: routine sockets %d, system lookups %d; want 7 and 1", rc.RoutineSockets, rc.SystemLookups)
	}
}
