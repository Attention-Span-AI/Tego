// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/syslookup"
)

// TestVerdictAndReceiptNameAnObservedUnspecSend is GAPS C61 on the dashboard's side. An observe run continues a send
// whose address is AF_UNSPEC (rule net.unspec-send, dst unspec): the dashboard's verdict used to leave it out as a
// disconnect, as the receipt counted it. Both now list the attempt under an unread destination, without claiming a send result; a
// connect(2) disassociation (rule net.unspec) stays out of both.
func TestVerdictAndReceiptNameAnObservedUnspecSend(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	const id = "r-unsp-0001-sendxx"
	seq := 0
	var ls []string
	add := func(kind, extra string) {
		ls = append(ls, line(id, "svc", seq, t0.Add(time.Duration(seq)*time.Millisecond), kind, extra))
		seq++
	}
	add("run_start", `"tier":"observe","command":["python3","probe.py"],"cwd":"/w/proj"`)
	add("net", `"rule":"net.unspec","verdict":"observed","dst":"unspec","proto":"udp"`)
	add("net", `"rule":"net.unspec-send","verdict":"observed","dst":"unspec","proto":"udp"`)
	add("net", `"rule":"net.unspec-send","verdict":"observed","dst":"unspec","proto":"udp"`)
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
			if d.Observed != 2 {
				t.Errorf("verdict: %q observed %d times, want 2", d.Key, d.Observed)
			}
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
	want := []string{syslookup.UnreadSendPlace}
	if !slices.Equal(verdict, want) || !slices.Equal(places, want) {
		t.Errorf("places: verdict %q, receipt %q; want %q on both", verdict, places, want)
	}
	if rc.RoutineSockets != 1 {
		t.Errorf("receipt routine sockets %d, want 1 (the connect(2) reset only)", rc.RoutineSockets)
	}
}
