// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An event's copy of a body is the body as a JSON string and nothing larger, encoded once,
// and it is counted by the budget for as long as the payload holding it is reachable.
//
// encoding/json's defaults escape <, > and & as six bytes each, so a body the agent fills with '<' comes
// out six times its size, and the old path also copied the body into a string and re-marshalled the whole
// payload around it: about 46 times the body allocated per event, none of it counted, and the payload
// then waited in the run queue after derive had given the exchange's bytes back (§3). Every byte class
// is here: the ones JSON must escape, the ones encoding/json escapes by choice, and runes of every width,
// so the copy has to decode back to exactly the body, blob(sha) included.
func TestAnEventCopyIsItsBodyEncodedOnce(t *testing.T) {
	var ascii []byte
	for c := range 0x80 {
		ascii = append(ascii, byte(c))
	}
	cases := []struct {
		name string
		body []byte
		// most is the longest the copy may be; 0 leaves the length to quotedLen alone.
		most int
	}{
		{"markup is copied as itself", bytes.Repeat([]byte("<>&"), 4096), 3*4096 + 2},
		{"every ASCII byte", ascii, 0},
		{"runes of every width and the JavaScript line separators", []byte("é漢🙂\u2028\u2029"), 0},
		{"a JSON request body", []byte(`{"model":"claude-opus-5","messages":[{"role":"user",` +
			`"content":"a \"quoted\" line\nand a path C:\\tmp"}]}`), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Listener{opts: Options{Bodies: true}, budget: newBudget(0, 0)}
			meta := record.SSLRequestPayload{Endpoint: "anthropic", Method: "POST", Path: "/v1/messages?a=<b>&c",
				Size: len(tc.body)}
			raw, cut, err := l.encodePayload(meta, tc.body, false, nil)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if cut {
				t.Error("a body the budget had room for was reported cut")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("the payload is not a JSON object: %v\n%s", err, raw)
			}
			member := fields["body"]
			var got string
			if err := json.Unmarshal(member, &got); err != nil {
				t.Fatalf("the body member is not a JSON string: %v", err)
			}
			if got != string(tc.body) {
				t.Errorf("the copy decodes to %q, want the body %q byte for byte", got, tc.body)
			}
			if len(member) != quotedLen(tc.body) {
				t.Errorf("the copy is %d bytes, want quotedLen's %d", len(member), quotedLen(tc.body))
			}
			if tc.most > 0 && len(member) > tc.most {
				t.Errorf("the copy of a %d byte body is %d bytes, want at most %d: markup needs no "+
					"escaping inside a JSON string", len(tc.body), len(member), tc.most)
			}
			var back record.SSLRequestPayload
			if err := json.Unmarshal(raw, &back); err != nil || back.Path != meta.Path || back.Size != meta.Size {
				t.Errorf("the payload's own fields came back as %+v (%v), want %+v", back, err, meta)
			}
			if used := l.budget.used.Load(); used != int64(len(member)) {
				t.Errorf("the budget counts %d bytes while the payload is held, want the copy's %d",
					used, len(member))
			}
			runtime.KeepAlive(raw)
		})
	}
}

// A size cut that lands inside a multi-byte rune keeps the prefix up to that rune, as a budget cut does, and
// does not lose the whole copy; a body that is not text before its tail is still left off.
func TestSizeCutMidRuneKeepsThePrefix(t *testing.T) {
	whole := strings.Repeat("é", 1500)
	cutBody := []byte(whole)[:1001]
	l := &Listener{opts: Options{Bodies: true}, budget: newBudget(1<<20, 0), gaps: map[string]int64{}}
	ev := &record.Event{}
	l.setPayload(ev, record.SSLRequestPayload{Method: "POST"}, cutBody, true, true, nil)
	var p struct {
		Body *string `json:"body"`
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Body == nil || *p.Body != whole[:1000] {
		t.Fatalf("kept %v, want the 1000 bytes before the split rune", p.Body)
	}
	bad := append([]byte{0xff, 'a'}, cutBody...)
	ev = &record.Event{}
	l.setPayload(ev, record.SSLRequestPayload{Method: "POST"}, bad, true, true, nil)
	if strings.Contains(string(ev.Payload), `"body"`) {
		t.Errorf("a body invalid before its tail was kept: %s", ev.Payload)
	}
}

// A copy the budget cannot hold whole keeps the longest prefix whose encoding fits, cut
// between runes, and says it was cut; one that fits nothing is left off. A cut inside a rune would leave
// bytes a JSON decoder turns into U+FFFD, so blob(sha) would hash something the wire never carried.
func TestAnEventCopyKeepsWhatTheBudgetGrants(t *testing.T) {
	body := []byte(strings.Repeat("aé\n", 100))
	for _, room := range []int{0, 1, 2, 3, 4, 5, 6, 7, 50, quotedLen(body) - 1} {
		l := &Listener{opts: Options{Bodies: true}, budget: newBudget(1<<20, 0)}
		l.budget.take(int(l.budget.limit)-room, int(l.budget.limit)-room)
		raw, cut, err := l.encodePayload(record.SSLRequestPayload{Method: "POST"}, body, false, nil)
		if err != nil {
			t.Fatalf("room %d: encode: %v", room, err)
		}
		if !cut {
			t.Errorf("room %d: a copy the budget could not hold whole was not reported cut", room)
		}
		var p struct {
			Body *string `json:"body"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("room %d: %v", room, err)
		}
		if p.Body == nil {
			if room >= 3 {
				t.Errorf("room %d: no copy at all, when %q fits", room, "a")
			}
			continue
		}
		kept := *p.Body
		if kept == "" || !strings.HasPrefix(string(body), kept) || !utf8.ValidString(kept) {
			t.Errorf("room %d: kept %q, want a non-empty prefix of the body cut between runes", room, kept)
		}
		if n := quotedLen([]byte(kept)); n > room {
			t.Errorf("room %d: the copy is %d bytes, more than the budget granted", room, n)
		}
		_, width := utf8.DecodeRune(body[len(kept):])
		if next := quotedLen(body[:len(kept)+width]); next <= room {
			t.Errorf("room %d: kept %d bytes when the next rune fits too (%d)", room, len(kept), next)
		}
		runtime.KeepAlive(raw)
	}
}

// A copy that fits nothing reserves nothing. At 2 or 3 bytes of room and a body whose first
// rune does not fit beside the quotes, the empty prefix's two quote bytes were counted as the copy's cost
// and never given back, since no copy was made to hold them: every such event left the budget 2 bytes
// smaller for the rest of the run.
func TestAnEmptyEventCopyGivesItsGrantBack(t *testing.T) {
	for _, body := range []string{"éé", "\\n", "\x01a"} {
		for _, room := range []int{2, 3} {
			l := &Listener{opts: Options{Bodies: true}, budget: newBudget(1<<20, 0)}
			l.budget.take(int(l.budget.limit)-room, int(l.budget.limit)-room)
			before := l.budget.used.Load()
			raw, _, err := l.encodePayload(record.SSLRequestPayload{Method: "POST"}, []byte(body), false, nil)
			if err != nil {
				t.Fatalf("%q room %d: encode: %v", body, room, err)
			}
			if strings.Contains(string(raw), `"body"`) {
				continue
			}
			if after := l.budget.used.Load(); after != before {
				t.Errorf("%q room %d: no copy was kept, yet the budget counts %d bytes more", body, room,
					after-before)
			}
			runtime.KeepAlive(raw)
		}
	}
}

// A ledger writer that falls behind cannot make capture hold more than the budget.
//
// An event's copy of a body waits in the run queue until the single writer reaches it, and that queue is
// thousands of events deep. The sink here keeps every event, which is what a writer that has not reached
// them yet amounts to, and the agent sends one full request after another. Were the copies given back
// with the exchange, as the old path did, each would be counted only for the moment it was made and the
// sink would end up holding every body sent — here several times the budget, and in a real run as many
// bodies as the queue has slots. Counted until they are unreachable, the copies stop at the budget: the
// later requests keep less of their bodies and say so, while the upstream still gets every byte (§7).
func TestAWriterThatFallsBehindCannotMakeCaptureHoldMore(t *testing.T) {
	const (
		maxBody = 4096
		size    = 4000
		calls   = 12
	)
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}, Options{MaxBody: maxBody, MaxCaptureBytes: 1})
	limit := h.listener.budget.limit
	body := bytes.Repeat([]byte("<"), size)
	if int64(calls*quotedLen(body)) <= 2*limit {
		t.Fatalf("%d copies of %d bytes do not overrun a budget of %d, so nothing here is under pressure",
			calls, quotedLen(body), limit)
	}
	for range calls {
		if status := roundTrip(t, h, newPost(t, h, body)); status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
	}
	h.sink.waitFor(t, record.KindSSLResponse, calls)

	// Every exchange has ended, so once the last derive has given its buffers back, what the budget
	// counts is exactly the copies the sink is holding.
	held := func() (sum int64) {
		for _, ev := range h.sink.all() {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(ev.Payload, &fields); err != nil {
				t.Fatalf("payload: %v", err)
			}
			sum += int64(len(fields["body"]))
		}
		return sum
	}
	deadline := time.Now().Add(5 * time.Second)
	for h.listener.budget.used.Load() != held() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	copies, used := held(), h.listener.budget.used.Load()
	if copies > limit {
		t.Errorf("the sink holds %d bytes of body copies against a budget of %d: a writer that falls "+
			"behind makes capture hold whatever the agent sends", copies, limit)
	}
	if used != copies {
		t.Errorf("the budget counts %d bytes while the sink holds %d bytes of copies and nothing else is "+
			"in flight: a copy is counted only while something holds it", used, copies)
	}
	if gapCount(h.listener, GapSizeCap) == 0 {
		t.Error("the copies the budget cut short were not counted as size-cap gaps (I4)")
	}
	waitForBudgetReturned(t, h)
}

// Bytes counted for copies nothing references any more come back without anyone else
// collecting.
//
// A copy's reservation goes back when the collector finds it unreachable, and the collector runs when the
// heap has grown enough, which a capture the budget is refusing is not doing: its buffers are the
// allocations it has stopped making. So a take that comes up short while copies are counted starts a
// collection itself. Here the whole budget is held for an array that is dropped straight away, the heap
// is left small, and nothing in the test collects: capture must still get its room back.
func TestAShortTakeAsksForTheCollectionItIsWaitingOn(t *testing.T) {
	b := newBudget(1<<20, 0)
	func() {
		copyOfABody := make([]byte, 4096)
		b.holdWhileReachable(copyOfABody, b.take(int(b.limit), int(b.limit)))
	}()
	if got := b.take(1, 1); got != 0 {
		t.Fatalf("take(1) = %d with the whole budget held", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b.take(1, 1) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the budget still counts %d bytes for an array nothing has referenced for 5s: "+
				"capture waits on a collection nobody asked for", b.used.Load())
		}
		time.Sleep(time.Millisecond)
	}
	if n := b.awaiting.Load(); n != 0 {
		t.Errorf("%d bytes still awaiting the collector after the copy went back", n)
	}
}

// A copy something still references stays counted however often the collector runs, and goes
// back once nothing does.
func TestACopyStaysCountedWhileItIsReachable(t *testing.T) {
	b := newBudget(1<<20, 0)
	copyOfABody := make([]byte, 4096)
	b.holdWhileReachable(copyOfABody, b.take(len(copyOfABody), len(copyOfABody)))
	runtime.GC()
	runtime.GC()
	if used := b.used.Load(); used != int64(len(copyOfABody)) {
		t.Errorf("used = %d while the copy is still referenced, want %d", used, len(copyOfABody))
	}
	runtime.KeepAlive(copyOfABody)
	deadline := time.Now().Add(5 * time.Second)
	for b.used.Load() != 0 && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
	if used := b.used.Load(); used != 0 {
		t.Errorf("used = %d after the copy became unreachable, want 0", used)
	}
}
