// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSamplesWithNoWakeupAreReadOnTheReadInterval: trace_proc submits its opens, file operations and connects
// with BPF_RB_NO_WAKEUP, so nothing wakes a drain waiting on an empty ring when they arrive; the drain's own
// timed read has to fetch them. With the read deadline at the next flush, as it was, such samples waited for the
// flush interval (5 s by default, an hour here) or for the next exec or exit to wake the reader, and the uprobe
// source's hooks with them. Here they must be handled within a few read intervals, long before the flush.
func TestSamplesWithNoWakeupAreReadOnTheReadInterval(t *testing.T) {
	q := newQuietRing()
	r, sink, hook := startQuiet(t, context.Background(), q, Options{ReadInterval: 20 * time.Millisecond})
	q.push(endOfRun(70, 4000)...)
	want := "exec 70 77 /usr/bin/python3.13|open 70 77 /usr/lib/x86_64-linux-gnu/libssl.so.3|exit 70"
	deadline := time.Now().Add(2 * time.Second)
	for strings.Join(hook.all(), "|") != want {
		if time.Now().After(deadline) {
			t.Fatalf("2 s after samples reached the ring without a wakeup, the hook has seen %q: the drain only "+
				"reads them at its next flush (an hour away here)", hook.all())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(sink.byKind(record.KindExec)); n != 1 {
		t.Errorf("%d exec events, want 1", n)
	}
	stopWithin(t, r, 5*time.Second)
}

// TestReadDeadlineIsTheNearerOfReadAndFlush pins readBy: the drain's next read waits no longer than
// ReadInterval, and no longer than the next flush either.
func TestReadDeadlineIsTheNearerOfReadAndFlush(t *testing.T) {
	r := &Recorder{opts: Options{ReadInterval: 50 * time.Millisecond}}
	now := time.Unix(1000, 0)
	if got := r.readBy(now, now.Add(5*time.Second)); !got.Equal(now.Add(50 * time.Millisecond)) {
		t.Errorf("readBy with the flush 5 s away = %v, want now+50ms", got.Sub(now))
	}
	if got := r.readBy(now, now.Add(10*time.Millisecond)); !got.Equal(now.Add(10 * time.Millisecond)) {
		t.Errorf("readBy with the flush 10 ms away = %v, want the flush", got.Sub(now))
	}
	if r, err := New(Options{Rules: newFixture(t).rules, Reader: newQuietRing()}); err != nil || r.opts.ReadInterval != DefaultReadInterval {
		t.Errorf("New's ReadInterval = %v (%v), want DefaultReadInterval", r.opts.ReadInterval, err)
	}
}
