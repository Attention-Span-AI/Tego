// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLanesNumberTurnsInFlight: a process's turns in flight at once take distinct lanes, a turn after the
// others ended takes the lowest free one, processes are counted apart, and a retry takes its original's lane
// when that lane is free.
func TestLanesNumberTurnsInFlight(t *testing.T) {
	l := newLanes()
	a := l.acquire(10, "x1", "")
	b := l.acquire(10, "x2", "")
	c := l.acquire(20, "y1", "")
	if a != 1 || b != 2 || c != 1 {
		t.Fatalf("lanes %d %d for one process's two turns, %d for another's first; want 1 2 1", a, b, c)
	}
	l.release(10, a)
	if got := l.acquire(10, "x3", ""); got != 1 {
		t.Errorf("a turn after lane 1 ended took lane %d, want 1", got)
	}
	l.release(10, 1)
	l.release(10, 2)
	if got := l.acquire(10, "x4", "x2"); got != 2 {
		t.Errorf("a retry of the turn that held lane 2 took lane %d, want 2", got)
	}
	if got := l.acquire(10, "x5", "x2"); got != 1 {
		t.Errorf("a retry whose original's lane is busy took lane %d, want the lowest free, 1", got)
	}
}

// TestLinesCarryThePeersProcess: at the forwarder, its lines were stamped by the pipeline with the launcher's pid and
// tid, so the ledger named tego as the model's caller. They carry the pid of the run's process that holds the
// connection, which R19a's admission resolves, and no tid, which a socket does not have.
func TestLinesCarryThePeersProcess(t *testing.T) {
	if _, err := liveCgroupID(); err != nil {
		t.Skipf("peer admission cannot place this process in a cgroup here: %v", err)
	}
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, Options{})
	resp := h.post("/v1/messages", []byte(`{"model":"m"}`), nil)
	_ = resp.Body.Close()
	req := h.sink.waitFor(t, record.KindSSLRequest, 1)[0]
	res := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	for _, ev := range []*record.Event{req, res} {
		if ev.PID != os.Getpid() || ev.TID != 0 || ev.Lane != 1 {
			t.Errorf("%s stamped pid %d tid %d lane %d, want this process %d, no tid, lane 1", ev.Kind, ev.PID, ev.TID,
				ev.Lane, os.Getpid())
		}
	}
}

// TestConcurrentTurnsTakeTwoLanes: two turns of one process in flight at once are two lanes, so derive sees two
// threads and R34 leaves an action between them unattributed; a turn after both ended is lane 1 again.
func TestConcurrentTurnsTakeTwoLanes(t *testing.T) {
	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()
	var mu sync.Mutex
	calls := 0
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		first := calls <= 2
		mu.Unlock()
		if first {
			arrived.Done()
			select {
			case <-both:
			case <-time.After(10 * time.Second):
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, Options{})
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := h.post("/v1/messages", []byte(`{"model":"m","n":`+strings.Repeat("1", i+1)+`}`), nil)
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	h.sink.waitFor(t, record.KindSSLResponse, 2)
	resp := h.post("/v1/messages", []byte(`{"model":"m","n":3}`), nil)
	_ = resp.Body.Close()
	reqs := h.sink.waitFor(t, record.KindSSLRequest, 3)
	lanes := map[uint64]int{}
	for _, ev := range reqs[:2] {
		lanes[ev.Lane]++
	}
	if lanes[1] != 1 || lanes[2] != 1 {
		t.Errorf("two turns in flight at once took lanes %v, want 1 and 2", lanes)
	}
	if reqs[2].Lane != 1 {
		t.Errorf("a turn after both ended took lane %d, want 1", reqs[2].Lane)
	}
}
