// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// C205: an HTTP client's ask is placed on the process that holds its connection, and a process that hides its
// descriptors (PR_SET_DUMPABLE 0) is placed by exclusion or not at all. C206: the lookup is one exact request, and a
// connection's holder is searched for once.

// fakeProcs is a run's processes as a test lays them out.
type fakeProcs struct {
	mu     sync.Mutex
	dirs   map[uint64]string
	pids   map[string][]int
	state  map[int]fdState // a process's descriptors: absent is fdsRead
	holder int             // the pid that holds the socket
	start  map[int]uint64
	// Counts of what the relay asked.
	nDir, nPids, nHolds, nStart int
}

func (f *fakeProcs) Dir(id uint64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nDir++
	if d, ok := f.dirs[id]; ok {
		return d, nil
	}
	return "", errors.New("no such cgroup")
}

func (f *fakeProcs) Pids(dir string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nPids++
	return append([]int(nil), f.pids[dir]...)
}

func (f *fakeProcs) Holds(pid int, inode uint64) (bool, fdState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nHolds++
	st := f.state[pid]
	return st == fdsRead && pid == f.holder && inode == 77, st
}

func (f *fakeProcs) Start(pid int) (uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nStart++
	s, ok := f.start[pid]
	return s, ok
}

func (f *fakeProcs) counts() (pids, holds int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.nPids, f.nHolds
}

// layout is a run whose socket was made in cgroup 5 (dir "a", pids 100 and 200) under the run's cgroup 1 (dir "r", the
// same two and one more, 300).
func layout(holder int, state map[int]fdState) *fakeProcs {
	return &fakeProcs{
		dirs:   map[uint64]string{5: "a", 1: "r"},
		pids:   map[string][]int{"a": {100, 200}, "r": {100, 200, 300}},
		state:  state,
		holder: holder,
		start:  map[int]uint64{100: 1000, 200: 2000, 300: 3000},
	}
}

// askedRelay is an Adjustable relay for an http server whose calls to write_file are asked about, with the fake processes
// and a socket lookup that answers inode 77 in cgroup 5; every ask is approved and its request kept.
func askedRelay(t *testing.T, procs procView) (*Service, *sink, string, *[]ask.Request, *sync.Mutex) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc((&recorder{}).handler))
	t.Cleanup(up.Close)
	s, sk, _ := start(t, nil, Server{Name: "web", URL: up.URL + "/mcp", Rules: webRules()})
	h := s.https[0]
	h.admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	h.procs = procs
	h.sockInfo = func(netip.AddrPort, netip.AddrPort) (peer.SocketInfo, error) {
		return peer.SocketInfo{CgroupID: 5, Inode: 77}, nil
	}
	var mu sync.Mutex
	var reqs []ask.Request
	s.ConfigureMCPAsk(func(_ context.Context, r ask.Request) (ask.Decision, error) {
		mu.Lock()
		reqs = append(reqs, r)
		mu.Unlock()
		return ask.Decision{Approved: true}, nil
	})
	return s, sk, s.httpURLs()["web"], &reqs, &mu
}

func TestHTTPAskPlacesAClientThatHidesItsDescriptorsByExclusion(t *testing.T) {
	// 100 can be read and does not hold the socket; 200 hides its descriptors; 300 is not in the cgroup the socket was
	// made in. The socket is 200's.
	procs := layout(0, map[int]fdState{200: fdsHidden})
	_, sk, relay, reqs, mu := askedRelay(t, procs)
	code, body, _ := postJSON(t, relay, toolCall(1, "write_file"))
	if code != 200 || strings.Contains(body, "-32001") {
		t.Fatalf("status %d: %s: the asked call of a client whose descriptors are hidden was refused", code, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 || (*reqs)[0].PID != 200 || (*reqs)[0].TID != 200 || (*reqs)[0].Target != "web write_file" {
		t.Fatalf("asked %+v, want one card for process 200", *reqs)
	}
	l := sk.of(record.KindMCP)
	if len(l) != 1 || l[0].Verdict != record.VerdictAllow || l[0].PID != 200 || l[0].Authority != record.AuthorityHuman {
		t.Fatalf("mcp lines %+v", l)
	}
}

func TestHTTPAskNamesTheReadableHolderEvenWithHiddenProcessesAround(t *testing.T) {
	procs := layout(100, map[int]fdState{200: fdsHidden, 300: fdsHidden})
	_, _, relay, reqs, mu := askedRelay(t, procs)
	postJSON(t, relay, toolCall(1, "write_file"))
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 || (*reqs)[0].PID != 100 {
		t.Fatalf("asked %+v, want process 100, which holds the socket", *reqs)
	}
}

// TestHTTPAskIsRefusedWhenNoProcessCanBeTold: two processes that hide their descriptors, or one whose descriptors could
// not be listed for another reason, leave no process to name; a pid is never guessed, and the call is refused
// ask-unavailable and recorded.
func TestHTTPAskIsRefusedWhenNoProcessCanBeTold(t *testing.T) {
	for _, c := range []struct {
		name  string
		state map[int]fdState
	}{
		{"two hidden", map[int]fdState{100: fdsHidden, 200: fdsHidden}},
		{"one hidden, one unreadable", map[int]fdState{100: fdsUnknown, 200: fdsHidden}},
		{"hidden only in the run's wider cgroup, with another beside it", map[int]fdState{200: fdsHidden, 300: fdsHidden}},
		{"none hidden: the holder is nowhere", map[int]fdState{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, sk, relay, reqs, mu := askedRelay(t, layout(0, c.state))
			code, body, _ := postJSON(t, relay, toolCall(1, "write_file"))
			mu.Lock()
			n := len(*reqs)
			mu.Unlock()
			if code != 200 || !strings.Contains(body, "ask-unavailable") || n != 0 {
				t.Fatalf("status %d: %s, asked %d times", code, body, n)
			}
			l := sk.of(record.KindMCP)
			if len(l) != 1 || l[0].Verdict != record.VerdictRefused || string(l[0].Reason) != "ask-unavailable" || l[0].PID != 0 {
				t.Fatalf("mcp lines %+v", l)
			}
		})
	}
}

// TestHTTPConnectionSearchesForItsHolderOnce: a keep-alive connection that sends many calls pays for one search of the
// run's processes; each later call re-reads the holder's start and, at most, its descriptor list (C206).
func TestHTTPConnectionSearchesForItsHolderOnce(t *testing.T) {
	procs := layout(100, map[int]fdState{})
	_, _, relay, reqs, mu := askedRelay(t, procs)
	c := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}
	for i := range 8 {
		resp, err := c.Post(relay, "application/json", strings.NewReader(toolCall(i+1, "write_file")))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	mu.Lock()
	n := len(*reqs)
	mu.Unlock()
	pids, holds := procs.counts()
	if n != 8 {
		t.Fatalf("asked %d times, want 8", n)
	}
	if pids != 1 {
		t.Fatalf("the run's processes were listed %d times for 8 calls on one connection, want once", pids)
	}
	if holds > 1+7 {
		t.Fatalf("%d descriptor lists for 8 calls: the first call's search read one (the holder was first) and each later call at most one", holds)
	}
}

// TestHTTPHolderIsSearchedAgainWhenTheProcessIsAnother: the start time names one process over time; a pid reissued to
// another process is not the connection's holder.
func TestHTTPHolderIsSearchedAgainWhenTheProcessIsAnother(t *testing.T) {
	procs := layout(100, map[int]fdState{})
	_, _, relay, reqs, mu := askedRelay(t, procs)
	c := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}
	post := func(id int) {
		resp, err := c.Post(relay, "application/json", strings.NewReader(toolCall(id, "write_file")))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	post(1)
	procs.mu.Lock()
	procs.start[100] = 9999 // 100 is another process now
	procs.holder = 200
	procs.mu.Unlock()
	post(2)
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 2 || (*reqs)[0].PID != 100 || (*reqs)[1].PID != 200 {
		t.Fatalf("asked %+v, want process 100 then 200", *reqs)
	}
}

func TestPeerSocketInodeTakesTheExactLookup(t *testing.T) {
	old := socketInfo
	t.Cleanup(func() { socketInfo = old })
	socketInfo = func(netip.AddrPort, netip.AddrPort) (peer.SocketInfo, error) {
		return peer.SocketInfo{CgroupID: 4, Inode: 31337}, nil
	}
	opened := 0
	tcpTableOpened = func(string) { opened++ }
	t.Cleanup(func() { tcpTableOpened = nil })
	ino, err := peerSocketInode(netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2"))
	if err != nil || ino != 31337 || opened != 0 {
		t.Fatalf("inode %d, error %v, %d table reads: the exact lookup was not used", ino, err, opened)
	}
	// Where it fails (a kernel without TCP socket diagnostics), the tables answer, and an error is never an admission.
	socketInfo = func(netip.AddrPort, netip.AddrPort) (peer.SocketInfo, error) {
		return peer.SocketInfo{}, peer.ErrNoTCPDiag
	}
	if _, err := peerSocketInode(netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2")); err == nil || opened == 0 {
		t.Fatalf("a connection no table holds was placed: %v, %d table reads", err, opened)
	}
}

// TestHTTPConnectionWhoseHolderCannotBeToldIsNotSearchedOnEveryCall: a holder that could not be named is not looked for
// again by each call that follows on the connection within a moment; each is refused, as the first was.
func TestHTTPConnectionWhoseHolderCannotBeToldIsNotSearchedOnEveryCall(t *testing.T) {
	procs := layout(0, map[int]fdState{100: fdsHidden, 200: fdsHidden})
	_, sk, relay, reqs, mu := askedRelay(t, procs)
	c := &http.Client{Transport: &http.Transport{MaxConnsPerHost: 1}}
	for i := range 6 {
		resp, err := c.Post(relay, "application/json", strings.NewReader(toolCall(i+1, "write_file")))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	mu.Lock()
	n := len(*reqs)
	mu.Unlock()
	pids, _ := procs.counts()
	if n != 0 || pids > 2 {
		t.Fatalf("asked %d times; the run's processes were listed %d times for 6 calls (one search lists the socket's cgroup and the run's)", n, pids)
	}
	if l := sk.of(record.KindMCP); len(l) != 6 || l[5].Verdict != record.VerdictRefused {
		t.Fatalf("mcp lines %d", len(l))
	}
}
