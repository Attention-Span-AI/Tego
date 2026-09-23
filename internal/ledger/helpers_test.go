// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stepClock is a scripted Clock: every reading advances by step, so lines are deterministic and mono_ns is
// strictly increasing. Advance adds an extra delta before the next reading.
type stepClock struct {
	mu   sync.Mutex
	wall time.Time
	mono uint64
	step time.Duration
}

func newStepClock(start time.Time, mono uint64, step time.Duration) *stepClock {
	return &stepClock{wall: start, mono: mono, step: step}
}

func (c *stepClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.mono += uint64(d)
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(c.step)
	return c.wall
}

func (c *stepClock) Mono() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mono += uint64(c.step)
	return c.mono
}

// runID mints a run id whose time36 field encodes at, with a fixed host8 and rand6.
func runID(at time.Time, rand6 string) string {
	t36 := strconv.FormatInt(at.UnixNano(), 36)
	return "r-3f9c2a1b-" + strings.Repeat("0", 13-len(t36)) + t36 + "-" + rand6
}

var (
	fixedStart = time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	testRef    = record.RunRef{ID: runID(fixedStart, "k7m2pq"), Agent: "retriever"}
)

// memAnchor is an in-memory ChainAnchor that can be told to fail.
type memAnchor struct {
	mu    sync.Mutex
	heads map[string]string
	fail  error
}

func (a *memAnchor) Append(run, head string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return a.fail
	}
	if a.heads == nil {
		a.heads = map[string]string{}
	}
	a.heads[run] = head
	return nil
}

func (a *memAnchor) Head(run string) (string, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.heads[run]
	return h, ok, nil
}

// openTestWriter opens a Writer in a fresh temp run directory with a scripted clock and an in-memory anchor.
func openTestWriter(t *testing.T, opts ...Option) (*Writer, string, *memAnchor) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "runs", testRef.ID)
	anchor := &memAnchor{}
	all := append([]Option{WithClock(newStepClock(fixedStart, 5_000_000_000, time.Millisecond)), WithAnchor(anchor)}, opts...)
	w, err := Open(dir, testRef, all...)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return w, dir, anchor
}

func startPayload() record.RunStartPayload {
	return record.RunStartPayload{
		LauncherPID: 48211, LauncherStartNS: 4_990_000_000, TegoVersion: "0.1.0-dev", Commit: "5330a30",
		Tier: "landlock", Capture: "forwarder", Kernel: "6.17.0-41-generic", ContractHash: strings.Repeat("7a", 32),
		Parsers: map[string]string{"anthropic": "1", "mcp": "1", "openai": "0"}, StopGrace: "10s",
		Command: []string{"python3", "agent.py", "--query", "summarize the repo"}, Cwd: "/home/u/proj",
		Limits: &record.Limits{Tokens: new(int64(60000)), CostUSD: new(2.0), Wall: "10m", StallAfter: "120s",
			Repeats: new(3)},
	}
}

// gapEvent is a minimal valid non-action event.
func gapEvent(why string) *record.Event {
	e := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
	_ = e.SetPayload(record.GapPayload{What: record.GapRecord, Why: why})
	return e
}

// fsEvent is a minimal valid action event.
func fsEvent(path string, payload any) *record.Event {
	e := &record.Event{
		Kind: record.KindFS, Source: record.SourceLandlock, PID: 48212, TID: 48212, Cgroup: 9001,
		Rule: "fs.write[./out]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
		Attr: record.Unattributed(),
	}
	if payload == nil {
		payload = record.FSPayload{Op: record.FSOpen, Path: path, Flags: 0x241}
	}
	_ = e.SetPayload(payload)
	return e
}

// tearTail puts the first half of a valid next line on disk without going through Append: what a process
// killed inside write(2) leaves behind.
func tearTail(t *testing.T, w *Writer) {
	t.Helper()
	e := gapEvent("torn")
	e.V, e.Run, e.Agent, e.Seq, e.Prev, e.TS = record.Version, w.ref.ID, w.ref.Agent, w.Seq(), w.Head(), fixedStart
	line, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.events.Write(line[:len(line)/2]); err != nil {
		t.Fatal(err)
	}
}

// startRun writes run_start and n gap events.
func startRun(t *testing.T, w *Writer, n int) {
	t.Helper()
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatalf("WriteRunStart: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := w.Append(gapEvent("e" + strconv.Itoa(i))); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
}

func readAll(t *testing.T, dir string) []*record.Event {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	var out []*record.Event
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatalf("Iter: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func verify(t *testing.T, dir string, anchor ChainAnchor) VerifyReport {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	rep, err := r.Verify(context.Background(), anchor)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return rep
}

func stateOf(t *testing.T, dir string) RunState {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer r.Close()
	s, err := r.State()
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	return s
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return st.Mode().Perm()
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
