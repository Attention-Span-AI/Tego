// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// syncBuffer is a bytes.Buffer a renderer writes on one goroutine while the test reads it on another.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const followRun = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"

// liveRun is a run directory whose lock the test holds, standing for a live Writer, and the chain so far.
type liveRun struct {
	t    *testing.T
	dir  string
	lock *os.File
	seq  uint64
	prev string
}

func newLiveRun(t *testing.T) *liveRun {
	t.Helper()
	dir := filepath.Join(t.TempDir(), followRun)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	return &liveRun{t: t, dir: dir, lock: lock}
}

// add appends one chained line of kind k.
func (r *liveRun) add(k record.Kind) {
	r.t.Helper()
	e := &record.Event{
		V: record.Version, Seq: r.seq, Prev: r.prev, TS: time.Unix(0, int64(r.seq)*int64(time.Millisecond)).UTC(),
		Run: followRun, Agent: "synthetic", PID: 1, TID: 1, Kind: k, Source: record.SourceSupervisor,
	}
	var payload any
	switch k {
	case record.KindRunStart:
		payload = record.RunStartPayload{TegoVersion: "0.1.0-dev", Tier: "landlock", Capture: "off", StopGrace: "10s",
			Command: []string{"true"}, Cwd: "/home/u/proj", ContractHash: strings.Repeat("7a", 32)}
	case record.KindRunEnd:
		payload = record.RunEndPayload{Reason: record.RunEndExit}
	default:
		e.Source, e.Rule, e.Verdict, e.Authority = record.SourceLandlock, "fs.read[.]", record.VerdictAllow,
			record.AuthorityRule
		e.Attr = &record.Attribution{Confidence: "likely", Method: "tid"}
		payload = record.FSPayload{Op: record.FSOpen, Path: "/home/u/proj/a.txt"}
	}
	if err := e.SetPayload(payload); err != nil {
		r.t.Fatal(err)
	}
	line, err := e.MarshalLine()
	if err != nil {
		r.t.Fatalf("marshal seq %d: %v", r.seq, err)
	}
	f, err := os.OpenFile(filepath.Join(r.dir, ledger.EventsFile), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		r.t.Fatal(err)
	}
	r.seq++
	r.prev = e.ID
}

// waitFor waits until out holds want lines.
func waitFor(t *testing.T, out *syncBuffer, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for strings.Count(out.String(), "\n") < want {
		if time.Now().After(deadline) {
			t.Fatalf("output holds %d lines, want %d:\n%s", strings.Count(out.String(), "\n"), want, out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// followRender runs render over a Follower of r on a goroutine; the count and error arrive on the channel.
func followRender(t *testing.T, r *liveRun, out *syncBuffer, f Filter,
	render func(context.Context, *syncBuffer, *ledger.Follower, Filter) (int, error)) <-chan [2]any {
	t.Helper()
	fl, err := ledger.Follow(r.dir, ledger.Cursor{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fl.Close() })
	ch := make(chan [2]any, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		n, err := render(ctx, out, fl, f)
		ch <- [2]any{n, err}
	}()
	return ch
}

func tableRender(ctx context.Context, w *syncBuffer, fl *ledger.Follower, f Filter) (int, error) {
	return FollowTable(ctx, w, fl, f)
}

func jsonRender(ctx context.Context, w *syncBuffer, fl *ledger.Follower, f Filter) (int, error) {
	return FollowJSON(ctx, w, fl, f)
}

// TestFollowTableShowsEachRowAsItArrives: the table of a live run is on the terminal as soon as the follow has
// caught up, long before widthSample rows, each later line follows within moments, and at the end the output is
// what `events` prints for the whole run.
func TestFollowTableShowsEachRowAsItArrives(t *testing.T) {
	r := newLiveRun(t)
	r.add(record.KindRunStart)
	r.add(record.KindFS)
	r.add(record.KindFS)
	var out syncBuffer
	done := followRender(t, r, &out, Filter{}, tableRender)
	waitFor(t, &out, 4) // the header and three rows, flushed when the follow caught up
	r.add(record.KindFS)
	waitFor(t, &out, 5)
	r.add(record.KindRunEnd)
	_ = r.lock.Close() // the writer is done
	res := <-done
	if res[1] != nil || res[0].(int) != 5 {
		t.Fatalf("FollowTable = %v, %v; want 5 rows and a clean end", res[0], res[1])
	}
	rd, err := ledger.OpenReader(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	var want bytes.Buffer
	if _, err := Table(t.Context(), &want, rd, Filter{}); err != nil {
		t.Fatal(err)
	}
	if out.String() != want.String() {
		t.Fatalf("follow printed\n%s\nevents prints\n%s", out.String(), want.String())
	}
}

// TestFollowJSONIsTheStoredBytes: --follow --json prints each line byte for byte as it arrives, and at the end
// the output is the ledger file.
func TestFollowJSONIsTheStoredBytes(t *testing.T) {
	r := newLiveRun(t)
	r.add(record.KindRunStart)
	var out syncBuffer
	done := followRender(t, r, &out, Filter{}, jsonRender)
	waitFor(t, &out, 1)
	r.add(record.KindFS)
	waitFor(t, &out, 2)
	r.add(record.KindRunEnd)
	_ = r.lock.Close()
	res := <-done
	if res[1] != nil || res[0].(int) != 3 {
		t.Fatalf("FollowJSON = %v, %v; want 3 lines and a clean end", res[0], res[1])
	}
	stored, err := os.ReadFile(filepath.Join(r.dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != string(stored) {
		t.Fatalf("follow printed\n%s\nthe ledger holds\n%s", out.String(), stored)
	}
}

// TestFollowStopsAtTheLimitAndNamesABreak: --limit ends the follow at that many matches, without waiting for the
// run; a break in the chain names the file, as events does.
func TestFollowStopsAtTheLimitAndNamesABreak(t *testing.T) {
	r := newLiveRun(t)
	r.add(record.KindRunStart)
	r.add(record.KindFS)
	r.add(record.KindFS)
	var out syncBuffer
	f, err := ParseFilter([]string{"fs"}, nil, nil, nil, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	res := <-followRender(t, r, &out, f, jsonRender)
	if res[1] != nil || res[0].(int) != 1 {
		t.Fatalf("FollowJSON --limit 1 = %v, %v", res[0], res[1])
	}
	r.seq, r.prev = 7, strings.Repeat("ef", 32) // a gap: the chain breaks at line 4
	r.add(record.KindFS)
	var out2 syncBuffer
	res = <-followRender(t, r, &out2, Filter{}, tableRender)
	err, _ = res[1].(error)
	if !errors.Is(err, ledger.ErrCorruptLedger) || !strings.Contains(err.Error(), filepath.Join(r.dir, ledger.EventsFile)) {
		t.Fatalf("a break: %v, want ErrCorruptLedger naming the file", res[1])
	}
	if rows := strings.Count(out2.String(), "\n") - 1; rows != 3 {
		t.Fatalf("%d rows before the break, want 3:\n%s", rows, out2.String())
	}
}
