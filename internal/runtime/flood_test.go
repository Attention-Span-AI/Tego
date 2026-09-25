// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stressEnv lengthens the flood from its plain-run second to 10 s:
// TEGO_STRESS=1 go test -run PipelineFlood -v ./internal/runtime/.
const stressEnv = "TEGO_STRESS"

// TestPipelineFlood floods every lane at once, two producers each, into a real ledger Writer: the supervisor
// lane with nothing but refusals (each a refused line and a last-refusal.json rewrite), the capture lane with
// 8 KiB request bodies, the rest with fs lines. Every emitted event must be a line or counted in a gap, and
// the pipeline must stop when cancelled. The log line is the review's measure: before last-refusal.json was
// written off Append's path (M2), a refusal flood held the ledger to 140k lines in 10 s where 515k were
// written without it.
func TestPipelineFlood(t *testing.T) {
	dur := time.Second
	if os.Getenv(stressEnv) != "" {
		dur = 10 * time.Second
	}
	ref := record.RunRef{ID: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever"}
	dir := filepath.Join(t.TempDir(), ref.ID)
	w, err := ledger.Open(dir, ref, ledger.WithAnchor(ledger.NewFileChainAnchor(filepath.Join(t.TempDir(), "chain.log"))))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{}); err != nil {
		t.Fatal(err)
	}
	q := NewQueue(QueueCapacity)
	p := newPipeline(q, w.Append, ledger.RedactStage, w.SplitBlobsStage, runStamp{PID: 1, TID: 1, Cgroup: 2}, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	var captureLost atomic.Int64
	p.onCaptureLost = func(n int64) { captureLost.Add(n) }
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	close(started)
	done := make(chan struct{})
	go func() { _ = p.run(ctx, started); close(done) }()

	var emitted [numLanes]atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	body := strings.Repeat("y", 8<<10)
	for l := Lane(0); l < numLanes; l++ {
		for range 2 {
			wg.Go(func() {
				sink := q.Lane(l)
				for {
					select {
					case <-stop:
						return
					default:
					}
					var ev *record.Event
					switch l {
					case LaneSupervisor:
						ev = &record.Event{Kind: record.KindNet, Source: record.SourceSeccomp, Rule: "net.deny",
							Verdict: record.VerdictRefused, Reason: record.ReasonNetNotAllowed}
						_ = ev.SetPayload(record.NetPayload{Proto: "tcp", Dst: "10.0.0.1:443"})
					case LaneCapture:
						ev = &record.Event{Kind: record.KindSSLRequest, Source: record.SourceForwarder}
						_ = ev.SetPayload(map[string]any{"method": "POST", "path": "/v1/messages", "body": body})
						time.Sleep(200 * time.Microsecond)
					default:
						ev = &record.Event{Kind: record.KindFS, Source: record.SourceLandlock, Rule: "fs.read[/work]", Verdict: record.VerdictAllow}
						_ = ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/work/f"})
					}
					sink.Emit(ev)
					emitted[l].Add(1)
				}
			})
		}
	}
	time.Sleep(dur)
	close(stop)
	wg.Wait()
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the pipeline did not stop after its context was cancelled")
	}
	p.drain()
	q.Close()
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	var total int64
	for l := range emitted {
		total += emitted[l].Load()
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	kinds := map[record.Kind]int64{}
	var lost int64
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		kinds[e.Kind]++
		if e.Kind == record.KindGap {
			var g record.GapPayload
			if err := e.DecodePayload(&g); err != nil {
				t.Fatal(err)
			}
			if g.Why == GapChannelFull || g.Why == GapStageRefused {
				lost += int64(g.Count)
			}
		}
	}
	actions := kinds[record.KindFS] + kinds[record.KindNet] + kinds[record.KindSSLRequest]
	t.Logf("%v: emitted %d, written %d action lines (%.0f/s) and %d refused lines, %d counted lost, capture lost %d",
		dur, total, actions, float64(actions)/dur.Seconds(), kinds[record.KindRefused], lost, captureLost.Load())
	if actions+lost != total {
		t.Errorf("accounting: %d written + %d counted lost != %d emitted", actions, lost, total)
	}
	if kinds[record.KindRefused] == 0 {
		t.Error("no refused line: the supervisor lane's refusals were not mirrored")
	}
	b, err := os.ReadFile(filepath.Join(dir, ledger.LastRefusalFile))
	if err != nil || !strings.Contains(string(b), `"reason":"net-not-allowed"`) {
		t.Errorf("last-refusal.json after Close: %s (%v)", b, err)
	}
}

// BenchmarkFillRequestSeq is an ssl_response given its request's seq, by body size: the payload is read for
// an existing request_seq and copied with the field inserted, on the pipeline goroutine.
func BenchmarkFillRequestSeq(b *testing.B) {
	for _, n := range []int{1 << 10, 256 << 10, 4 << 20} {
		b.Run(strconv.Itoa(n>>10)+"KiB", func(b *testing.B) {
			p := &pipeline{}
			payload, err := json.Marshal(map[string]any{"status": 200, "body": strings.Repeat("q", n)})
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				p.rememberRequest(7, 3)
				ev := &record.Event{Kind: record.KindSSLResponse, Pair: 7, Payload: payload}
				p.fillRequestSeq(ev)
			}
		})
	}
}
