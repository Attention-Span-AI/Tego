// SPDX-License-Identifier: Apache-2.0

package cgroup_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/observe"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestOrdinarySubmountListenerHandoffEmitsOneRefusal(t *testing.T) {
	h, rt, path, sink, events := cgroup.OrdinarySubmountHandoffFixture(t)
	marked, ok := h.ListenerDevices()
	if !ok || !marked(unix.Mkdev(0, 77)) {
		t.Fatal("prepared listener did not hand over the different-device submount it marked")
	}
	mt, err := h.MountTable()
	if err != nil {
		t.Fatal(err)
	}
	// A post-6.12 ordering reports chain success even though the listener's subsequent decision refused the open.
	e := bpf.FSEvent{Hdr: bpf.Header{Version: observe.Version, Kind: uint16(observe.KindOpen), Size: uint32(observe.FSSize),
		TSMonoNS: 1, PID: uint32(os.Getpid()), TID: uint32(os.Getpid())}, Dev: 77, Ino: 1, PathOk: 1, RetOk: 1}
	copy(e.Path[:], path)
	ring := &handoffRing{sample: append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&e)), unsafe.Sizeof(e))...),
		consumed: make(chan struct{}), closed: make(chan struct{})}
	r, err := observe.New(observe.Options{Rules: rt, Reader: ring})
	if err != nil {
		t.Fatal(err)
	}
	r.SetListenerDevices(marked)
	r.SetMountTable(mt, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx, source.RunRef{ID: "run-1", Agent: "a"}, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Stop() }) // The explicit stop checks its error; cleanup also covers an early test failure.
	select {
	case <-ring.consumed:
	case <-time.After(2 * time.Second):
		t.Fatal("recorder did not consume the submount open")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	var fs []*record.Event
	for _, ev := range events() {
		if ev.Kind == record.KindFS {
			fs = append(fs, ev)
		}
	}
	if len(fs) != 1 || fs[0].Verdict != record.VerdictRefused || fs[0].Source != record.SourceFanotify || fs[0].Rule != "fs.deny_read[./outside/secret/]" {
		for _, ev := range fs {
			t.Logf("filesystem line: %+v", ev)
		}
		t.Fatalf("got %d filesystem lines, want exactly the listener's one refusal", len(fs))
	}
}

// handoffRing replays one record, then obeys the reader's deadline and close.
type handoffRing struct {
	mu               sync.Mutex
	sample           []byte
	deadline         time.Time
	consumed, closed chan struct{}
	once             sync.Once
}

func (r *handoffRing) ReadInto(rec *ringbuf.Record) error {
	r.mu.Lock()
	if r.sample != nil {
		rec.RawSample = append(rec.RawSample[:0], r.sample...)
		r.sample = nil
		close(r.consumed)
		r.mu.Unlock()
		return nil
	}
	deadline := r.deadline
	r.mu.Unlock()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-r.closed:
		return ringbuf.ErrClosed
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func (r *handoffRing) SetDeadline(deadline time.Time) {
	r.mu.Lock()
	r.deadline = deadline
	r.mu.Unlock()
}

func (r *handoffRing) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}
