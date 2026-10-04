// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// Drive the production openRing path while Stop overlaps initialization. The recorder owns its
// loaded map descriptors and ring reader; the fixture's separately opened pinned maps remain usable.
func TestIntegrationRecorderStopDuringStartupClosesOwnedMaps(t *testing.T) {
	root, dir := pinRoot(t, "start-stop")
	outer, lost := pinRecorderMaps(t, dir)
	ring := placeRing(t, outer, 3)
	runSet := seedRunSet(t, dir, map[uint64]uint32{41: 3})
	entered, release := make(chan struct{}), make(chan struct{})
	r, err := New(Options{BPFHash: "start-stop", PinRoot: root, namespaceCheck: func() error {
		close(entered)
		<-release
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan error, 1), make(chan error, 1)
	go func() {
		started <- r.Start(context.Background(), source.RunRef{ID: "r", Agent: "a", CgroupID: 41}, &fakeSink{})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("Start did not reach namespace validation")
	}
	go func() { stopped <- r.Stop() }()
	select {
	case err := <-stopped:
		t.Errorf("Stop returned before startup finished: %v", err)
		// Keep the result available for the common join below.
		stopped <- err
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for name, done := range map[string]<-chan error{"Start": started, "Stop": stopped} {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not finish", name)
		}
	}
	if r.reader == nil {
		t.Fatal("startup never opened the run's ring")
	}
	var sample ringbuf.Record
	r.reader.SetDeadline(time.Now())
	if err := r.reader.ReadInto(&sample); !errors.Is(err, ringbuf.ErrClosed) {
		t.Errorf("owned reader after Stop = %v, want ringbuf.ErrClosed", err)
	}
	for _, closer := range r.owned {
		if m, ok := closer.(*ebpf.Map); ok && m.FD() >= 0 {
			t.Errorf("the recorder's ring descriptor remains open: %d", m.FD())
		}
	}
	for name, m := range map[string]*ebpf.Map{"ring outer": r.rings, "lost counter": r.lostMap} {
		if m.FD() >= 0 {
			t.Errorf("the recorder's %s descriptor remains open: %d", name, m.FD())
		}
	}
	if p, ok := r.runSetOwned.(*pinnedRunSet); !ok || p.m.FD() >= 0 {
		t.Error("the recorder's run-set descriptor remains open")
	}
	for name, m := range map[string]*ebpf.Map{"fixture ring outer": outer, "fixture lost counter": lost, "fixture ring": ring, "fixture run set": runSet} {
		if _, err := m.Info(); err != nil {
			t.Errorf("Stop closed %s owned by the fixture: %v", name, err)
		}
	}
	if r.Reading() {
		t.Error("the stopped recorder reports that it is reading")
	}
}
