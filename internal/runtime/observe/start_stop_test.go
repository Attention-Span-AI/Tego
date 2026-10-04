// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

func TestRecorderCannotStartAfterStop(t *testing.T) {
	ring := newFakeRing()
	r, err := New(Options{Reader: ring})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(context.Background(), source.RunRef{ID: "r", Agent: "a"}, &fakeSink{}); !errors.Is(err, ErrStopped) {
		t.Errorf("Start after Stop = %v, want ErrStopped", err)
		_ = r.Stop() // join the incorrectly restarted drain before the test exits
	}
	if err := r.AddProcessHook(nil); !errors.Is(err, ErrStopped) {
		t.Errorf("AddProcessHook after Stop = %v, want ErrStopped", err)
	}
	if r.Reading() {
		t.Error("a stopped recorder reports that it is reading")
	}
}

func TestRecorderStopJoinsStartupBeforeClosingReader(t *testing.T) {
	ring := newFakeRing()
	entered, release := make(chan struct{}), make(chan struct{})
	r, err := New(Options{Reader: ring, RunSet: &fakeRunSet{rows: map[uint64]uint32{41: 3}},
		namespaceCheck: func() error {
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
	if r.Reading() {
		t.Error("a recorder still selecting its run's ring reports that it is reading")
	}
	go func() { stopped <- r.Stop() }()
	select {
	case <-ring.closed:
		t.Error("Stop closed the reader while Start could still publish owned resources")
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
	select {
	case <-ring.closed:
	default:
		t.Error("Stop left the initialized reader open")
	}
	if r.Reading() {
		t.Error("a stopped recorder reports that it is reading")
	}
}
