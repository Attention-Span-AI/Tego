// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestStartDoesNotWaitForTheTrustRoots: the forwarder starts loading the system trust roots when it starts, and
// starting never waits for the load. The load here is held until the test lets it go, standing for a disk that is slow
// for Tego; Start must return, with the load begun and unfinished. (If Start waited, the test would end at its hang
// guard, not pass.)
func TestStartDoesNotWaitForTheTrustRoots(t *testing.T) {
	began := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})
	m, err := NewManager([]agent.ModelEndpoint{{Provider: "anthropic", Host: "a.example"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	// Registered after Stop so that it runs first: the load is let go before anything waits for Start's goroutines.
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
		<-finished
	})
	m.loadRoots = func() {
		close(began)
		<-release
		close(finished)
	}

	started := make(chan error, 1)
	go func() { started <- m.Start(context.Background(), testRun, &fakeSink{}) }()
	const hangGuard = 30 * time.Second
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(hangGuard):
		t.Fatalf("Start did not return in %s while the trust roots were loading: it waits for the load", hangGuard)
	}
	select {
	case <-began:
	case <-time.After(hangGuard):
		t.Fatal("Start did not begin loading the trust roots")
	}
	select {
	case <-finished:
		t.Fatal("the load finished before the test let it go")
	default:
	}
	close(release)
}

// TestThePreloadRunsTheSystemLoad: with no stand-in, the background load is the process's real one (x509's system pool,
// the one every handshake uses), and it ends.
func TestThePreloadRunsTheSystemLoad(t *testing.T) {
	done := make(chan struct{})
	preloadRoots(func() {
		loadSystemRoots()
		close(done)
	})
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the preload did not end")
	}
}
