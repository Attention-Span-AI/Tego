// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestCompilerColdGrammarCancellationReleasesAdmission(t *testing.T) {
	cache := new(grammarFingerprintCache)
	previous := builtinGrammar
	builtinGrammar = cache
	started, release, initialized := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		_, _ = cache.get(context.Background(), func() (string, error) {
			calls.Add(1)
			close(started)
			<-release
			return "cached-test-fingerprint", nil
		})
		close(initialized)
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, cap(slots))
	received := 0
	t.Cleanup(func() {
		defer func() { builtinGrammar = previous }()
		cancel()
		close(release)
		<-initialized
		for received < cap(slots) {
			select {
			case <-done:
				received++
			case <-time.After(time.Second):
				t.Error("canceled cache waiter did not finish after test release")
				return
			}
		}
	})
	for i := 0; i < cap(slots); i++ {
		go func() { _, err := Check(ctx, Request{Machine: &config.Machine{}}); done <- err }()
	}
	waitSlots(t, cap(slots))
	cancel()
	for i := 0; i < cap(slots); i++ {
		select {
		case err := <-done:
			received++
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cold grammar cancellation: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("cold grammar initialization held a canceled HTTP worker")
		}
	}
	if len(slots) != 0 {
		t.Fatal("canceled cold grammar wait kept admission slots")
	}
	if calls.Load() != 1 {
		t.Fatal("requests started more than one grammar initializer")
	}
	select {
	case <-initialized:
		t.Fatal("the test initializer finished before being released")
	default:
	}
}

func TestGrammarFingerprintCacheSharesResult(t *testing.T) {
	cache := new(grammarFingerprintCache)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls int
	compute := func() (string, error) { calls++; return "fingerprint", nil }
	if _, err := cache.get(ctx, compute); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("already canceled wait started initialization")
	}
	for i := 0; i < 2; i++ {
		value, err := cache.get(context.Background(), compute)
		if value != "fingerprint" || err != nil {
			t.Fatalf("cached result: %q %v", value, err)
		}
	}
	if calls != 1 {
		t.Fatal("warm request recomputed the grammar")
	}
}

func TestGrammarFingerprintCachePanicFailsClosed(t *testing.T) {
	cache := new(grammarFingerprintCache)
	for i := 0; i < 2; i++ {
		value, err := cache.get(context.Background(), func() (string, error) { panic("private implementation detail") })
		if value != "" || err == nil || err.Error() != "built-in grammar initialization failed" {
			t.Fatal("initializer panic did not become a shared generic failure")
		}
	}
}
