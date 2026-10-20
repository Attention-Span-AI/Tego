// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package bpf

import (
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/platform/startphase"
)

// timing turns a test build's phase timing on for one test, with the lines collected rather than printed. The
// startphase sinks are process-wide, so the tests that use it do not run in parallel.
func timing(t *testing.T) (phases func() map[string]time.Duration, stacks func() []string) {
	t.Helper()
	var mu sync.Mutex
	ph := map[string]time.Duration{}
	var st []string
	prev, prevStat, prevStack := startphase.Default, startphase.DefaultStat, startphase.DefaultStack
	startphase.Default = func(name string, d time.Duration) { mu.Lock(); ph[name] = d; mu.Unlock() }
	startphase.DefaultStat = func(string, int64) {}
	startphase.DefaultStack = func(name string, n int, frames string) {
		mu.Lock()
		st = append(st, name+" "+frames)
		mu.Unlock()
	}
	t.Cleanup(func() {
		startphase.Default, startphase.DefaultStat, startphase.DefaultStack = prev, prevStat, prevStack
	})
	return func() map[string]time.Duration {
			mu.Lock()
			defer mu.Unlock()
			out := map[string]time.Duration{}
			for k, v := range ph {
				out[k] = v
			}
			return out
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), st...)
		}
}

// TestTestBuildAsksForStatisticsOnlyWithTiming: a test build asks the verifier for its statistics (and nothing more)
// only while its loads are attributed; with the phases timed but no TEGO_TEST_LOAD_STATS, or with neither, it loads
// as a product build does.
func TestTestBuildAsksForStatisticsOnlyWithTiming(t *testing.T) {
	prev, prevStat := startphase.Default, startphase.DefaultStat
	t.Cleanup(func() { startphase.Default, startphase.DefaultStat = prev, prevStat })
	for _, c := range []struct {
		name  string
		phase startphase.Sink
		stat  func(string, int64)
	}{
		{"neither", nil, nil},
		{"timed, not attributed", func(string, time.Duration) {}, nil},
	} {
		startphase.Default, startphase.DefaultStat = c.phase, c.stat
		if got := LoadOptions(); !reflect.DeepEqual(got, ebpf.ProgramOptions{}) || BeginLoad(nil, "m", "p") != nil {
			t.Fatalf("%s: LoadOptions() = %+v, want the zero options and no trace", c.name, got)
		}
	}
	startphase.Default, startphase.DefaultStat = prev, prevStat
	timing(t)
	if got := LoadOptions(); got.LogLevel != ebpf.LogLevelStats || got.LogDisabled || got.KernelTypes != nil {
		t.Fatalf("timing on: LoadOptions() = %+v, want LogLevelStats alone", got)
	}
}

// TestSamplerReportsTheStacksOfASlowLoad drives the stack sampler with a stand-in for /proc/self/task/<tid>/stack:
// a load that takes longer than the threshold reports the frames its thread was in, under the maps phase's name when
// no program was loaded. Run with -race: the sampler is a goroutine of its own beside the load.
func TestSamplerReportsTheStacksOfASlowLoad(t *testing.T) {
	_, stacks := timing(t)
	prevRead, prevEvery, prevSlow := readTaskStack, sampleEvery, slowLoad
	t.Cleanup(func() { readTaskStack, sampleEvery, slowLoad = prevRead, prevEvery, prevSlow })
	var mu sync.Mutex
	reads := 0
	readTaskStack = func(tid int) (string, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		return "[<0>] __mutex_lock+0x1/0x2\n[<0>] bpf_trampoline_get+0x1/0x2\n", nil
	}
	sampleEvery, slowLoad = 2*time.Millisecond, 10*time.Millisecond
	tr := BeginLoad(nil, "load.obj.trace_proc.maps", "load.prog.trace_proc")
	if tr == nil {
		t.Fatal("BeginLoad returned no trace with timing on")
	}
	time.Sleep(40 * time.Millisecond)
	tr.End(nil)
	mu.Lock()
	n := reads
	mu.Unlock()
	if n == 0 {
		t.Fatal("the sampler never read the loading thread's stack")
	}
	got := stacks()
	if len(got) == 0 || !strings.HasPrefix(got[0], "load.obj.trace_proc.maps __mutex_lock<bpf_trampoline_get") {
		t.Fatalf("stacks %q", got)
	}
	// The sampler has stopped: no read after End.
	time.Sleep(10 * time.Millisecond)
	mu.Lock()
	after := reads
	mu.Unlock()
	if after != n {
		t.Fatalf("the sampler read %d more stacks after End", after-n)
	}
}

// TestSamplerStopsOnAnUnreadableStack: a stack the process may not read (no CAP_SYS_ADMIN) stops the sampler at its
// first read rather than retrying every tick.
func TestSamplerStopsOnAnUnreadableStack(t *testing.T) {
	timing(t)
	prevRead, prevEvery := readTaskStack, sampleEvery
	t.Cleanup(func() { readTaskStack, sampleEvery = prevRead, prevEvery })
	var mu sync.Mutex
	reads := 0
	readTaskStack = func(int) (string, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		return "", os.ErrPermission
	}
	sampleEvery = time.Millisecond
	tr := BeginLoad(nil, "m", "p")
	time.Sleep(20 * time.Millisecond)
	tr.End(nil)
	mu.Lock()
	defer mu.Unlock()
	if reads != 1 {
		t.Fatalf("%d reads of an unreadable stack, want 1", reads)
	}
}
