// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
)

// fakeCounter stands in for a program's recursion_misses.
type fakeCounter struct {
	n      uint64
	err    error
	closed int
}

func (c *fakeCounter) misses() (uint64, error) { return c.n, c.err }
func (c *fakeCounter) close() error            { c.closed++; return nil }

// fakeLinker names links whose counters are the given fakes.
type fakeLinker map[string]*fakeCounter

func (f fakeLinker) skipLinks() []namedLink {
	var out []namedLink
	for name, c := range f {
		if c == nil {
			out = append(out, namedLink{name: name, open: func() (programCounter, error) {
				return nil, errors.New("program gone")
			}})
			continue
		}
		out = append(out, namedLink{name: name, open: func() (programCounter, error) { return c, nil }})
	}
	return out
}

// countingKernel replaces kernelCountsSkips for one test.
func countingKernel(t *testing.T, err error) {
	t.Helper()
	old := kernelCountsSkips
	kernelCountsSkips = func() error { return err }
	t.Cleanup(func() { kernelCountsSkips = old })
}

// TestSkipWantIsWhatTheRunReliesOn: every run watches cgroup_mkdir; a plane run watches its mode's hooks, the exec pin
// check only when pinned; a run with listener policy watches the listener cleanup; nothing else (ADR 0148).
func TestSkipWantIsWhatTheRunReliesOn(t *testing.T) {
	hook := planeProgram(ebpfbindings.PlaneHooks[0], ebpfbindings.PlaneLSM)
	fmrHook := planeProgram(ebpfbindings.PlaneHooks[0], ebpfbindings.PlaneFmodRet)
	pin := ebpfbindings.PlaneExecPinProgram(ebpfbindings.PlaneLSM)
	for _, c := range []struct {
		name             string
		mode             ebpfbindings.PlaneMode
		pinned, listener bool
		has, hasNot      []string
	}{
		{name: "fanotify fallback", has: []string{ebpfbindings.ProgCgroupMkdir},
			hasNot: []string{hook, pin, ebpfbindings.ProgBindResult, ebpfbindings.ProgCgroupRmdir, ebpfbindings.ProgFileOpen}},
		{name: "lsm unpinned", mode: ebpfbindings.PlaneLSM, has: []string{ebpfbindings.ProgCgroupMkdir, hook},
			hasNot: []string{pin, fmrHook, ebpfbindings.ProgListenResult}},
		{name: "lsm pinned with listener", mode: ebpfbindings.PlaneLSM, pinned: true, listener: true,
			has: []string{hook, pin, ebpfbindings.ProgBindResult, ebpfbindings.ProgListenResult,
				ebpfbindings.ProgURingBindResult, ebpfbindings.ProgURingListenResult}},
		{name: "fmod_ret", mode: ebpfbindings.PlaneFmodRet, has: []string{fmrHook}, hasNot: []string{hook}},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := skipWant(c.mode, c.pinned, c.listener)
			if want[ebpfbindings.ProgCgroupMkdir] != skipTracking {
				t.Errorf("cgroup_mkdir is not watched as tracking: %v", want)
			}
			for _, name := range c.has {
				if _, ok := want[name]; !ok {
					t.Errorf("%s not watched", name)
				}
			}
			for _, name := range c.hasNot {
				if _, ok := want[name]; ok {
					t.Errorf("%s watched", name)
				}
			}
			for name, class := range want {
				if name != ebpfbindings.ProgCgroupMkdir && class != skipDeciding {
					t.Errorf("%s watched as %v", name, class)
				}
			}
		})
	}
}

// TestSkipWatchSumsEachClassFromTheLinksItWants: only wanted links are opened, and each class sums its own.
func TestSkipWatchSumsEachClassFromTheLinksItWants(t *testing.T) {
	countingKernel(t, nil)
	mkdir, hook, recorder := &fakeCounter{n: 4}, &fakeCounter{n: 10}, &fakeCounter{n: 124}
	want := map[string]skipClass{ebpfbindings.ProgCgroupMkdir: skipTracking, "tego_lsm_file_open": skipDeciding}
	w, err := buildSkipWatch(want, fakeLinker{ebpfbindings.ProgCgroupMkdir: mkdir, ebpfbindings.ProgFileOpen: recorder},
		fakeLinker{"tego_lsm_file_open": hook}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.read()
	if err != nil || got != (ProgramSkips{Deciding: 10, Tracking: 4, Programs: 2}) {
		t.Fatalf("read = %+v, %v", got, err)
	}
	hook.n = 11
	if got, _ := w.read(); got.Deciding != 11 {
		t.Fatalf("read after a skip = %+v", got)
	}
	if err := w.close(); err != nil || mkdir.closed != 1 || hook.closed != 1 || recorder.closed != 0 {
		t.Fatalf("close: %v (closed %d %d %d)", err, mkdir.closed, hook.closed, recorder.closed)
	}
	if _, err := w.read(); err == nil {
		t.Fatal("a closed watch read as no skips")
	}
}

// TestSkipWatchFailsWholeOnOneUnreadableCounter: a partial sum would read as fewer skips.
func TestSkipWatchFailsWholeOnOneUnreadableCounter(t *testing.T) {
	countingKernel(t, nil)
	want := map[string]skipClass{ebpfbindings.ProgCgroupMkdir: skipTracking, "a": skipDeciding}
	w, err := buildSkipWatch(want, fakeLinker{ebpfbindings.ProgCgroupMkdir: {n: 1}, "a": {err: errors.New("EBADF")}})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := w.read(); err == nil || !strings.Contains(err.Error(), "EBADF") {
		t.Fatalf("read = %+v, %v; want the counter's error", got, err)
	}
}

// TestBuildSkipWatchFailsClosed: a kernel that counts no skips, or a wanted program that cannot be opened, is no watch,
// and what was opened before the failure is closed.
func TestBuildSkipWatchFailsClosed(t *testing.T) {
	countingKernel(t, errors.New("no recursion_misses"))
	if _, err := buildSkipWatch(map[string]skipClass{"a": skipDeciding}, fakeLinker{"a": {}}); err == nil {
		t.Fatal("a kernel with no skip counter was watched")
	}
	countingKernel(t, nil)
	opened := &fakeCounter{}
	_, err := buildSkipWatch(map[string]skipClass{"a": skipDeciding, "b": skipDeciding},
		fakeLinker{"a": opened}, fakeLinker{"b": nil})
	if err == nil || !strings.Contains(err.Error(), "program gone") {
		t.Fatalf("err = %v", err)
	}
	if opened.closed != 1 {
		t.Fatalf("the counter opened before the failure was closed %d times, want once", opened.closed)
	}
}

// TestProgramSkipsRefusesWithoutAttachedPrograms: a handle that has not prepared, or whose kernel names no links,
// refuses rather than read as no skips.
func TestProgramSkipsRefusesWithoutAttachedPrograms(t *testing.T) {
	if _, err := (&Handle{}).ProgramSkips(); err == nil {
		t.Fatal("an unprepared handle read its skip counters")
	}
	h := &Handle{kern: &fakeKernel{}, prepared: true}
	if _, err := h.ProgramSkips(); err == nil || !strings.Contains(err.Error(), "names no links") {
		t.Fatalf("err = %v", err)
	}
}
