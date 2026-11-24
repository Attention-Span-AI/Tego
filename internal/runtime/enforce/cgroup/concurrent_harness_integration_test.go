// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

// Skip and Fatal both leave a testing function through Goexit. A skipped compiler must never arm the watchdog;
// a skipped tier check must release it before the next test can begin.
func TestConcurrentSetupWatchdogLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		buildSkip, tierSkip  bool
		wantStarts, wantEnds int
	}{
		{name: "build skips", buildSkip: true},
		{name: "tier skips", tierSkip: true, wantStarts: 1, wantEnds: 1},
		{name: "ready", wantStarts: 1, wantEnds: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built, starts, stops := false, 0, 0
			t.Run("setup", func(t *testing.T) {
				bin := concurrentSetup(t,
					func() string {
						if tc.buildSkip {
							t.Skip("compiler unavailable")
						}
						built = true
						return "test-binary"
					},
					func(bin string) {
						if starts != 1 || stops != 0 || bin != "test-binary" {
							t.Errorf("tier check: starts %d, stops %d, binary %q", starts, stops, bin)
						}
						if tc.tierSkip {
							t.Skip("tier unavailable")
						}
					},
					func() func() {
						if !built {
							t.Error("watchdog started before compilation finished")
						}
						starts++
						return func() { stops++ }
					})
				if stops != 1 || bin != "test-binary" {
					t.Errorf("completed setup: stops %d, binary %q", stops, bin)
				}
			})
			if starts != tc.wantStarts || stops != tc.wantEnds {
				t.Errorf("after setup ended: starts %d, stops %d; want %d and %d", starts, stops, tc.wantStarts, tc.wantEnds)
			}
		})
	}
}

func TestConcurrentKernelLogEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		openErr    error
		seekErr    error
		readErrs   []error
		wantErr    string
		wantFault  bool
		wantClosed int
	}{
		{name: "missing device", openErr: syscall.ENOENT, wantErr: "evidence unavailable"},
		{name: "permission denied", openErr: syscall.EPERM, wantErr: "evidence unavailable"},
		{name: "seek failed", seekErr: syscall.ESPIPE, wantErr: "evidence unavailable", wantClosed: 1},
		{name: "read failed", readErrs: []error{syscall.EIO}, wantErr: "evidence unavailable", wantClosed: 1},
		{name: "read failed after fault", readErrs: []error{nil, syscall.EIO}, wantErr: "evidence incomplete", wantFault: true, wantClosed: 1},
		{name: "records overwritten", readErrs: []error{syscall.EPIPE, syscall.EAGAIN}, wantErr: "records overwritten", wantClosed: 1},
		{name: "fault despite overwrite", readErrs: []error{syscall.EPIPE, nil, syscall.EAGAIN}, wantErr: "records overwritten", wantFault: true, wantClosed: 1},
		{name: "interrupted", readErrs: []error{syscall.EINTR, syscall.EAGAIN}, wantClosed: 1},
		{name: "clean end", readErrs: []error{syscall.EAGAIN}, wantClosed: 1},
		{name: "fault", readErrs: []error{nil, syscall.EAGAIN}, wantFault: true, wantClosed: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed, seeks, reads := 0, 0, 0
			k := openKernelLogWith(kernelLogOps{
				open: func() (int, error) { return 42, tc.openErr },
				seekEnd: func(fd int) error {
					seeks++
					return tc.seekErr
				},
				read: func(fd int, buf []byte) (int, error) {
					if reads == len(tc.readErrs) {
						t.Fatal("read past the log's end")
					}
					err := tc.readErrs[reads]
					reads++
					if err != nil {
						return 0, err
					}
					return copy(buf, "1,455,287231235,-;BUG: kernel NULL pointer dereference\n"), nil
				},
				close: func(fd int) error { closed++; return nil },
			})
			faults, err := k.ofNote()
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("evidence error %v, want %q", err, tc.wantErr)
			}
			if gotFault := strings.Contains(faults, "BUG:"); gotFault != tc.wantFault {
				t.Errorf("fault evidence %q, want fault %v", faults, tc.wantFault)
			}
			k.close()
			k.close()
			if closed != tc.wantClosed {
				t.Errorf("closed %d descriptors, want %d", closed, tc.wantClosed)
			}
			if tc.openErr != nil && seeks != 0 || (tc.openErr != nil || tc.seekErr != nil) && reads != 0 {
				t.Errorf("after unavailable evidence: seeks %d, reads %d", seeks, reads)
			}
		})
	}
	for _, tc := range []struct {
		name string
		read func(int, []byte) (int, error)
	}{
		{"unexpected end", func(int, []byte) (int, error) { return 0, nil }},
		{"closed", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &kernelLog{fd: 42, ops: kernelLogOps{read: tc.read}}
			if tc.read == nil {
				k.fd = -1
			}
			if _, err := k.ofNote(); err == nil {
				t.Error("unreadable kernel evidence reported as clean")
			}
		})
	}
}

func TestConcurrentKernelLogBoundedWhileDraining(t *testing.T) {
	var evidence kernelFaultEvidence
	for i := range 1000 {
		evidence.add(fmt.Sprintf("BUG: fault %d", i))
		if len(evidence.kept) > 60 || cap(evidence.kept) > 128 {
			t.Fatalf("retained %d records with capacity %d while draining", len(evidence.kept), cap(evidence.kept))
		}
	}
	got := evidence.faults()
	if lines := strings.Split(got, "\n"); len(lines) != 60 || lines[0] != "BUG: fault 940" || lines[59] != "BUG: fault 999" {
		t.Errorf("want the last 60 fault records, got %q", got)
	}
	readCount := 0
	k := &kernelLog{fd: 42, ops: kernelLogOps{read: func(_ int, buf []byte) (int, error) {
		readCount++
		if readCount <= 1000 {
			return copy(buf, fmt.Sprintf("1,%d,0,-;BUG: fault %d\n", readCount, readCount-1)), nil
		}
		return 0, syscall.EAGAIN
	}}}
	if drained, err := k.ofNote(); err != nil || drained != got {
		t.Errorf("streamed evidence differs: %v\n%s", err, drained)
	}
}

func TestConcurrentKernelLogSeekFailureCloses(t *testing.T) {
	k := openKernelLogWith(kernelLogOps{
		open:    func() (int, error) { return 42, nil },
		seekEnd: func(int) error { return syscall.ESPIPE },
		read:    func(int, []byte) (int, error) { return 0, syscall.EAGAIN },
		close:   func(int) error { return syscall.EBADF },
	})
	_, err := k.ofNote()
	if !errors.Is(err, syscall.ESPIPE) || !errors.Is(err, syscall.EBADF) {
		t.Errorf("seek/close failure lost: %v", err)
	}
}
