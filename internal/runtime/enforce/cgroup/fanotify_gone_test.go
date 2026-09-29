// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// recordingHandler keeps every log record it is handed.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// TestResponseForAGoneOpenerIsLoggedOncePerClass is §6 E10: a response the kernel refuses because the opener
// is gone (ESRCH, ENOENT) is not an error and fails nothing, but it is logged, at debug and once per errno, so a
// pids cap killing a busy cgroup cannot flood the run's log. Any other write error is still returned.
func TestResponseForAGoneOpenerIsLoggedOncePerClass(t *testing.T) {
	h := &recordingHandler{}
	l := &fanotifyListener{fd: -1, run: Run{ID: "run-1", Log: slog.New(h)}, now: time.Now, marks: map[string]uint64{}}
	var next []error
	l.write = func(int, []byte) (int, error) {
		err := next[0]
		next = next[1:]
		if err != nil {
			return 0, err
		}
		return 8, nil
	}
	for _, err := range []error{unix.ESRCH, unix.ENOENT, unix.ESRCH, unix.ENOENT, unix.ESRCH} {
		next = []error{err}
		if got := l.writeResponse(7, unix.FAN_ALLOW); got != nil {
			t.Fatalf("writeResponse with the opener gone (%v) = %v, want nil", err, got)
		}
	}
	next = []error{unix.EINTR, nil}
	if err := l.writeResponse(7, unix.FAN_DENY); err != nil || len(next) != 0 {
		t.Fatalf("an interrupted write = %v with %d writes left, want it retried to success", err, len(next))
	}
	next = []error{unix.EBADF}
	if err := l.writeResponse(7, unix.FAN_DENY); err == nil {
		t.Fatal("a write failing EBADF was swallowed")
	}
	if len(h.records) != 2 {
		t.Fatalf("%d log records for five responses to gone openers, want 2 (one per errno): %v", len(h.records), h.records)
	}
	for _, r := range h.records {
		if r.Level != slog.LevelDebug {
			t.Errorf("record %q at %v, want debug", r.Message, r.Level)
		}
	}
}
