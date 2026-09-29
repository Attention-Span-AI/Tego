// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestStopLogsTheProcessCache: the process cache's counters reach the run's log once the drain has stopped, the
// one place they are read.
func TestStopLogsTheProcessCache(t *testing.T) {
	f := newFixture(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := sample{PID: 4242, TID: 4242, MonoNS: 1, Kind: KindOpen} // no /proc entry: one rebuild, gone
	runRecorder(t, f, Options{FlushInterval: time.Hour, Logger: logger},
		fsSample(h, 0, 1, 2049, "/usr/lib/libc.so", ""))
	out := buf.String()
	if !strings.Contains(out, "recorder process cache") || !strings.Contains(out, "rebuilds=1") ||
		!strings.Contains(out, "gone=1") {
		t.Fatalf("log = %q, want the process cache's counters", out)
	}
}
