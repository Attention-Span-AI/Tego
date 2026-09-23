// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseCounter(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		key    string
		want   uint64
		wantOK bool
	}{
		{"populated 1", "populated 1\nfrozen 0\n", "populated", 1, true},
		{"populated 0", "populated 0\nfrozen 0\n", "populated", 0, true},
		{"oom_kill", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 2\noom_group_kill 0\n", "oom_kill", 2, true},
		{"max", "max 7\n", "max", 7, true},
		{"missing key", "populated 1\n", "frozen", 0, false},
		{"prefix is not a key", "oom_kill_x 5\n", "oom_kill", 0, false},
		{"malformed", "populated x\n", "populated", 0, false},
		{"negative", "populated -1\n", "populated", 0, false},
		{"overflow", "populated 99999999999999999999\n", "populated", 0, false},
		{"empty", "", "populated", 0, false},
		{"no newline", "populated 1", "populated", 1, true},
		{"crlf", "populated 1\r\n", "populated", 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseCounter([]byte(tc.data), tc.key)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("parseCounter(%q, %q) = %d,%v want %d,%v", tc.data, tc.key, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func FuzzParseCounter(f *testing.F) {
	f.Add([]byte("populated 1\nfrozen 0\n"), "populated")
	f.Add([]byte("oom_kill 18446744073709551615\n"), "oom_kill")
	f.Add([]byte("\x00 \n"), "")
	f.Add([]byte("  low 3  \nhigh x\nhigh 4\n"), "high")
	// A key that holds a space or a line break, or none at all, names no line; a count that is found reads
	// back from a line of its own, which the earlier version of this test never checked.
	f.Fuzz(func(t *testing.T, data []byte, key string) {
		n, ok := parseCounter(data, key)
		if !ok {
			return
		}
		if key == "" || strings.ContainsAny(key, " \n") {
			t.Fatalf("parseCounter(%q, %q) = %d: a key no line can hold matched", data, key, n)
		}
		if again, ok := parseCounter([]byte(key+" "+strconv.FormatUint(n, 10)+"\n"), key); !ok || again != n {
			t.Fatalf("parseCounter(%q, %q) = %d, which reads back as %d, %v", data, key, n, again, ok)
		}
	})
}

// TestWaitLeavesNoCallbackBehind is WaitEmpty and Events on a ctx that ends: wait returns ctx's error and
// its caller closes the watcher straight away. The callback that cuts the read short runs on a goroutine of
// its own, and wait must not return before it has; otherwise the callback reads the watcher's file while
// close releases it. That is the data race `go test -race` reported in TestIntegrationLifecycle, whose
// WaitEmpty on a live child had a 200 ms ctx end as the 200 ms poll fallback did. Here each round has a
// notification queued before wait reads, so the read returns at once whether or not the callback, which a
// ctx that has already ended starts at once, has run yet, and the race detector sees any access it makes
// after wait has returned.
func TestWaitLeavesNoCallbackBehind(t *testing.T) {
	path := filepath.Join(t.TempDir(), fileEvents)
	if err := os.WriteFile(path, []byte("populated 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		w := newWatcher(path)
		if w.f == nil {
			t.Skip("no inotify here: the watcher polls, and polling starts no callback")
		}
		if err := os.WriteFile(path, []byte("populated 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// The queued notification makes this nil; ctx's end, when the callback cut the read first.
		if err := w.wait(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("wait on an ended ctx: %v", err)
		}
		w.close()
	}
}
