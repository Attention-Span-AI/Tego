// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// olderBlock and olderFile are the overlay file's shape before the pin's fields (internal/liveblock/entry.go and
// overlay.go at 0e29f7bf6^), as a tego from before them reads and writes it: no older binary can be built here.
type olderBlock struct {
	Kind  liveblock.Kind `json:"kind"`
	Value string         `json:"value"`
	By    string         `json:"by"`
	At    time.Time      `json:"at"`
	Until time.Time      `json:"until,omitzero"`
	From  time.Time      `json:"from,omitzero"`
	Real  string         `json:"real,omitempty"`
	Match string         `json:"match,omitempty"`
}

type olderFile struct {
	V       int               `json:"v"`
	Run     string            `json:"run"`
	Serial  uint64            `json:"serial"`
	Blocks  []olderBlock      `json:"blocks"`
	Changes []json.RawMessage `json:"changes"`
	Paused  bool              `json:"paused,omitempty"`
}

// olderRewrite has a tego from before the pin read the run's overlay file and write it back, which drops the pin.
func olderRewrite(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, liveblock.FileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var o olderFile
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&o); err != nil {
		t.Fatalf("a reader from before the pin cannot read this file: %v", err)
	}
	out, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The launcher meets an older writer in both orders, as the debt row (A36, "What remains") and ADR 0125's 2026-11-18
// amendment say it does. A limit it first sees with no pin (written, or rewritten, by a tego from before the pin's
// fields) it pins itself at first sight, and a forward wall step after that does not end it. A limit it already holds
// by its writer's pin keeps that pin when an older writer rewrites the file without it: pin skips a key it knows, so a
// wall clock stepped more than a day past the limit before BOOTTIME reaches the pin still leaves the block in force.
func TestLauncherMeetsAnOlderWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		// rewriteFirst: the older writer rewrites the file before the launcher's first poll.
		rewriteFirst bool
	}{
		{"an entry first seen without a pin", true},
		{"a pinned entry an older writer rewrites", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := pauseRunner(t)
			b := &liveBlocks{}
			ctx := context.Background()
			at := time.Now()
			updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
				_, _, err := o.AddUntil(liveblock.KindPath, "/srv/x", "uid:1 pid:2 cli", at, at.Add(2*time.Hour))
				return err
			})
			o, err := liveblock.Read(r.dir, string(r.id))
			if err != nil || len(o.Blocks) != 1 {
				t.Fatalf("overlay %+v, %v", o, err)
			}
			e := o.Blocks[0]
			if e.Boot == "" {
				t.Skip("this machine names no boot, so no writer keeps a pin: there is none to drop")
			}
			if tc.rewriteFirst {
				olderRewrite(t, r.dir)
			}
			// First sight: an hour before the limit by the wall clock, with BOOTTIME half an hour further on than the
			// writer's reading would put it, so a pin the launcher makes itself is not the writer's.
			now := liveblock.Clock{Wall: e.Until.Add(-time.Hour), Boot: e.UntilBoot - 30*time.Minute, BootID: e.Boot}
			want := e.UntilBoot // the writer's pin, which the launcher takes
			if tc.rewriteFirst {
				want = now.Pin(e.Until) // no pin in the file: the launcher pins the limit at its first sight
			}
			old := liveNow
			liveNow = func() liveblock.Clock { return now }
			t.Cleanup(func() { liveNow = old })
			r.pollLiveBlocks(ctx, b)
			key := liveblock.DeadlineKey(e.Key(), e.Until)
			if got := b.pins[key]; got != want {
				t.Fatalf("the launcher holds the limit at %v, want %v", got, want)
			}
			if !tc.rewriteFirst {
				olderRewrite(t, r.dir)
			}
			// The wall clock steps 25 h past the limit; BOOTTIME is still an hour short of the launcher's pin.
			now = liveblock.Clock{Wall: e.Until.Add(25 * time.Hour), Boot: want - time.Hour, BootID: e.Boot}
			r.pollLiveBlocks(ctx, b)
			if got := b.pins[key]; got != want {
				t.Fatalf("after the older writer the launcher holds the limit at %v, want its first pin %v", got, want)
			}
			if !b.Load().HasPath() {
				t.Fatal("a forward wall step ended the block before BOOTTIME reached the launcher's pin")
			}
			now.Boot = want
			r.pollLiveBlocks(ctx, b)
			if b.Load().HasPath() {
				t.Fatal("the block outlived both clocks")
			}
		})
	}
}
