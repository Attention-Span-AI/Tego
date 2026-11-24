// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A tego from before the pin's fields (Entry.Boot, Entry.UntilBoot; ADR 0125 decision 4, amendment 2026-11-18) and
// this one share a run's overlay file. No binary of that tego can be built here, so its reader is the entry's and the
// overlay's shape before the fields (internal/liveblock/entry.go and overlay.go at 0e29f7bf6^), copied below, decoded
// as its Decode did: encoding/json, unknown fields ignored.

// olderEntry is Entry before the pin's fields.
type olderEntry struct {
	Kind  Kind      `json:"kind"`
	Value string    `json:"value"`
	By    string    `json:"by"`
	At    time.Time `json:"at"`
	Until time.Time `json:"until,omitzero"`
	From  time.Time `json:"from,omitzero"`
	Real  string    `json:"real,omitempty"`
	Match string    `json:"match,omitempty"`
}

// olderOverlay is Overlay as that tego held it; its changes are kept as they were read.
type olderOverlay struct {
	V       int               `json:"v"`
	Run     string            `json:"run"`
	Serial  uint64            `json:"serial"`
	Blocks  []olderEntry      `json:"blocks"`
	Changes []json.RawMessage `json:"changes"`
	Paused  bool              `json:"paused,omitempty"`
}

// rewriteAsOlder reads the overlay file in dir with the older shape and writes it back as that tego would: what it
// reads is the file's limit without its pin. It fails the test when the older reader cannot read this tego's file.
func rewriteAsOlder(t *testing.T, dir string) olderOverlay {
	t.Helper()
	path := filepath.Join(dir, FileName)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var o olderOverlay
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&o); err != nil {
		t.Fatalf("a reader from before the pin cannot read this file: %v\n%s", err, b)
	}
	out, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

// The debt row's two sentences, in order. An older reader ignores the pin: it reads the limit of a pinned entry as
// written and nothing else. An older writer drops the pin when it rewrites the file, and this tego then holds that
// entry as it holds one with no pin: no later write pins it again (a pin is made once, with its limit), and a writer
// drops it by the wall clock with the day's margin, so a forward step of more than a day drops it while BOOTTIME is
// still short of the pin it had. That is the residual the row states; with the pin kept the same step keeps it
// (TestForwardStepKeepsABlockTheLauncherHolds).
func TestAnOlderWriterDropsThePin(t *testing.T) {
	dir := t.TempDir()
	fc, pinned := pinnedBlock(t, dir)
	older := rewriteAsOlder(t, dir)
	if len(older.Blocks) != 1 || older.Blocks[0].Value != "/srv/x" || !older.Blocks[0].Until.Equal(pinned.Until) {
		t.Fatalf("the older reader read %+v, want the block on /srv/x until %v", older.Blocks, pinned.Until)
	}
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"boot"`) || strings.Contains(string(b), `"until_boot"`) {
		t.Fatalf("the older writer kept the pin: %s", b)
	}
	o, err := Read(dir, testRun)
	if err != nil {
		t.Fatalf("this tego cannot read the older writer's file: %v", err)
	}
	e, ok := timedBlock(o)
	if _, pinnedNow := e.UntilPin(fc.c); !ok || e.Boot != "" || e.UntilBoot != 0 || pinnedNow {
		t.Fatalf("after the older writer: %+v (found %v), want the entry with no pin", e, ok)
	}
	// A write before the limit, BOOTTIME half an hour ahead of the wall clock's pace: pinning now would make a pin,
	// and none is made.
	until := pinned.Until
	fc.c = Clock{Wall: t0.Add(30 * time.Minute), Boot: 2 * time.Hour, BootID: bootA}
	if e, ok := timedBlock(writeBlock(t, dir, nil)); !ok || e.Boot != "" || e.UntilBoot != 0 {
		t.Fatalf("a write before the limit: kept %v as %+v; it must not pin the limit again", ok, e)
	}
	fc.c = Clock{Wall: until.Add(23 * time.Hour), Boot: 2*time.Hour + time.Minute, BootID: bootA}
	if e, ok := timedBlock(writeBlock(t, dir, nil)); !ok || e.Boot != "" || e.UntilBoot != 0 {
		t.Fatalf("a write inside the day: kept %v as %+v; it must neither drop the entry nor pin it again", ok, e)
	}
	// BOOTTIME (2h02m) is still short of the pin the entry had (3h), and the wall clock is a day past the limit.
	fc.c = Clock{Wall: until.Add(25 * time.Hour), Boot: 2*time.Hour + 2*time.Minute, BootID: bootA}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); ok {
		t.Fatal("the entry the older writer unpinned outlived the wall clock's day: the row says the wall clock decides it")
	}
}
