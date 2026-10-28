// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPauseResume: a pause and a resume ride the overlay's one sequence of serials, a resume undoes a pause and
// nothing else, and asking twice changes nothing.
func TestPauseResume(t *testing.T) {
	o := New(testRun)
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	if _, ok := o.Resume("cli", at); ok {
		t.Fatal("a resume of a run that is not paused changed the overlay")
	}
	if _, ok, err := o.Add(KindExec, "curl", "cli", at); !ok || err != nil {
		t.Fatalf("Add = %v, %v", ok, err)
	}
	c, ok := o.Pause("uid:1000 pid:7 dashboard", at)
	if !ok || !o.Paused || c.Serial != 2 || c.Op != OpPause || c.Kind != "" || c.Value != "" || !c.Control() {
		t.Fatalf("Pause = %+v, %v; overlay paused %v", c, ok, o.Paused)
	}
	if _, ok := o.Pause("cli", at); ok {
		t.Fatal("a second pause changed the overlay")
	}
	c, ok = o.Resume("cli", at)
	if !ok || o.Paused || c.Serial != 3 || c.Op != OpResume {
		t.Fatalf("Resume = %+v, %v", c, ok)
	}
	if len(o.Blocks) != 1 {
		t.Fatalf("a resume touched the blocks: %+v", o.Blocks)
	}
	changes, lost := o.Since(1)
	if lost != 0 || len(changes) != 2 || changes[0].Op != OpPause || changes[1].Op != OpResume {
		t.Fatalf("Since(1) = %+v, %d", changes, lost)
	}
}

// TestRemoveKeepsPause: removing a block (the run page's Remove, or an Undo lifting the block its change placed)
// changes the blocks only: a pause asked stays asked, every other block stays, and the removal takes the next serial.
func TestRemoveKeepsPause(t *testing.T) {
	o := New(testRun)
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	for _, k := range []Kind{KindRead, KindWrite} {
		if _, ok, err := o.Add(k, "/p/proj/out", "cli", at); !ok || err != nil {
			t.Fatalf("Add(%s) = %v, %v", k, ok, err)
		}
	}
	if _, ok := o.Pause("cli", at); !ok {
		t.Fatal("Pause changed nothing")
	}
	c, ok, err := o.Remove(KindWrite, "/p/proj/out", "dashboard", at)
	if !ok || err != nil || c.Op != OpRemove || c.Kind != KindWrite || c.Serial != 4 || c.Control() {
		t.Fatalf("Remove = %+v, %v, %v", c, ok, err)
	}
	if !o.Paused || len(o.Blocks) != 1 || o.Blocks[0].Kind != KindRead {
		t.Fatalf("after Remove: paused %v, blocks %+v", o.Paused, o.Blocks)
	}
}

// TestPauseEncodesAndDecodes: a paused overlay survives its file form, a pause names no kind or value in it, and an
// add's bytes are as they were before pauses existed.
func TestPauseEncodesAndDecodes(t *testing.T) {
	o := New(testRun)
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	if _, _, err := o.Add(KindExec, "curl", "cli", at); err != nil {
		t.Fatal(err)
	}
	o.Pause("cli", at)
	b, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"paused":true`)) || !bytes.Contains(b, []byte(`{"serial":2,"op":"pause","by":"cli"`)) ||
		!bytes.Contains(b, []byte(`{"serial":1,"op":"add","kind":"exec","value":"curl"`)) {
		t.Fatalf("encoded overlay %s", b)
	}
	got, err := Decode(b, testRun)
	if err != nil || !got.Paused || got.Serial != 2 {
		t.Fatalf("Decode = %+v, %v", got, err)
	}
	o.Resume("cli", at)
	if b, err = o.Encode(); err != nil || bytes.Contains(b, []byte(`"paused"`)) {
		t.Fatalf("a resumed overlay still names paused: %s, %v", b, err)
	}
}

// TestDecodeRefusesBadPause: a pause naming a block, an op nobody knows, a paused flag the last pause or resume
// contradicts, and a paused flag no pause asked (every change listed, none a pause) are each refused, so the launcher never reads a half-written intent.
func TestDecodeRefusesBadPause(t *testing.T) {
	at := time.Date(2026, 10, 27, 12, 3, 0, 0, time.UTC)
	cases := map[string]func(o *Overlay){
		"pause with a kind": func(o *Overlay) {
			o.Pause("cli", at)
			o.Changes[len(o.Changes)-1].Kind = KindExec
		},
		"pause with a value": func(o *Overlay) {
			o.Pause("cli", at)
			o.Changes[len(o.Changes)-1].Value = "curl"
		},
		"unknown op": func(o *Overlay) {
			o.Pause("cli", at)
			o.Changes[len(o.Changes)-1].Op = "freeze"
		},
		"paused but last change a resume": func(o *Overlay) {
			o.Pause("cli", at)
			o.Resume("cli", at)
			o.Paused = true
		},
		"not paused but last change a pause": func(o *Overlay) {
			o.Pause("cli", at)
			o.Paused = false
		},
		"paused with no change at all": func(o *Overlay) { o.Paused = true },
		"paused with every change listed and none a pause": func(o *Overlay) {
			if _, _, err := o.Add(KindExec, "curl", "cli", at); err != nil {
				panic(err)
			}
			o.Paused = true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := New(testRun)
			mutate(o)
			b, err := json.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Decode(b, testRun); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Decode(%s) = %v, want ErrInvalid", b, err)
			}
		})
	}
	// A paused flag whose pause the overlay no longer lists (it keeps the newest MaxChanges) is still read.
	o := New(testRun)
	o.Pause("cli", at)
	o.Changes = o.Changes[:0]
	b, _ := json.Marshal(o)
	if got, err := Decode(b, testRun); err != nil || !got.Paused {
		t.Fatalf("a pause past the kept changes: %+v, %v", got, err)
	}
}

// TestPauseThroughUpdate: the one writer persists a pause and a resume, and a second pause asked under the lock
// writes nothing.
func TestPauseThroughUpdate(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	pause := func(on bool) (bool, error) {
		var ok bool
		_, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
			if on {
				_, ok = o.Pause(By("cli"), time.Now())
			} else {
				_, ok = o.Resume(By("cli"), time.Now())
			}
			return ok, nil
		})
		return ok, err
	}
	if ok, err := pause(true); !ok || err != nil {
		t.Fatalf("pause = %v, %v", ok, err)
	}
	sig := Stat(dir)
	if ok, err := pause(true); ok || err != nil {
		t.Fatalf("second pause = %v, %v", ok, err)
	}
	if Stat(dir) != sig {
		t.Fatal("a pause that changed nothing rewrote the file")
	}
	got, err := Read(dir, testRun)
	if err != nil || !got.Paused || !strings.HasSuffix(got.Changes[0].By, " cli") {
		t.Fatalf("Read = %+v, %v", got, err)
	}
	if ok, err := pause(false); !ok || err != nil {
		t.Fatalf("resume = %v, %v", ok, err)
	}
	if got, err := Read(dir, testRun); err != nil || got.Paused || got.Serial != 2 {
		t.Fatalf("after resume: %+v, %v", got, err)
	}
}

// TestControlMark: a directory takes a pause once MarkControl made its mark (making it twice is fine, and keeps it
// 0600); no mark, a directory in its place, or a symlink to a file does not count, and MarkControl does not follow a
// symlink.
func TestControlMark(t *testing.T) {
	dir := t.TempDir()
	if TakesControl(dir) {
		t.Fatal("a directory with no mark takes a pause")
	}
	for range 2 {
		if err := MarkControl(dir); err != nil {
			t.Fatal(err)
		}
	}
	if st, err := os.Lstat(filepath.Join(dir, ControlName)); err != nil || st.Mode().Perm() != 0o600 || !TakesControl(dir) {
		t.Fatalf("the mark: %v, %v; takes %v", st, err, TakesControl(dir))
	}
	other := t.TempDir()
	if err := os.Mkdir(filepath.Join(other, ControlName), 0o700); err != nil {
		t.Fatal(err)
	}
	if TakesControl(other) {
		t.Fatal("a directory named as the mark counts")
	}
	link := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(link, ControlName)); err != nil {
		t.Fatal(err)
	}
	if err := MarkControl(link); err == nil {
		t.Fatal("MarkControl followed a symlink")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("MarkControl made the symlink's target: %v", err)
	}
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if TakesControl(link) {
		t.Fatal("a symlink to a file counts as the mark")
	}
}
