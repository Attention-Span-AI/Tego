// SPDX-License-Identifier: Apache-2.0

package mcptools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateReadStatSince(t *testing.T) {
	dir := t.TempDir()
	if sig := Stat(dir); sig.Exists || sig.Errored {
		t.Fatalf("Stat of no file = %+v, want zero", sig)
	}
	if _, err := Read(dir, "r1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read of no file = %v, want ErrNotExist", err)
	}
	at := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	o, err := Update(context.Background(), dir, "r1", func(o *Overlay) (bool, error) {
		return o.Set("files", "delete_file", Allow, By("cli"), at)
	})
	if err != nil || o.Serial != 1 {
		t.Fatalf("Update = %+v, %v", o, err)
	}
	first := Stat(dir)
	if !first.Exists {
		t.Fatal("no file after Update")
	}
	// An unchanged switch writes nothing and records no change.
	if _, err := Update(context.Background(), dir, "r1", func(o *Overlay) (bool, error) {
		return o.Set("files", "delete_file", Allow, "x", at)
	}); err != nil {
		t.Fatal(err)
	}
	if Stat(dir) != first {
		t.Fatal("an unchanged switch rewrote the file")
	}
	if _, err := Update(context.Background(), dir, "r1", func(o *Overlay) (bool, error) {
		if _, err := o.Set("files", "read_file", Deny, "x", at); err != nil {
			return false, err
		}
		return o.Reset("files", "delete_file", "x", at)
	}); err != nil {
		t.Fatal(err)
	}
	if Stat(dir) == first {
		t.Fatal("a change kept the same signature")
	}
	got, err := Read(dir, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := got.Lookup("files", "read_file"); !ok || e.Decision != Deny || e.Serial != 2 {
		t.Fatalf("Lookup read_file = %+v %v", e, ok)
	}
	if _, ok := got.Lookup("files", "delete_file"); ok {
		t.Fatal("a reset switch is still in force")
	}
	if ch := got.Since(1); len(ch) != 2 || ch[0].Op != OpSet || ch[1].Op != OpReset {
		t.Fatalf("Since(1) = %+v", ch)
	}
	if _, err := Read(dir, "r2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read for another run = %v, want ErrInvalid", err)
	}
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", fi.Mode(), err)
	}
}

func TestSetRefusesInvalid(t *testing.T) {
	o := New("r")
	for _, c := range [][3]string{{"", "t", Allow}, {"s", "bad name", Allow}, {"s", "t", "maybe"}} {
		if _, err := o.Set(c[0], c[1], c[2], "x", time.Now()); !errors.Is(err, ErrInvalid) {
			t.Errorf("Set%q = %v, want ErrInvalid", c, err)
		}
	}
}

func TestChangesBounded(t *testing.T) {
	o := New("r")
	for i := 0; i < MaxChanges+10; i++ {
		d := []string{Allow, Deny}[i%2]
		if _, err := o.Set("s", "t", d, "x", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if len(o.Changes) != MaxChanges || o.Lost != 10 {
		t.Fatalf("changes %d lost %d", len(o.Changes), o.Lost)
	}
	if _, err := o.Encode(); err != nil {
		t.Fatal(err)
	}
}

func TestUntrustedRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, FileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, "r"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("group-writable overlay = %v, want ErrUntrusted", err)
	}
	// Update never replaces an overlay it cannot read.
	if _, err := Update(context.Background(), dir, "r", func(*Overlay) (bool, error) { return true, nil }); err == nil {
		t.Fatal("Update replaced an untrusted overlay")
	}
	link := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, FileName), filepath.Join(link, FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, "r"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("symlinked overlay = %v, want ErrUntrusted", err)
	}
}

func TestLockSerializesWriters(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lock(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := Update(ctx, dir, "r", func(*Overlay) (bool, error) { return false, nil }); err == nil {
		t.Fatal("Update ran while another writer held the lock")
	}
	unlock()
	if _, err := Update(context.Background(), dir, "r", func(*Overlay) (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSeenBounds(t *testing.T) {
	dir := t.TempDir()
	s, err := ReadSeen(dir)
	if err != nil || len(s) != 0 {
		t.Fatalf("ReadSeen of none = %v, %v", s, err)
	}
	var many []string
	for i := 0; i < MaxSeenPerServer+50; i++ {
		many = append(many, fmt.Sprintf("tool_%04d", i))
	}
	many = append(many, "bad name", "")
	if !s.Merge("files", many) {
		t.Fatal("Merge did not grow")
	}
	if s.Merge("files", []string{"tool_0000"}) {
		t.Fatal("Merge of a known tool grew")
	}
	if s.Merge("bad server", []string{"x"}) {
		t.Fatal("Merge took an invalid server")
	}
	if err := WriteSeen(dir, s); err != nil {
		t.Fatal(err)
	}
	got, err := ReadSeen(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got["files"]); n != MaxSeenPerServer {
		t.Fatalf("seen %d tools, want %d", n, MaxSeenPerServer)
	}
	for _, name := range got["files"] {
		if !ValidName(name) {
			t.Fatalf("invalid name %q kept", name)
		}
	}
}
