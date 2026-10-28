// SPDX-License-Identifier: Apache-2.0

package modelroutes

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const model = "api.anthropic.com:443"

func TestUpdateReadStatSince(t *testing.T) {
	dir := t.TempDir()
	if sig := Stat(dir); sig.Exists || sig.Errored {
		t.Fatalf("Stat of no file = %+v, want zero", sig)
	}
	if _, err := Read(dir, "r1"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Read of no file = %v, want ErrNotExist", err)
	}
	at := time.Date(2026, 10, 27, 18, 0, 0, 0, time.UTC)
	o, err := Update(context.Background(), dir, "r1", func(o *Overlay) (bool, error) {
		return o.Set(model, "corp", By("cli"), at)
	})
	if err != nil || o.Serial != 1 {
		t.Fatalf("Update = %+v, %v", o, err)
	}
	first := Stat(dir)
	// An endpoint already on the route writes nothing and records no change.
	if _, err := Update(context.Background(), dir, "r1", func(o *Overlay) (bool, error) {
		return o.Set(model, "corp", "x", at)
	}); err != nil {
		t.Fatal(err)
	}
	if Stat(dir) != first {
		t.Fatal("an unchanged route rewrote the file")
	}
	if _, err := Update(context.Background(), dir, "r1", func(o *Overlay) (bool, error) {
		if _, err := o.Set(model, "local", "x", at); err != nil {
			return false, err
		}
		return o.Set(model, Direct, "x", at) // Direct is a clear
	}); err != nil {
		t.Fatal(err)
	}
	got, err := Read(dir, "r1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Lookup(model); ok {
		t.Fatal("a cleared route is still in force")
	}
	ch := got.Since(1)
	if len(ch) != 2 || ch[0].Op != OpSet || ch[0].RouteAfter() != "local" || ch[1].Op != OpClear || ch[1].RouteAfter() != Direct {
		t.Fatalf("Since(1) = %+v", ch)
	}
	if _, err := Read(dir, "r2"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Read for another run = %v, want ErrInvalid", err)
	}
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", fi.Mode(), err)
	}
	if ok, err := got.Clear(model, "x", at); ok || err != nil {
		t.Fatalf("Clear of nothing = %v, %v", ok, err)
	}
}

func TestSetRefusesInvalid(t *testing.T) {
	o := New("r")
	for _, c := range [][2]string{{"", "corp"}, {"api.anthropic.com", "corp"}, {model, "Corp Proxy"}, {"h:0", "corp"}} {
		if _, err := o.Set(c[0], c[1], "x", time.Now()); !errors.Is(err, ErrInvalid) {
			t.Errorf("Set%q = %v, want ErrInvalid", c, err)
		}
	}
}

func TestDecodeRefuses(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field": `{"version":1,"run":"r","serial":0,"routes":[],"changes":[],"extra":1}`,
		"version":       `{"version":2,"run":"r","serial":0,"routes":[],"changes":[]}`,
		"direct entry":  `{"version":1,"run":"r","serial":1,"routes":[{"model":"h:1","route":"direct","by":"x","at":"2026-10-27T00:00:00Z","serial":1}],"changes":[]}`,
		"dup model":     `{"version":1,"run":"r","serial":2,"routes":[{"model":"h:1","route":"a","by":"x","at":"2026-10-27T00:00:00Z","serial":1},{"model":"h:1","route":"b","by":"x","at":"2026-10-27T00:00:00Z","serial":2}],"changes":[]}`,
		"future serial": `{"version":1,"run":"r","serial":0,"routes":[{"model":"h:1","route":"a","by":"x","at":"2026-10-27T00:00:00Z","serial":1}],"changes":[]}`,
		"clear w route": `{"version":1,"run":"r","serial":1,"routes":[],"changes":[{"serial":1,"op":"clear","model":"h:1","route":"a","by":"x","at":"2026-10-27T00:00:00Z"}]}`,
		"bad op":        `{"version":1,"run":"r","serial":1,"routes":[],"changes":[{"serial":1,"op":"swap","model":"h:1","by":"x","at":"2026-10-27T00:00:00Z"}]}`,
	} {
		if _, err := Decode([]byte(doc), "r"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestChangesBounded(t *testing.T) {
	o := New("r")
	for i := range MaxChanges + 10 {
		route := "a"
		if i%2 == 1 {
			route = "b"
		}
		if _, err := o.Set(model, route, "x", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if len(o.Changes) != MaxChanges || o.Lost != 10 {
		t.Fatalf("changes %d, lost %d", len(o.Changes), o.Lost)
	}
	if _, err := o.Encode(); err != nil {
		t.Fatal(err)
	}
}

func TestReadRefusesUntrusted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(`{"version":1,"run":"r","serial":0,"routes":[],"changes":[]}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, FileName), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, "r"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a world-writable file = %v, want ErrUntrusted", err)
	}
	if err := os.Remove(filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/hostname", filepath.Join(dir, FileName)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir, "r"); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a symlink = %v, want ErrUntrusted", err)
	}
	if b := By("dashboard"); !strings.HasSuffix(b, " dashboard") || !strings.HasPrefix(b, "uid:") {
		t.Fatalf("By = %q", b)
	}
}
