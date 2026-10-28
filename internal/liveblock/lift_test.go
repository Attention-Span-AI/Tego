// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLiftAndRestore: a lift records op lift with its limit and a MAC that checks under the run's key; a restore
// records op restore with neither; neither touches the blocks.
func TestLiftAndRestore(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 7
	o := New(testRun)
	if _, _, err := o.Add(KindExec, "curl", "b", t0); err != nil {
		t.Fatal(err)
	}
	until := t0.Add(72 * time.Hour)
	c, err := o.Lift(KindRead, "/home/u/billing-exports/", "uid:1 pid:2 cli", t0, until, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.Op != OpLift || c.Value != "/home/u/billing-exports" || !c.Until.Equal(until) || c.Serial != 2 ||
		c.Rule() != "live.fence[read:/home/u/billing-exports]" || !LiftMACOK(key, testRun, c) {
		t.Fatalf("lift = %+v", c)
	}
	if got := o.Changes[len(o.Changes)-1]; got != c {
		t.Fatalf("the overlay lists %+v, Lift returned %+v", got, c)
	}
	r, err := o.Restore(KindRead, "/home/u/billing-exports", "uid:1 pid:2 cli", t0.Add(time.Hour))
	if err != nil || r.Op != OpRestore || r.MAC != "" || !r.Until.IsZero() || r.Serial != 3 {
		t.Fatalf("restore = %+v, %v", r, err)
	}
	if len(o.Blocks) != 1 {
		t.Fatalf("a lift or a restore changed the blocks: %+v", o.Blocks)
	}
	if _, err := o.Encode(); err != nil || o.V != VersionModes {
		t.Fatalf("Encode: version %d, %v", o.V, err)
	}
	for name, err := range map[string]error{
		"path kind":   func() error { _, err := o.Lift(KindPath, "/x", "b", t0, time.Time{}, key); return err }(),
		"short key":   func() error { _, err := o.Lift(KindRead, "/x", "b", t0, time.Time{}, key[:16]); return err }(),
		"until early": func() error { _, err := o.Lift(KindRead, "/x", "b", t0, t0, key); return err }(),
		"write kind":  func() error { _, err := o.Restore(KindWrite, "/x", "b", t0); return err }(),
		"bad value":   func() error { _, err := o.Restore(KindExec, "two words", "b", t0); return err }(),
	} {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

// TestLiftMACBindsEveryField: changing any field the MAC binds, or the run, or the key, changes the MAC.
func TestLiftMACBindsEveryField(t *testing.T) {
	key := make([]byte, 32)
	base := Change{Serial: 4, Op: OpLift, Kind: KindNet, Value: "api.stripe.com:443", By: "uid:1 pid:2 cli", At: t0,
		Until: t0.Add(time.Hour)}
	mac := LiftMAC(key, testRun, base)
	if len(mac) != 64 || !hexMAC(mac) {
		t.Fatalf("LiftMAC = %q", mac)
	}
	withMAC := base
	withMAC.MAC = "ignored"
	if LiftMAC(key, testRun, withMAC) != mac {
		t.Fatal("the MAC reads the change's own MAC field")
	}
	for name, c := range map[string]Change{
		"serial": func() Change { c := base; c.Serial++; return c }(),
		"op":     func() Change { c := base; c.Op = OpRestore; return c }(),
		"kind":   func() Change { c := base; c.Kind = KindExec; return c }(),
		"value":  func() Change { c := base; c.Value = "api.stripe.com:80"; return c }(),
		"by":     func() Change { c := base; c.By = "uid:1 pid:3 cli"; return c }(),
		"at":     func() Change { c := base; c.At = c.At.Add(time.Millisecond); return c }(),
		"until":  func() Change { c := base; c.Until = time.Time{}; return c }(),
	} {
		if LiftMAC(key, testRun, c) == mac {
			t.Errorf("changing %s keeps the MAC", name)
		}
	}
	if LiftMAC(key, "r-0123abcd-mabc12-zzzzzz", base) == mac {
		t.Error("another run keeps the MAC")
	}
	other := make([]byte, 32)
	other[31] = 1
	if LiftMAC(other, testRun, base) == mac {
		t.Error("another key keeps the MAC")
	}
	good := base
	good.MAC = mac
	if !LiftMACOK(key, testRun, good) || LiftMACOK(other, testRun, good) || LiftMACOK(key[:31], testRun, good) {
		t.Fatal("LiftMACOK does not check the MAC under exactly its key")
	}
}

// TestKeyFile: WriteKey makes a 0600 key once; ReadKey reads it back and refuses a key of another mode, a symlink and
// a file of the wrong size.
func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	key, err := WriteKey(dir)
	if err != nil || len(key) != 32 {
		t.Fatalf("WriteKey = %d bytes, %v", len(key), err)
	}
	if _, err := WriteKey(dir); err == nil {
		t.Fatal("a second WriteKey replaced the key")
	}
	got, err := ReadKey(dir)
	if err != nil || string(got) != string(key) {
		t.Fatalf("ReadKey = %x, %v", got, err)
	}
	p := filepath.Join(dir, KeyName)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(dir); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a 0644 key: %v, want ErrUntrusted", err)
	}
	link := t.TempDir()
	if err := os.Symlink(p, filepath.Join(link, KeyName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(link); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a symlinked key: %v, want ErrUntrusted", err)
	}
	short := t.TempDir()
	if err := os.WriteFile(filepath.Join(short, KeyName), make([]byte, 31), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(short); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a 31-byte key: %v, want ErrUntrusted", err)
	}
	if _, err := ReadKey(t.TempDir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no key: %v, want os.ErrNotExist", err)
	}
	if os.Geteuid() != 0 {
		t.Log("the other-owner case needs root to make the file; skipped")
	}
}
