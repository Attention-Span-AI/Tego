// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

const liveRun = "r-3f9c2a1b-0dllq06ts7402-l1vexx"

// liveDir makes a run directory under a fresh root whose events file holds first as its run_start payload's members.
func liveDir(t *testing.T, first string) (root, dir string) {
	t.Helper()
	root = t.TempDir()
	dir = filepath.Join(root, liveRun)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line := `{"v":1,"seq":0,"id":"` + zeros64 + `","prev":"","ts":"2026-10-27T12:00:00Z","mono_ns":1,"run":"` + liveRun +
		`","agent":"probe","pid":10,"tid":10,"cgroup":1,"kind":"run_start","source":"launcher",` + first + "}\n"
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, dir
}

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000001"

func TestStartFacts(t *testing.T) {
	_, dir := liveDir(t, `"tier":"observe","command":["sh"],"fs_reads":{"reads":"direct","why":"records-only"}`)
	if f := StartFacts(dir); !f.Observe || f.ReadsSeen {
		t.Fatalf("watched run: %+v", f)
	}
	_, dir = liveDir(t, `"tier":"landlock","command":["sh"],"fs_reads":{"reads":"held","why":"contract"}`)
	if f := StartFacts(dir); f.Observe || !f.ReadsSeen {
		t.Fatalf("held run: %+v", f)
	}
	if f := StartFacts(t.TempDir()); f.Observe || f.ReadsSeen {
		t.Fatalf("no ledger: %+v", f)
	}
}

// TestLiveSerials: each block maps to its own latest add's serial, and one whose add was dropped from the change list
// maps to the overlay's serial.
func TestLiveSerials(t *testing.T) {
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"]`)
	now := time.Now()
	_, err := liveblock.Update(context.Background(), dir, liveRun, func(o *liveblock.Overlay) (bool, error) {
		for _, step := range []struct {
			add   bool
			kind  liveblock.Kind
			value string
		}{{true, liveblock.KindExec, "curl"}, {true, liveblock.KindPath, "/p/data"}, {false, liveblock.KindExec, "curl"}, {true, liveblock.KindExec, "curl"}} {
			var err error
			if step.add {
				_, _, err = o.Add(step.kind, step.value, "uid:1 pid:1 cli", now)
			} else {
				_, _, err = o.Remove(step.kind, step.value, "uid:1 pid:1 cli", now)
			}
			if err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	lb, err := Live(root, liveRun)
	if err != nil {
		t.Fatal(err)
	}
	if lb.Serial != 4 || len(lb.Blocks) != 2 {
		t.Fatalf("Live = serial %d, %d blocks", lb.Serial, len(lb.Blocks))
	}
	if got := lb.Serials["exec:curl"]; got != 4 {
		t.Errorf("exec:curl serial = %d, want 4 (its re-add)", got)
	}
	if got := lb.Serials["path:/p/data"]; got != 2 {
		t.Errorf("path:/p/data serial = %d, want 2", got)
	}
	o := &liveblock.Overlay{Serial: 9, Blocks: []liveblock.Entry{{Kind: liveblock.KindNet, Value: "example.com"}}}
	if got := liveOf(o).Serials["net:example.com"]; got != 9 {
		t.Errorf("a block with no listed add = %d, want the overlay's 9", got)
	}
	if lb, err := Live(t.TempDir(), liveRun); err == nil || lb.Blocks != nil {
		t.Errorf("Live of a missing run = %+v, %v", lb, err)
	}
}

// TestUnblockRefusedInsideARun: a process inside a run may not remove a live block; adding one only tightens and is
// not refused for that reason.
func TestUnblockRefusedInsideARun(t *testing.T) {
	root, _ := liveDir(t, `"tier":"landlock","command":["sh"]`)
	defer func(f func() (bool, error)) { selfInRun = f }(selfInRun)
	selfInRun = func() (bool, error) { return true, nil }
	_, err := Block(context.Background(), root, liveRun, "exec", "curl", false)
	if !errors.Is(err, ErrGoverned) {
		t.Fatalf("unblock inside a run: %v, want ErrGoverned", err)
	}
	if _, err := Block(context.Background(), root, liveRun, "exec", "curl", true); errors.Is(err, ErrGoverned) {
		t.Fatalf("block inside a run refused as governed: %v", err)
	}
	// Unknowable (a cgroup namespace): refused as well (it fails closed).
	selfInRun = func() (bool, error) { return true, errors.New("cgroup namespace") }
	if in, err := SelfGoverned(); !in || err == nil {
		t.Fatalf("SelfGoverned on an error: %v %v, want true with the error", in, err)
	}
	if _, err := Block(context.Background(), root, liveRun, "exec", "curl", false); !errors.Is(err, ErrGoverned) {
		t.Fatalf("unblock from an unknowable cgroup: %v, want ErrGoverned", err)
	}
	selfInRun = func() (bool, error) { return false, nil }
	if _, err := Block(context.Background(), root, liveRun, "exec", "curl", false); err != nil {
		t.Fatalf("unblock outside a run: %v", err)
	}
}

// holdRunLock takes run directory dir's lock on its own descriptor, as a launcher does, so a probe from this process
// reads the run as live (flock locks belong to the open file, not the process).
func holdRunLock(t *testing.T, dir string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

// TestBlockOlderLauncher: a read or write block is refused on a run whose launcher predates those kinds (record_minor
// below 24, or none): that launcher would fail to read the overlay and ignore every later change. Exec, net and path
// blocks still go through there, and both kinds are placed on a run at 24.
func TestBlockOlderLauncher(t *testing.T) {
	ctx := context.Background()
	for _, start := range []string{`"tier":"landlock","command":["sh"]`, `"tier":"landlock","command":["sh"],"record_minor":23,"fs_reads":{"reads":"held","why":"contract"}`} {
		root, dir := liveDir(t, start)
		holdRunLock(t, dir)
		for _, kind := range []string{"read", "write"} {
			if _, err := Block(ctx, root, liveRun, kind, "/p/x", true); !errors.Is(err, ErrOldLauncher) {
				t.Errorf("%s on %s: %v, want ErrOldLauncher", kind, start, err)
			}
		}
		for _, kv := range [][2]string{{"exec", "curl"}, {"net", "example.com"}, {"path", "/p/x"}} {
			if _, err := Block(ctx, root, liveRun, kv[0], kv[1], true); err != nil {
				t.Errorf("%s on %s: %v", kv[0], start, err)
			}
		}
		if bs, err := Blocks(root, liveRun); err != nil || len(bs) != 3 {
			t.Errorf("blocks on %s: %+v %v, want the three older kinds only", start, bs, err)
		}
	}
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":24,"fs_reads":{"reads":"held","why":"contract"}`)
	holdRunLock(t, dir)
	for _, kind := range []string{"read", "write"} {
		if _, err := Block(ctx, root, liveRun, kind, "/p/x", true); err != nil {
			t.Errorf("%s at record_minor 24: %v", kind, err)
		}
	}
}
