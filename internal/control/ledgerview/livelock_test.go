// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// holderEnv makes this test binary a run's lock holder (TestHelperLockHolder): the test re-executes itself.
const holderEnv = "TEGO_LEDGERVIEW_TEST_LOCK_HOLDER"

// TestHelperLockHolder is not a test: run with holderEnv set to a run directory, it takes <dir>/lock as the run's
// launcher holds it and waits to be killed (a minute at most).
func TestHelperLockHolder(t *testing.T) {
	dir := os.Getenv(holderEnv)
	if dir == "" {
		t.Skip("helper process")
	}
	f, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		os.Exit(3)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		os.Exit(4)
	}
	time.Sleep(time.Minute)
	os.Exit(5)
}

// startLauncher starts a process that holds run directory dir's lock as its launcher does and returns once it holds
// it; kill kills it and returns once it is gone, so the kernel has let its lock go.
func startLauncher(t *testing.T, dir string) (kill func()) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperLockHolder$")
	cmd.Env = append(os.Environ(), holderEnv+"="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	var once sync.Once
	kill = func() { once.Do(func() { _ = cmd.Process.Kill(); <-done }) }
	t.Cleanup(kill)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if held, err := ledger.LockHeld(dir); err == nil && held {
			return kill
		}
		if time.Now().After(deadline) {
			t.Fatal("the helper never held the run's lock")
		}
	}
}

// setProbeAge sets lockProbeAge until the test ends.
func setProbeAge(t *testing.T, d time.Duration) {
	t.Helper()
	keep := lockProbeAge
	t.Cleanup(func() { lockProbeAge = keep })
	lockProbeAge = d
}

// askingRun writes a run that started and asked, and has not ended.
func askingRun(t *testing.T, root, id string) {
	t.Helper()
	t0 := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	writeRun(t, root, id,
		line(id, "asker", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`),
		line(id, "asker", 1, t0.Add(time.Second), "ask", `"ask_id":"q-1","hold":"open","op":"open","target":"/p/held/a"`))
}

// TestAListedRunNobodyHoldsIsLost: a run the live index lists while no process holds its lock is lost, not running.
// Its launcher died without run_end (killed, out of memory) and left the entry, with its lock file or before making
// one; the dashboard showed such a run as running until a sweep ended it, its ask as waiting on a person.
func TestAListedRunNobodyHoldsIsLost(t *testing.T) {
	root := t.TempDir()
	dead, early := "r-aaaa-0051-deadxx", "r-aaaa-0052-earlyx"
	for _, id := range []string{dead, early} {
		askingRun(t, root, id)
		listLive(t, root, id)
	}
	// The lock line a launcher writes stays in the file after the kernel lets its lock go.
	if err := os.WriteFile(filepath.Join(root, dead, ledger.LockFile), []byte("4242 1 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{dead, early} {
		if r := s.Find(id); r == nil || r.State() != "lost" || r.Live {
			t.Fatalf("%s: %+v, want lost", id, r)
		}
		r, err := LoadRun(root, id)
		if err != nil || r.State() != "lost" {
			t.Fatalf("LoadRun %s: %v %v, want lost", id, r, err)
		}
	}
	if p := s.Pending(); len(p) != 0 {
		t.Fatalf("a lost run's asks wait on a person: %+v", p)
	}
	if l := s.Lost(); len(l) != 2 {
		t.Fatalf("never answered %+v, want both runs' asks", l)
	}
}

// TestAListedRunRunsWhileItsLauncherHoldsTheLock: a listed run whose launcher (another process) holds the lock is
// running with its ask waiting; once the launcher is killed it reads as lost, at most lockProbeAge after (the answer
// is kept that long), and the change moves the revision so open pages redraw it.
func TestAListedRunRunsWhileItsLauncherHoldsTheLock(t *testing.T) {
	root, id := t.TempDir(), "r-aaaa-0053-launch"
	askingRun(t, root, id)
	listLive(t, root, id)
	kill := startLauncher(t, filepath.Join(root, id))
	setProbeAge(t, time.Hour)
	s1, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if r := s1.Find(id); r.State() != "running" || !r.Live || len(s1.Pending()) != 1 {
		t.Fatalf("with its launcher: %s, live %v, pending %+v; want running with its ask waiting", r.State(), r.Live, s1.Pending())
	}
	kill()
	s2, _ := Load(root)
	if r := s2.Find(id); r.State() != "running" || s2.Rev != s1.Rev {
		t.Fatalf("within lockProbeAge of the probe: %s, rev %d then %d; want the kept answer", r.State(), s1.Rev, s2.Rev)
	}
	lockProbeAge = 0
	s3, _ := Load(root)
	r := s3.Find(id)
	if r.State() != "lost" || r.Live || len(s3.Pending()) != 0 || len(s3.Lost()) != 1 {
		t.Fatalf("its launcher killed: %s, live %v, pending %+v; want lost, its ask never answered", r.State(), r.Live, s3.Pending())
	}
	if ch := s3.Changed(s2.Rev); s3.Rev <= s2.Rev || len(ch) != 1 || ch[0].ID != id {
		t.Fatalf("the run going lost: rev %d -> %d, changed %v", s2.Rev, s3.Rev, ch)
	}
	if r, err := LoadRun(root, id); err != nil || r.State() != "lost" {
		t.Fatalf("LoadRun: %v %v, want lost", r, err)
	}
}

// TestTheLockProbeNeverDelaysALauncher: while pages probe the listed runs' locks as often as they can (no answer
// kept), every launcher's one try at its run's lock succeeds: ledger.Open with no retry, which fails at once on any
// hold. A launcher lists its run only once it holds the lock, so no probe meets a lock a launcher is taking, and a
// probe of a lock a launcher holds takes nothing. Each run reads as running while its writer holds the lock and as
// ended once it closed. The probes hold nothing after they return: a sweep takes each dead run's lock at its first
// try.
func TestTheLockProbeNeverDelaysALauncher(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	if err := ledger.MakeDirs(root); err != nil {
		t.Fatal(err)
	}
	setProbeAge(t, 0)
	// Runs whose launchers died, their lock files free: each probe takes such a lock and lets it go.
	var dead []string
	for i := range 3 {
		id := fmt.Sprintf("r-aaaa-%04d-deadxx", 60+i)
		askingRun(t, root, id)
		if err := os.WriteFile(filepath.Join(root, id, ledger.LockFile), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		listLive(t, root, id)
		dead = append(dead, id)
	}
	s := Open(root)
	var looks atomic.Int64
	stop, first := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer once.Do(func() { close(first) })
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := s.Snapshot(); err != nil {
				t.Error(err)
				return
			}
			looks.Add(1)
			once.Do(func() { close(first) })
		}
	}()
	<-first
	before := looks.Load()
	start := record.RunStartPayload{LauncherPID: 1, LauncherStartNS: 1, TegoVersion: "0.1.0-dev", Tier: "landlock",
		Capture: "off", Kernel: "6.17.0", ContractHash: strings.Repeat("7a", 32), StopGrace: "10s", Command: []string{"sh"},
		Cwd: "/p"}
	launch := func(i int) error {
		id := fmt.Sprintf("r-3f9c2a1b-0dllq06ts%04d-launch", i)
		w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "launcher"},
			ledger.WithAnchor(ledger.NewFileChainAnchor(anchor)))
		if err != nil {
			return fmt.Errorf("launch %d met a hold of its lock: %w", i, err)
		}
		if err := ledger.MarkLive(root, id); err != nil {
			return err
		}
		if err := w.WriteRunStart(start); err != nil {
			return err
		}
		if r, err := s.Run(id); err != nil || r.State() != "running" {
			return fmt.Errorf("launch %d while its writer holds the lock: %v %v, want running", i, r, err)
		}
		if err := w.Close(record.RunEndPayload{Reason: "exit"}); err != nil {
			return err
		}
		if err := ledger.ClearLive(root, id); err != nil {
			return err
		}
		if r, err := s.Run(id); err != nil || r.State() != "ended" {
			return fmt.Errorf("launch %d closed: %v %v, want ended", i, r, err)
		}
		return nil
	}
	var err error
	for i := 0; i < 20 && err == nil; i++ {
		err = launch(i)
	}
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if looks.Load() == before {
		t.Fatal("no snapshot probed beside the launches")
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	for _, id := range dead {
		f, err := os.OpenFile(filepath.Join(root, id, ledger.LockFile), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Errorf("a sweep of %s met a hold after the probes returned: %v", id, err)
		}
		_ = f.Close()
	}
}

// TestTheLockProbeAsksOnlyListedRunDirectories: only a run directory the index lists is probed, never a run it does
// not list (a launcher may be taking that lock), a listed name that is no run id or a run directory reached through
// a link; one answer per lockProbeAge, and none kept for a run the index no longer lists.
func TestTheLockProbeAsksOnlyListedRunDirectories(t *testing.T) {
	root := t.TempDir()
	listed, unlisted, linked := "r-aaaa-0071-listed", "r-aaaa-0072-unlist", "r-aaaa-0073-linked"
	askingRun(t, root, listed)
	askingRun(t, root, unlisted)
	if err := os.Symlink(filepath.Join(root, listed), filepath.Join(root, linked)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{listed, linked, "not-a-run"} {
		listLive(t, root, id)
	}
	var mu sync.Mutex
	var asked []string
	keep := lockHeld
	t.Cleanup(func() { lockHeld = keep })
	lockHeld = func(dir string) (bool, error) {
		mu.Lock()
		asked = append(asked, dir)
		mu.Unlock()
		return keep(dir)
	}
	setProbeAge(t, time.Hour)
	s := Open(root)
	for range 3 {
		if _, err := s.Snapshot(); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{listed, unlisted} {
			if _, err := s.Run(id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if want := []string{filepath.Join(root, listed)}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("probed %q, want %q once", asked, want)
	}
	lockProbeAge = 0
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 {
		t.Fatalf("probed %q; an answer older than lockProbeAge must be asked again", asked)
	}
	if err := os.Remove(filepath.Join(root, ".live", listed)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	s.liveMu.Lock()
	_, kept := s.probes[listed]
	s.liveMu.Unlock()
	if kept || len(asked) != 2 {
		t.Fatalf("after the entry went: kept %v, probed %q", kept, asked)
	}
}
