// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// holdAdmissionMigration holds the real migration flock and signals only after
// the adopter has attempted and failed to acquire it. No sleep orders the edit.
func holdAdmissionMigration(t *testing.T, f *adoptFixture) (<-chan struct{}, func()) {
	t.Helper()
	store, err := openAdoptStore(f.state)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := store.lockMoves(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{})
	old := movesFlock
	var once sync.Once
	movesFlock = func(fd, how int) error {
		err := old(fd, how)
		if errors.Is(err, unix.EWOULDBLOCK) {
			once.Do(func() { close(waiting) })
		}
		return err
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { _ = lock.Close() }) }
	t.Cleanup(func() { release(); movesFlock = old })
	return waiting, release
}

func assertAdmissionCleanup(t *testing.T, f *adoptFixture) {
	t.Helper()
	if len(f.host.moves) != 0 {
		t.Fatalf("refused adoption moved processes: %v", f.host.moves)
	}
	if got := f.host.in(adoptSession); len(got) != 4 {
		t.Fatalf("session changed: %v", got)
	}
	root, err := LedgerRoot(f.deps.Config)
	if err != nil {
		t.Fatal(err)
	}
	if left := leftBehind(t, root); len(left) != 0 {
		t.Errorf("partial ledger state: %v", left)
	}
	if left := recordsLeft(f.state); len(left) != 0 {
		t.Errorf("partial adoption state: %v", left)
	}
	if f.cgroups.created != f.cgroups.removed {
		t.Errorf("scope leaked: created=%d removed=%d", f.cgroups.created, f.cgroups.removed)
	}
	if h := f.backend.handle; h == nil || h.detached == 0 || h.closed == 0 {
		t.Errorf("prepared handle not cleaned: %+v", h)
	}
}

// TestAdoptFinalAdmissionReloadsConfiguration exercises actual config loading
// after a real migration-lock wait. Empty snapshots get no exemption.
func TestAdoptFinalAdmissionReloadsConfiguration(t *testing.T) {
	for _, mutation := range []string{"baseline added", "selected file corrupted", "ordinary bytes changed", "equal bytes replaced"} {
		t.Run(mutation, func(t *testing.T) {
			f := newAdoptFixture(t)
			f.backend.plane = "lsm"
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			layer := filepath.Join(dir, "config.yaml")
			text := "ledger_root: " + f.root + "\n"
			if err := os.WriteFile(layer, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			load := func() (*config.Machine, error) {
				m, _, err := config.LoadSources(config.Sources{User: layer}, dir, os.Getuid(), config.TrustAbort)
				return m, err
			}
			var err error
			f.deps.Config, err = load()
			if err != nil {
				t.Fatal(err)
			}
			f.deps.ReloadConfig = load
			waiting, release := holdAdmissionMigration(t, f)
			spec := f.spec(t)
			spec.Boundary = true
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := Adopt(ctx, f.rt, spec, f.deps); done <- err }()
			select {
			case <-waiting:
			case err := <-done:
				t.Fatalf("did not wait: %v", err)
			case <-ctx.Done():
				t.Fatal("did not reach migration lock")
			}
			want := "adoption configuration changed before migration"
			switch mutation {
			case "baseline added":
				text += "baseline: {env: {deny: [NEW_SECRET]}}\n"
				want = ErrBaselineRecordUnavailable.Error()
			case "selected file corrupted":
				text = "baseline: [invalid-schema]\n"
				want = "adoption configuration before migration: config: invalid layer"
			case "ordinary bytes changed":
				text += "# changed while waiting\n"
			case "equal bytes replaced":
				if err := os.Rename(layer, layer+".old"); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(layer, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			release()
			err = <-done
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("Adopt = %v, want product refusal %q", err, want)
			}
			if mutation == "baseline added" && !errors.Is(err, ErrBaselineRecordUnavailable) {
				t.Fatalf("new baseline did not reach release gate: %v", err)
			}
			assertAdmissionCleanup(t, f)
		})
	}
}

func TestAdoptFinalAdmissionRechecksPlaneAfterWait(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = "fmod_ret"
	var admitted atomic.Bool
	admitted.Store(true)
	checks := 0
	f.backend.admission = func() error {
		checks++
		if !admitted.Load() {
			return errors.New("preemption full: the hook then proceeds undecided")
		}
		return nil
	}
	waiting, release := holdAdmissionMigration(t, f)
	spec := f.spec(t)
	spec.Boundary = true
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Adopt(ctx, f.rt, spec, f.deps); done <- err }()
	select {
	case <-waiting:
	case err := <-done:
		t.Fatalf("did not wait: %v", err)
	case <-ctx.Done():
		t.Fatal("did not reach migration lock")
	}
	// Lock contention synchronizes after the first admission check and Arm.
	admitted.Store(false)
	release()
	err := <-done
	if !errors.Is(err, ErrAdoptNoPlane) || !strings.Contains(err.Error(), "preemption full") {
		t.Fatalf("Adopt = %v, want live mode refusal", err)
	}
	if checks != 2 {
		t.Errorf("admission checks=%d, want before Arm and after lock wait", checks)
	}
	assertAdmissionCleanup(t, f)
}

func TestAdoptFinalAdmissionRechecksAnchorAfterWait(t *testing.T) {
	f := newAdoptFixture(t)
	f.backend.plane = "lsm"
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	layer := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(layer, []byte("ledger_root: "+f.root+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func() (*config.Machine, error) {
		m, _, err := config.LoadSources(config.Sources{User: layer}, dir, os.Getuid(), config.TrustAbort)
		return m, err
	}
	var err error
	f.deps.Config, err = load()
	if err != nil {
		t.Fatal(err)
	}
	f.deps.ReloadConfig = load
	f.deps.AnchorPath = filepath.Join(dir, ledger.ChainLogFile)
	waiting, release := holdAdmissionMigration(t, f)
	spec := f.spec(t)
	spec.Boundary = true
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	// A regressed migration must finish promptly so the refusal assertion,
	// rather than the test deadline, exposes the missing final check.
	spec.Started = func(AdoptStarted) { cancel() }
	done := make(chan error, 1)
	go func() {
		_, err := Adopt(ctx, f.rt, spec, f.deps)
		done <- err
		close(done)
	}()
	defer func() {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("adopter did not finish after cancellation and lock release")
		}
	}()
	select {
	case <-waiting:
	case err := <-done:
		t.Fatalf("did not wait: %v", err)
	case <-ctx.Done():
		t.Fatal("did not reach migration lock")
	}
	// Only the file changes. The containing directory and trusted configuration
	// retain their identities while final admission waits for the real flock.
	if info, err := os.Lstat(f.deps.AnchorPath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("preparation did not create a regular anchor: %v, %v", info, err)
	}
	target := filepath.Join(dir, "unrelated")
	const contents = "not an anchor\n"
	if err := os.WriteFile(target, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.deps.AnchorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, f.deps.AnchorPath); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("anchor refusal did not finish before the adoption timeout")
	}
	if !errors.Is(err, ledger.ErrLinkRefused) || !strings.Contains(err.Error(), "adoption chain anchor before migration") {
		t.Fatalf("Adopt = %v, want product chain-anchor link refusal", err)
	}
	assertAdmissionCleanup(t, f)
	if got, err := os.ReadFile(target); err != nil || string(got) != contents {
		t.Fatalf("link target changed: %q, %v", got, err)
	}
}
