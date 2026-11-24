// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/setup"
)

const stalledComposeName = "test-stalled-composition"

// The test binary stalls before a composition's filesystem probes. A ready
// marker distinguishes a blocked child from a request cancelled before launch.
func composeStalledHelperForTest(r Request) bool {
	if r.ComposeOptions == nil || r.ComposeOptions.Name != stalledComposeName {
		return false
	}
	if err := os.WriteFile(filepath.Join(r.ComposeOptions.Dir, "compose-ready"), nil, 0600); err != nil {
		return true
	}
	_, _ = os.Stdout.Write([]byte{readyMark})
	time.Sleep(time.Hour)
	return true
}

func TestComposeCancellationStopsBlockedHelper(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Compose(ctx, setup.Options{Dir: dir, Name: stalledComposeName, Presets: []string{"no-secrets"}})
		done <- err
	}()
	ready := filepath.Join(dir, "compose-ready")
	deadline := time.NewTimer(Budget)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
waiting:
	for {
		if _, err := os.Stat(ready); err == nil {
			break waiting
		}
		select {
		case err := <-done:
			t.Fatalf("composition bypassed the blocked helper: %v", err)
		case <-deadline.C:
			t.Fatal("composition helper did not reach its blocking boundary")
		case <-tick.C:
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("blocked composition cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked composition held its caller after cancellation")
	}
	waitSlots(t, 0)
}

func TestComposePreservesSetupMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/project\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := setup.Options{Dir: dir, Home: t.TempDir(), Name: "composed", Command: "/bin/sh", Presets: []string{"no-secrets", "repo-only-writes"}, Writes: []string{"./out/"}, Reads: true}
	want, err := setup.Compose(o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Compose(t.Context(), o)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Contract) != string(want.Contract) || !reflect.DeepEqual(got.MakeDirs, want.MakeDirs) ||
		!reflect.DeepEqual(got.Ignore, want.Ignore) || !reflect.DeepEqual(got.Notes, want.Notes) ||
		!reflect.DeepEqual(got.Presets, want.Presets) || !reflect.DeepEqual(got.Grants, want.Grants) {
		t.Fatal("child composition lost contract bytes or setup metadata")
	}
	if len(got.MakeDirs) < 2 {
		t.Fatalf("fixture did not plan generated directories: %v", got.MakeDirs)
	}
	for _, path := range got.MakeDirs {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("composition created %s: %v", path, err)
		}
	}
	// Create uses only exported metadata; the private compose filter state is
	// unnecessary when compilation uses the explicit planned-directory list.
	if _, err := setup.CreateContext(t.Context(), got, dir); err != nil {
		t.Fatalf("round-tripped composition cannot create its planned folders: %v", err)
	}
}
