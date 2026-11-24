// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stageHangGuard ends a test whose write never reaches a controlled stage or never returns (a hang). It is not a speed
// estimate: a write reaches a stage after its disk syncs, which a busy host can hold for longer than any short bound
// (the gate saw four stages miss a 5 s one while the package ran 49 s against 13 s), so each wait ends when its event
// happens and a fast host finishes at once.
const stageHangGuard = 5 * time.Minute

func TestCanceledWriteDoesNotResumeAfterGuard(t *testing.T) {
	for _, operation := range []string{"replace", "create"} {
		stages := []string{"resolved", "lock", "rename"}
		if operation == "replace" {
			stages = append(stages, "read", "bak", "temp")
		}
		for _, stage := range stages {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				g, existing := fixture(t)
				path := existing
				if operation == "create" {
					path = filepath.Join(filepath.Dir(existing), "new.yaml")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				arrived, resume := make(chan struct{}), make(chan struct{})
				paused := false
				setHook(t, func(at string) error {
					if at == stage && !paused {
						paused = true
						close(arrived)
						<-resume
					}
					return nil
				})
				done := make(chan error, 1)
				go func() {
					var err error
					if operation == "replace" {
						_, err = Replace(ctx, g, path, Sum([]byte(textA)), []byte(textB), Change{})
					} else {
						_, err = Create(ctx, g, path, []byte(textB), Change{})
					}
					done <- err
				}()
				select {
				case <-arrived:
				case err := <-done:
					t.Fatalf("write ended before controlled %s: %v", stage, err)
				case <-time.After(stageHangGuard):
					close(resume)
					t.Fatal("write did not reach controlled stage")
				}
				// The caller has abandoned its request while the guard or temporary
				// write cannot answer. Recovery must not commit the requested file.
				cancel()
				close(resume)
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Errorf("write after cancellation: %v, want context.Canceled", err)
					}
				case <-time.After(stageHangGuard):
					t.Fatal("write did not return after recovery")
				}
				if operation == "replace" {
					if got := mustRead(t, path); got != textA {
						t.Errorf("expired replacement committed %q", got)
					}
				} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("expired creation committed a file: %v", err)
				}
				if stage == "resolved" {
					if _, err := os.Lstat(filepath.Join(g.LedgerRoot, JournalDirName)); !errors.Is(err, os.ErrNotExist) {
						t.Errorf("expired path resolution created a journal directory: %v", err)
					}
				}
				if entries, err := ReadJournal(g.LedgerRoot); err != nil || len(entries) != 0 {
					t.Errorf("expired write journaled entries=%+v err=%v", entries, err)
				}
				entries, err := os.ReadDir(filepath.Dir(path))
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.Contains(entry.Name(), ".tego-rule-") || strings.Contains(entry.Name(), ".tego-new-") {
						t.Errorf("expired write retained temporary file %s", entry.Name())
					}
				}
			})
		}
	}
}

func TestCanceledWriteDoesNotInspectPath(t *testing.T) {
	g, existing := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(filepath.Dir(existing), "absent", "agent.yaml")
	if _, err := Replace(ctx, g, path, Sum([]byte(textA)), []byte(textB), Change{}); !errors.Is(err, context.Canceled) {
		t.Errorf("replace inspected a path after cancellation: %v", err)
	}
	if _, err := Create(ctx, g, path, []byte(textB), Change{}); !errors.Is(err, context.Canceled) {
		t.Errorf("create inspected a path after cancellation: %v", err)
	}
	if _, err := Revert(ctx, g, "absent", RevertOptions{}); !errors.Is(err, context.Canceled) {
		t.Errorf("revert inspected its journal after cancellation: %v", err)
	}
	if _, err := Undo(ctx, g, path, RevertOptions{}); !errors.Is(err, context.Canceled) {
		t.Errorf("undo inspected a path after cancellation: %v", err)
	}
}
