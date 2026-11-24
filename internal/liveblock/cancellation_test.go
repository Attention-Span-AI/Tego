// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCanceledUpdateDoesNotInspectPath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := Update(ctx, filepath.Join(t.TempDir(), "absent"), testRun, func(*Overlay) (bool, error) {
		called = true
		return true, nil
	})
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled update inspected its path or ran its callback: err=%v called=%v", err, called)
	}
}

func TestCanceledUpdateDoesNotCommitAfterCallback(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "existing"}[exists], func(t *testing.T) {
			dir := t.TempDir()
			var before []byte
			if exists {
				_, err := Update(context.Background(), dir, testRun, func(o *Overlay) (bool, error) {
					_, changed, err := o.Add(KindExec, "curl", "fixture", time.Now())
					return changed, err
				})
				if err != nil {
					t.Fatal(err)
				}
				before, err = os.ReadFile(filepath.Join(dir, FileName))
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			_, err := Update(ctx, dir, testRun, func(o *Overlay) (bool, error) {
				_, changed, err := o.Add(KindExec, "git", "expired request", time.Now())
				cancel() // A path check/callback returned only after the caller left.
				return changed, err
			})
			if !errors.Is(err, context.Canceled) {
				t.Errorf("update committed after cancellation: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, FileName))
			if exists {
				if err != nil || string(got) != string(before) {
					t.Errorf("existing overlay changed: %q, %v", got, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Errorf("expired request created an overlay: %q, %v", got, err)
			}
		})
	}
}
