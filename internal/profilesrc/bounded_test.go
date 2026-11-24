// SPDX-License-Identifier: Apache-2.0

package profilesrc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestDirBoundedGraphReads(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "shared.yaml")
	if err := os.WriteFile(path, []byte("version: 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := Dir{Root: root}
	if _, data, err := s.ResolveBounded(context.Background(), "shared", 32); err != nil || string(data) != "version: 0\n" {
		t.Fatalf("bounded regular read: %q %v", data, err)
	}
	if _, _, err := s.ResolveBounded(context.Background(), "shared", 3); !errors.Is(err, agent.ErrLoadBudget) {
		t.Fatalf("overflow: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := s.ResolveBounded(ctx, "missing", 32); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation before I/O: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe.yaml"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ResolveBounded(context.Background(), "pipe", 32); !errors.Is(err, agent.ErrNotAFile) {
		t.Fatalf("profile stream could block the request: %v", err)
	}
}
