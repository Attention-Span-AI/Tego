// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProjectDirectoryHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ProjectDirectory(ctx, DirectoryRequest{Typed: t.TempDir()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled preflight: %v", err)
	}
}

func TestProjectDirectoryChildPreservesGuards(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(project, alias); err != nil {
		t.Fatal(err)
	}
	for _, typed := range []string{project, alias} {
		got, err := ProjectDirectory(t.Context(), DirectoryRequest{Typed: typed})
		if err != nil || got != project {
			t.Fatalf("canonical preflight: %q %v", got, err)
		}
	}
	for _, req := range []DirectoryRequest{{Typed: project, Refuse: []string{root}}, {Typed: "relative"}, {Typed: filepath.Join(root, "missing")}} {
		if got, err := ProjectDirectory(t.Context(), req); err == nil {
			t.Fatalf("untrusted project accepted: %q", got)
		}
	}
}
