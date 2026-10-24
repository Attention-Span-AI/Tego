// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/maze/scan"
)

// fakeTego writes an executable tego script into dir that leaves a mark beside itself and prints out.
func fakeTego(t *testing.T, dir, out string) (mark string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mark = filepath.Join(dir, "ran")
	script := "#!/bin/sh\n: > '" + mark + "'\nprintf '%s\\n' '" + out + "' >&2\nexit 2\n"
	if err := os.WriteFile(filepath.Join(dir, "tego"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return mark
}

// TestVerifyEngineSkipsAProjectTego: a tego inside the project, first on PATH, is never run on save.
func TestVerifyEngineSkipsAProjectTego(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the engine check runs on Linux only")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	mark := fakeTego(t, bin, "planted")
	checked, _, note := verifyEngine(context.Background(), scan.Env{Path: bin}, root, filepath.Join(t.TempDir(), "claude.yaml"))
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("the project's own tego was run")
	}
	if checked || !strings.Contains(note, "inside this project") {
		t.Errorf("checked %v, note %q", checked, note)
	}

	// The same through a link to the project.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, _, note := verifyEngine(context.Background(), scan.Env{Path: filepath.Join(link, "bin")}, root, "x.yaml"); !strings.Contains(note, "inside this project") {
		t.Errorf("through a link: note %q", note)
	}
	if _, err := os.Stat(mark); err == nil {
		t.Fatal("the project's own tego was run through a link")
	}
}

// TestVerifyEngineSaysWhyItStopped: an engine that stops before its summary line has its first line shown.
func TestVerifyEngineSaysWhyItStopped(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the engine check runs on Linux only")
	}
	bin := t.TempDir()
	mark := fakeTego(t, bin, "tego: the machine config is not owned by root")
	checked, _, note := verifyEngine(context.Background(), scan.Env{Path: bin}, t.TempDir(), filepath.Join(t.TempDir(), "claude.yaml"))
	if _, err := os.Stat(mark); err != nil {
		t.Fatal("the engine outside the project was not run")
	}
	if checked || !strings.Contains(note, "the machine config is not owned by root") {
		t.Errorf("checked %v, note %q", checked, note)
	}
}
