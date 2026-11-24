// SPDX-License-Identifier: Apache-2.0

package guide

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdRunPathChecksOnlyItsFixedList(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "systemd-run")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	missing := filepath.Join(dir, "missing")
	if path, err := systemdRunPath([]string{missing}); path != "" || err == nil {
		t.Fatalf("PATH supplied a runner outside the list: %q, %v", path, err)
	}
	if path, err := systemdRunPath([]string{missing, fake}); path != fake || err != nil {
		t.Fatalf("fixed executable: %q, %v", path, err)
	}
	if err := os.Chmod(fake, 0o644); err != nil {
		t.Fatal(err)
	}
	if path, err := systemdRunPath([]string{fake, dir}); path != "" || err == nil {
		t.Fatalf("unusable entries: %q, %v", path, err)
	}
}

// A PATH-only systemd-run used to make the guide offer automatic entry even when the handoff could not find its
// fixed executable. Both must ask the same question, including when the executable is absent from PATH.
func TestOpenScopeUsesTheHandoffsRunnerCheck(t *testing.T) {
	prev := scopeRunner
	t.Cleanup(func() { scopeRunner = prev })
	for _, available := range []bool{true, false} {
		t.Run(map[bool]string{true: "fixed runner available", false: "PATH runner only"}[available], func(t *testing.T) {
			dir := t.TempDir()
			if !available {
				if err := os.WriteFile(filepath.Join(dir, "systemd-run"), []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			scopeRunner = func() (string, error) {
				called = true
				if available {
					return "/usr/bin/systemd-run", nil
				}
				return systemdRunPath([]string{filepath.Join(dir, "absent")})
			}
			env := func(name string) string {
				if name == "PATH" {
					return dir
				}
				return ""
			}
			o := openScope(env, os.Getuid(), t.TempDir(), reader{})
			if !called {
				t.Fatal("guide did not check the handoff's fixed runner")
			}
			missingRunner := strings.Contains(o.Missing, "systemd-run is missing from /usr/bin and /bin")
			if missingRunner == available {
				t.Fatalf("available=%v: %+v", available, o)
			}
		})
	}
}
