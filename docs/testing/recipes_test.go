// SPDX-License-Identifier: Apache-2.0

package testingrecipes

import (
	_ "embed"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed alma-systemd-version.sh
var almaVersionProbe string

//go:embed contracts-stalled-mount.py
var stalledMountRecipe string

//go:embed contracts-stalled-mount-selfcheck.py
var stalledMountSelfcheck string

//go:embed contracts-fuse-server.py
var stalledMountServer string

func TestStalledMountRecipeRejectsWrongEvidence(t *testing.T) {
	dir := t.TempDir()
	recipe := filepath.Join(dir, "contracts-stalled-mount.py")
	check := filepath.Join(dir, "selfcheck.py")
	server := filepath.Join(dir, "contracts-fuse-server.py")
	for path, script := range map[string]string{recipe: stalledMountRecipe, check: stalledMountSelfcheck, server: stalledMountServer} {
		if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command("python3", "-I", check, recipe).CombinedOutput()
	if err != nil {
		t.Fatalf("recipe evidence self-check failed: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

func TestAlmaVersionProbeChecksStatus(t *testing.T) {
	for _, tt := range []struct {
		name, command, want string
		fail                bool
	}{
		{"success", "printf 'systemd 252\\n+PAM +AUDIT\\n'", "systemd 252\n", false},
		{"failure-with-output", "printf 'broken systemd\\n'; exit 7", "", true},
		{"missing", "", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			standin := filepath.Join(dir, "systemd")
			if tt.command != "" {
				if err := os.WriteFile(standin, []byte("#!/bin/sh\n"+tt.command+"\n"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.ReplaceAll(almaVersionProbe, "/usr/lib/systemd/systemd", standin)
			cmd := exec.Command("/bin/sh", "-c", script)
			out, err := cmd.Output()
			if (err != nil) != tt.fail {
				t.Fatalf("probe returned %v, want failure=%v, stdout=%q", err, tt.fail, out)
			}
			if string(out) != tt.want {
				t.Fatalf("stdout=%q, want %q", out, tt.want)
			}
		})
	}
}
