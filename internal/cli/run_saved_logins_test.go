// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSavedLogins(t *testing.T) {
	for _, kind := range []string{"saved", "exported", "exported-empty", "missing", "readable", "linked", "foreign"} {
		t.Run(kind, func(t *testing.T) {
			f := onFixture(t, "fresh")
			if kind == "foreign" && os.Geteuid() != 0 {
				t.Skip("changing a file to a foreign owner is unavailable to this uid")
			}
			if err := saveLogin(f.Home, "CODEX_API_KEY", "saved-token"); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.Home, agentEnvRel)
			t.Setenv("CODEX_API_KEY", "")
			if err := os.Unsetenv("CODEX_API_KEY"); err != nil {
				t.Fatal(err)
			}
			want := "saved-token"
			switch kind {
			case "exported":
				t.Setenv("CODEX_API_KEY", "exported-token")
				want = "exported-token"
			case "exported-empty":
				t.Setenv("CODEX_API_KEY", "")
				want = ""
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				want = ""
			case "readable":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
				want = ""
			case "foreign":
				if err := os.Chown(path, 1, -1); err != nil {
					t.Skipf("cannot give the test file a foreign owner: %v", err)
				}
				want = ""
			case "linked":
				target := path + "-target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				want = ""
			}
			contract := filepath.Join(f.Project, "saved-login.yaml")
			if err := os.WriteFile(contract, []byte("version: 0\nname: login\ncommand: [/bin/sh]\nenv: {pass: [CODEX_API_KEY]}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			old := launchEnviron
			t.Cleanup(func() { launchEnviron = old })
			seen := "not-called"
			launchEnviron = func() []string {
				seen = os.Getenv("CODEX_API_KEY")
				cancel() // Stop before backend selection or launching a real program.
				return os.Environ()
			}
			var out bytes.Buffer
			_ = runRun(ctx, runOptions{contract: contract, offline: true}, &out)
			if seen != want {
				t.Fatalf("run compile saw %q, want %q: %s", seen, want, &out)
			}
			unsafe := kind == "readable" || kind == "foreign" || kind == "linked"
			lines := strings.Count(out.String(), "Ignored saved logins:")
			if unsafe && lines != 1 || !unsafe && lines != 0 {
				t.Fatalf("saved login diagnostic count %d: %s", lines, &out)
			}
		})
	}
}
