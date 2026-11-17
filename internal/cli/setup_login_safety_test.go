// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSavedLoginFileSafety(t *testing.T) {
	for _, attack := range []string{"readable", "env-link", "env-hardlink", "rc-link", "rc-hardlink", "directory-link"} {
		t.Run(attack, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Chmod(home, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("unchanged\n"), 0600); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(home, ".config", "tego")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, agentEnvRel)
			switch attack {
			case "readable":
				if err := os.WriteFile(path, []byte("OLD='old'\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "env-link":
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "env-hardlink":
				if err := os.Link(outside, path); err != nil {
					t.Fatal(err)
				}
			case "rc-link":
				if err := os.Symlink(outside, filepath.Join(home, ".bashrc")); err != nil {
					t.Fatal(err)
				}
			case "rc-hardlink":
				if err := os.Link(outside, filepath.Join(home, ".bashrc")); err != nil {
					t.Fatal(err)
				}
			case "directory-link":
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Dir(outside), dir); err != nil {
					t.Fatal(err)
				}
			}
			old, _ := os.Open(path)
			if old != nil {
				defer func() { _ = old.Close() }()
			}
			err := saveLogin(home, "CODEX_API_KEY", "new-secret")
			b, _ := os.ReadFile(outside)
			if string(b) != "unchanged\n" {
				t.Fatalf("outside overwritten: %q", b)
			}
			if attack != "readable" {
				if err == nil {
					t.Fatal("unsafe target accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if old != nil {
				b, _ = io.ReadAll(old)
				if string(b) != "OLD='old'\n" {
					t.Fatalf("secret exposed to old reader: %q", b)
				}
			}
			fi, err := os.Stat(path)
			if err != nil || fi.Mode().Perm() != 0600 {
				t.Fatalf("mode: %v %v", fi, err)
			}
		})
	}
}
