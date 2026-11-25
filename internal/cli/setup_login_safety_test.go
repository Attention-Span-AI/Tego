// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
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
			if attack != "rc-link" && string(b) != "unchanged\n" {
				t.Fatalf("outside overwritten: %q", b)
			}
			if err != nil {
				t.Fatal(err)
			}
			if old != nil {
				b, _ = io.ReadAll(old)
				want := "OLD='old'\n"
				if attack != "readable" {
					want = "unchanged\n"
				}
				if string(b) != want {
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

func TestSavedLoginOrdinaryLayouts(t *testing.T) {
	for _, layout := range []string{"linked-home", "linked-config", "linked-bashrc", "group-writable", "hardlinks"} {
		t.Run(layout, func(t *testing.T) {
			f := onFixture(t, "fresh")
			noLogins(t)
			fakeProgram(t, "claude")
			target := t.TempDir()
			switch layout {
			case "linked-home":
				real := f.Home + "-real"
				if err := os.Rename(f.Home, real); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(real, f.Home); err != nil {
					t.Fatal(err)
				}
			case "linked-config":
				if err := os.Rename(filepath.Join(f.Home, ".config"), filepath.Join(target, "config")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(target, "config"), filepath.Join(f.Home, ".config")); err != nil {
					t.Fatal(err)
				}
			case "linked-bashrc":
				rc := filepath.Join(target, "bashrc")
				if err := os.WriteFile(rc, []byte("# dotfiles\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(rc, filepath.Join(f.Home, ".bashrc")); err != nil {
					t.Fatal(err)
				}
			case "group-writable":
				if err := os.Chmod(f.Home, 0775); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Join(f.Home, ".config/tego"), 0775); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(f.Home, ".config/tego"), 0775); err != nil {
					t.Fatal(err)
				}
			case "hardlinks":
				if err := saveLogin(f.Home, "CODEX_API_KEY", "old"); err != nil {
					t.Fatal(err)
				}
				for i, rel := range []string{agentEnvRel, ".bashrc"} {
					if err := os.Link(filepath.Join(f.Home, rel), filepath.Join(target, []string{"env", "rc"}[i])); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Chdir(f.Home)
			code, out, errs := runGuide(t, "2\n2\nsk-layout\n1\n1\n1\n")
			if code != 0 || !strings.Contains(out, "Ready") || strings.Contains(out, "Couldn't save") {
				t.Fatalf("guide: %d %s %s", code, out, errs)
			}
			if got := savedLogin(f.Home, "ANTHROPIC_API_KEY"); got != "sk-layout" {
				t.Fatalf("saved: %q", got)
			}
			rc, err := os.ReadFile(filepath.Join(f.Home, ".bashrc"))
			if err != nil || !strings.Contains(string(rc), bashrcLine) {
				t.Fatalf("loader: %q %v", rc, err)
			}
			log, err := openDashboardLog(f.Home)
			if err != nil {
				t.Fatal(err)
			}
			if err := log.Close(); err != nil {
				t.Fatal(err)
			}
			code, out, errs = runGuide(t, "1\n1\n1\n1\n1\n")
			if code != 0 || !strings.Contains(out, "Ready") {
				t.Fatalf("replace rules: %d %s %s", code, out, errs)
			}
			if layout == "linked-bashrc" {
				fi, err := os.Lstat(filepath.Join(f.Home, ".bashrc"))
				if err != nil || fi.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("dotfile link replaced: %v %v", fi, err)
				}
			}
		})
	}
}

func TestSecretReadChecks(t *testing.T) {
	if err := ownGuideFile(&unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uint32(os.Geteuid() + 1), Nlink: 1}); err == nil {
		t.Fatal("foreign owner accepted")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config/tego"), 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, agentEnvRel)
	if err := os.WriteFile(p, []byte("CODEX_API_KEY='exposed'\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGuideFile(home, agentEnvRel); err == nil {
		t.Fatal("readable secret accepted")
	}
}

func TestGuideContinuesAfterUnsafeLoginFile(t *testing.T) {
	for _, kind := range []string{"directory", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			f := onFixture(t, "fresh")
			noLogins(t)
			fakeProgram(t, "claude")
			path := filepath.Join(f.Home, agentEnvRel)
			if kind == "directory" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			var diag bytes.Buffer
			if got := readSavedLogins(f.Home, &diag); len(got) != 0 || strings.Count(diag.String(), "\n") != 1 || !strings.Contains(diag.String(), "not a regular file") {
				t.Fatalf("unsafe read: %v %s", got, &diag)
			}
			t.Chdir(f.Home)
			code, out, errs := runGuide(t, "2\n2\nsk-session\n1\n1\n1\n")
			if code != 0 || !strings.Contains(out, "Ready") || !strings.Contains(out, "Couldn't save the login") || os.Getenv("ANTHROPIC_API_KEY") != "sk-session" {
				t.Fatalf("guide lost session login or stopped: %d %s %s", code, out, errs)
			}
		})
	}
}
