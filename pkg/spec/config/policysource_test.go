// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestPolicySystemPlacementAndAbsence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   os.FileMode
		setup  string
		want   string
		absent bool
	}{
		{"present", 0644, "file", "", false}, {"absent", 0644, "missing", "", true},
		{"writable source", 0666, "file", "writable", false}, {"unreadable", 0600, "file", "readable", false},
		{"unsafe absence", 0777, "parent", "writable", false}, {"dangling", 0644, "link", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "etc", "tego")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "general.yaml")
			switch tc.setup {
			case "file":
				if err := os.WriteFile(path, []byte("source"), tc.mode); err != nil {
					t.Fatal(err)
				}
			case "parent":
				if err := os.Chmod(dir, tc.mode); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("missing", path); err != nil {
					t.Fatal(err)
				}
			}
			got, absent, err := readPolicySourceAt(root, "/etc/tego/general.yaml", true, os.Getuid(), os.Getuid(), 100)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %+v absent=%v err=%v", got, absent, err)
				}
				return
			}
			if tc.setup == "link" {
				if err == nil || absent {
					t.Fatalf("dangling became absence: %v %v", absent, err)
				}
				return
			}
			if err != nil || absent != tc.absent {
				t.Fatalf("got %+v absent=%v err=%v", got, absent, err)
			}
			if !absent && (string(got.Data) != "source" || got.Owner != os.Getuid() || got.Resolved != path || len(got.Walk) < 3) {
				t.Fatalf("wrong descriptor provenance: %+v", got)
			}
		})
	}
}

func TestPolicyUserClosedWalkAndBounds(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".tego")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "general.yaml")
	if err := os.WriteFile(path, []byte("source"), 0600); err != nil {
		t.Fatal(err)
	}
	read := func() error {
		_, absent, err := readPolicySourceAt(root, "/.tego/general.yaml", false, 0, os.Getuid(), 100)
		if absent {
			t.Fatal("present source became absent")
		}
		return err
	}
	if err := read(); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{root, dir, path} {
		st, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0777); err != nil {
			t.Fatal(err)
		}
		if err := read(); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("unsafe %s: %v", target, err)
		}
		if err := os.Chmod(target, st.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := readPolicySourceAt(root, "/.tego/general.yaml", false, 0, os.Getuid(), 3); err == nil {
		t.Fatal("oversize source accepted")
	}
	if err := os.Link(path, filepath.Join(root, "other")); err != nil {
		t.Fatal(err)
	}
	if err := read(); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("hard link accepted: %v", err)
	}
	for _, bad := range []string{"relative.yaml", "/proc/self/cwd/general.yaml"} {
		if _, absent, err := ReadPolicySource(bad, false, os.Getuid(), 100); err == nil || absent {
			t.Fatalf("unsafe path %s: absent=%v err=%v", bad, absent, err)
		}
	}
}

// Each row is an ordinary source layout, including symlinks used for atomic policy
// publication. Link mode 0777 says nothing about the resolved directory's privacy.
func TestPolicyUserOrdinaryLayouts(t *testing.T) {
	for _, tc := range []struct {
		name       string
		link       string
		target     string
		parentLink bool
		dirMode    os.FileMode
		fileMode   os.FileMode
		want       string
	}{
		{"private regular", "", "/.tego/general.yaml", false, 0700, 0600, ""},
		{"public regular directory", "", "/.tego/general.yaml", false, 0755, 0600, "directory must be private"},
		{"relative sibling link", "general-v1.yaml", "/.tego/general-v1.yaml", false, 0700, 0600, ""},
		{"absolute sibling link", "/.tego/general-v1.yaml", "/.tego/general-v1.yaml", false, 0700, 0600, ""},
		{"relative nested link", "versions/general-v1.yaml", "/.tego/versions/general-v1.yaml", false, 0700, 0600, ""},
		{"absolute nested link", "/.tego/versions/general-v1.yaml", "/.tego/versions/general-v1.yaml", false, 0700, 0600, ""},
		{"relative public target directory", "versions/general-v1.yaml", "/.tego/versions/general-v1.yaml", false, 0755, 0600, "directory must be private"},
		{"absolute public target directory", "/.tego/versions/general-v1.yaml", "/.tego/versions/general-v1.yaml", false, 0755, 0600, "directory must be private"},
		{"public regular file", "", "/.tego/general.yaml", false, 0700, 0644, "source must be private"},
		{"relative parent directory link", "", "/policy/general.yaml", true, 0700, 0600, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, tc.target)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(target), tc.dirMode); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("source"), tc.fileMode); err != nil {
				t.Fatal(err)
			}
			if tc.parentLink {
				if err := os.Symlink("policy", filepath.Join(root, ".tego")); err != nil {
					t.Fatal(err)
				}
			} else if tc.link != "" {
				if err := os.Symlink(tc.link, filepath.Join(root, ".tego", "general.yaml")); err != nil {
					t.Fatal(err)
				}
			}
			got, absent, err := readPolicySourceAt(root, "/.tego/general.yaml", false, 0, os.Getuid(), 100)
			if tc.want != "" {
				if !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), tc.want) || absent {
					t.Fatalf("want %q refusal: got %+v absent=%v err=%v", tc.want, got, absent, err)
				}
				return
			}
			if err != nil || absent || string(got.Data) != "source" || got.Resolved != target {
				t.Fatalf("valid layout: got %+v absent=%v err=%v, want resolved %s", got, absent, err, target)
			}
		})
	}
}

// These deterministic swaps exercise the directory check between opening the
// source and reading its bytes, without a race loop or a caller-path second walk.
func TestPolicyPrivateDirectoryDescriptorBinding(t *testing.T) {
	for _, replacement := range []string{"parent renamed", "file replaced"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, ".tego")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "general.yaml")
			if err := os.WriteFile(path, []byte("trusted"), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if err := checkDirectoryForRead(f, path, os.Getuid(), true); err != nil {
				t.Fatalf("initial private source: %v", err)
			}
			moved := dir + ".moved"
			if replacement == "parent renamed" {
				if err := os.Rename(dir, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(moved, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
				t.Fatal(err)
			}
			err = checkDirectoryForRead(f, path, os.Getuid(), true)
			var ue *UntrustedError
			if !errors.As(err, &ue) || !errors.Is(err, ErrUntrusted) {
				t.Fatalf("descriptor changed placement: got %v, want untrusted refusal", err)
			}
			if replacement == "parent renamed" && (ue.Path != moved || !strings.Contains(ue.Reason, "directory must be private")) {
				t.Fatalf("checked replacement instead of actual nonprivate parent: %+v", ue)
			}
		})
	}
}
