// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInitPreservesAContractCreatedAfterPlanning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, initContract)
	write, err := planContract(path, false)
	if err != nil || !write {
		t.Fatalf("plan absent contract: write=%v err=%v", write, err)
	}
	foreign := []byte("version: 0\nname: theirs\ncommand: [true]\n")
	if err := os.WriteFile(path, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeContract(path, "mine", false); !errors.Is(err, errForeign) {
		t.Errorf("publish after another writer: %v, want errForeign", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(foreign) {
		t.Fatalf("concurrently created contract was overwritten: %q", got)
	}
}

func TestInitPublishPreservesALinkUnlessForced(t *testing.T) {
	dir := t.TempDir()
	path, target := filepath.Join(dir, initContract), filepath.Join(dir, "other.yaml")
	foreign := []byte("private contract\n")
	if err := os.WriteFile(target, foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeContract(path, "mine", false); !errors.Is(err, errForeign) {
		t.Fatalf("unforced link publication: %v", err)
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("link changed: %q %v", got, err)
	}
	if err := writeContract(path, "mine", true); err != nil {
		t.Fatalf("forced link replacement: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != string(foreign) {
		t.Fatalf("link target changed: %q %v", got, err)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("forced destination is not regular: %v %v", fi, err)
	}
	if leftover, err := filepath.Glob(filepath.Join(dir, ".agent.yaml.*")); err != nil || len(leftover) != 0 {
		t.Fatalf("temporary files remain: %v %v", leftover, err)
	}
}

func TestInitPreservesADanglingLinkCreatedAfterPlanning(t *testing.T) {
	dir := t.TempDir()
	path, target := filepath.Join(dir, initContract), filepath.Join(dir, "not-created.yaml")
	write, err := planContract(path, false)
	if err != nil || !write {
		t.Fatalf("plan absent contract: write=%v err=%v", write, err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeContract(path, "mine", false); !errors.Is(err, errForeign) {
		t.Fatalf("publish after dangling link creation: %v, want errForeign", err)
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("dangling link changed: %q %v", got, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dangling link target was created: %v", err)
	}
	if err := writeContract(path, "mine", true); err != nil {
		t.Fatalf("forced dangling link replacement: %v", err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("forced destination is not regular: %v %v", fi, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("force created the dangling link target: %v", err)
	}
}

// TestInitPublishesWithoutHardLinks: a project on a filesystem with no hard links (vfat, exFAT, vboxsf answer
// link(2) with EPERM; some FUSE and network mounts with EOPNOTSUPP or ENOSYS) failed `tego init` with 125 and
// left no agent.yaml: unforced publication needed link(2) and had no fallback. renameat2(RENAME_NOREPLACE)
// publishes there, and still refuses a contract created after planning.
func TestInitPublishesWithoutHardLinks(t *testing.T) {
	prev := linkContract
	t.Cleanup(func() { linkContract = prev })
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EOPNOTSUPP, syscall.ENOSYS} {
		linkContract = func(oldname, newname string) error {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errno}
		}
		dir := t.TempDir()
		path := filepath.Join(dir, initContract)
		if err := writeContract(path, "mine", false); err != nil {
			t.Fatalf("%v: publish on a filesystem without hard links: %v", errno, err)
		}
		if got, err := os.ReadFile(path); err != nil || !strings.Contains(string(got), `name: "mine"`) {
			t.Fatalf("%v: published contract %q, %v", errno, got, err)
		}
		if err := writeContract(path, "again", false); !errors.Is(err, errForeign) {
			t.Errorf("%v: publish over an existing contract: %v, want errForeign", errno, err)
		}
		if got, _ := os.ReadFile(path); !strings.Contains(string(got), `name: "mine"`) {
			t.Errorf("%v: existing contract was overwritten: %q", errno, got)
		}
		if names, _ := filepath.Glob(filepath.Join(dir, ".agent.yaml.*")); len(names) != 0 {
			t.Errorf("%v: temporary files left behind: %v", errno, names)
		}
	}
}
