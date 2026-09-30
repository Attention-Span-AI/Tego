// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// init writes into a project directory the agent may have prepared: a symlink or FIFO planted where
// agent.yaml or .gitignore should be must be refused, never followed and never blocked on.
func TestReadInitFileRefusesWhatIsNotAPlainFile(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, exists, err := readInitFile(plain)
	if err != nil || !exists || string(data) != "hello" {
		t.Fatalf("plain: %q %v %v", data, exists, err)
	}
	if _, exists, err := readInitFile(filepath.Join(dir, "absent")); err != nil || exists {
		t.Errorf("absent: exists=%v err=%v", exists, err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(plain, link); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readInitFile(link); !errors.Is(err, errNotProjectFile) || !exists {
		t.Errorf("symlink: exists=%v err=%v, want errNotProjectFile", exists, err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no mkfifo:", err)
	}
	if _, _, err := readInitFile(fifo); !errors.Is(err, errNotProjectFile) {
		t.Errorf("fifo: %v, want errNotProjectFile (and no hang)", err)
	}
	if _, _, err := readInitFile(dir); !errors.Is(err, errNotProjectFile) {
		t.Errorf("directory: %v, want errNotProjectFile", err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, maxInitFile+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := readInitFile(big); err == nil || !exists {
		t.Errorf("oversized: exists=%v err=%v, want a refusal", exists, err)
	}
}

func TestEnsureLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")

	if added, err := ensureLine(path, ".tego/"); err != nil || !added {
		t.Fatalf("create: %v %v", added, err)
	}
	if added, err := ensureLine(path, ".tego/"); err != nil || added {
		t.Fatalf("second call must add nothing: %v %v", added, err)
	}
	if b, _ := os.ReadFile(path); string(b) != ".tego/\n" {
		t.Fatalf("content %q", b)
	}

	// A file that lacks its final newline gets one before the appended line, and a line that is present
	// with surrounding blanks counts as present.
	if err := os.WriteFile(path, []byte("node_modules\n  keep  "), 0o644); err != nil {
		t.Fatal(err)
	}
	if added, err := ensureLine(path, "keep"); err != nil || added {
		t.Fatalf("a present line with blanks: %v %v", added, err)
	}
	if added, err := ensureLine(path, "new"); err != nil || !added {
		t.Fatalf("append: %v %v", added, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "node_modules\n  keep  \nnew\n" {
		t.Fatalf("content %q", b)
	}

	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureLine(link, "y"); err == nil {
		t.Error("a symlinked .gitignore must be refused")
	}
	if b, _ := os.ReadFile(target); string(b) != "x\n" {
		t.Errorf("the link's target was written through: %q", b)
	}
}
