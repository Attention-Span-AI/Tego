// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// TestOwnLogHoldsOnlyItsDirectoryAndFile is ADR 0023 C17's table check: an appender that writes and rotates
// holds exactly ~/.tego (a strict owner, since it carries the rotation flock) and the current tego.log, and
// every refused open (a planted link, a FIFO, a hard-linked log, a loose directory, a directory renamed in after
// the mkdir) and a rotation that fails with the file open leave no descriptor behind.
func TestOwnLogHoldsOnlyItsDirectoryAndFile(t *testing.T) {
	refused := map[string]func(home string){
		"symlinked log": func(home string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := os.Symlink("/etc/passwd", logPath(home, "")); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(home string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := syscall.Mkfifo(logPath(home, ""), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked log": func(home string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := os.WriteFile(logPath(home, ""), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(logPath(home, ""), filepath.Join(home, ownLogDir, "second-name")); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable directory": func(home string) {
			mustMkdir(t, filepath.Join(home, ownLogDir))
			if err := os.Chmod(filepath.Join(home, ownLogDir), 0o770); err != nil {
				t.Fatal(err)
			}
		},
	}
	logs := map[string]*ownLog{}
	homes := map[string]string{}
	for name, setup := range refused {
		l, home := testOwnLog(t)
		setup(home)
		logs[name], homes[name] = l, home
	}
	// The made directory is not empty by the time it is opened (something renamed in after the mkdir): with an
	// owner to hand it to, it is refused rather than chowned.
	made, madeHome := testOwnLog(t)
	made.owner = ownLogOwner{uid: os.Geteuid(), gid: os.Getegid()}
	// A rotation that cannot rename the log (tego.log.1 is a directory) breaks the appender with its file open.
	rot, rotHome := testOwnLog(t)
	rot.max, rot.files = 1, 2
	mustMkdir(t, filepath.Join(rotHome, ownLogDir))
	mustMkdir(t, logPath(rotHome, ".1"))
	ok, _ := testOwnLog(t)
	ok.max, ok.files = 200, 3
	testutil.NoFDLeak(t)
	t.Cleanup(func() { // before NoFDLeak's check: the appender's own two descriptors are expected
		if ok.f != nil {
			_ = ok.f.Close()
		}
		if err := ok.dir.Close(); err != nil {
			t.Errorf("closing ~/.tego: %v", err)
		}
	})
	for name, l := range logs {
		if _, err := l.Write([]byte("refused\n")); err == nil {
			t.Errorf("%s: Write succeeded", name)
		}
	}
	prev := ownLogMkdirHook
	ownLogMkdirHook = func() {
		if err := os.WriteFile(filepath.Join(madeHome, ownLogDir, "planted"), nil, 0o600); err != nil {
			t.Error(err)
		}
	}
	_, err := made.Write([]byte("refused\n"))
	ownLogMkdirHook = prev
	if err == nil {
		t.Error("made directory not empty: Write succeeded")
	}
	if _, err := rot.Write([]byte("first\n")); err != nil {
		t.Fatalf("the rotating appender's first line: %v", err)
	}
	if _, err := rot.Write([]byte("second\n")); err == nil {
		t.Error("a rotation onto a directory succeeded")
	}
	line := strings.Repeat("x", 63) + "\n"
	for i := range 40 {
		if _, err := ok.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if _, err := os.Stat(logPath(ok.home, ".2")); err != nil {
		t.Errorf("no second rotation: the strict directory's flock was not taken: %v", err)
	}
}
