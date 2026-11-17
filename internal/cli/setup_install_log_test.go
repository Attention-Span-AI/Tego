// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGuideInstallLogPublication(t *testing.T) {
	oldInstall, oldUID := guideInstall, learnEUID
	t.Cleanup(func() { guideInstall, learnEUID = oldInstall, oldUID })
	learnEUID = func() int { return 1000 }
	for _, kind := range []string{"symlink", "hardlink", "readable", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, ".tego")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			log := filepath.Join(dir, "setup-install.log")
			outside := filepath.Join(home, "backup")
			if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(outside, log)
			case "hardlink":
				err = os.Link(outside, log)
			case "readable":
				err = os.WriteFile(log, nil, 0644)
			case "fifo":
				err = unix.Mkfifo(log, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			guideInstall = func(_ context.Context, _ string, out io.Writer) error {
				called = true
				_, err := io.WriteString(out, "private install output")
				return err
			}
			var output bytes.Buffer
			g := newWalk(nil, &output, false)
			done := make(chan bool, 1)
			go func() { done <- g.installAgent(context.Background(), guideAgents[0], home) }()
			var ok bool
			select {
			case ok = <-done:
			case <-time.After(15 * time.Second):
				// Release an old truncating FIFO open before failing, so the
				// reproduction itself leaves no goroutine behind.
				fd, err := unix.Open(log, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				<-done
				if err == nil {
					_ = unix.Close(fd)
				}
				t.Fatal("opening the installer log blocked on a FIFO")
			}
			if kind == "fifo" {
				if ok || called {
					t.Fatal("installer ran with a FIFO log")
				}
				return
			}
			if !ok || !called {
				t.Fatalf("install refused ordinary owned log: %s", &output)
			}
			if b, err := os.ReadFile(outside); err != nil || string(b) != "unchanged" {
				t.Fatalf("backup changed: %q %v", b, err)
			}
			fi, err := os.Lstat(log)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
				t.Fatalf("log: %v %v", fi, err)
			}
		})
	}
}
