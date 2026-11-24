// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
)

// TestMain prints this binary's clock times in UTC: the pages print them in the local zone (time.Local), and the
// Locked goldens (TestLockedPagesUnchanged) hold them in UTC. time.Local is a variable that every time.Now reads, so it
// is set once, here, before any test or goroutine of one runs, and never again. A test that set it for its own length
// raced each goroutine still reading the clock then, such as the connection goroutines of an earlier test's HTTP
// server, which finish after its Close (the race job failed TestLockedPagesUnchanged so after TestEventsStream).
// t.Setenv("TZ") does not reach it either, since time.Local is read from TZ only once.
//
// It also fails the binary when a helper worker of this image outlives the tests. Some fixtures hold a worker in a
// read that never returns or stop it; each one left behind keeps one of the uid's helper reservations on the machine
// that ran the tests until someone kills it.
func TestMain(m *testing.M) {
	if handled, code := draftcompile.Helper(os.Args, os.Stdin, os.Stdout); handled {
		os.Exit(code)
	}
	time.Local = time.UTC
	code := m.Run()
	if left := helperWorkersLeft(10 * time.Second); len(left) != 0 {
		fmt.Fprintf(os.Stderr, "FAIL: helper workers of this test image outlived its tests: pids %v\n", left)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// helperWorkersLeft lists the helper processes of this test image that are
// still alive, after waiting up to wait for them to end. A process that has
// exited and waits to be reaped has ended: its image link no longer reads.
func helperWorkersLeft(wait time.Duration) []int {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	deadline := time.Now().Add(wait)
	for {
		var left []int
		dirs, _ := filepath.Glob("/proc/[0-9]*")
		for _, dir := range dirs {
			pid, _ := strconv.Atoi(filepath.Base(dir))
			if image, err := os.Readlink(dir + "/exe"); err != nil || image != exe || pid == os.Getpid() {
				continue
			}
			args, _ := os.ReadFile(dir + "/cmdline")
			if words := strings.Split(string(args), "\x00"); len(words) > 1 && words[1] == contracts.HelperCommand {
				left = append(left, pid)
			}
		}
		if len(left) == 0 || time.Now().After(deadline) {
			return left
		}
		time.Sleep(20 * time.Millisecond)
	}
}
