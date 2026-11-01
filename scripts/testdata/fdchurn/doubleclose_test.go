// SPDX-License-Identifier: Apache-2.0

// Package doubleclose is scripts/fd-churn_test.sh's fixture, the bug class of ADR 0023 in its smallest form:
// one goroutine closes a number twice while another opens a file, which the kernel's lowest-free-number rule
// gives the number the first close freed, so the second close takes the other goroutine's file. It lives under
// testdata, so no ./... pattern builds it; the script names it.
package doubleclose

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// fixtureEnv selects the fixture's mode: "bug" closes twice, "fixed" closes once, and unset skips.
const fixtureEnv = "TEGO_FDCHURN_FIXTURE"

// TestDoubleClose fails when the victim's descriptor stops naming the victim's file while the victim holds it.
func TestDoubleClose(t *testing.T) {
	mode := os.Getenv(fixtureEnv)
	if mode == "" {
		t.Skip("fixture of scripts/fd-churn_test.sh")
	}
	path := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var want unix.Stat_t
	if err := unix.Stat(path, &want); err != nil {
		t.Fatal(err)
	}
	for range 500 {
		n, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var lost error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = unix.Close(n)
			// What runs between the two closes in the real bug: a path that forgot it had handed the number
			// on, or a finalizer the collector ran late.
			for range 20 {
				_ = unix.Getpid()
			}
			if mode == "bug" {
				_ = unix.Close(n) // the bug: a second close of a number this goroutine no longer owns
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				v, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err != nil {
					lost = err
					return
				}
				for range 5 {
					var st unix.Stat_t
					if err := unix.Fstat(v, &st); err != nil {
						lost = err
						return // v is gone: nothing of the victim's is left to close
					}
					if st.Ino != want.Ino || st.Dev != want.Dev {
						lost = unix.EBADF
						return // v names another file now, which is not the victim's to close
					}
				}
				_ = unix.Close(v)
			}
		}()
		close(start)
		wg.Wait()
		if lost != nil {
			t.Fatalf("the victim's descriptor was closed under it: %v", lost)
		}
	}
}
