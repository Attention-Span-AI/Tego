// SPDX-License-Identifier: Apache-2.0

package dnsbroker

import (
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// A signal that arrives while the liveness check polls a pidfd is no exit: poll(2) with a zero timeout returns
// EINTR when a signal is pending, and the Go runtime signals its own threads (SIGURG) all the time; read as
// "exited", the broker refused a live relay's or sender's query.
func TestPidfdAliveUnderSignals(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd_open: %v", err)
	}
	defer unix.Close(fd)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
					_ = unix.Kill(os.Getpid(), unix.SIGURG)
				}
			}
		})
	}
	dead := 0
	for range 200000 {
		if !pidfdAlive(fd) {
			dead++
		}
	}
	close(stop)
	wg.Wait()
	if dead != 0 {
		t.Fatalf("this live process read as exited %d times in 200000 under signals", dead)
	}
	if pidfdAlive(-1) {
		t.Fatal("no descriptor read as a live process")
	}
}
