// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// A signal that arrives while the liveness check polls the peer's pidfd is no exit. poll(2) with a zero timeout
// returns EINTR when a signal is pending, and the Go runtime signals its own threads (SIGURG, for preemption) all
// the time; read as "exited", it refused a live person's answer as unauthorized or dropped it unanswered
// (TestBrokerRecordsBeforeApprovalAndSingleWinner failed about once in a hundred runs).
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
}
