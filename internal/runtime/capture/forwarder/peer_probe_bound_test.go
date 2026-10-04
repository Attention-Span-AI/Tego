// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPeerProbeBoundsActualNewSocketDescriptors(t *testing.T) {
	var fds []int
	for range 16 {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, fd)
		t.Cleanup(func() { _ = unix.Close(fd) })
	}
	a := newProcAdmitter()
	pid := os.Getpid()
	a.fds[pid] = &procFDs{names: map[string]uint64{}, top: fds[0] - 1}
	if _, found := a.probe(pid, ^uint64(0)); found {
		t.Fatal("found an inode the kernel cannot have allocated")
	}
	if got := a.links.Load(); got != topProbe {
		t.Fatalf("missing socket probed %d descriptors, want the fixed bound %d", got, topProbe)
	}
}
