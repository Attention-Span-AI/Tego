// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// pty is a pseudo-terminal pair a test hands an agent as its terminal, with everything written to the
// terminal collected from the master side.
type pty struct {
	master, slave *os.File

	mu  sync.Mutex
	out bytes.Buffer
}

// openPTY opens /dev/ptmx, unlocks its slave (TIOCSPTLCK) and opens it by number (TIOCGPTN), and reads
// the master until it is closed. Both ends close at cleanup.
func openPTY(t *testing.T) *pty {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	var n int
	err = sys.FileDo(master, func(fd int) error {
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
			return err
		}
		var err error
		n, err = unix.IoctlGetInt(fd, unix.TIOCGPTN)
		return err
	})
	if err != nil {
		_ = master.Close()
		t.Fatalf("unlock the pty: %v", err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		t.Fatalf("open the pty slave: %v", err)
	}
	p := &pty{master: master, slave: slave}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
		<-done
	})
	return p
}

// termios reads the terminal's modes through the slave.
func (p *pty) termios(t *testing.T) unix.Termios {
	t.Helper()
	var tio *unix.Termios
	err := sys.FileDo(p.slave, func(fd int) error {
		var err error
		tio, err = unix.IoctlGetTermios(fd, unix.TCGETS)
		return err
	})
	if err != nil {
		t.Fatalf("TCGETS: %v", err)
	}
	return *tio
}

// written is everything the terminal has been sent so far.
func (p *pty) written() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.out.Bytes())
}

// waitWritten waits up to d for want to appear in what the terminal was sent, and reports whether it did.
func (p *pty) waitWritten(want []byte, d time.Duration) bool {
	for end := time.Now().Add(d); ; time.Sleep(10 * time.Millisecond) {
		if bytes.Contains(p.written(), want) {
			return true
		}
		if time.Now().After(end) {
			return false
		}
	}
}
