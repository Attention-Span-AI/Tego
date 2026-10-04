// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReserveBPFDescriptors(t *testing.T) {
	const key = "TEGO_TEST_RESERVE_FDS_CASE"
	mode := os.Getenv(key)
	if mode == "" {
		for _, mode := range []string{"grow", "occupied", "limited", "async-grow", "async-occupied", "async-limited", "async-concurrent"} {
			t.Run(mode, func(t *testing.T) {
				// Keep fd-table growth and the restrictive rlimit in their own process.
				cmd := exec.Command(os.Args[0], "-test.run=^TestReserveBPFDescriptors$")
				cmd.Env = append(os.Environ(), key+"="+mode)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
			})
		}
		return
	}
	async := strings.HasPrefix(mode, "async-")
	mode = strings.TrimPrefix(mode, "async-")
	dir := t.TempDir()
	held, err := os.Create(filepath.Join(dir, "build.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(held.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	occupied := -1
	var original unix.Stat_t
	switch mode {
	case "grow", "concurrent":
	case "occupied":
		sentinel, err := os.Create(filepath.Join(dir, "sentinel"))
		if err != nil {
			t.Fatal(err)
		}
		defer sentinel.Close()
		occupied, err = unix.FcntlInt(sentinel.Fd(), unix.F_DUPFD_CLOEXEC, 128)
		if err != nil || occupied != 128 {
			t.Fatalf("occupy target: fd=%d err=%v", occupied, err)
		}
		defer unix.Close(occupied)
		if err := unix.Fstat(occupied, &original); err != nil {
			t.Fatal(err)
		}
	case "limited":
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
		limit.Cur = min(limit.Cur, 128)
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown test mode %q", mode)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	capacity := fdTableSize(t)
	if mode == "concurrent" {
		var joins []func()
		for range 8 {
			finish := StartDescriptorReservation(held)
			if finish == nil {
				t.Fatal("could not start concurrent descriptor reservation")
			}
			joins = append(joins, finish)
		}
		reserveBPFDescriptors(held) // the loader's synchronous barrier
		for _, finish := range joins {
			finish()
		}
	} else if async {
		finish := StartDescriptorReservation(held)
		if finish == nil {
			t.Fatal("could not start descriptor reservation")
		}
		finish()
		finish() // multiple joiners observe completion without taking ownership
	} else {
		reserveBPFDescriptors(held)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("descriptor leak: before=%d after=%d err=%v", len(before), len(after), err)
	}
	if _, err := held.Stat(); err != nil {
		t.Fatalf("original lock descriptor was closed: %v", err)
	}
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("original build lock was released: competing flock=%v", err)
	}
	if occupied >= 0 {
		var got unix.Stat_t
		if err := unix.Fstat(occupied, &got); err != nil || got.Dev != original.Dev || got.Ino != original.Ino {
			t.Fatalf("occupied descriptor was replaced: stat=%+v err=%v", got, err)
		}
	}
	if mode == "grow" || mode == "concurrent" {
		size := fdTableSize(t)
		if size < 256 {
			t.Fatalf("descriptor table was not reserved: FDSize=%d", size)
		}
	}
	if mode != "limited" && fdTableSize(t) > max(capacity, 256) {
		t.Fatalf("reservation forced another expansion: before=%d after=%d", capacity, fdTableSize(t))
	}
}

// A CLI stream may be a Go pipe rather than an inherited NewFile. Reserving
// descriptors must preserve its nonblocking I/O and write deadlines.
func TestReserveBPFDescriptorsPreservesPipe(t *testing.T) {
	for _, async := range []bool{false, true} {
		name := "sync"
		if async {
			name = "async"
		}
		t.Run(name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			raw, err := writer.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			flags := func() int {
				t.Helper()
				var flags int
				var flagErr error
				if err := raw.Control(func(fd uintptr) {
					flags, flagErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
				}); err != nil {
					t.Fatal(err)
				}
				if flagErr != nil {
					t.Fatal(flagErr)
				}
				return flags
			}
			before := flags()
			if before&unix.O_NONBLOCK == 0 {
				t.Fatal("Go pipe is not nonblocking")
			}
			if async {
				finish := StartDescriptorReservation(writer)
				if finish == nil {
					t.Fatal("could not start pipe descriptor reservation")
				}
				finish()
			} else {
				reserveBPFDescriptors(writer)
			}
			if after := flags(); after != before {
				t.Fatalf("pipe flags changed: before=%#x after=%#x", before, after)
			}
			var fillErr error
			if err := raw.Control(func(fd uintptr) {
				capacity, err := unix.FcntlInt(fd, unix.F_GETPIPE_SZ, 0)
				if err != nil {
					fillErr = err
					return
				}
				filled, err := unix.Write(int(fd), make([]byte, capacity))
				if err != nil || filled != capacity {
					fillErr = fmt.Errorf("fill pipe: wrote %d of %d bytes: %v", filled, capacity, err)
					return
				}
				if _, err := unix.Write(int(fd), []byte{1}); !errors.Is(err, unix.EAGAIN) {
					fillErr = fmt.Errorf("full pipe write: %v, want EAGAIN", err)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if fillErr != nil {
				t.Fatal(fillErr)
			}
			if err := writer.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			// A regression must fail within a second even if the write becomes
			// a blocking syscall that cannot honor the Go deadline.
			unblock := time.AfterFunc(time.Second, func() { _ = reader.Close() })
			defer unblock.Stop()
			if n, err := writer.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("full pipe write: n=%d err=%v, want deadline exceeded", n, err)
			}
		})
	}
}

func TestReserveBPFDescriptorsClosedAndNil(t *testing.T) {
	if finish := StartDescriptorReservation(nil); finish != nil {
		t.Fatal("nil stream started descriptor reservation")
	}
	reserveBPFDescriptors(nil)
	held, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	// A newly opened sentinel may reuse the closed stream's number; neither
	// reservation path may close or change the replacement's descriptor.
	sentinel, err := os.CreateTemp(t.TempDir(), "sentinel")
	if err != nil {
		t.Fatal(err)
	}
	defer sentinel.Close()
	reserveBPFDescriptors(held)
	finish := StartDescriptorReservation(held)
	if finish == nil {
		t.Fatal("closed stream did not return a completion function")
	}
	finish()
	if _, err := sentinel.WriteString("still open"); err != nil {
		t.Fatalf("replacement descriptor was changed: %v", err)
	}
}

func fdTableSize(t *testing.T) int {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "FDSize:") {
			var size int
			if _, err := fmt.Sscanf(line, "FDSize: %d", &size); err != nil {
				t.Fatal(err)
			}
			return size
		}
	}
	t.Fatal("process status has no FDSize")
	return 0
}
