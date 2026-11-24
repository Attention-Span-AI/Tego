// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/pathcheck"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == contracts.HelperCommand {
		pathcheck.Register("test.source-read", blockedCatalogueRead)
		// The HTTP regression owns this marker and every PID written beside it.
		// Stop only a worker of this test image, before it can inspect a path.
		executable, err := os.Executable()
		if err == nil && len(os.Args) > 2 {
			if fi, err := os.Stat(executable + ".count"); err == nil && fi.IsDir() {
				if err := os.WriteFile(filepath.Join(executable+".count", os.Args[2]+"-"+strconv.Itoa(os.Getpid())), nil, 0o600); err != nil {
					os.Exit(125)
				}
			}
			if _, err := os.Stat(executable + ".nostart"); err == nil && os.Args[2] == "worker" {
				// A worker that never becomes ready: stopped before its first frame.
				_ = os.WriteFile(executable+".pid."+strconv.Itoa(os.Getpid()), nil, 0o600)
				_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
			}
			if _, err := os.Stat(executable + ".hang"); err == nil && os.Args[2] == "worker" {
				stopOnceReady(executable + ".pid." + strconv.Itoa(os.Getpid()))
			}
		}
		os.Exit(contracts.HelperMain(os.Args[2:]))
	}
}

// stopOnceReady stops this worker the moment it has told its caller it is ready, so the request is never read: the
// caller's location budget has started and nothing ever answers, as when the worker blocks on a mount that does
// not answer. Stopping it earlier, before the ready frame, would model a checker that did not start, which is
// another refusal with its own words. Frames are length-prefixed (eight bytes, big endian); the ready frame is the
// one-byte body 2 (contracts.frameReady). The pid file is written first, for the test that kills the worker.
func stopOnceReady(pidFile string) {
	r, w, err := os.Pipe()
	if err != nil {
		os.Exit(125)
	}
	out := os.Stdout
	os.Stdout = w
	go func() {
		for {
			var length [8]byte
			if _, err := io.ReadFull(r, length[:]); err != nil {
				return
			}
			body := make([]byte, binary.BigEndian.Uint64(length[:]))
			if _, err := io.ReadFull(r, body); err != nil {
				return
			}
			if _, err := out.Write(append(length[:], body...)); err != nil {
				return
			}
			if len(body) == 1 && body[0] == 2 {
				_ = os.WriteFile(pidFile, nil, 0o600)
				// Nothing after the ready frame reaches the caller: this goroutine is the only way out of the
				// worker, and it stays here once the stop is asked for. The worker's own reply waits in the pipe
				// behind it, whichever thread runs first. (Stopping alone left a window in which this goroutine
				// went on to forward a quick reply before the stop was delivered, which a busy or single CPU
				// made wide.) The stopped process is ended by its test, as before.
				_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP)
				select {}
			}
		}
	}()
}

// Exercise a real descriptor read inside the request's worker. It answers
// source metadata and then waits indefinitely instead of returning a deadline.
func blockedCatalogueRead(_ context.Context, payload []byte) ([]byte, error) {
	var path string
	if err := pathcheck.Decode(payload, &path); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	defer w.Close()
	exe, _ := os.Executable()
	if err := os.WriteFile(exe+".catalogue-read", nil, 0600); err != nil {
		return nil, err
	}
	go endWithCaller()
	_, err = io.ReadAll(r)
	return nil, err
}

// endWithCaller ends this test worker once its caller has closed the request
// pipe. The read above never returns, as on a mount that does not answer, and
// the caller neither waits for the worker nor kills it. Nothing else would end
// the process, and each worker left behind holds one of the uid's helper
// reservations on the machine that ran the tests.
func endWithCaller() {
	fds := []unix.PollFd{{Fd: 0, Events: unix.POLLHUP}}
	for {
		_, err := unix.Poll(fds, -1)
		if err != nil && !errors.Is(err, unix.EINTR) {
			os.Exit(125)
		}
		if err == nil && fds[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			os.Exit(0)
		}
	}
}
