// SPDX-License-Identifier: Apache-2.0

// Command read-opener is ADR 0077's per-open measurement, run as the agent of a tego run by
// test/bench/read-notify/run.sh: it opens one regular file read-only n times from one OS thread pinned to one CPU,
// timing each open(2)+close(2) pair, and prints
//
//	RESULT median_ns <ns> p99_ns <ns> fails <count>
//
// the median and the nearest-rank 99th percentile of the pairs. Under a contract with reason.reads: on every such open
// is told to the supervisor and continued; with off the filter lets it through, so the difference of two runs is what
// reason reads cost an open. The loop allocates nothing and calls no runtime function between the clock reads.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/test/perf"
)

func main() {
	n := flag.Int("n", 20000, "opens")
	cpu := flag.Int("cpu", -1, "pin to this CPU (-1: do not pin)")
	path := flag.String("path", "", "the file to open")
	flag.Parse()
	if *path == "" || *n <= 0 {
		fmt.Fprintln(os.Stderr, "read-notify: -path and a positive -n are required")
		os.Exit(2)
	}
	runtime.LockOSThread()
	if *cpu >= 0 {
		var set unix.CPUSet
		set.Set(*cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			fmt.Fprintln(os.Stderr, "read-notify: sched_setaffinity:", err)
			os.Exit(1)
		}
	}
	p, err := unix.BytePtrFromString(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read-notify:", err)
		os.Exit(2)
	}
	cwd := unix.AT_FDCWD
	lat := make([]float64, *n)
	fails := 0
	for i := range lat {
		t0 := time.Now()
		fd, _, e := unix.Syscall6(unix.SYS_OPENAT, uintptr(cwd), uintptr(unsafe.Pointer(p)), uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
		if e == 0 {
			_ = unix.Close(int(fd))
		} else {
			fails++
		}
		lat[i] = float64(time.Since(t0).Nanoseconds())
	}
	runtime.KeepAlive(p)
	fmt.Printf("RESULT median_ns %.0f p99_ns %.0f fails %d\n", perf.Median(lat), perf.Percentile(lat, 99), fails)
}
