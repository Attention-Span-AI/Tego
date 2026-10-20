// SPDX-License-Identifier: Apache-2.0

// Command execbench is the perf suite's exec loop (ADR 0048 P2's K7): fork+exec+wait of a minimal static image that
// exits at once (perf.TrueImage), -n times, from one OS thread pinned to one CPU, so the time per iteration is the
// kernel's fork and exec, and what the supervisor and the decision plane add to an exec:
//
//	execbench [-n 10000] [-cpu 3] [-argv BYTES] IMAGE
//
// IMAGE is exec'd as ["true", "status", filler...]: with -argv over the two words' bytes, filler elements of up to
// 32 KiB make the vector's bytes (each element's NUL counted) exactly -argv. It prints "RESULT exec_p50 <ns>",
// "RESULT exec_p99 <ns>" (over the iterations) and "RESULT exec_failed <n>", the iterations whose exec did not run
// and exit 0; the driver fails a sample with any.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/test/perf"
)

func main() {
	n := flag.Int("n", 10000, "iterations")
	cpu := flag.Int("cpu", -1, "pin to this CPU (-1: do not pin)")
	argvBytes := flag.Int("argv", 0, "the vector's bytes, each element's NUL counted (0: the two words alone)")
	flag.Parse()
	if flag.NArg() != 1 || *n <= 0 {
		fmt.Fprintln(os.Stderr, "usage: execbench [-n N] [-cpu C] [-argv BYTES] IMAGE")
		os.Exit(2)
	}
	runtime.LockOSThread()
	if *cpu >= 0 {
		var set unix.CPUSet
		set.Set(*cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			fmt.Fprintln(os.Stderr, "execbench: sched_setaffinity:", err)
			os.Exit(1)
		}
	}
	argv := vector(*argvBytes)
	attr := &syscall.ProcAttr{Env: []string{}, Files: []uintptr{0, 1, 2}}
	ns := make([]float64, 0, *n)
	failed := 0
	for range *n {
		t0 := time.Now()
		pid, err := syscall.ForkExec(flag.Arg(0), argv, attr)
		if err != nil {
			failed++
			continue
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil || !ws.Exited() || ws.ExitStatus() != 0 {
			failed++
			continue
		}
		ns = append(ns, float64(time.Since(t0).Nanoseconds()))
	}
	fmt.Printf("RESULT exec_p50 %.0f\nRESULT exec_p99 %.0f\nRESULT exec_failed %d\n", perf.Percentile(ns, 50),
		perf.Percentile(ns, 99), failed)
}

// vector is ["true", "status"], then filler elements of up to 32 KiB until the vector's bytes are exactly total.
func vector(total int) []string {
	argv := []string{"true", "status"}
	left := total - len("true") - 1 - len("status") - 1
	for left > 0 {
		take := min(left, 32768)
		argv = append(argv, strings.Repeat("x", take-1))
		left -= take
	}
	return argv
}
