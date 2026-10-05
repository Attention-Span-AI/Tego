// SPDX-License-Identifier: Apache-2.0

// Command openbench is the perf suite's raw open(2)+close(2) loop: no interpreter, no allocation in the loop, one
// OS thread pinned to one CPU, so the per-open cost it prints is the kernel's (LSM hooks included) and not a
// runtime's. It replaces the python probe that measured fmod_ret about 2 µs slower than lsm (qa-perf, P7).
//
//	openbench [-n 200000] [-nref 2000] [-reps 3] [-cpu 1] [-gate FILE] [-up] [-rename A:B] PATH...
//	openbench [-n 200000] [-reps 3] [-cpu 1] [-up] [-socket] [-setsockopt]
//
// Per PATH it prints "RESULT open_<i> <ns>": the best of -reps rounds of -n opens, in nanoseconds per open+close
// pair. A PATH written !PATH is one the run refuses: each of its -nref opens must fail with EACCES, and its figure
// is the refused open's time (ADR 0043 C10's refused rows; fewer than -n, since each refusal is a ledger line).
// -rename A:B first loops -n renames of the directory A to B and back, one rename a step, and prints "RESULT
// rename_0 <ns>" per rename (C10's rename.dir). -up first prints "RESULT up <monotonic ns>", which the driver reads as "the agent is running", and -gate
// then waits for FILE to exist, so a driver can start many runs and release them together. -socket loops
// socket(AF_INET, SOCK_STREAM, 0)+close instead and prints "RESULT socket_0 <ns>": the perf suite's socket check,
// cgroup/sock_create's cost (ADR 0018 PR 2). -setsockopt loops setsockopt(IPPROTO_TCP, TCP_NODELAY, 1) on one TCP
// socket and prints "RESULT setsockopt_0 <ns>": cgroup/setsockopt's cost on an option it passes (ADR 0018 (7)). The
// two may be given together; neither opens a PATH.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	n := flag.Int("n", 200000, "opens per round")
	reps := flag.Int("reps", 3, "rounds per path; the best is printed")
	cpu := flag.Int("cpu", -1, "pin to this CPU (-1: do not pin)")
	gate := flag.String("gate", "", "wait until this file exists before the loop")
	up := flag.Bool("up", false, "print RESULT up first")
	sock := flag.Bool("socket", false, "loop socket(AF_INET, SOCK_STREAM, 0)+close(2) and print RESULT socket_0")
	sopt := flag.Bool("setsockopt", false, "loop setsockopt(IPPROTO_TCP, TCP_NODELAY) and print RESULT setsockopt_0")
	nref := flag.Int("nref", 2000, "opens per round of a !PATH, each refused")
	rename := flag.String("rename", "", "A:B: loop renames of directory A to B and back, and print RESULT rename_0")
	flag.Parse()
	runtime.LockOSThread()
	if *cpu >= 0 {
		var set unix.CPUSet
		set.Set(*cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			fmt.Fprintln(os.Stderr, "openbench: sched_setaffinity:", err)
			os.Exit(1)
		}
	}
	if *up {
		fmt.Printf("RESULT up %d\n", time.Now().UnixNano())
	}
	for *gate != "" {
		if _, err := os.Stat(*gate); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if *sock {
		best := int64(-1)
		for r := 0; r < *reps; r++ {
			t := time.Now()
			for j := 0; j < *n; j++ {
				fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					fmt.Fprintf(os.Stderr, "openbench: socket: %v\n", err)
					os.Exit(1)
				}
				_ = unix.Close(fd)
			}
			ns := time.Since(t).Nanoseconds() / int64(*n)
			if best < 0 || ns < best {
				best = ns
			}
		}
		fmt.Printf("RESULT socket_0 %d\n", best)
	}
	if *sopt {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openbench: socket: %v\n", err)
			os.Exit(1)
		}
		best := int64(-1)
		for r := 0; r < *reps; r++ {
			t := time.Now()
			for j := 0; j < *n; j++ {
				if err := unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, j&1); err != nil {
					fmt.Fprintf(os.Stderr, "openbench: setsockopt: %v\n", err)
					os.Exit(1)
				}
			}
			ns := time.Since(t).Nanoseconds() / int64(*n)
			if best < 0 || ns < best {
				best = ns
			}
		}
		_ = unix.Close(fd)
		fmt.Printf("RESULT setsockopt_0 %d\n", best)
	}
	if *sock || *sopt {
		return
	}
	if *rename != "" {
		a, b, ok := strings.Cut(*rename, ":")
		ns, err := bestOf(*reps, *n, func(j int) error {
			if j%2 == 0 {
				return unix.Rename(a, b)
			}
			return unix.Rename(b, a)
		})
		if !ok || err != nil {
			fmt.Fprintf(os.Stderr, "openbench: rename %s: %v\n", *rename, err)
			os.Exit(1)
		}
		if *n%2 == 1 { // the loop left A at B
			_ = unix.Rename(b, a)
		}
		fmt.Printf("RESULT rename_0 %d\n", ns)
	}
	for i, p := range flag.Args() {
		ns, err := openLoop(p, *reps, *n, *nref)
		if err != nil {
			fmt.Fprintln(os.Stderr, "openbench:", err)
			os.Exit(1)
		}
		fmt.Printf("RESULT open_%d %d\n", i, ns)
	}
}

// openLoop is one PATH's figure: the best of reps rounds of n open+close pairs, or of nref refused opens of a
// path written !PATH, each of which must fail with EACCES.
func openLoop(p string, reps, n, nref int) (int64, error) {
	path, refused := strings.CutPrefix(p, "!")
	if !refused {
		return bestOf(reps, n, func(int) error {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return fmt.Errorf("open %s: %w", path, err)
			}
			_ = unix.Close(fd)
			return nil
		})
	}
	return bestOf(reps, nref, func(int) error {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			_ = unix.Close(fd)
			return fmt.Errorf("open %s: opened, want EACCES", path)
		case err != unix.EACCES:
			return fmt.Errorf("open %s: %w, want EACCES", path, err)
		}
		return nil
	})
}

// bestOf runs reps rounds of n steps and answers the best round's nanoseconds per step; a step's error ends it.
func bestOf(reps, n int, step func(j int) error) (int64, error) {
	best := int64(-1)
	for r := 0; r < reps; r++ {
		t := time.Now()
		for j := 0; j < n; j++ {
			if err := step(j); err != nil {
				return 0, err
			}
		}
		ns := time.Since(t).Nanoseconds() / int64(n)
		if best < 0 || ns < best {
			best = ns
		}
	}
	return best, nil
}
