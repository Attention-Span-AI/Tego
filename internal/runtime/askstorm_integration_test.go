// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An approved write-open repeated under a standing approval, while every thread of the tego process is signalled as
// fast as one goroutine can (custom-agent POC, item 5): every open delivers its descriptor, and no line says one was
// not delivered. Before the ADDFD|SEND ioctl blocked signals, a signal inside it made the kernel complete the agent's
// open with 0, a descriptor nobody delivered, and the agent's write failed: 211 of 3,000 such opens under this flood
// in a measured run, and 1 of 3,000 with no flood at all (the POC's one in about 2,800).
func TestIntegrationApprovedOpensSurviveASignalStorm(t *testing.T) {
	const opens = 1000
	script := "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt " + strconv.Itoa(opens) + " ]; do\n" +
		"  if ! { echo x > held/report.md; } 2>>out/err; then echo \"$i\" >> out/fails; fi\n" +
		"  i=$((i+1))\ndone\necho done > out/done\n"
	s := newScene(t, "60s", "  ask: [\"./held/\"]\n", script)
	held := filepath.Join(s.f.dir, "held")
	if err := os.Mkdir(held, 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, held)
	// A run that loses its listener is stopped with SIGABRT, below, for the Go runtime's dump of every goroutine.
	s.env = append(s.env, "GOTRACEBACK=all")
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["op"] != "open" || req["target"] != filepath.Join(held, "report.md") {
		t.Fatalf("the held request %v: want the write-open of held/report.md", req)
	}
	s.answer(t, "approve", filepath.Base(dir), req["ask_id"].(string), "--always")

	stop := make(chan struct{})
	var flood sync.WaitGroup
	flood.Add(1)
	sent := 0
	// atFirstFailure is tego's descriptors and threads at the moment the agent's first open failed, read by the
	// flood goroutine, which watches out/fails as it signals: a failure's cause is gone by the time the run ends.
	// lostListener is the same once tego holds no seccomp listener while the agent has not finished: every
	// notified syscall of the agent then fails ENOSYS, out/fails included, and nothing records it. The flood then
	// aborts tego (SIGABRT, GOTRACEBACK=all), whose goroutines tego run's output then shows.
	var atFirstFailure, lostListener string
	go func() {
		defer flood.Done()
		pid := run.Process.Pid
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			// Looked at every eighth round, so the watch costs the storm little of its rate.
			if round%8 == 0 && atFirstFailure == "" && s.out("fails") != "" {
				atFirstFailure = processState(pid)
			}
			if round%8 == 0 && lostListener == "" && !holdsListener(pid) && s.out("done") == "" {
				lostListener = processState(pid)
				_ = unix.Kill(pid, unix.SIGABRT)
			}
			tasks, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/task")
			if err != nil {
				return
			}
			for _, task := range tasks {
				if tid, err := strconv.Atoi(task.Name()); err == nil && unix.Tgkill(pid, tid, unix.SIGURG) == nil {
					sent++
				}
			}
		}
	}()
	var stopOnce sync.Once
	halt := func() { stopOnce.Do(func() { close(stop) }); flood.Wait() }
	t.Cleanup(func() {
		halt()
		if t.Failed() && atFirstFailure != "" {
			t.Logf("tego at the agent's first failed open:\n%s", atFirstFailure)
		}
		if t.Failed() && lostListener != "" {
			t.Logf("tego when it no longer held the listener, with the agent still running:\n%s", lostListener)
		}
	})
	evs := s.finish(t, run, dir)
	halt()
	if s.out("done") == "" {
		t.Fatal("the agent did not finish")
	}
	if fails := strings.Fields(s.out("fails")); len(fails) != 0 {
		t.Fatalf("%d of %d approved opens failed under %d signals (first at %s): %s", len(fails), opens, sent, fails[0], s.out("err"))
	}
	delivered, undelivered := 0, 0
	for _, l := range lines(t, evs, record.KindFS) {
		if l["_authority"] != "human" {
			continue
		}
		if l["fd_delivered"] == true {
			delivered++
		} else {
			undelivered++
		}
	}
	if delivered != opens || undelivered != 0 {
		t.Fatalf("%d delivered and %d undelivered human lines; want %d delivered", delivered, undelivered, opens)
	}
	t.Logf("%d approved opens delivered under %d signals", opens, sent)
}

// processState is pid's descriptors (each one's link) and its threads' states and wait channels.
func processState(pid int) string {
	var b strings.Builder
	base := "/proc/" + strconv.Itoa(pid)
	fds, _ := os.ReadDir(base + "/fd")
	for _, fd := range fds {
		l, _ := os.Readlink(base + "/fd/" + fd.Name())
		b.WriteString("fd " + fd.Name() + " -> " + l + "\n")
	}
	tasks, _ := os.ReadDir(base + "/task")
	for _, task := range tasks {
		stat, _ := os.ReadFile(base + "/task/" + task.Name() + "/stat")
		wchan, _ := os.ReadFile(base + "/task/" + task.Name() + "/wchan")
		st := string(stat)
		if i := strings.LastIndexByte(st, ')'); i >= 0 && len(st) > i+2 {
			st = st[i+2 : i+3]
		}
		b.WriteString("task " + task.Name() + " " + st + " " + string(wchan) + "\n")
	}
	return b.String()
}

// holdsListener reports whether pid holds a seccomp listener, or cannot be read (gone: the run is over).
func holdsListener(pid int) bool {
	base := "/proc/" + strconv.Itoa(pid) + "/fd"
	fds, err := os.ReadDir(base)
	if err != nil {
		return true
	}
	for _, fd := range fds {
		if l, _ := os.Readlink(base + "/" + fd.Name()); strings.Contains(l, "seccomp notify") {
			return true
		}
	}
	return false
}
