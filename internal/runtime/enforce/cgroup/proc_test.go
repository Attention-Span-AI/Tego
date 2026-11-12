// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// TestParseCgroupFile covers the shapes /proc/<pid>/cgroup takes: a pure v2 host, a hybrid host where v1
// lines come first, a task in a deleted cgroup, and the malformed inputs a reader of another process's
// /proc must survive.
func TestParseCgroupFile(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
		err  error
	}{
		{"pure v2", "0::/user.slice/user-1000.slice/session-3.scope\n", "/user.slice/user-1000.slice/session-3.scope", nil},
		{"root", "0::/\n", "/", nil},
		{"hybrid", "12:pids:/user.slice\n5:memory:/user.slice\n0::/user.slice/tego.slice\n", "/user.slice/tego.slice", nil},
		{"deleted", "0::/user.slice/run-abc.scope (deleted)\n", "/user.slice/run-abc.scope", nil},
		{"no trailing newline", "0::/a/b", "/a/b", nil},
		{"v1 only", "12:pids:/user.slice\n", "", ErrProcFormat},
		{"empty", "", "", ErrProcFormat},
		{"garbage", "not a cgroup file at all\n", "", ErrProcFormat},
		{"unified with controllers", "0:cpu:/x\n", "", ErrProcFormat},
		{"relative path", "0::relative\n", "", ErrProcFormat},
		{"empty path", "0::\n", "", ErrProcFormat},
		{"truncated", "0:", "", ErrProcFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCgroupFile([]byte(tc.in))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCgroupFile: %v", err)
			}
			if got != tc.want {
				t.Fatalf("= %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseStartTicks covers the one field of /proc/<pid>/stat this package reads, including the comm values
// that break naive splitting: spaces, parentheses, and both together.
func TestParseStartTicks(t *testing.T) {
	t.Parallel()
	// Fields after "pid (comm)" are state plus 50 numbers; start time is the 20th of them.
	tail := func(start string) string {
		fields := make([]string, 0, 30)
		fields = append(fields, "S")
		for i := 0; i < 28; i++ {
			if i == 18 {
				fields = append(fields, start)
				continue
			}
			fields = append(fields, "0")
		}
		return strings.Join(fields, " ")
	}
	cases := []struct {
		name string
		in   string
		want uint64
		err  error
	}{
		{"simple", "42 (bash) " + tail("991122"), 991122, nil},
		{"comm with space", "42 (my prog) " + tail("7"), 7, nil},
		{"comm with parens", "42 (weird (name)) " + tail("8"), 8, nil},
		{"comm that looks numeric", "42 (99) " + tail("123"), 123, nil},
		{"no comm", "42 bash S 0 0", 0, ErrProcFormat},
		{"too few fields", "42 (bash) S 1 2 3", 0, ErrProcFormat},
		{"non numeric start", "42 (bash) " + tail("notanumber"), 0, ErrProcFormat},
		{"empty", "", 0, ErrProcFormat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseStartTicks([]byte(tc.in))
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("err = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseStartTicks: %v", err)
			}
			if got != tc.want {
				t.Fatalf("= %d, want %d", got, tc.want)
			}
		})
	}
}

// TestProcStartTicksLive reads this process's own start time out of the real /proc and asserts the readers
// agree with each other, which is what the slot allocator's liveness check depends on.
func TestProcStartTicksLive(t *testing.T) {
	t.Parallel()
	self, err := selfOwner()
	if err != nil {
		t.Fatalf("selfOwner: %v", err)
	}
	if self.PID != uint32(os.Getpid()) || self.StartTicks == 0 {
		t.Fatalf("selfOwner = %+v", self)
	}
	if !self.alive() {
		t.Fatal("this process reports itself as not alive")
	}
	if (owner{PID: self.PID, StartTicks: self.StartTicks + 1}).alive() {
		t.Fatal("a differing start time must not count as the same process")
	}
	if (owner{}).alive() {
		t.Fatal("the zero owner must never be alive")
	}
	if _, err := procStartTicks(1 << 30); !errors.Is(err, ErrProcGone) {
		t.Fatalf("procStartTicks(impossible pid) = %v, want ErrProcGone", err)
	}
}

// TestAZombieOwnerIsNotAlive is a launcher killed under a parent that has not reaped it yet: its /proc/<pid>/stat
// stays, state Z with the same start ticks, and counted as alive its slot was neither purged by the reaper nor
// reclaimed until the parent waited. A zombie is dead; a zombie leader whose other threads run is not.
func TestAZombieOwnerIsNotAlive(t *testing.T) {
	t.Parallel()
	cmd := exec.Command("sleep", "0")
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a child: %v", err)
	}
	pid := cmd.Process.Pid
	ticks, err := procStartTicks(pid)
	if err != nil {
		_ = cmd.Wait()
		t.Fatalf("procStartTicks(child): %v", err)
	}
	// Wait for the child to exit without reaping it: it stays a zombie until cmd.Wait.
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			_ = cmd.Wait()
			t.Fatalf("read the child's stat: %v", err)
		}
		st, err := proc.ParseStat(data)
		if err != nil {
			_ = cmd.Wait()
			t.Fatal(err)
		}
		if st.State == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Wait()
			t.Fatalf("the child never exited (state %c)", st.State)
		}
		time.Sleep(5 * time.Millisecond)
	}
	o := owner{PID: uint32(pid), StartTicks: ticks}
	if o.alive() {
		_ = cmd.Wait()
		t.Fatal("an unreaped zombie owner counts as alive")
	}
	_ = cmd.Wait()
	if o.alive() {
		t.Fatal("a reaped owner counts as alive")
	}

	line := func(state byte, threads int) []byte {
		fields := make([]string, 0, 50)
		fields = append(fields, string(state))
		for n := 4; n <= 52; n++ {
			switch n {
			case 20:
				fields = append(fields, fmt.Sprint(threads))
			case 22:
				fields = append(fields, "4242")
			default:
				fields = append(fields, "1")
			}
		}
		return []byte("7 (launcher) " + strings.Join(fields, " ") + "\n")
	}
	for _, tc := range []struct {
		state   byte
		threads int
		gone    bool
	}{{'S', 1, false}, {'R', 4, false}, {'Z', 1, true}, {'Z', 3, false}, {'X', 1, true}} {
		ticks, err := liveTicksOf(7, line(tc.state, tc.threads))
		if gone := errors.Is(err, ErrProcGone); gone != tc.gone {
			t.Errorf("state %c, %d threads: err %v, want gone %v", tc.state, tc.threads, err, tc.gone)
		}
		if !tc.gone && ticks != 4242 {
			t.Errorf("state %c: ticks %d, want 4242", tc.state, ticks)
		}
	}
}

// releasedStat is a /proc/<pid>/stat line of a task released while it was read: fs/proc/array.c's do_task_stat
// could not take its sighand lock, so process group and session are -1, ppid and num_threads 0. A reader on kernel
// 6.17 caught it for a live process whose old leader an execve from another thread released (de_thread), so it
// does not say the process is gone (internal/platform/proc's releasedStatLine gives the source lines).
const releasedStat = "842314 (exe) Z 0 -1 -1 0 -1 4228108 40251 0 0 0 4 27 0 0 20 0 0 0 82606841 0 0 0 0 0 0 0 " +
	"0 0 0 0 0 1 0 0 -1 6 0 0 0 0 0 0 0 0 0 0 0 0 0\n"

// TestAReleasedLineIsNoProofTheOwnerIsGone: liveStartTicks reads a released line again (proc.ReadStat); a line
// that stays released is ErrProcFormat, never ErrProcGone, so aliveBy keeps the owner's slot (it may be a live
// launcher mid-exec), as for any line it cannot read.
func TestAReleasedLineIsNoProofTheOwnerIsGone(t *testing.T) {
	t.Parallel()
	if _, err := liveTicksOf(842314, []byte(releasedStat)); !errors.Is(err, ErrProcFormat) || errors.Is(err, ErrProcGone) {
		t.Fatalf("liveTicksOf(released) = %v, want ErrProcFormat and not ErrProcGone", err)
	}
	if _, err := parseStartTicks([]byte(releasedStat)); !errors.Is(err, ErrProcFormat) || errors.Is(err, ErrProcGone) {
		t.Fatalf("parseStartTicks(released) = %v, want ErrProcFormat and not ErrProcGone", err)
	}
	o := owner{PID: 842314, StartTicks: 82606841}
	if !o.aliveBy(func(pid int) (uint64, error) { return liveTicksOf(pid, []byte(releasedStat)) }) {
		t.Fatal("an owner whose stat read as a released line counts as gone")
	}
}

// TestCgroupPathOfPIDLive reads this process's own cgroup, which every Linux box running the suite has.
func TestCgroupPathOfPIDLive(t *testing.T) {
	t.Parallel()
	path, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 line for this process: %v", err)
	}
	if !strings.HasPrefix(path, "/") {
		t.Fatalf("cgroup path %q is not absolute", path)
	}
	if _, err := cgroupPathOfPID(1 << 30); !errors.Is(err, ErrProcGone) {
		t.Fatalf("cgroupPathOfPID(impossible pid) = %v, want ErrProcGone", err)
	}
}

// TestInSubtree covers the membership test the fanotify listener makes per event: the run's own cgroup and
// anything nested under it belong to the run, and a sibling whose name merely starts the same does not.
func TestInSubtree(t *testing.T) {
	t.Parallel()
	const run = "/user.slice/tego.slice/run-abc.scope"
	cases := []struct {
		candidate string
		want      bool
	}{
		{run, true},
		{run + "/worker", true},
		{run + "/a/b/c", true},
		{"/user.slice/tego.slice/run-abcd.scope", false},
		{"/user.slice/tego.slice", false},
		{"/user.slice/tego.slice/run-xyz.scope", false},
		{"/", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := inSubtree(run, tc.candidate); got != tc.want {
			t.Errorf("inSubtree(%q, %q) = %v, want %v", run, tc.candidate, got, tc.want)
		}
	}
	if inSubtree("", "/anything") {
		t.Error("an empty run path must match nothing")
	}
	if !inSubtree(run+"/", run+"/x") {
		t.Error("a trailing slash on the run path must not change the answer")
	}
}

// FuzzParseCgroupFile drives the reader of another process's /proc, which §8 I11 requires a fuzz target for:
// the bytes belong to a process the run does not control.
func FuzzParseCgroupFile(f *testing.F) {
	f.Add([]byte("0::/user.slice\n"))
	f.Add([]byte("12:pids:/a\n0::/b\n"))
	f.Add([]byte("0::/x (deleted)\n"))
	f.Add([]byte{})
	f.Add([]byte("0::\x00\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		path, err := parseCgroupFile(b)
		if err != nil {
			return
		}
		if !strings.HasPrefix(path, "/") {
			t.Fatalf("accepted a relative cgroup path %q", path)
		}
		// Whatever comes back must be usable as a subtree test without panicking.
		_ = inSubtree(path, path+"/child")
	})
}

// FuzzParseStartTicks drives the other /proc reader for the same reason.
func FuzzParseStartTicks(f *testing.F) {
	f.Add([]byte("1 (init) S " + strings.Repeat("0 ", 18) + "77 " + strings.Repeat("0 ", 9)))
	f.Add([]byte(")"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := parseStartTicks(b); err != nil {
			return
		}
	})
}
