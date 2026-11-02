// SPDX-License-Identifier: Apache-2.0

package ledgerview

import "testing"

// TestSystemNoise: Logs hides only what a program reads of the system on its own. A refused line, a write, a secret by
// its path and what another process holds are never noise, whatever folder they are in.
func TestSystemNoise(t *testing.T) {
	read := func(p string) Event { return Event{Kind: "fs", Op: "read", Verdict: "allow", Target: p} }
	with := func(e Event, f func(*Event)) Event { f(&e); return e }
	for _, c := range []struct {
		name string
		e    Event
		want bool
	}{
		{"a library", read("/lib/x86_64-linux-gnu/libc.so.6"), true},
		{"process status", read("/proc/self/maps"), true},
		{"a watched read", with(read("/proc/version"), func(e *Event) { e.Verdict = "observed" }), true},
		{"a file of the project", read("/w/proj/main.go"), false},
		{"a refused read", with(read("/usr/lib/x"), func(e *Event) { e.Verdict = "refused" }), false},
		{"a refused line", Event{Kind: "refused", Op: "open", Target: "/dev/tty"}, false},
		{"an asked read", with(read("/usr/lib/x"), func(e *Event) { e.Verdict = "ask" }), false},
		{"a write", with(read("/dev/shm/x"), func(e *Event) { e.Op = "write" }), false},
		{"a delete", with(read("/usr/lib/x"), func(e *Event) { e.Op = "unlink" }), false},
		{"another process's environment", read("/proc/1234/environ"), false},
		{"its own environment", read("/proc/self/environ"), false},
		{"a thread's environment", read("/proc/1234/task/1240/environ"), false},
		{"a process's memory", read("/proc/1234/mem"), false},
		{"a file through a process's root", read("/proc/1234/root/etc/shadow"), false},
		{"a file through a process's cwd", read("/proc/self/cwd/notes.txt"), false},
		{"a key through a process's root", read("/proc/self/root/home/u/.ssh/id_rsa"), false},
	} {
		e := c.e
		markSecret(&e)
		if got := SystemNoise(&e); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
