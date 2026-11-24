// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"testing"
)

// reusedPidRun is a run in which the kernel gave pid 300 to a second process. The lines' monotonic clock (mono_ns,
// 1000 + seq in xrun) and the processes' start times (the boot clock, in exec_id) are one clock here (the machine
// was never suspended). Process A (pid 300, started at 1001) writes lines 3 and 5. Process B (pid 300 again, started
// at 1008, after A had gone) writes lines 10 and 11 before it starts its program at line 12: the record holds nothing
// of B before that line but B's start time, in its own exec_id. Process E (pid 400) keeps writing throughout.
func reusedPidRun(t testing.TB, bStart int) (*xrun, map[string]uint64) {
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-reuse1")
	s := map[string]uint64{}
	fs := func(pid int, path string) uint64 {
		return x.add(pid, fmt.Sprintf(`"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"%s"`, path))
	}
	x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/home/u/proj","tier":"landlock","launcher_pid":100,"launcher_start_ns":5`) // seq 0
	s["codex"] = x.exec(200, 1000, "100/5", false, "codex")                                                                                                    // seq 1, mono 1001
	s["a"] = x.exec(300, 1001, "200/1000", false, "bash")                                                                                                      // seq 2, mono 1002
	s["a3"] = fs(300, "/a/3")                                                                                                                                  // seq 3
	fs(400, "/e/4")                                                                                                                                            // seq 4
	s["a5"] = fs(300, "/a/5")                                                                                                                                  // seq 5
	for i := 6; i < 10; i++ {
		fs(400, fmt.Sprintf("/e/%d", i)) // seqs 6-9
	}
	s["b10"] = fs(300, "/b/10")                                       // seq 10, mono 1010: B's, started at 1008
	s["b11"] = fs(300, "/b/11")                                       // seq 11
	s["b"] = x.exec(300, bStart, "200/1000", false, "sed", "-n", "p") // seq 12, mono 1012
	s["b13"] = fs(300, "/b/13")                                       // seq 13
	x.add(100, `"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	return x, s
}

// TestReusedPidIsTwoProcessesBeforeItsExec (C102): a pid the kernel reused inside one run is two processes from the
// second one's start, not from its first exec line. The lines B wrote before its program started are B's (its exec_id
// says when it started), in the process tree and on the line page; they were A's, bash's, as long as the view took
// the newest process whose first exec is at or before the line.
func TestReusedPidIsTwoProcessesBeforeItsExec(t *testing.T) {
	x, s := reusedPidRun(t, 1008)
	r := x.write(t)
	tr := ProcessTree(r)
	var a, b *ProcNode
	walk(tr.Root, func(n *ProcNode) {
		switch n.ExecID {
		case x.run + "/300/1001":
			a = n
		case x.run + "/300/1008":
			b = n
		}
	})
	if a == nil || b == nil {
		t.Fatalf("the tree holds no node for process A (%v) or B (%v)", a != nil, b != nil)
	}
	// A: its exec line and lines 3 and 5. B: lines 10 and 11 (before its exec), its exec line and line 13.
	if a.Counts.Lines != 3 || b.Counts.Lines != 4 {
		t.Errorf("process A has %d lines, B %d; want 3 (exec, two files) and 4 (two files before its exec, the exec, one after)", a.Counts.Lines, b.Counts.Lines)
	}
	if b.FirstSeq != s["b10"] {
		t.Errorf("B's first line is %d, want %d (the first line of the pid after A's)", b.FirstSeq, s["b10"])
	}
	for _, name := range []string{"b10", "b11", "b13"} {
		lv, err := Explain(x.root, r, s[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if lv.Proc == nil || lv.Proc.ExecID != x.run+"/300/1008" {
			t.Errorf("%s: process %+v, want B (exec_id .../300/1008)", name, lv.Proc)
		}
	}
	for _, name := range []string{"a3", "a5"} {
		lv, err := Explain(x.root, r, s[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if lv.Proc == nil || lv.Proc.ExecID != x.run+"/300/1001" || lv.Proc.Name != "bash" {
			t.Errorf("%s: process %+v, want A (bash, exec_id .../300/1001)", name, lv.Proc)
		}
	}
	// Before B's exec it ran no program of its own the record names: the page says so rather than call it bash.
	if lv, _ := Explain(x.root, r, s["b11"]); lv.Proc != nil && lv.Proc.HasExec {
		t.Errorf("b11: process %+v names a program before B's exec", lv.Proc)
	}
}

// TestReusedPidLinesStayWithTheEarlierProcessUntilTheLaterOneStarted: the same run with B's start time after its two
// early lines (1012, the instant of its exec) puts them back with A, as the view always read them: a line moves to a
// later process only when that process's own start time says it had started.
func TestReusedPidLinesStayWithTheEarlierProcessUntilTheLaterOneStarted(t *testing.T) {
	x, s := reusedPidRun(t, 1012)
	r := x.write(t)
	for _, name := range []string{"b10", "b11"} {
		lv, err := Explain(x.root, r, s[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if lv.Proc == nil || lv.Proc.ExecID != x.run+"/300/1001" {
			t.Errorf("%s: process %+v, want A: B had not started by then", name, lv.Proc)
		}
	}
	lv, err := Explain(x.root, r, s["b13"])
	if err != nil || lv.Proc == nil || lv.Proc.ExecID != x.run+"/300/1012" {
		t.Errorf("b13: process %+v (%v), want B", lv.Proc, err)
	}
}
