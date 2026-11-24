// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// TestRecordedCommandConsumers: a program whose path holds a space is one program to every consumer that names it,
// because each reads the path and the arguments the line recorded (recordedCommand) and none splits the joined text:
// the comparison's row, the refusal group, the line's subject, the agent the run is recognised as and the program two
// runs share.
func TestRecordedCommandConsumers(t *testing.T) {
	root := t.TempDir()
	const run, other = "r-aaaaaaaa-0000000000003-pathsx", "r-aaaaaaaa-0000000000004-pathsx"
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	writeRun(t, root, run,
		line(run, "agent", 0, t0, "run_start", `"tier":"landlock","command":["/opt/my tools/codex","--no-daemon"],"cwd":"/w"`),
		line(run, "agent", 1, t0.Add(time.Second), "exec", `"path":"/opt/my tools/curl","argv":["/opt/my tools/curl","--help"],"verdict":"allow","rule":"exec[curl]"`),
		line(run, "agent", 2, t0.Add(2*time.Second), "refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"/opt/my tools/wget"`),
		// A line that recorded its arguments and no path: the first argument is the program, whole.
		line(run, "agent", 3, t0.Add(3*time.Second), "exec", `"argv":["/opt/my tools/tar","-x"],"verdict":"allow","rule":"exec[tar]"`))
	writeRun(t, root, other,
		line(other, "agent", 0, t0, "run_start", `"tier":"landlock","command":["/usr/bin/codex"],"cwd":"/w"`))
	snap, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Find(run)
	rows, _ := collect(r, func(s string) string { return s })
	var programs []string
	for k := range rows {
		if k.class == ClassExec {
			programs = append(programs, k.target)
		}
	}
	slices.Sort(programs)
	if got := strings.Join(programs, ","); got != "curl,tar" { // the comparison counts action lines, not mirrors
		t.Errorf("comparison programs = %q, want curl,tar", got)
	}
	evs := r.AllEvents()
	for i, want := range map[int]string{1: "curl", 2: "wget", 3: "tar"} {
		e := &evs[i]
		if _, got, _ := groupSubject(e); got != want {
			t.Errorf("line %d: group subject = %q, want %q", i, got, want)
		}
		if got := SubjectOf(e); got != (Subject{Class: "program", Value: want}) {
			t.Errorf("line %d: subject = %+v, want the program %q", i, got, want)
		}
	}
	if got := Signal(r, Sensitive{}).agent; got != "codex" {
		t.Errorf("recognised agent = %q, want codex", got)
	}
	if !SameProgram(r, snap.Find(other)) {
		t.Error("the run of /opt/my tools/codex and the run of /usr/bin/codex ran different programs")
	}
}
