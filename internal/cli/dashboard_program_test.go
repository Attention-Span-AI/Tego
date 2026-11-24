// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// A running dashboard is reused only when it runs the same program bytes as the one a new dashboard would start, by the
// SHA-256 its log records (handoff.ProgramLine); the file times of the log and the program do not decide. A dashboard
// that runs these bytes is current even when its log is older than the file, a program with other bytes is not, and a
// log with no such line is from a tego before the line, so not this one.
func TestDashboardReuseComparesTheProgramBytes(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".tego"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := dashboardStandIn(t).URL + "/?t=0123abcd"
	this := thisProgramFile(t)
	old := "tego program file: dev=1 ino=2 size=3 mtime=4 ctime=5\n" // the line an earlier tego wrote
	for _, c := range []struct {
		name    string
		started *string // nil: a log with no program line
		log     string  // the whole log when started is nil
		logAt   time.Time
		current bool
	}{
		{"a dashboard of an older tego-control", ptr(olderProgramFile(this)), "", time.Now().Add(time.Hour), false},
		{"this program, its log older than any file", &this, "", time.Now().Add(-time.Hour), true},
		{"a log from a tego before the program line", nil, "Tego dashboard: " + link + "\n", time.Now(), false},
		{"a log with the file-attribute line of an earlier tego", nil, old + "Tego dashboard: " + link + "\n", time.Now(), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.started != nil {
				startedBy(t, home, *c.started, "Tego dashboard: "+link+"\n")
			} else if err := os.WriteFile(dashboardLog(home), []byte(c.log), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(dashboardLog(home), c.logAt, c.logAt); err != nil {
				t.Fatal(err)
			}
			if u, current := dashboardAt(home); u != link || current != c.current {
				t.Errorf("dashboardAt = %q, current %v; want %q, current %v", u, current, link, c.current)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// The line the dashboard writes reads back as the sum it names, and nothing else reads as one.
func TestProgramLineRoundTrip(t *testing.T) {
	p := testProgram
	if got, ok := handoff.RecordedProgram([]byte("Tego dashboard: http://127.0.0.1:1/?t=x\n" + handoff.ProgramLine(p))); !ok || got != p {
		t.Fatalf("read back %q %v, want %q", got, ok, p)
	}
	line := handoff.ProgramLine(p)
	for _, log := range []string{"", "Tego dashboard: http://127.0.0.1:1/?t=x\n", line[:len(line)-2] + "x\n", line[:len(line)-3] + "\n",
		"x" + line, handoff.ProgramLine(strings.ToUpper(p)), "tego program sha256:" + p + "\n", handoff.ProgramLinePrefix + " \n"} {
		if got, ok := handoff.RecordedProgram([]byte(log)); ok {
			t.Errorf("%q read as a program line: %q", log, got)
		}
	}
}

// When no program to compare with can be named the dashboard is not reused unchecked: tego dashboard starts a new one
// once and says why in a plain line.
func TestDashboardIsRestartedWhenThisProgramCannotBeRead(t *testing.T) {
	f := onFixture(t, "fresh")
	starts := 0
	prev, prevProgram := guideDashboard, thisProgram
	t.Cleanup(func() { guideDashboard, thisProgram = prev, prevProgram })
	guideDashboard = func(_ context.Context, home string) string {
		starts++
		return "http://127.0.0.1:1/?t=started"
	}
	link := dashboardStandIn(t).URL + "/?t=0123abcd"
	if err := os.MkdirAll(filepath.Dir(dashboardLog(f.Home)), 0o700); err != nil {
		t.Fatal(err)
	}
	startedBy(t, f.Home, thisProgramFile(t), link+"\n")
	thisProgram = func() (string, bool) { return "", false }
	if u, current := dashboardAt(f.Home); u != link || current {
		t.Fatalf("an unreadable program file reused the dashboard: %q, current %v", u, current)
	}
	code, out, errs := run(t, "dashboard")
	if code != identity.ExitOK || starts != 1 || !strings.Contains(out, "no pinned tego-control to compare the running dashboard with") {
		t.Fatalf("exit %d, %d starts, no plain line:\n%s%s", code, starts, out, errs)
	}
}
