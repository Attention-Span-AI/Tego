// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// xrun builds a run's events file line by line with real chain links (each line's prev is the line before's id)
// and the pid of each line chosen by the test.
type xrun struct {
	root, run string
	start     time.Time
	lines     []string
	ids       []string
}

func newXRun(t testing.TB, run string) *xrun {
	t.Helper()
	return &xrun{root: t.TempDir(), run: run, start: time.Date(2026, 10, 26, 3, 38, 51, 0, time.UTC)}
}

// add appends a line of pid with the fields rest after the common ones, and returns its seq.
func (x *xrun) add(pid int, rest string) uint64 {
	seq := len(x.lines)
	id := fmt.Sprintf("%064x", seq+0xabc000)
	prev := ""
	if seq > 0 {
		prev = x.ids[seq-1]
	}
	x.lines = append(x.lines, fmt.Sprintf(`{"v":1,"seq":%d,"id":"%s","prev":"%s","ts":"%s","mono_ns":%d,"run":"%s","agent":"codex","pid":%d,"tid":%d,"cgroup":7,%s}`+"\n",
		seq, id, prev, x.start.Add(time.Duration(seq)*10*time.Millisecond).Format(time.RFC3339Nano), 1000+seq, x.run, pid, pid, rest))
	x.ids = append(x.ids, id)
	return uint64(seq) //nolint:gosec // a test's few lines
}

// exec appends an exec line of pid (start time start) under parent "<pid>/<start>", allowed or refused.
func (x *xrun) exec(pid int, start int, parent string, refused bool, argv ...string) uint64 {
	verdict, extra := "allow", ""
	if refused {
		verdict, extra = "refused", `"reason":"exec-not-allowed",`
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return x.add(pid, fmt.Sprintf(`"kind":"exec","source":"seccomp","rule":"exec[%s]","verdict":"%s","authority":"rule",%s"argv":[%s],"exec_id":"%s/%d/%d","parent_exec_id":"%s/%s","path":"/usr/bin/%s"`,
		filepath.Base(argv[0]), verdict, extra, strings.Join(quoted, ","), x.run, pid, start, x.run, parent, filepath.Base(argv[0])))
}

func (x *xrun) write(t testing.TB) *Run {
	t.Helper()
	writeRun(t, x.root, x.run, x.lines...)
	r, err := LoadRun(x.root, x.run)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// codexShaped is a run shaped like a Codex run: the launcher (pid 100) starts codex (200), codex runs bash (300),
// bash runs curl (400), which connects; a pipeline subshell (500) forks without starting a program and its child
// (501) is refused awk; codex's child 600 is refused lsb_release; pid 700 writes a line and never starts a program.
func codexShaped(t testing.TB) (*xrun, map[string]uint64) {
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-proc01")
	seqs := map[string]uint64{}
	seqs["start"] = x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/home/u/proj","tier":"landlock","launcher_pid":100,"launcher_start_ns":5,"launcher_uid":1000,"launcher_user":"alice"`)
	seqs["codex"] = x.exec(200, 6, "100/5", false, "codex", "--no-daemon")
	seqs["bash"] = x.exec(300, 7, "200/6", false, "/bin/bash", "-c", "curl -s https://example.com")
	seqs["curl"] = x.exec(400, 8, "300/7", false, "curl", "-s", "https://example.com")
	seqs["net"] = x.add(400, `"kind":"net","source":"seccomp","rule":"net[tcp://example.com:443]","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","host":"example.com","proto":"tcp"`)
	seqs["awk"] = x.exec(501, 9, "500/9", true, "awk", "{print $1}")
	seqs["lsb"] = x.exec(600, 10, "200/6", true, "lsb_release", "-a")
	seqs["lsbread"] = x.add(600, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/etc/os-release"`)
	seqs["forked"] = x.add(700, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/etc/hosts"`)
	return x, seqs
}

func names(refs []ProcRef) []string {
	out := make([]string, len(refs))
	for i, r := range refs {
		switch {
		case r.Unrecorded:
			out[i] = fmt.Sprintf("unrecorded(%d)", r.PID)
		case r.Launcher:
			out[i] = "launcher"
		default:
			out[i] = r.Name
		}
	}
	return out
}

// TestProcessChain: a curl two levels under codex names the chain bash, codex, tego launcher, on its exec line and
// on its later lines; a pipeline child whose parent forked without exec ends in an unrecorded parent and says why; a
// refused exec is marked and changes nothing the process runs; a pid that started no program has no program and no
// chain, and the page says so; the launcher's own lines name it.
func TestProcessChain(t *testing.T) {
	x, seqs := codexShaped(t)
	r := x.write(t)
	explain := func(name string) *LineView {
		t.Helper()
		lv, err := Explain(x.root, r, seqs[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return lv
	}
	for _, name := range []string{"curl", "net"} {
		lv := explain(name)
		if lv.Proc == nil || lv.Proc.Name != "curl" || lv.Proc.PID != 400 || lv.Proc.ExecSeq != seqs["curl"] {
			t.Fatalf("%s: proc %+v, want curl (pid 400) from line %d", name, lv.Proc, seqs["curl"])
		}
		if got := strings.Join(names(lv.Chain), " → "); got != "bash → codex → launcher" {
			t.Errorf("%s: chain %s, want bash → codex → launcher", name, got)
		}
		if lv.ChainNote != "" || lv.Cwd != "/home/u/proj" || lv.CwdPerProcess {
			t.Errorf("%s: note %q cwd %q per-process %v", name, lv.ChainNote, lv.Cwd, lv.CwdPerProcess)
		}
	}
	if s := explain("net").Sentence; !strings.HasPrefix(s, "curl (pid 400, child of bash) connected to example.com") {
		t.Errorf("net sentence %q", s)
	}

	awk := explain("awk")
	if awk.Proc == nil || !awk.Proc.Refused || awk.Proc.Name != "awk" {
		t.Fatalf("awk: proc %+v, want a refused attempt at awk", awk.Proc)
	}
	if got := names(awk.Chain); len(got) != 1 || got[0] != "unrecorded(500)" {
		t.Errorf("awk chain %v, want the forked pid 500 alone", got)
	}
	if !strings.Contains(awk.ChainNote, "pid 500") || !strings.Contains(awk.ChainNote, "forked without starting a program") {
		t.Errorf("awk chain note %q", awk.ChainNote)
	}
	if !strings.Contains(awk.Chain[0].Words, "forked, no exec recorded") {
		t.Errorf("unrecorded words %q", awk.Chain[0].Words)
	}

	lsb := explain("lsbread")
	if lsb.Proc == nil || !lsb.Proc.Refused || !strings.Contains(lsb.Proc.Words, "still ran its parent's program") {
		t.Errorf("after a refused exec: proc %+v", lsb.Proc)
	}
	if got := strings.Join(names(lsb.Chain), " → "); got != "codex → launcher" {
		t.Errorf("lsb chain %s", got)
	}

	forked := explain("forked")
	if forked.Proc != nil || len(forked.Chain) != 0 || !strings.Contains(forked.ProcNote, "started no program") {
		t.Errorf("a pid with no exec: proc %+v chain %v note %q", forked.Proc, forked.Chain, forked.ProcNote)
	}

	start := explain("start")
	if start.Proc == nil || !start.Proc.Launcher || len(start.Chain) != 0 {
		t.Errorf("run_start: proc %+v chain %v, want the launcher", start.Proc, start.Chain)
	}
}

// TestExplainLineByRunID: ExplainLine reads the run through the root's store, and a line the run does not hold is
// os.ErrNotExist.
func TestExplainLineByRunID(t *testing.T) {
	x, seqs := codexShaped(t)
	x.write(t)
	lv, err := ExplainLine(x.root, x.run, seqs["curl"])
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(lv.Chain), " → "); got != "bash → codex → launcher" {
		t.Errorf("chain %s", got)
	}
	if _, err := ExplainLine(x.root, x.run, 999); !os.IsNotExist(err) {
		t.Errorf("a missing line: %v, want not exist", err)
	}
}
