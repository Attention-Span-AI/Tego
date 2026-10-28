// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// refusedExec appends a refused exec of pid (exec_id <pid>/<start>, parent <parent>) at path, and its kind=refused
// mirror, as the supervisor writes a refused exec.
func (x *xrun) refusedExec(pid, start int, parent, path string, argv ...string) uint64 {
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	seq := x.add(pid, fmt.Sprintf(`"kind":"exec","source":"seccomp","rule":"unmatched","verdict":"refused","authority":"rule","reason":"exec-not-allowed","argv":[%s],"exec_id":"%s/%d/%d","parent_exec_id":"%s/%s","path":"%s"`,
		strings.Join(quoted, ","), x.run, pid, start, x.run, parent, path))
	x.add(pid, fmt.Sprintf(`"kind":"refused","source":"seccomp","rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"%s"`, path))
	return seq
}

// treeShaped is a run shaped like the supply-chain demo's enforced run (1g24r4): the launcher (100) starts codex
// (200); codex's children 210 and 211 are refused lsb_release and getconf, each tried at two paths of a PATH search;
// bash (300) runs "curl https://example.com" and is refused when it execs curl in place; codex connects to two hosts
// and is refused a unix socket; two pipeline subshells (500, 502) fork without exec, each opening /dev/null, and
// their children are refused awk and allowed sed; pid 700 writes two lines and never starts a program; one line names
// no pid. Its keys name the lines the test looks for.
func treeShaped(t testing.TB) (*xrun, map[string]uint64) {
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-tree01")
	s := map[string]uint64{}
	s["start"] = x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/home/u/proj","tier":"landlock","launcher_pid":100,"launcher_start_ns":5,"launcher_uid":1000,"launcher_user":"alice"`)
	x.add(100, `"kind":"gap","source":"supervisor","what":"record","why":"no-price-table"`)
	s["codex"] = x.exec(200, 6, "100/5", false, "codex", "--no-daemon")
	x.add(200, `"kind":"fs","source":"seccomp","rule":"fs.read[/]","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/etc/os-release"`)
	s["lsb"] = x.refusedExec(210, 7, "200/6", "/usr/bin/lsb_release", "lsb_release", "-a")
	x.refusedExec(210, 7, "200/6", "/bin/lsb_release", "lsb_release", "-a")
	s["getconf"] = x.refusedExec(211, 7, "200/6", "/usr/bin/getconf", "getconf", "LONG_BIT")
	x.refusedExec(211, 7, "200/6", "/bin/getconf", "getconf", "LONG_BIT")
	for _, h := range []string{"chatgpt.com", "api.openai.com", "chatgpt.com"} {
		x.add(200, fmt.Sprintf(`"kind":"net","source":"seccomp","rule":"net[tcp://%s:443]","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","host":"%s","proto":"tcp"`, h, h))
	}
	x.add(200, `"kind":"refused","source":"supervisor","rule":"unmatched","reason":"net-not-allowed","op":"net","target":"unix:/run/user/1000/bus"`)
	s["bash"] = x.exec(300, 8, "200/6", false, "/bin/bash", "-c", "curl https://example.com")
	s["curl"] = x.refusedExec(300, 8, "200/6", "/usr/bin/curl", "curl", "https://example.com")
	s["sub500"] = x.add(500, `"kind":"fs","source":"seccomp","rule":"fs.write[/dev/null]","verdict":"allow","authority":"rule","op":"open","flags":1,"path":"/dev/null"`)
	s["awk"] = x.refusedExec(501, 9, "500/9", "/usr/bin/awk", "awk", "{print $1}")
	x.add(502, `"kind":"fs","source":"seccomp","rule":"fs.write[/dev/null]","verdict":"allow","authority":"rule","op":"open","flags":1,"path":"/dev/null"`)
	s["sed"] = x.exec(503, 9, "502/9", false, "sed", "/^$/d")
	s["p700"] = x.add(700, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"unlink","path":"/tmp/x"`)
	x.add(700, `"kind":"fs","source":"seccomp","rule":"unmatched","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/tmp/y"`)
	x.add(0, `"kind":"gap","source":"supervisor","what":"record","why":"dropped"`)
	x.add(100, `"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	return x, s
}

func walk(n *ProcNode, f func(*ProcNode)) {
	f(n)
	for _, c := range n.Children {
		walk(c, f)
	}
}

func childNames(n *ProcNode) []string {
	var out []string
	for _, c := range n.Children {
		out = append(out, c.Words())
	}
	return out
}

// TestProcessTree is LG-P5's acceptance (a) on a run shaped like 1g24r4: codex hangs from the launcher; the refused
// lsb_release and getconf attempts are one folded attempt each under codex; bash's refused curl is an attempt of
// bash, which keeps its own program; the subshells that forked without exec hang from the launcher, honestly marked,
// with their children under them; a pid with lines and no exec is its own node; the lines add up to the run's lines
// in Logs, and each process's lines are what Logs shows for its pid.
func TestProcessTree(t *testing.T) {
	x, s := treeShaped(t)
	r := x.write(t)
	tr := ProcessTree(r)
	if tr != ProcessTree(r) {
		t.Error("the tree is built again for the same version of the run")
	}
	root := tr.Root
	if !root.Launcher || root.PID != 100 || root.Key() != "100-5" {
		t.Fatalf("root %+v, want the launcher (pid 100)", root)
	}
	want := []string{"codex (pid 200)", "pid 500, forked, no exec recorded", "pid 502, forked, no exec recorded", "pid 700, forked, no exec recorded"}
	if got := childNames(root); !slices.Equal(got, want) {
		t.Fatalf("launcher's children %q, want %q", got, want)
	}
	codex := root.Children[0]
	if codex.ParentUnknown || codex.ExecSeq != s["codex"] || codex.Command() != "codex --no-daemon" {
		t.Errorf("codex %+v", codex)
	}
	if got := childNames(codex); !slices.Equal(got, []string{"lsb_release (pid 210)", "getconf (pid 211)", "bash (pid 300)"}) {
		t.Fatalf("codex's children %q", got)
	}
	lsb := codex.Children[0]
	if !lsb.Refused || len(lsb.Execs) != 1 {
		t.Fatalf("lsb_release: refused %v, execs %+v, want one folded refused attempt", lsb.Refused, lsb.Execs)
	}
	if a := lsb.Execs[0]; a.Count != 2 || !slices.Equal(a.Paths, []string{"/usr/bin/lsb_release", "/bin/lsb_release"}) || a.Seq != s["lsb"] || a.Command() != "lsb_release -a" {
		t.Errorf("lsb_release attempt %+v", a)
	}
	if c := lsb.Counts; c.Lines != 2 || c.Refused != 2 || c.Execs != 2 {
		t.Errorf("lsb_release counts %+v, want its two exec lines, both refused, its mirrors not counted", c)
	}
	bash := codex.Children[2]
	if bash.Refused || bash.Name != "bash" || bash.ExecSeq != s["bash"] || len(bash.Execs) != 2 || !bash.Execs[1].Refused || bash.Execs[1].Name != "curl" {
		t.Errorf("bash %+v: want bash running, with a refused attempt at curl", bash)
	}
	if c := codex.Counts; c.Connects != 4 || c.Hosts != 2 || c.Reads != 1 || c.Refused != 1 || c.Lines != 6 {
		t.Errorf("codex counts %+v", c)
	}
	if want := []HostCount{{"chatgpt.com", 2}, {"api.openai.com", 1}}; !slices.Equal(codex.Hosts, want) {
		t.Errorf("codex hosts %v, want %v", codex.Hosts, want)
	}
	if b := codex.Below; b.Procs != 3 || b.Refused != 5 {
		t.Errorf("under codex %+v, want 3 processes and 5 refusals", b)
	}
	sub := root.Children[1]
	if !sub.Unrecorded || !sub.ParentUnknown || sub.Counts.Lines != 1 || sub.Counts.Writes != 1 || sub.FirstSeq != s["sub500"] {
		t.Errorf("subshell 500 %+v", sub)
	}
	if got := childNames(sub); len(got) != 1 || got[0] != "awk (pid 501)" || !sub.Children[0].Refused || !sub.HasRefusal() {
		t.Errorf("subshell 500's children %q", got)
	}
	if got := childNames(root.Children[2]); len(got) != 1 || got[0] != "sed (pid 503)" || root.Children[2].HasRefusal() {
		t.Errorf("subshell 502's children %q", got)
	}
	if p := root.Children[3]; p.Key() != "700-u" || p.Counts.Lines != 2 || p.ExecID != "" {
		t.Errorf("pid 700 %+v", p)
	}
	if tr.Procs != 10 || tr.Unrecorded != 3 || tr.NoPID != 1 {
		t.Errorf("procs %d, unrecorded %d, no pid %d; want 10, 3, 1", tr.Procs, tr.Unrecorded, tr.NoPID)
	}
	if root.Counts.Lines != 3 {
		t.Errorf("the launcher has %d lines, want run_start, the gap and run_end", root.Counts.Lines)
	}

	// The numbers agree with Logs and with the run's refusals.
	snap, err := Load(x.root)
	if err != nil {
		t.Fatal(err)
	}
	if pg := snap.Query(Filter{Run: r.ID}); tr.Lines+tr.NoPID != pg.Matched {
		t.Errorf("tree lines %d + %d without a pid, Logs %d", tr.Lines, tr.NoPID, pg.Matched)
	}
	if tr.Refused != r.Refusals {
		t.Errorf("tree refusals %d, run %d", tr.Refused, r.Refusals)
	}
	sum := 0
	walk(root, func(n *ProcNode) {
		sum += n.Counts.Lines
		if pg := snap.Query(Filter{Run: r.ID, PID: n.PID}); n.Counts.Lines != pg.Matched {
			t.Errorf("%s: %d lines, Logs pid:%d %d", n.Words(), n.Counts.Lines, n.PID, pg.Matched)
		}
	})
	if sum != tr.Lines || root.Counts.Lines+root.Below.Lines != tr.Lines {
		t.Errorf("lines on the nodes %d, below the root %d, tree %d", sum, root.Counts.Lines+root.Below.Lines, tr.Lines)
	}
}

// TestProcessTreeLoopAndNoLauncher: exec ids that name each other as parents (a malformed ledger) still put each
// process in the tree once, hung from the root; a run with no run_start still has a root.
func TestProcessTreeLoopAndNoLauncher(t *testing.T) {
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-tree02")
	x.exec(800, 1, "801/1", false, "a")
	x.exec(801, 1, "800/1", false, "b")
	x.exec(802, 1, "801/1", false, "c")
	tr := ProcessTree(x.write(t))
	seen := map[string]int{}
	walk(tr.Root, func(n *ProcNode) { seen[n.Key()]++ })
	if len(seen) != 4 || tr.Procs != 4 {
		t.Fatalf("nodes %v (%d processes), want the root and a, b, c once each", seen, tr.Procs)
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("%s is in the tree %d times", k, n)
		}
	}
	if !tr.Root.Launcher || tr.Root.Key() != "launcher" || len(tr.Root.Children) != 1 || !tr.Root.Children[0].ParentUnknown {
		t.Errorf("root %+v: want one loop member hung from it, marked parent unknown", tr.Root)
	}
}

// TestProcessTreeBudget is LG-P5's acceptance (c): the tree of the biggest run of the ledger root in
// TEGO_LOGS_BENCH_LEDGER (read only; give it a copy, such as the 350,000-line synthetic one), cold per version, is
// built in under 30 ms. Skipped without one; TEGO_LOGS_BENCH_STRICT=1 fails a miss, otherwise it is logged.
func TestProcessTreeBudget(t *testing.T) {
	root := os.Getenv("TEGO_LOGS_BENCH_LEDGER")
	if root == "" {
		t.Skip("TEGO_LOGS_BENCH_LEDGER names no ledger root to measure")
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	var big *Run
	for _, r := range s.Runs {
		if big == nil || r.Lines > big.Lines {
			big = r
		}
	}
	if big == nil {
		t.Skip("the ledger root holds no run")
	}
	r, err := LoadRun(root, big.ID)
	if err != nil {
		t.Fatal(err)
	}
	evs := r.AllEvents()
	// Each new version of a run builds its line index and its tree from scratch: that is the cold cost, measured
	// five times on the same lines (the median is the figure; the box is shared, so one take can be slow).
	var index, tree, total []time.Duration
	var tr *ProcTree
	for range 5 {
		runtime.GC() // the load's and the last take's garbage is not this take's cost
		a := time.Now()
		x := buildLineIndex(r.ID, evs)
		i := time.Since(a)
		tr = buildProcTree(r.ID, evs, x)
		index, tree, total = append(index, i), append(tree, time.Since(a)-i), append(total, time.Since(a))
	}
	a := time.Now()
	walk(tr.Root, func(n *ProcNode) { n.Command() })
	t.Logf("every command masked (a page shows at most a few hundred): %.2f ms", ms(time.Since(a)))
	med := func(d []time.Duration) time.Duration { slices.Sort(d); return d[len(d)/2] }
	t.Logf("run %s: %d lines, %d processes; median of 5 cold builds: line index %.2f ms, tree %.2f ms, total %.2f ms (fastest %.2f ms)",
		r.ID, r.Lines, tr.Procs, ms(med(index)), ms(med(tree)), ms(med(total)), ms(total[0]))
	if m := med(total); m > 30*time.Millisecond {
		if os.Getenv("TEGO_LOGS_BENCH_STRICT") == "1" {
			t.Errorf("cold tree %v, budget 30ms", m)
		} else {
			t.Logf("over budget: cold tree %v, budget 30ms", m)
		}
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// TestExecIDs: the index's straight read of exec_id and parent_exec_id gives what decoding the line gives, and
// declines (so the line is decoded) a key that is missing, written twice, not at a key's place, or escaped.
func TestExecIDs(t *testing.T) {
	x, _ := treeShaped(t)
	n := 0
	for _, l := range x.lines {
		if !strings.Contains(l, `"kind":"exec"`) {
			continue
		}
		var p struct {
			ID     string `json:"exec_id"`
			Parent string `json:"parent_exec_id"`
		}
		if err := json.Unmarshal([]byte(l), &p); err != nil {
			t.Fatal(err)
		}
		id, parent, ok := execIDs(l)
		if !ok || id != p.ID || parent != p.Parent {
			t.Errorf("execIDs %q %q %v, decoded %q %q", id, parent, ok, p.ID, p.Parent)
		}
		n++
	}
	if n < 8 {
		t.Fatalf("%d exec lines checked", n)
	}
	if id, parent, ok := execIDs(`{"kind":"exec","exec_id":"r/1/2"}`); !ok || id != "r/1/2" || parent != "" {
		t.Errorf("no parent_exec_id: %q %q %v", id, parent, ok)
	}
	for _, raw := range []string{
		`{"kind":"exec","argv":["x"]}`,
		`{"kind":"exec","exec_id":"r/1/2","g":{"parent_exec_id":"r/9/9"},"parent_exec_id":"r/0/1"}`,
		`{"kind":"exec","exec_id":"r/1/2","parent_exec_id":"r/0/1","g":{"exec_id":"r/9/9"}}`,
		`{"kind":"exec","exec_id":"r/1/\u0032","parent_exec_id":"r/0/1"}`,
		`{"kind":"exec", "exec_id":"r/1/2","parent_exec_id":"r/0/1"}`,
	} {
		if id, parent, ok := execIDs(raw); ok {
			t.Errorf("%s: read %q %q, want it decoded instead", raw, id, parent)
		}
	}
}

// BenchmarkProcessTree builds the tree of a 2,000-process run, each with its own command, from its line index, and
// masks every command as a page showing them all would, with the mask memo empty each time (a first build) or full
// (a new version of a live run).
func BenchmarkProcessTree(b *testing.B) {
	x := newXRun(b, "r-3f9c2a1b-0dmeggtrb9ncn-tree03")
	x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"launcher_pid":100,"launcher_start_ns":5`)
	x.exec(200, 6, "100/5", false, "codex")
	for i := 0; i < 2000; i++ {
		pid := 1000 + i
		x.exec(pid, 7, "200/6", i%7 == 0, "git", "status", "--porcelain", fmt.Sprintf("path/%d", i))
		x.add(pid, `"kind":"fs","source":"seccomp","rule":"fs.read[/]","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/repo/.git/HEAD"`)
	}
	r := x.write(b)
	evs := r.AllEvents()
	idx := r.lineIndexOf()
	for _, cold := range []bool{true, false} {
		name := map[bool]string{true: "first", false: "again"}[cold]
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if cold {
					treeMaskMu.Lock()
					clear(treeMasks)
					treeMaskMu.Unlock()
				}
				walk(buildProcTree(r.ID, evs, idx).Root, func(n *ProcNode) { n.Command() })
			}
		})
	}
}
