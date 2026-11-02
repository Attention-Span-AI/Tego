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

// line is one ledger line with the common fields filled; extra is the payload and shared fields, as JSON members.
func line(run, agent string, seq int, ts time.Time, kind, extra string) string {
	l := fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"%s","pid":10,"tid":10,"cgroup":1,"kind":"%s","source":"supervisor"`,
		seq, seq+1, ts.UTC().Format(time.RFC3339Nano), seq+1, run, agent, kind)
	if extra != "" {
		l += "," + extra
	}
	return l + "}\n"
}

// writeRun writes a run's events file under root.
func writeRun(t testing.TB, root, run string, lines ...string) {
	t.Helper()
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(lines, "")), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSummarizesAndFolds(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	writeRun(t, root, "r-aaaa-0001-cleanx",
		line("r-aaaa-0001-cleanx", "clean", 0, t0, "run_start", `"tier":"landlock","command":["sh"],"cwd":"/p","contract_source":{"path":"/p/agent.yaml"}`),
		line("r-aaaa-0001-cleanx", "clean", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	r2 := "r-aaaa-0002-harmxx"
	writeRun(t, root, r2,
		line(r2, "harm", 0, t0.Add(time.Minute), "run_start", `"tier":"landlock","command":["sh","agent.sh"]`),
		line(r2, "harm", 1, t0.Add(time.Minute+1), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`),
		line(r2, "harm", 2, t0.Add(time.Minute+2), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`),
		line(r2, "harm", 3, t0.Add(time.Minute+3), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"family(16)"`),
		line(r2, "harm", 4, t0.Add(time.Minute+4), "ask", `"ask_id":"ask-1","hold":"exec"`),
		line(r2, "harm", 5, t0.Add(time.Minute+5), "ask", `"ask_id":"ask-2","hold":"exec"`),
		line(r2, "harm", 6, t0.Add(time.Minute+6), "answer", `"ask_id":"ask-1","by":"human","after_s":1`))
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", r2), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Runs) != 2 || s.Runs[0].ID != r2 {
		t.Fatalf("runs %d, first %v; want 2, newest %s first", len(s.Runs), s.Runs[0].ID, r2)
	}
	harm, clean := s.Runs[0], s.Runs[1]
	if harm.State() != "running" || clean.State() != "ended" || clean.Tier != "landlock" || clean.Contract != "/p/agent.yaml" {
		t.Fatalf("states %s %s, clean %+v", harm.State(), clean.State(), clean)
	}
	if harm.Refusals != 3 || harm.Asks != 2 {
		t.Fatalf("refusals %d asks %d, want 3 and 2", harm.Refusals, harm.Asks)
	}
	if p := s.Pending(); len(p) != 1 || p[0].AskID != "ask-2" {
		t.Fatalf("pending %+v, want ask-2 only", p)
	}
	rows := s.Refusals(0)
	if len(rows) != 2 {
		t.Fatalf("refusal rows %d, want 2 (nscd folded)", len(rows))
	}
	var nscd, netlink *Row
	for i := range rows {
		switch {
		case strings.Contains(rows[i].Target, "nscd"):
			nscd = &rows[i]
		case rows[i].Target == "netlink":
			netlink = &rows[i]
		}
	}
	if nscd == nil || nscd.Count != 2 || !nscd.SystemLookup || netlink == nil || netlink.SystemLookup {
		t.Fatalf("rows %+v", rows)
	}
	// Hiding system lookups hides them from the page and counts them, never dropping them from a run's count.
	pg := s.Query(Filter{Verdicts: []string{"refused"}, HideSys: true})
	if pg.SysHidden != 2 || pg.Matched != 1 || harm.Refusals != 3 {
		t.Fatalf("hidden %d matched %d", pg.SysHidden, pg.Matched)
	}
	if pg := s.Query(Filter{Text: "NSCD"}); pg.Matched != 2 || pg.Groups != 1 {
		t.Fatalf("text filter matched %d groups %d", pg.Matched, pg.Groups)
	}
}

func TestQueryPagesByCursor(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	var ls []string
	for i := 0; i < 25; i++ {
		ls = append(ls, line("r-aaaa-0003-pagexx", "p", i, t0.Add(time.Duration(i)*time.Second), "exec", `"verdict":"allow","argv":["x"]`))
	}
	writeRun(t, root, "r-aaaa-0003-pagexx", ls...)
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[uint64]bool{}
	f := Filter{PageSize: 10}
	for pages := 0; ; pages++ {
		pg := s.Query(f)
		for _, r := range pg.Rows {
			if seen[r.Seq] {
				t.Fatalf("seq %d twice", r.Seq)
			}
			seen[r.Seq] = true
		}
		if pg.Next == "" {
			break
		}
		if pages > 5 {
			t.Fatal("paging does not end")
		}
		f.Before = pg.Next
	}
	if len(seen) != 25 {
		t.Fatalf("saw %d lines, want 25", len(seen))
	}
}

func TestLoadIsBounded(t *testing.T) {
	defer func(runs, lines int) { MaxRuns, MaxLines = runs, lines }(MaxRuns, MaxLines)
	MaxRuns, MaxLines = 200, 20000
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for i := 0; i < MaxRuns+3; i++ {
		id := fmt.Sprintf("r-aaaa-%04d-boundx", i)
		writeRun(t, root, id, line(id, "b", 0, t0, "run_start", ""))
	}
	big := "r-bbbb-0001-bigxxx"
	ls := []string{line(big, "big", 0, t0, "run_start", "")}
	for i := 1; i <= MaxLines+10; i++ {
		ls = append(ls, line(big, "big", i, t0.Add(time.Millisecond), "exec", `"verdict":"allow"`))
	}
	ls = append(ls, line(big, "big", MaxLines+11, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":3`))
	writeRun(t, root, big, ls...)
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !s.RunsCut || len(s.Runs) != MaxRuns || s.TotalRuns != MaxRuns+4 {
		t.Fatalf("runs cut %v, %d read of %d", s.RunsCut, len(s.Runs), s.TotalRuns)
	}
	if s.Lines > MaxLines+MaxRuns { // each run reads at least its first line
		t.Fatalf("read %d lines, budget %d", s.Lines, MaxLines)
	}
	r, err := LoadRun(root, big)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Cut || r.Lines != MaxLines || !r.Ended || r.ExitCode != 3 {
		t.Fatalf("big run: cut %v lines %d ended %v exit %d", r.Cut, r.Lines, r.Ended, r.ExitCode)
	}
	if _, err := LoadRun(root, "../etc"); !os.IsNotExist(err) {
		t.Fatalf("LoadRun(../etc) = %v, want not exist", err)
	}
}

func TestIsSystemLookup(t *testing.T) {
	for in, want := range map[string]bool{
		"unix:/run/nscd/socket": true, "/var/run/dbus/system_bus_socket": true, "unix:/run/systemd/userdb/io.systemd.Multiplexer": true,
		"unix:/run/systemd/resolve/io.systemd.Resolve": true, "unix:/run/docker.sock": false, "127.0.0.1:8": false, "family(16)": false,
	} {
		if got := IsSystemLookup(in); got != want {
			t.Errorf("IsSystemLookup(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestRefreshReadsOnlyAppendedLines: a later load sees lines appended since the first, waits for a line without
// its newline, and reads a replaced file from the start.
func TestRefreshReadsOnlyAppendedLines(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	id := "r-cccc-0001-growxx"
	writeRun(t, root, id, line(id, "g", 0, t0, "run_start", ""), line(id, "g", 1, t0, "exec", `"verdict":"allow"`))
	path := filepath.Join(root, id, "events.jsonl")
	r, err := LoadRun(root, id)
	if err != nil || r.Lines != 2 {
		t.Fatalf("first load: %d lines, %v", r.Lines, err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	third := line(id, "g", 2, t0, "refused", `"verdict":"refused"`)
	if _, err := f.WriteString(third + "\n" + line(id, "g", 3, t0, "exec", `"verdict":"allow"`)[:20]); err != nil {
		t.Fatal(err)
	}
	if r, _ = LoadRun(root, id); r.Lines != 3 || r.Refusals != 1 {
		t.Fatalf("after append: %d lines %d refusals, want 3 and 1 (the partial line waits)", r.Lines, r.Refusals)
	}
	_ = f.Close()
	writeRun(t, root, id, line(id, "g", 0, t0, "run_start", "")) // a new file in the run's place
	if r, _ = LoadRun(root, id); r.Lines != 1 || r.Refusals != 0 {
		t.Fatalf("after replace: %d lines %d refusals, want 1 and 0", r.Lines, r.Refusals)
	}
}

// An ask line names its own operation, target and rule: a pending ask shows them, never "no target", and never those
// of an earlier line with verdict ask, which may belong to another ask.
func TestPendingAskNamesItsOwnTarget(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	r := "r-aaaa-0003-askxxx"
	writeRun(t, root, r,
		line(r, "asker", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`),
		line(r, "asker", 1, t0.Add(1), "fs", `"rule":"fs.ask[./old/]","verdict":"ask","op":"open","path":"/p/old/a"`),
		line(r, "asker", 2, t0.Add(2), "ask", `"ask_id":"q-1","hold":"open","op":"open","target":"/p/held/request.txt","ask_rule":"fs.ask[./held/]"`),
		line(r, "asker", 3, t0.Add(3), "ask", `"ask_id":"q-2","hold":"exec"`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	// Not listed in .live: the run is lost, and a lost run's asks wait on nobody.
	if p := s.Pending(); len(p) != 0 {
		t.Fatalf("a lost run's asks are pending: %+v", p)
	}
	markLive(t, root, r, true)
	if s, err = Load(root); err != nil {
		t.Fatal(err)
	}
	p := s.Pending()
	if len(p) != 2 {
		t.Fatalf("pending %+v, want 2", p)
	}
	if a := p[0]; a.AskID != "q-1" || a.Op != "open" || a.Target != "/p/held/request.txt" || a.Rule != "fs.ask[./held/]" {
		t.Fatalf("q-1 %+v, want open /p/held/request.txt under fs.ask[./held/]", a)
	}
	// An ask line of an older ledger, with no target of its own, still takes the line with verdict ask before it.
	if a := p[1]; a.AskID != "q-2" || a.Target != "/p/old/a" || a.Rule != "fs.ask[./old/]" {
		t.Fatalf("q-2 %+v, want the earlier ask line's /p/old/a", a)
	}
}

// A held fs mutation's ask (ADR 0047) names both ends: a pending rename shows where it goes, so nobody approves a move
// whose destination they were never shown.
func TestPendingMutationAskShowsBothNames(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r := "r-aaaa-0004-askmut"
	writeRun(t, root, r,
		line(r, "asker", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`),
		line(r, "asker", 1, t0.Add(1), "ask", `"ask_id":"q-1","hold":"mutation","op":"rename","target":"/p/held/a.tmp","target2":"/p/held/a","ask_rule":"fs.ask[./held/]"`))
	markLive(t, root, r, true)
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	p := s.Pending()
	if len(p) != 1 || p[0].Op != "rename" || p[0].Target != "/p/held/a.tmp → /p/held/a" || p[0].Hold != "mutation" {
		t.Fatalf("pending %+v, want rename /p/held/a.tmp → /p/held/a held as a mutation", p)
	}
}

// TestDurationOfALostRun: a lost run's time stops at its newest line, whatever the clock says; a running run's grows
// and an ended run's is its end line's.
func TestDurationOfALostRun(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	const lost, ended = "r-aaaa-0031-lostxx", "r-aaaa-0032-endedx"
	writeRun(t, root, lost,
		line(lost, "a", 0, t0, "run_start", `"tier":"landlock","command":["a"],"cwd":"/w"`),
		line(lost, "a", 1, t0.Add(90*time.Second), "exec", `"verdict":"allow","path":"/bin/echo"`))
	writeRun(t, root, ended,
		line(ended, "a", 0, t0, "run_start", `"tier":"landlock","command":["a"],"cwd":"/w"`),
		line(ended, "a", 1, t0.Add(30*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	later := t0.Add(1000 * time.Hour)
	r := s.Find(lost)
	if r.State() != "lost" {
		t.Fatalf("state %s", r.State())
	}
	if got := r.Duration(later); got != 90*time.Second {
		t.Errorf("a lost run lasted %s, want its 1m30s of lines", got)
	}
	if got := s.Find(ended).Duration(later); got != 30*time.Second {
		t.Errorf("an ended run lasted %s", got)
	}
	r.Live = true
	if got := r.Duration(later); got != 1000*time.Hour {
		t.Errorf("a running run lasted %s", got)
	}
}
