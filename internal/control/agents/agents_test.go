// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

func fixtureService(t *testing.T, f *guidetest.Fixture) Service {
	t.Helper()
	in := f.Inputs(t)
	return Service{Inputs: func(context.Context) guide.Inputs { return in }, Ledger: f.Ledger}
}

func TestLoadSavedScanStates(t *testing.T) {
	for _, tc := range []struct {
		state, status        string
		rows, history, hints int
	}{
		{"missing", "missing", 0, 0, 0},
		{"a", "fresh", 1, 0, 0},
		{"b", "fresh", 1, 0, 0},
		{"zero", "fresh", 0, 0, 0},
		{"partial", "fresh", 1, 0, 0},
		{"systemd-login", "fresh", 1, 0, 0},
		{"partial-b", "fresh", 1, 0, 0},
		{"partial-zero", "fresh", 0, 0, 0},
		{"partial-limit", "fresh", 1, 0, 0},
		{"stale", "stale", 0, 1, 0},
		{"another-boot", "another-boot", 0, 1, 0},
		{"future", "future", 0, 1, 0},
		{"unknown-boot", "unknown", 0, 1, 0},
		{"failed", "failed", 0, 1, 0},
		{"forged-user", "unreadable", 0, 0, 0},
		{"foreign-recipient", "unreadable", 0, 0, 0},
		{"invalid", "unreadable", 0, 0, 0},
		{"wrong-mode", "unreadable", 0, 0, 0},
		{"settings-only", "fresh", 0, 0, 1},
		{"project-only", "fresh", 0, 0, 1},
	} {
		t.Run(tc.state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, tc.state)
			path := filepath.Join(f.Home, ".tego", "scan", "last.json")
			before, beforeErr := os.ReadFile(path)
			v := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
			if v.ScanStatus != tc.status || len(v.Rows) != tc.rows || len(v.Historical) != tc.history || len(v.Evidence) != tc.hints {
				t.Fatalf("state %s: status %s, rows %d, historical %d, evidence %d", tc.state, v.ScanStatus, len(v.Rows), len(v.Historical), len(v.Evidence))
			}
			if v.ScanNotice == "" || v.RefreshCommand != "tego scan" || !strings.Contains(v.RefreshInstruction, "project folder") {
				t.Fatalf("missing status or refresh instructions: %+v", v)
			}
			if v.Privacy != "When Tego lists a setting, it keeps the name and never the value" || v.OverviewURL != "/overview" {
				t.Fatalf("missing home navigation or privacy line: %+v", v)
			}
			if tc.rows == 0 && !strings.Contains(v.Empty, "does not establish that no agents exist") {
				t.Fatalf("empty view claims absence: %q", v.Empty)
			}
			if tc.status != "missing" && tc.status != "unreadable" {
				// The scan's footer is worded for a person here; the CLI's own wording stays in result.Footer.
				for _, want := range []string{"Agents that go by a name Tego has no rule for.", "Programs that stopped before or while the scan ran.", "Agents that run on other computers."} {
					if !slices.Contains(v.ScanNotLooked, want) {
						t.Errorf("not-looked-at list lacks %q: %q", want, v.ScanNotLooked)
					}
				}
				if len(v.ScanLines) == 0 || strings.Contains(strings.Join(v.ScanLines, "\n")+v.Footer, "Scope: ") {
					t.Errorf("scan lines %q still use the CLI wording", v.ScanLines)
				}
				if !strings.Contains(v.ScanLabel, "program run by the same user outside Tego can change this saved scan") || v.ScanAge == "" || v.ScanFinished.IsZero() {
					t.Fatalf("scan provenance or age missing: %+v", v)
				}
			}
			for _, row := range v.Rows {
				if row.RecordCommand != "" || !strings.Contains(row.RecordNotice, "working folder") {
					t.Fatalf("scan without a working folder acquired a command: %+v", row)
				}
				if strings.Contains(row.Membership, "in Tego run ") {
					t.Fatalf("saved membership promoted into a current run fact: %s", row.Membership)
				}
			}
			if tc.state == "systemd-login" {
				for _, want := range []string{"3130", "any program can make itself unreadable"} {
					if !strings.Contains(strings.Join(v.ScanLines, "\n")+v.Footer+strings.Join(v.NotKnown, "\n"), want) {
						t.Errorf("partial scan hid %q", want)
					}
				}
			}
			after, afterErr := os.ReadFile(path)
			if beforeErr == nil && (afterErr != nil || !bytes.Equal(before, after)) || os.IsNotExist(beforeErr) && !os.IsNotExist(afterErr) {
				t.Fatal("loading changed the saved result")
			}
		})
	}
}

func TestLoadRechecksSavedFileAndFreshness(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	for _, tc := range []struct {
		at     time.Time
		status string
		rows   int
	}{
		{guidetest.CheckTime.Add(5 * time.Minute), "fresh", 1},
		{guidetest.CheckTime.Add(5*time.Minute + time.Nanosecond), "stale", 1},
	} {
		v := s.Load(t.Context(), tc.at)
		if v.ScanStatus != tc.status || len(v.Rows) != tc.rows {
			t.Fatalf("at %s: status %s, rows %d", tc.at, v.ScanStatus, len(v.Rows))
		}
	}
	f.PutScan(t, "invalid")
	v := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
	if v.ScanStatus != "unreadable" || len(v.Rows) != 1 || v.Rows[0].NotSeenLatest || len(v.Historical)+len(v.Evidence) != 0 {
		t.Fatalf("replacement hid remembered discovery or reused current evidence: %+v", v)
	}
}

func TestLoadRejectsUnsafeAndOversizedSavedFiles(t *testing.T) {
	for _, state := range []string{"wrong-owner", "directory-mode", "symlink", "hardlink", "directory", "huge"} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, "a")
			in := f.Inputs(t)
			path := filepath.Join(f.Home, ".tego", "scan", "last.json")
			switch state {
			case "wrong-owner":
				in.UID++
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "symlink", "directory":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if state == "symlink" {
					if err := os.Symlink("missing-target", path); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(f.Root, "extra-link")); err != nil {
					t.Fatal(err)
				}
			case "huge":
				if err := os.WriteFile(path, bytes.Repeat([]byte(" "), result.MaxBytes+1), 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := Service{Inputs: func(context.Context) guide.Inputs { return in }, Ledger: f.Ledger}
			v := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
			if v.ScanStatus != "unreadable" || len(v.Rows)+len(v.Historical)+len(v.Evidence) != 0 {
				t.Fatalf("unsafe %s evidence displayed: %+v", state, v)
			}
			if state == "huge" && !strings.Contains(v.ScanNotice, "1 MiB") || state == "directory-mode" && !strings.Contains(v.ScanNotice, "chmod 700") {
				t.Fatalf("missing safe repair/limit wording: %s", v.ScanNotice)
			}
		})
	}
}

func TestLoadConformanceSnapshotsKeepMetadataSeparate(t *testing.T) {
	for _, tc := range []struct {
		file                   string
		rows, evidence, others int
	}{
		{"basic", 2, 1, 1},
		{"project", 2, 2, 1},
		{"configured", 0, 3, 0},
	} {
		t.Run(tc.file, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			s := conformanceScan(t, tc.file)
			if err := result.Save(f.Home, uint32(os.Getuid()), s); err != nil {
				t.Fatal(err)
			}
			v := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
			if v.ScanStatus != "fresh" || len(v.Rows) != tc.rows || len(v.Evidence) != tc.evidence || len(v.OtherPrograms) != tc.others || v.OtherCount != s.Counts.Other || v.OtherListed != s.OtherListed {
				t.Fatalf("%s: %+v", tc.file, v)
			}
			for _, row := range v.Rows {
				if row.Name == "other-interpreter" || row.Name == "langgraph" {
					t.Fatalf("metadata or unknown-purpose program became an agent: %+v", row)
				}
				if row.Agent.Folder != "" && row.RecordCommand != "cd /home/person/project && tego watch -- <the command you start it with>" {
					t.Fatalf("unexpected record template: %q", row.RecordCommand)
				}
			}
			fi, err := os.Stat(filepath.Join(f.Home, ".tego", "scan", "last.json"))
			if err != nil || fi.Mode().Perm() != 0600 {
				t.Fatalf("saved scan permissions: %v, %v", fi, err)
			}
		})
	}
}

func conformanceScan(t *testing.T, name string) result.Snapshot {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "scan", "v1", "fixtures", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := result.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	s.As = result.Identity{UID: uid, Recipient: uid, Root: uid == 0}
	s.Started, s.Finished, s.Boot = guidetest.CheckTime, guidetest.CheckTime, result.Path(guidetest.BootID)
	for n, item := range s.Items {
		switch item.Kind {
		case "process", "other_program":
			p := item.Process()
			p.UID = uid
			s.Items[n].Detail = result.Detail(p)
		case "user_unit", "timer":
			u := item.Unit()
			u.UID = &uid
			s.Items[n].Detail = result.Detail(u)
		}
	}
	return s
}

func TestWatchLineOrdinaryFoldersAndUnsafeInputs(t *testing.T) {
	for _, tc := range []struct{ folder, word string }{
		{"/home/me/bot", "/home/me/bot"},
		{"/home/Me/Agent Projects/bot", "'/home/Me/Agent Projects/bot'"},
		{"/home/me/l'été", `'/home/me/l'\''été'`},
		{"/home/me/日本語", "'/home/me/日本語'"},
		{"/home/me/a; touch injected", "'/home/me/a; touch injected'"},
		{"/home/me/$(touch injected)", "'/home/me/$(touch injected)'"},
		{"/home/me/`touch injected`", "'/home/me/`touch injected`'"},
		{`/home/me/a\b`, `'/home/me/a'\\'b'`},
		{"/", "/"},
	} {
		t.Run(tc.folder, func(t *testing.T) {
			want := "cd " + tc.word + " && tego watch -- <the command you start it with>"
			if got := watchLine(tc.folder); got != want {
				t.Fatalf("watchLine(%q) = %q, want %q", tc.folder, got, want)
			}
		})
	}
	for _, folder := range []string{"", "bot", "./bot", "../bot", "~/bot", "/home/me/line\nbreak", "/home/me/tab\tname", "/home/me/\x1b[31m", "/home/me/\x00", "/home/me/\u202etxt", "/home/me/\u200bname", "/home/me/\u2028line", "/home/me/\xff", "/" + strings.Repeat("x", 4096)} {
		if got := watchLine(folder); got != "" {
			t.Errorf("unsafe folder %q yielded a copyable command %q", folder, got)
		}
	}
}

func TestWatchLineRepositoryLayouts(t *testing.T) {
	for _, group := range []string{"examples", "pkg/spec/presets/v1", "spec/policy/conformance"} {
		t.Run(group, func(t *testing.T) {
			root := filepath.Join("..", "..", "..", filepath.FromSlash(group))
			measured := 0
			err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() || filepath.Ext(path) != ".yaml" {
					return nil
				}
				folder, err := filepath.Abs(filepath.Dir(path))
				if err != nil {
					return err
				}
				measured++
				if got := watchLine(folder); got == "" {
					t.Errorf("ordinary %s folder %q refused", group, folder)
				}
				return nil
			})
			if err != nil || measured == 0 {
				t.Fatalf("measured %d %s layouts: %v", measured, group, err)
			}
			t.Logf("%s: %d ordinary YAML fixture folders accepted", group, measured)
		})
	}
}

func TestRefusedTodayCountsActionsOnceInLocalDay(t *testing.T) {
	// The DST transition makes the local calendar day 25 hours, so 24h arithmetic
	// would silently exclude the final hour.
	loc, err := time.LoadLocation("America/Toronto")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, loc)
	since := time.Date(2026, 11, 1, 0, 0, 0, 0, loc)
	until := since.AddDate(0, 0, 1)
	root := t.TempDir()
	const run = "r-aaaa-0001-countx"
	deny := `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:443"`
	mirror := `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:443"`
	writeLedger(t, root, run,
		ledgerLine(run, 0, 1, since.Add(-time.Hour), "run_start", `"tier":"landlock","command":["sh"]`),
		ledgerLine(run, 1, 2, since.Add(-time.Nanosecond), "refused", mirror),
		ledgerLine(run, 2, 3, since, "net", deny),
		ledgerLine(run, 3, 3, since, "refused", mirror),
		ledgerLine(run, 4, 4, since.Add(time.Hour), "fs", `"verdict":"refused","rule":"fs.deny_read[x]","reason":"read-denied","op":"open","path":"/x"`),
		ledgerLine(run, 5, 5, until.Add(-time.Nanosecond), "refused", mirror),
		ledgerLine(run, 6, 6, until, "refused", mirror),
		ledgerLine(run, 7, 7, until.Add(time.Hour), "run_end", `"reason":"exit","exit_code":0`))
	c := refusals(root, now)
	if c.Value != 3 || c.Partial || !c.Since.Equal(since) || !c.Until.Equal(until) || c.Until.Sub(c.Since) != 25*time.Hour {
		t.Fatalf("today count %+v; want 3 once each in [%s, %s)", c, since, until)
	}
	if !strings.Contains(c.Notice, "counted once") || !strings.Contains(c.Notice, "not recorded at all") {
		t.Fatalf("count loses its limits: %s", c.Notice)
	}
}

func TestRefusedTodayDisclosesIncompleteLedger(t *testing.T) {
	for _, state := range []string{"bad-line", "reads-unknown", "unreadable-root"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			now := guidetest.CheckTime
			const run = "r-aaaa-0002-countx"
			start := `"tier":"landlock","command":["sh"]`
			if state == "reads-unknown" {
				start += `,"capabilities":{"record.reads_mmap_chmod":false}`
			}
			lines := []string{ledgerLine(run, 0, 1, now, "run_start", start), ledgerLine(run, 1, 2, now, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:443"`)}
			if state == "bad-line" {
				lines = append(lines, "{broken\n")
			}
			writeLedger(t, root, run, lines...)
			if state == "unreadable-root" {
				root = filepath.Join(root, "regular-file")
				if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c := refusals(root, now)
			if !c.Partial || c.Notice == "" || state != "unreadable-root" && c.Value != 1 {
				t.Fatalf("%s missing lower-bound notice: %+v", state, c)
			}
		})
	}
}

func ledgerLine(run string, seq int, mono uint64, at time.Time, kind, extra string) string {
	return fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"bot","pid":10,"tid":10,"cgroup":1,"kind":"%s","source":"supervisor",%s}`+"\n", seq, seq+1, at.UTC().Format(time.RFC3339Nano), mono, run, kind, extra)
}

func writeLedger(t *testing.T, root, run string, lines ...string) {
	t.Helper()
	dir := filepath.Join(root, run)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(lines, "")), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAgeWords(t *testing.T) {
	now := guidetest.CheckTime
	for _, tc := range []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, "Time unknown"},
		{now.Add(time.Second), "Future time"},
		{now.Add(-59 * time.Second), "Just now"},
		{now.Add(-time.Minute), "1 minute ago"},
		{now.Add(-5 * time.Minute), "5 minutes ago"},
		{now.Add(-time.Hour), "1 hour ago"},
		{now.Add(-2 * time.Hour), "2 hours ago"},
		{now.Add(-24 * time.Hour), "1 day ago"},
		{now.Add(-36 * time.Hour), "1 day ago"},
		{now.Add(-48 * time.Hour), "2 days ago"},
	} {
		if got := age(tc.at, now); got != tc.want {
			t.Errorf("age(%s) = %q, want %q", tc.at, got, tc.want)
		}
	}
}

func TestObservationKeepsCheckedEvidence(t *testing.T) {
	i := result.Item{ID: "x", Kind: "process", Name: "claude", Evidence: []result.Evidence{{RuleID: "claude-native", Fact: "exe-name", SourceID: "source-1"}}, Detail: result.Detail(result.Process{Exe: result.Path("/bin/claude"), Cwd: result.Path("/work"), Membership: "in-run", RunID: result.Path("r-aaaa-0001-claude")})}
	o := observation(i, guidetest.CheckTime)
	if o.Path != "/bin/claude" || o.Folder != "/work" || o.Fact != "claude-native: exe-name (source-1)" || !o.SeenAt.Equal(guidetest.CheckTime) || !strings.Contains(o.Membership, "could not be checked against the record") {
		t.Fatalf("observation lost evidence or promoted cgroup membership: %+v", o)
	}
}

func TestHistoricalItemStaysOutOfCurrentRows(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	in := f.Inputs(t)
	r, err := result.Read(f.Home, uint32(in.UID), in.Host.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	r.Snapshot.Items[0].Caveats = append(r.Snapshot.Items[0].Caveats, "historical")
	if err := result.Save(f.Home, uint32(in.UID), r.Snapshot); err != nil {
		t.Fatal(err)
	}
	v := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime)
	if len(v.Rows) != 0 || len(v.Historical) != 1 || !strings.Contains(v.Historical[0].Fact, "historical") {
		t.Fatalf("historical observation became current: %+v", v)
	}
	st := guide.Compute(t.Context(), in)
	for _, step := range st.Steps {
		if step.ID == guide.StepFind && step.State == guide.Done {
			t.Fatal("historical item ticked guide Find")
		}
	}
}

func TestUnreadableRunStartsQualifyTodayCount(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	dir := filepath.Join(f.Ledger, "r-aaaaaaaa-0000000000003-unread")
	if err := os.MkdirAll(filepath.Join(dir, "events.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
	v := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime)
	if !v.RecordsPartial || !v.RefusedToday.Partial || !strings.Contains(v.RefusedToday.Notice, "can be higher") {
		t.Fatalf("omitted run is not qualified: %+v", v)
	}
}

func TestAgentsAndSetupShareIdentityFacts(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	in := f.Inputs(t)
	v := fixtureService(t, f).Load(t.Context(), in.Now)
	st := guide.Compute(t.Context(), in)
	if len(v.Rows) != len(st.Agents) || v.Next.Rule != st.Next.Rule {
		t.Fatal("setup/page inventory or next step diverged")
	}
	for i, row := range v.Rows {
		if row.ID != st.Agents[i].ID || row.Agent.Current != st.Agents[i].Current {
			t.Fatalf("identity differs: %+v vs %+v", row.Agent, st.Agents[i])
		}
	}
}

func TestObservationKeepsConfiguredNamesAndTypedDetail(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		detail any
		name   string
	}{
		{"mcp_server", result.Config{Server: "local-memory", Client: "claude", Transport: "stdio", Arguments: 3, Path: result.Path("/home/me/.claude.json")}, "local-memory"},
		{"user_unit", result.Unit{Name: "triage-agent.service", Arguments: 2, Path: result.Path("/home/me/.config/systemd/user/triage-agent.service")}, "triage-agent.service"},
	} {
		item := result.Item{ID: "item-1", Kind: tc.kind, Name: "claude", Detail: result.Detail(tc.detail)}
		o := observation(item, guidetest.CheckTime)
		if o.Name != tc.name || !bytes.Equal(o.Item.Detail, item.Detail) || !strings.Contains(o.Fact, "configured only") {
			t.Fatalf("configured name or detail lost: %+v", o)
		}
	}
}

// Each recorded run's row carries the count its run page shows (ledgerview.Run.Refusals, read from the same record
// as today's total), never an estimate; a row no record backs carries none.
func TestRowRefusalsMatchTheRecord(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	f.PutScan(t, "a")
	// the fixture's own recorded run, its record replaced by one with refused actions
	run := f.Runs[0]
	now := guidetest.CheckTime
	mirror := `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:443"`
	writeLedger(t, f.Ledger, run,
		ledgerLine(run, 0, 1, now, "run_start", `"tier":"landlock","command":["sh"]`),
		ledgerLine(run, 1, 2, now, "refused", mirror),
		ledgerLine(run, 2, 3, now, "fs", `"verdict":"refused","rule":"fs.deny_read[x]","reason":"read-denied","op":"open","path":"/x"`),
		ledgerLine(run, 3, 4, now, "refused", mirror),
		ledgerLine(run, 4, 5, now, "run_end", `"reason":"exit","exit_code":0`))
	snap, err := ledgerview.Load(f.Ledger)
	if err != nil {
		t.Fatal(err)
	}
	want := snap.Find(run)
	if want == nil || want.Refusals == 0 {
		t.Fatalf("fixture run has no refusals: %+v", want)
	}
	v := fixtureService(t, f).Load(t.Context(), now.Add(time.Minute))
	var got *Row
	for i, r := range v.Rows {
		if r.Agent.RunID == run {
			got = &v.Rows[i]
		}
		if r.Agent.RunID == "" && r.RefusalsKnown {
			t.Errorf("scan row %s claims a refusal count", r.ID)
		}
	}
	if got == nil {
		t.Fatalf("no row for %s among %d", run, len(v.Rows))
	}
	if !got.RefusalsKnown || got.Refusals != want.Refusals || got.RefusalsPartial {
		t.Fatalf("row says %d known=%t partial=%t; the run page says %d", got.Refusals, got.RefusalsKnown, got.RefusalsPartial, want.Refusals)
	}
	// a run whose record could not be read in full is a lower bound
	writeLedger(t, f.Ledger, run, ledgerLine(run, 0, 1, now, "run_start", `"tier":"landlock","command":["sh"]`), ledgerLine(run, 1, 2, now, "refused", mirror), "{broken\n")
	v = fixtureService(t, f).Load(t.Context(), now.Add(time.Minute))
	for _, r := range v.Rows {
		if r.Agent.RunID == run && (!r.RefusalsKnown || r.Refusals != 1 || !r.RefusalsPartial) {
			t.Fatalf("incomplete record: %+v", r)
		}
	}
}
