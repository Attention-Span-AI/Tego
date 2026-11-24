// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

func TestLoadRemembersDiscoveriesAfterEmptyReplacement(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	first := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
	if len(first.Rows) != 1 {
		t.Fatalf("first rows = %d", len(first.Rows))
	}
	f.PutScan(t, "zero")
	got := s.Load(t.Context(), guidetest.CheckTime.Add(2*time.Minute))
	if len(got.Rows) != 1 || got.Rows[0].ID != first.Rows[0].ID || !strings.Contains(got.Rows[0].Membership, "Not seen in the latest scan") {
		t.Fatalf("empty replacement hid discovery: rows %+v", got.Rows)
	}
}

func TestLoadDiscoveryFloodRetainsRemembered(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	first := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
	r, err := result.Read(f.Home, uint32(os.Getuid()), guidetest.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot
	snap.Started = snap.Started.Add(time.Minute)
	snap.Finished = snap.Started
	snap.Items = nil
	snap.Counts.Running, snap.Counts.Outside = 512, 512
	for n := range 512 {
		item := r.Snapshot.Items[0]
		item.ID = fmt.Sprintf("item-%d", n+1)
		p := item.Process()
		p.PID, p.Exe = n+20, result.Path(fmt.Sprintf("/bin/madeup-%d", n))
		item.Detail = result.Detail(p)
		snap.Items = append(snap.Items, item)
	}
	b, err := result.Encode(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.Home, ".tego", "scan", "last.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	got := s.Load(t.Context(), guidetest.CheckTime.Add(2*time.Minute))
	seen := false
	for _, row := range got.Rows {
		seen = seen || row.ID == first.Rows[0].ID
	}
	if !seen {
		t.Fatal("maximum-size scan flood hid remembered discovery")
	}
	if got.Rows[0].ID != first.Rows[0].ID {
		t.Fatal("oldest remembered discovery was ordered after the flood")
	}
	for _, row := range got.Rows[1:] {
		if !row.SeenAt.After(got.Rows[0].SeenAt) {
			t.Fatal("flood fixture did not test oldest-first ordering")
		}
	}
	if !strings.Contains(got.Footer, "cut short") {
		t.Fatal("overflow was not stated in footer")
	}
}

func TestLoadDiscoveryStoreUnsafeIsNotOverwritten(t *testing.T) {
	for _, state := range []string{"oversized", "symlink", "hardlink", "mode", "invalid", "directory-link", "home-link", "wrong-owner", "directory-mode", "busy"} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, "a")
			s := fixtureService(t, f)
			if got := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute)); len(got.Rows) != 1 {
				t.Fatal("missing initial observation")
			}
			path := filepath.Join(f.Home, ".tego", "agents", discoveryFile)
			switch state {
			case "oversized":
				if err := os.WriteFile(path, []byte(strings.Repeat(" ", discoveryBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".target"
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "invalid":
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "directory-link":
				dir := filepath.Dir(path)
				if err := os.Rename(dir, dir+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+".target", dir); err != nil {
					t.Fatal(err)
				}
			case "home-link":
				link := filepath.Join(f.Root, "home-link")
				if err := os.Symlink(f.Home, link); err != nil {
					t.Fatal(err)
				}
				in := f.Inputs(t)
				in.Home = link
				s.Inputs = func(context.Context) guide.Inputs { return in }
			case "wrong-owner":
				in := f.Inputs(t)
				in.UID++
				s.Inputs = func(context.Context) guide.Inputs { return in }
			case "directory-mode":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "busy":
				f.PutScan(t, "zero")
				d, err := discoveryDir(f.Home, uint32(os.Getuid()), false)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = d.Close() }()
				if err = d.Borrow(func(n int) error { return unix.Flock(n, unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got := s.Load(t.Context(), guidetest.CheckTime.Add(2*time.Minute))
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if state == "busy" && (len(got.Rows) != 1 || !got.Rows[0].Remembered || !strings.Contains(got.DiscoveryNotice, "Refresh")) {
				t.Fatalf("busy store hid committed observation or retry: %+v", got)
			}
			if !bytes.Equal(before, after) || got.DiscoveryNotice == "" {
				t.Fatalf("unsafe store overwritten or not explained: %q", got.DiscoveryNotice)
			}
			if state == "busy" {
				// A fresh observation can advance the response even while another viewer
				// owns persistence. Keeping the committed rows must not roll its time back.
				f.PutScan(t, "a")
				r, err := result.Read(f.Home, uint32(os.Getuid()), guidetest.BootID, guidetest.CheckTime)
				if err != nil {
					t.Fatal(err)
				}
				r.Snapshot.Started = r.Snapshot.Started.Add(time.Minute)
				r.Snapshot.Finished = r.Snapshot.Started
				if err := result.Save(f.Home, uint32(os.Getuid()), r.Snapshot); err != nil {
					t.Fatal(err)
				}
				fresh := s.Load(t.Context(), guidetest.CheckTime.Add(2*time.Minute))
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if len(fresh.Rows) != 1 || !fresh.Rows[0].LastSeen.Equal(r.Snapshot.Finished) || !bytes.Equal(before, after) {
					t.Fatal("busy response rolled back fresh last-seen or wrote store")
				}
			}
		})
	}
}

func TestLoadDiscoveryRetentionAndProvenance(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	first := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
	path := filepath.Join(f.Home, ".tego", "scan", "last.json")
	r, err := result.Read(f.Home, uint32(os.Getuid()), guidetest.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot
	snap.Started = snap.Started.Add(time.Minute)
	snap.Finished = snap.Started
	snap.Items[0].ID = "item-2"
	b, err := result.Encode(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	newer := s.Load(t.Context(), guidetest.CheckTime.Add(2*time.Minute))
	if len(newer.Rows) != 1 || newer.Rows[0].ID != first.Rows[0].ID || !newer.Rows[0].FirstSeen.Equal(guidetest.CheckTime) || !newer.Rows[0].LastSeen.Equal(snap.Finished) {
		t.Fatalf("identity/provenance changed: %+v", newer.Rows)
	}
	f.PutScan(t, "a")
	replay := s.Load(t.Context(), guidetest.CheckTime.Add(2*time.Minute))
	if len(replay.Rows) != 1 || !replay.Rows[0].SeenAt.Equal(snap.Finished) || !replay.Rows[0].LastSeen.Equal(snap.Finished) {
		t.Fatal("replayed older snapshot rolled back last-seen ordering")
	}
	f.PutScan(t, "zero")
	edge := s.Load(t.Context(), snap.Finished.Add(30*24*time.Hour))
	if len(edge.Rows) != 1 || edge.Rows[0].NotSeenLatest || edge.Rows[0].Agent.Current != "" {
		t.Fatalf("retained row claims a current stage: %+v", edge.Rows)
	}
	for _, stage := range edge.Rows[0].Agent.Stages {
		if stage.Fact.Established {
			t.Fatalf("absent observation retained tick: %+v", stage)
		}
	}
	expired := s.Load(t.Context(), snap.Finished.Add(30*24*time.Hour+time.Nanosecond))
	if len(expired.Rows) != 0 {
		t.Fatal("discovery remained past 30 days")
	}
}

func TestLoadDiscoveryStoreKeepsBoundedIdentityOnly(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	r, err := result.Read(f.Home, uint32(os.Getuid()), guidetest.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot
	for len(snap.Items[0].Evidence) < 8 {
		snap.Items[0].Evidence = append(snap.Items[0].Evidence, snap.Items[0].Evidence[0])
	}
	b, err := result.Encode(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(f.Home, ".tego", "scan", "last.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	s := fixtureService(t, f)
	for range 2 {
		got := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
		if got.DiscoveryNotice != "" || len(got.Rows) != 1 {
			t.Fatalf("valid maximum evidence made unreadable memory: %+v", got)
		}
	}
	b, err = os.ReadFile(filepath.Join(f.Home, ".tego", "agents", discoveryFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "exe-name") || strings.Contains(string(b), "pid 10") {
		t.Fatal("store retained scan evidence rather than only observation identity")
	}
}

func TestLoadInRunObservationOnlyCountsInFooter(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprint(stale), func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, "a")
			r, err := result.Read(f.Home, uint32(os.Getuid()), guidetest.BootID, guidetest.CheckTime)
			if err != nil {
				t.Fatal(err)
			}
			snap := r.Snapshot
			p := snap.Items[0].Process()
			snap.Items[0].Evidence = append(snap.Items[0].Evidence, result.Evidence{RuleID: "claude-native", SourceID: "source-1", Fact: "cgroup"})
			p.Membership = "in-run"
			p.RunID = result.Path("r-0123abcd-0000000000000-abcdef")
			snap.Items[0].Detail = result.Detail(p)
			snap.Counts.InRun = 1
			snap.Counts.Outside = 0
			if stale {
				snap.Started = snap.Started.Add(-time.Hour)
				snap.Finished = snap.Started
			}
			b, err := result.Encode(snap)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(f.Home, ".tego", "scan", "last.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			got := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
			if len(got.Rows)+len(got.Historical)+len(got.Evidence) != 0 || got.InRunObservations != 1 || !strings.Contains(got.Footer, "The scan saw 1 program inside a Tego run") {
				t.Fatalf("in-run scan adds a row or loses count: %+v", got)
			}
		})
	}
}

func TestDiscoveryOrderWhenStoreUnavailable(t *testing.T) {
	now := guidetest.CheckTime
	v := View{Rows: []Row{
		{ID: "new", SeenAt: now},
		{ID: "run-b", Agent: agentid.Agent{Runs: []agentid.Run{{ID: "b"}}}},
		{ID: "old", SeenAt: now.Add(-time.Hour)},
		{ID: "run-a", Agent: agentid.Agent{Runs: []agentid.Run{{ID: "a"}}}},
	}}
	v.remember("relative", uint32(os.Getuid()), result.ReadResult{}, os.ErrNotExist, now)
	want := []string{"run-b", "run-a", "old", "new"}
	for n, row := range v.Rows {
		if row.ID != want[n] {
			t.Fatalf("row %d = %s, want %s", n, row.ID, want[n])
		}
	}
	if v.DiscoveryNotice == "" {
		t.Fatal("store failure was not shown")
	}
}

func TestLoadOtherProgramsInsideRunOnlyCountFooter(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	snap := conformanceScan(t, "basic")
	item := snap.Items[len(snap.Items)-1]
	if item.Kind != "other_program" {
		t.Fatal("fixture does not end in other program")
	}
	p := item.Process()
	p.Membership = "in-run"
	p.RunID = result.Path("r-aaaaaaaa-0000000000003-inrunx")
	item.Evidence = append(item.Evidence, result.Evidence{RuleID: "other-interpreter", SourceID: item.Evidence[0].SourceID, Fact: "cgroup"})
	item.Detail = result.Detail(p)
	snap.Items = []result.Item{item}
	snap.Counts = result.Counts{Other: 1}
	if err := result.Save(f.Home, uint32(os.Getuid()), snap); err != nil {
		t.Fatal(err)
	}
	v := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
	if len(v.Rows)+len(v.OtherPrograms)+len(v.Historical)+len(v.Evidence) != 0 || v.InRunObservations != 1 {
		t.Fatalf("inside-run other program added a row or label: %+v", v)
	}
}

func TestLoadForgedScanCannotInheritRunTicks(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	rd, err := ledger.OpenReader(filepath.Join(f.Ledger, f.Runs[1]))
	if err != nil {
		t.Fatal(err)
	}
	var start record.RunStartPayload
	for e, err := range rd.Iter() {
		if err != nil {
			t.Fatal(err)
		}
		if err := e.DecodePayload(&start); err != nil {
			t.Fatal(err)
		}
		break
	}
	if err := rd.Close(); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	start.Command = []string{"/bin/claude", "--worker", "A"}
	start.LauncherUID = &uid
	const runID = "r-aaaaaaaa-0000000000003-worker"
	w, err := ledger.Open(filepath.Join(f.Ledger, runID), record.RunRef{ID: runID, Agent: "worker"}, ledger.WithAnchor(ledger.NewFileChainAnchor(f.Anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(start); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	s := fixtureService(t, f)
	before := s.Load(t.Context(), guidetest.CheckTime)
	var recorded agentid.Agent
	for _, row := range before.Rows {
		if len(row.Agent.Runs) == 1 && row.Agent.Runs[0].ID == runID {
			recorded = row.Agent
		}
	}
	if recorded.ID == "" || recorded.Current != agentid.VerifiedStage {
		t.Fatalf("fixture lacks checked enforcing row: %+v", recorded)
	}
	f.PutScan(t, "a")
	r, err := result.Read(f.Home, uid, guidetest.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Snapshot.Items[0].Process()
	p.Exe = result.Path(start.Command[0])
	p.Cwd = result.Path(start.Cwd)
	// A same-user writer fabricates a valid second worker observation. The
	// saved schema deliberately has no argument vector to distinguish worker B.
	r.Snapshot.Items[0].Detail = result.Detail(p)
	if err := result.Save(f.Home, uid, r.Snapshot); err != nil {
		t.Fatal(err)
	}
	after := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
	if len(after.Rows) != len(before.Rows)+1 {
		t.Fatalf("forged saved result joined a recorded row: %+v", after.Rows)
	}
	foundRecord, foundObservation := false, false
	for _, row := range after.Rows {
		if len(row.Agent.Runs) == 1 && row.Agent.Runs[0].ID == runID {
			foundRecord = true
			if !reflect.DeepEqual(row.Agent, recorded) {
				t.Fatalf("scan changed recorded row: before=%+v after=%+v", recorded, row.Agent)
			}
		}
		if len(row.Agent.Found) > 0 {
			foundObservation = true
			if len(row.Agent.Runs) != 0 {
				t.Fatal("observation inherited record")
			}
			for _, st := range row.Agent.Stages {
				if st.Fact.Established {
					t.Fatalf("saved observation inherited tick: %+v", st)
				}
			}
		}
	}
	if !foundRecord || !foundObservation {
		t.Fatal("record or separate observation missing")
	}
}

func TestRememberedRelationsUseCurrentRuns(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	uid := uint32(os.Getuid())
	r, err := result.Read(f.Home, uid, guidetest.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	p := r.Snapshot.Items[0].Process()
	p.Exe, p.Cwd = result.Path("/opt/agent"), result.Path("/work")
	r.Snapshot.Items[0].Detail = result.Detail(p)
	found := guide.ScanAgents(r.Snapshot, uid, "scan")[0]
	run := agentid.Run{ID: "recorded", Command: []string{found.Command}, Folder: found.Folder, UID: uid, UIDKnown: true}
	load := func(scan result.ReadResult, runs []agentid.Run) Row {
		t.Helper()
		v := View{}
		for _, a := range agentid.Resolve(guide.ScanAgents(scan.Snapshot, uid, "scan"), runs, nil) {
			v.Rows = append(v.Rows, Row{Agent: a})
		}
		v.remember(f.Home, uid, scan, nil, guidetest.CheckTime.Add(time.Minute))
		for _, row := range v.Rows {
			if len(row.Agent.Found) > 0 {
				if len(row.Agent.Runs) != 0 {
					t.Fatal("observation joined record")
				}
				for _, stage := range row.Agent.Stages {
					if stage.Fact.Established {
						t.Fatal("observation gained tick")
					}
				}
				return row
			}
		}
		t.Fatal("remembered observation disappeared")
		return Row{}
	}
	first := load(r, []agentid.Run{run})
	if !reflect.DeepEqual(first.Agent.RelatedRunIDs, []string{run.ID}) {
		t.Fatal("fixture lacks relation")
	}
	f.PutScan(t, "zero")
	empty, err := result.Read(f.Home, uid, guidetest.BootID, guidetest.CheckTime)
	if err != nil {
		t.Fatal(err)
	}
	remembered := load(empty, []agentid.Run{run})
	if !reflect.DeepEqual(remembered.Agent.RelatedRunIDs, first.Agent.RelatedRunIDs) || remembered.Agent.Relationship != first.Agent.Relationship {
		t.Fatalf("omission changed relation: %+v", remembered.Agent)
	}
	run.ID = "replacement-run"
	changed := load(empty, []agentid.Run{run})
	if !reflect.DeepEqual(changed.Agent.RelatedRunIDs, []string{run.ID}) {
		t.Fatalf("stale relation: %+v", changed.Agent)
	}
	removed := load(empty, nil)
	if len(removed.Agent.RelatedRunIDs) != 0 || !strings.Contains(removed.Agent.Relationship, "no exact") {
		t.Fatalf("removed run relation survived: %+v", removed.Agent)
	}
}

func TestRememberedUnusableScanIsNotOmission(t *testing.T) {
	for _, state := range []string{"stale", "failed", "unreadable"} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, "a")
			s := fixtureService(t, f)
			first := s.Load(t.Context(), guidetest.CheckTime.Add(time.Minute)).Rows[0]
			now := guidetest.CheckTime.Add(6 * time.Minute)
			path := filepath.Join(f.Home, ".tego", "scan", "last.json")
			if state == "unreadable" {
				if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "failed" {
				f.PutScan(t, "failed")
				now = guidetest.CheckTime.Add(2 * time.Minute)
			}
			v := s.Load(t.Context(), now)
			if len(v.Rows) != 1 {
				t.Fatalf("lost memory: %+v", v)
			}
			row := v.Rows[0]
			if row.NotSeenLatest || strings.Contains(row.Membership, "Not seen in the latest scan") || !strings.Contains(row.Membership, v.ScanNotice) || !row.LastSeen.Equal(first.LastSeen) || !strings.Contains(row.Agent.NextStep, "Scan again") {
				t.Fatalf("unusable scan conflated with omission: %+v", row)
			}
		})
	}
}

// The walk to the discovery store needs search permission on the home's ancestors, never read: an ancestor the
// user may search but not list is passed, as a whole-path open would pass it.
func TestDiscoveryDirNeedsOnlySearchOnAncestors(t *testing.T) {
	searchOnly := filepath.Join(t.TempDir(), "search-only")
	home := filepath.Join(searchOnly, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(searchOnly, 0o311); err != nil { // write and search, no read
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(searchOnly, 0o700) })
	d, err := discoveryDir(home, uint32(os.Getuid()), true)
	if err != nil {
		t.Fatalf("the discovery store beneath a 0311 ancestor: %v; want it opened, a walk needs only search there", err)
	}
	defer func() { _ = d.Close() }()
	if err = d.Borrow(func(n int) error { return unix.Flock(n, unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
		t.Fatalf("lock the store: %v", err)
	}
}

func TestForgetDropsOneDiscoveryAndKeepsTheRest(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	at := guidetest.CheckTime.Add(time.Minute)
	first := s.Load(t.Context(), at)
	if len(first.Rows) != 1 {
		t.Fatalf("rows = %d", len(first.Rows))
	}
	id := first.Rows[0].ID
	if err := s.Forget(t.Context(), "agent-discovery-"+strings.Repeat("0", 64), at); err != ErrNotRemembered {
		t.Fatalf("unknown id: %v", err)
	}
	if err := s.Forget(t.Context(), "../scan/last.json", at); err != ErrNotRemembered {
		t.Fatalf("a path as id: %v", err)
	}
	if err := s.Forget(t.Context(), id, at); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(f.Home, ".tego", "agents", discoveryFile)
	b, err := os.ReadFile(store)
	if err != nil || !strings.Contains(string(b), `"entries":[]`) {
		t.Fatalf("store after forget: %s %v", b, err)
	}
	if info, err := os.Stat(store); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("store mode: %v %v", info, err)
	}
	if err := s.Forget(t.Context(), id, at); err != ErrNotRemembered {
		t.Fatalf("second forget: %v", err)
	}
	// the saved scan was not touched, so it is remembered again by the next load
	if got := s.Load(t.Context(), at.Add(time.Second)); len(got.Rows) != 1 || got.Rows[0].ID != id {
		t.Fatalf("not remembered again: %+v", got.Rows)
	}
}

func TestForgetLeavesRunRowsAlone(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	at := guidetest.CheckTime.Add(time.Minute)
	before := s.Load(t.Context(), at)
	var runIDs []string
	for _, r := range before.Rows {
		if r.Agent.RunID != "" {
			runIDs = append(runIDs, r.ID)
			if err := s.Forget(t.Context(), r.ID, at); err != ErrNotRemembered {
				t.Fatalf("a recorded run's row was forgettable: %v", err)
			}
		}
	}
	if len(runIDs) == 0 {
		t.Fatal("fixture has no recorded run")
	}
	after := s.Load(t.Context(), at)
	if len(after.Rows) != len(before.Rows) {
		t.Fatalf("rows %d then %d", len(before.Rows), len(after.Rows))
	}
}

func TestForgetRefusesBusyAndUnsafeStores(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	s := fixtureService(t, f)
	at := guidetest.CheckTime.Add(time.Minute)
	id := s.Load(t.Context(), at).Rows[0].ID
	dir := filepath.Join(f.Home, ".tego", "agents")
	store := filepath.Join(dir, discoveryFile)
	want, err := os.ReadFile(store)
	if err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(int(d.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err = s.Forget(t.Context(), id, at); err != ErrForgetBusy {
		t.Fatalf("locked store: %v", err)
	}
	_ = d.Close()
	if err = os.Chmod(store, 0644); err != nil {
		t.Fatal(err)
	}
	if err = s.Forget(t.Context(), id, at); err != ErrForgetUnsafe {
		t.Fatalf("unsafe store: %v", err)
	}
	if err = os.Chmod(store, 0600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(store); !bytes.Equal(got, want) {
		t.Fatal("a refused forget changed the store")
	}
	if err = (Service{}).Forget(t.Context(), id, at); err != ErrForgetUnavailable {
		t.Fatalf("no inputs: %v", err)
	}
}
