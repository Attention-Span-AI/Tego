// SPDX-License-Identifier: Apache-2.0

package agentid

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func observed() Found {
	return Found{ID: "process-1", Name: "native agent", Command: "/opt/agent", Folder: "/work/one", UID: 1000,
		UIDKnown: true, Source: "scan:item-1", Fact: "program path matched", SeenAt: time.Unix(200, 0).UTC()}
}

func recorded() Run {
	return Run{ID: "run-1", Name: "agent", Command: []string{"/opt/agent"}, Folder: "/work/one", UID: 1000,
		UIDKnown: true, Source: "record:run-1", Started: time.Unix(100, 0).UTC(), Verification: Verified}
}

func stage(t *testing.T, a Agent, id string) Fact {
	t.Helper()
	for _, s := range a.Stages {
		if s.ID == id {
			return s.Fact
		}
	}
	t.Fatalf("stage %q missing", id)
	return Fact{}
}

func TestExactProgramFolderAndUIDOnlyRelatesInWords(t *testing.T) {
	f, r := observed(), recorded()
	got := Resolve([]Found{f}, []Run{r}, nil)
	if len(got) != 2 {
		t.Fatalf("scan must have its own row: %+v", got)
	}
	for _, row := range got {
		if len(row.Found) > 0 {
			if len(row.Runs) != 0 || row.Current != "observation" || !strings.Contains(row.Relationship, "may be the same program") {
				t.Errorf("observation relation: %+v", row)
			}
			if row.LastSeen != f.SeenAt {
				t.Errorf("observation time: %+v", row)
			}
		} else if row.RunID != r.ID || row.RunStarted != r.Started || row.LastSeen != r.Started || row.SelectionRule == "" {
			t.Errorf("recorded run provenance: %+v", row)
		}
	}
}

func TestCannotTellIdentityCases(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Found, *Run)
	}{
		{"same name different folder", func(f *Found, _ *Run) { f.Folder = "/work/two" }},
		{"renamed folder", func(f *Found, _ *Run) { f.Folder = "/work/renamed" }},
		{"folder alias", func(f *Found, _ *Run) { f.Folder = "/work/one/." }},
		{"program alias", func(f *Found, _ *Run) { f.Command = "/usr/local/bin/agent" }},
		{"bare command", func(_ *Found, r *Run) { r.Command = []string{"agent"} }},
		{"relative command", func(_ *Found, r *Run) { r.Command = []string{"./agent"} }},
		{"missing observed program", func(f *Found, _ *Run) { f.Command = "" }},
		{"missing observed folder", func(f *Found, _ *Run) { f.Folder = "" }},
		{"missing recorded folder", func(_ *Found, r *Run) { r.Folder = "" }},
		{"different uid", func(f *Found, _ *Run) { f.UID++ }},
		{"unknown observed uid", func(f *Found, _ *Run) { f.UIDKnown = false }},
		{"old record unknown uid", func(_ *Found, r *Run) { r.UIDKnown = false }},
		{"deleted observed path", func(f *Found, _ *Run) { f.Command += " (deleted)" }},
		{"deleted recorded path", func(f *Found, r *Run) { f.Command += " (deleted)"; r.Command[0] += " (deleted)" }},
		{"broken record", func(_ *Found, r *Run) { r.Verification = Broken }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, r := observed(), recorded()
			tt.edit(&f, &r)
			got := Resolve([]Found{f}, []Run{r}, nil)
			if len(got) != 2 {
				t.Fatalf("unestablished identity merged: %+v", got)
			}
			for _, a := range got {
				if len(a.Found) != 0 && stage(t, a, RecordedStage).CannotTell == "" {
					t.Errorf("observation lacks Cannot tell: %+v", a)
				}
			}
		})
	}
}

func TestInterpretersAndWrappersDoNotIdentifyWorkloads(t *testing.T) {
	for _, program := range []string{"python", "python3", "python3.13", "node", "bun", "deno", "java", "ruby", "sh", "bash", "dash", "zsh", "env"} {
		t.Run(program, func(t *testing.T) {
			f, r := observed(), recorded()
			f.Command = "/usr/bin/" + program
			r.Command = []string{f.Command, "agent.py"}
			if got := Resolve([]Found{f}, []Run{r}, nil); len(got) != 2 {
				t.Fatalf("workload guessed from %s: %+v", program, got)
			}
		})
	}
}

func TestAmbiguousCommandsStaySeparate(t *testing.T) {
	f, first, second := observed(), recorded(), recorded()
	first.Command = []string{"/opt/agent", "alpha"}
	second.ID, second.Command = "run-2", []string{"/opt/agent", "beta"}
	got := Resolve([]Found{f}, []Run{first, second}, nil)
	if len(got) != 3 {
		t.Fatalf("scan lost argument ambiguity: %+v", got)
	}
	for _, a := range got {
		if len(a.Found) > 0 && stage(t, a, RecordedStage).CannotTell == "" {
			t.Fatal("ambiguous match has no explanation")
		}
	}
}

func TestArgumentBoundariesAreIdentity(t *testing.T) {
	a, b := recorded(), recorded()
	a.Command = []string{"/opt/agent", "a b", "c"}
	b.ID, b.Command = "run-2", []string{"/opt/agent", "a", "b c"}
	if got := Resolve(nil, []Run{a, b}, nil); len(got) != 2 {
		t.Fatalf("space-joined commands collided: %+v", got)
	}
}

func TestIncompleteIdentityCannotCollideWithCommandWords(t *testing.T) {
	a, b := recorded(), recorded()
	a.Command = nil
	b.ID, b.Command = "run-2", []string{"incomplete", a.ID, a.Source}
	if rows := Resolve(nil, []Run{a, b}, nil); len(rows) != 2 {
		t.Fatalf("identity metadata collided with command words: %+v", rows)
	}
}

func TestStagesRequireTheirOwnFacts(t *testing.T) {
	r := recorded()
	r.ContractPath, r.Tier, r.Ended, r.Verification = "/contracts/agent.yaml", "landlock", true, Verified
	c := Contract{Path: r.ContractPath, CompileRunID: r.ID, Compiles: true}
	got := Resolve([]Found{observed()}, []Run{r}, []Contract{c})
	if len(got) != 2 {
		t.Fatalf("complete stages: %+v", got)
	}
	for _, row := range got {
		if len(row.Runs) == 0 {
			continue
		}
		if row.Current != VerifiedStage {
			t.Errorf("verified run state: %+v", row)
		}
		for _, s := range row.Stages {
			if s.ID == FoundStage {
				continue
			}
			if !s.Fact.Established || s.Fact.Text == "" || s.Fact.Source == "" {
				t.Errorf("stage lacks proof: %+v", s)
			}
		}
	}
	for _, tc := range []struct {
		name    string
		edit    func(*Run, *Contract)
		missing []string
	}{
		{"unchecked", func(r *Run, _ *Contract) { r.Verification = Unchecked }, []string{ContractStage, EnforcedStage, VerifiedStage}},
		{"cannot verify", func(r *Run, _ *Contract) { r.Verification = CannotVerify }, []string{ContractStage, EnforcedStage, VerifiedStage}},
		{"broken", func(r *Run, _ *Contract) { r.Verification = Broken }, []string{ContractStage, EnforcedStage, VerifiedStage}},
		{"running", func(r *Run, _ *Contract) { r.Ended = false }, []string{VerifiedStage}},
		{"observe", func(r *Run, _ *Contract) { r.Tier = "observe" }, []string{EnforcedStage, VerifiedStage}},
		{"unknown tier", func(r *Run, _ *Contract) { r.Tier = "future-tier" }, []string{EnforcedStage, VerifiedStage}},
		{"auto tier", func(r *Run, _ *Contract) { r.Tier = "auto" }, []string{EnforcedStage, VerifiedStage}},
		{"contract missing", func(_ *Run, c *Contract) { c.Path = "/contracts/else.yaml" }, []string{ContractStage}},
		{"compile context missing", func(_ *Run, c *Contract) { c.CompileRunID = "" }, []string{ContractStage}},
		{"compile context differs", func(_ *Run, c *Contract) { c.CompileRunID = "other-run" }, []string{ContractStage}},
		{"contract fails compile", func(_ *Run, c *Contract) { c.Compiles = false }, []string{ContractStage}},
		{"no contract source", func(r *Run, _ *Contract) { r.ContractPath = "" }, []string{ContractStage}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, c := r, c
			tc.edit(&r, &c)
			rows := Resolve(nil, []Run{r}, []Contract{c})
			if len(rows) != 1 {
				t.Fatalf("run evidence disappeared: %+v", rows)
			}
			for _, id := range tc.missing {
				fact := stage(t, rows[0], id)
				if fact.Established || fact.CannotTell == "" {
					t.Errorf("%s claimed without proof: %+v", id, fact)
				}
			}
		})
	}
}

func TestNoContractNameGuess(t *testing.T) {
	r := recorded()
	got := Resolve(nil, []Run{r}, []Contract{{Path: "/contracts/one.yaml", Compiles: true}})
	if fact := stage(t, got[0], ContractStage); fact.Established || fact.CannotTell == "" {
		t.Fatalf("folder name guessed a contract: %+v", fact)
	}
}

func TestConflictingContractResultsCannotEstablishContract(t *testing.T) {
	r := recorded()
	r.ContractPath = "/contracts/agent.yaml"
	got := Resolve(nil, []Run{r}, []Contract{{Path: r.ContractPath, CompileRunID: r.ID, Compiles: true}, {Path: r.ContractPath, CompileRunID: r.ID}})
	if fact := stage(t, got[0], ContractStage); fact.Established || fact.CannotTell == "" {
		t.Fatalf("conflicting checks established contract: %+v", fact)
	}
}

func TestSharedContractRequiresTheCheckedRunContext(t *testing.T) {
	for _, layout := range []string{"different folders", "same folder different arguments", "same identity different run"} {
		t.Run(layout, func(t *testing.T) {
			a, b := recorded(), recorded()
			a.ContractPath = "/contracts/shared.yaml"
			b.ID, b.ContractPath = "run-2", a.ContractPath
			switch layout {
			case "different folders":
				b.Folder = "/work/two"
			case "same folder different arguments":
				b.Command = []string{"/opt/agent", "other"}
			case "same identity different run":
				b.Tier = "cgroup"
			}
			checks := []Contract{{Path: a.ContractPath, CompileRunID: a.ID, Compiles: true}}
			rows := Resolve(nil, []Run{a, b}, checks)
			expectedRows := 2
			if len(rows) != expectedRows {
				t.Fatalf("got %d rows, want %d", len(rows), expectedRows)
			}
			for _, row := range rows {
				fact := stage(t, row, ContractStage)
				checked := slices.ContainsFunc(row.Runs, func(r Run) bool { return r.ID == a.ID })
				if fact.Established != checked || (!checked && fact.CannotTell == "") {
					t.Fatalf("compile context crossed identities: %+v", row)
				}
				if checked && (fact.RunID != a.ID || !strings.Contains(fact.Text, "in that run's context")) {
					t.Errorf("compile fact omits its context: %+v", fact)
				}
			}
			// A failure in another run's context must not erase the checked fact.
			checks = append(checks, Contract{Path: b.ContractPath, CompileRunID: b.ID, Compiles: false})
			for _, row := range Resolve(nil, []Run{a, b}, checks) {
				fact := stage(t, row, ContractStage)
				checked := slices.ContainsFunc(row.Runs, func(r Run) bool { return r.ID == a.ID })
				if fact.Established != checked {
					t.Fatalf("unrelated compile results conflict: %+v", row)
				}
			}
		})
	}
}

func TestKnownRootUIDAndRunOnlyRows(t *testing.T) {
	f, r := observed(), recorded()
	f.UID, r.UID = 0, 0
	if rows := Resolve([]Found{f}, []Run{r}, nil); len(rows) != 2 {
		t.Fatalf("known uid zero was treated as missing: %+v", rows)
	}
	rows := Resolve(nil, []Run{r}, nil)
	if len(rows) != 1 || !stage(t, rows[0], RecordedStage).Established {
		t.Fatalf("recorded agent requires scan: %+v", rows)
	}
}

func TestInputsAreNotMutated(t *testing.T) {
	r := recorded()
	rows := Resolve([]Found{observed()}, []Run{r}, nil)
	for _, row := range rows {
		if len(row.Runs) > 0 {
			row.Runs[0].Command[0] = "changed"
		}
	}
	if r.Command[0] != "/opt/agent" {
		t.Fatal("output aliases input command")
	}
}

func TestArgumentsStayOutOfDisplayAndJSON(t *testing.T) {
	r := recorded()
	r.Command = append(r.Command, "--token", "credential-never-display")
	rows := Resolve([]Found{observed()}, []Run{r}, nil)
	if rows[0].Command != "/opt/agent" {
		t.Fatalf("arguments entered display: %q", rows[0].Command)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"--token", "credential-never-display"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("arguments entered serialized inventory: %s", secret)
		}
	}
}

func TestPropertyDifferentFoldersNeverMerge(t *testing.T) {
	property := func(a, b uint32) bool {
		if a == b {
			return true
		}
		one, two := recorded(), recorded()
		one.Folder, two.Folder = "/work/"+stringKey(a), "/work/"+stringKey(b)
		two.ID = "run-2"
		return len(Resolve(nil, []Run{one, two}, nil)) == 2
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 500}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyInputOrderDoesNotChangeIdentity(t *testing.T) {
	property := func(seed uint8) bool {
		var runs []Run
		var found []Found
		for i := uint32(0); i < 8; i++ {
			r, f := recorded(), observed()
			r.ID, r.Folder = "run-"+stringKey(i), "/work/"+stringKey(i)
			f.ID, f.Folder = "found-"+stringKey(i), r.Folder
			runs, found = append(runs, r), append(found, f)
		}
		want := Resolve(found, runs, nil)
		if len(want) != 16 {
			return false
		}
		for i := 0; i < int(seed)%8; i++ {
			runs = append(runs[1:], runs[0])
			found = append(found[1:], found[0])
		}
		slices.Reverse(runs)
		return reflect.DeepEqual(Resolve(found, runs, nil), want)
	}
	if err := quick.Check(property, &quick.Config{MaxCount: 256}); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownScanIdentityCannotAttach(t *testing.T) {
	f := Found{ID: "scan-unknown", Name: "claude", Command: "/bin/claude", Folder: "/work", UID: 1, UIDKnown: true, IdentityUnknown: true}
	r := Run{ID: "run", Command: []string{"/bin/claude"}, Folder: "/work", UID: 1, UIDKnown: true}
	rows := Resolve([]Found{f}, []Run{r}, nil)
	if len(rows) != 2 {
		t.Fatalf("unknown identity attached: %+v", rows)
	}
	for _, a := range rows {
		if len(a.Found) > 0 && !strings.Contains(a.Stages[1].Fact.CannotTell, "unknown process identity") {
			t.Fatalf("lost identity uncertainty: %+v", a)
		}
	}
}
