// SPDX-License-Identifier: Apache-2.0

package agentid

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOutsideObservationCannotInheritRunTicks(t *testing.T) {
	for _, source := range []string{"second worker process", "saved scan forged by same user"} {
		t.Run(source, func(t *testing.T) {
			r, f := recorded(), observed()
			r.Command = []string{"/opt/agent", "--worker", "A"}
			r.Tier, r.Ended, r.Verification = "landlock", true, Verified
			f.Source = source // The scan has no arguments with which to distinguish worker B.
			before := Resolve(nil, []Run{r}, nil)[0]
			rows := Resolve([]Found{f}, []Run{r}, nil)
			if len(rows) != 2 {
				t.Fatalf("observation inherited run row: %+v", rows)
			}
			for _, row := range rows {
				if len(row.Found) > 0 {
					for _, id := range []string{FoundStage, RecordedStage, ContractStage, EnforcedStage, VerifiedStage} {
						if stage(t, row, id).Established {
							t.Errorf("observation inherited %s", id)
						}
					}
				} else if !reflect.DeepEqual(row, before) {
					t.Errorf("scan changed recorded row: before=%+v after=%+v", before, row)
				}
			}
		})
	}
}

func TestUncheckedRecordCannotEstablishLaterStages(t *testing.T) {
	for _, verdict := range []Verification{Unchecked, CannotVerify, Broken} {
		r := recorded()
		r.ContractPath, r.Tier, r.Ended = "/contracts/agent.yaml", "landlock", true
		r.Verification, r.VerificationReason = verdict, "record was not checked"
		row := Resolve(nil, []Run{r}, []Contract{{Path: r.ContractPath, CompileRunID: r.ID, Compiles: true}})[0]
		if row.VerificationReason != r.VerificationReason || !strings.Contains(stage(t, row, RecordedStage).Text, "recorded, not checked") || row.NextStep == "" {
			t.Errorf("verdict %v lacks reason and next step: %+v", verdict, row)
		}
		for _, id := range []string{ContractStage, EnforcedStage, VerifiedStage} {
			if stage(t, row, id).Established {
				t.Errorf("verdict %v established %s", verdict, id)
			}
		}
	}
}

func TestEveryTickNamesTheRowsSingleRun(t *testing.T) {
	old, newer := recorded(), recorded()
	old.Verification, old.VerificationReason, old.Tier = Broken, "hash chain is broken", "landlock"
	newer.ID, newer.Started, newer.Verification, newer.Tier = "newer", old.Started.Add(time.Hour), Verified, "cgroup"
	newer.Ended = true
	rows := Resolve(nil, []Run{old, newer}, nil)
	if len(rows) != 2 {
		t.Fatalf("different runs pooled stages: %+v", rows)
	}
	for _, row := range rows {
		if len(row.Runs) != 1 {
			t.Fatalf("row does not describe one run: %+v", row)
		}
		for _, s := range row.Stages {
			if s.Fact.Established && s.Fact.RunID != row.Runs[0].ID {
				t.Errorf("stage transferred from another run: %+v", s)
			}
		}
		if row.Runs[0].ID == old.ID && stage(t, row, EnforcedStage).Established {
			t.Fatal("older broken record gained enforcing tick")
		}
	}
}

func TestOrdinaryLaunchLayoutsKeepRunAndObservationSeparate(t *testing.T) {
	tests := []struct {
		name, command, program, folder, observedFolder string
		uid                                            uint32
		related                                        bool
	}{
		{"PATH claude", "claude", "/usr/local/bin/claude", "/work", "/work", 1000, false},
		{"relative agent", "./agent", "/work/agent", "/work", "/work", 1000, false},
		{"python script.py", "python", "/usr/bin/python3", "/work", "/work", 1000, false},
		{"absolute Python script.py", "/usr/bin/python3", "/usr/bin/python3", "/work", "/work", 1000, true},
		{"node cli.js", "node", "/usr/bin/node", "/work", "/work", 1000, false},
		{"absolute Node cli.js", "/usr/bin/node", "/usr/bin/node", "/work", "/work", 1000, true},
		{"npx", "npx", "/usr/bin/node", "/work", "/work", 1000, false},
		{"symlinked program", "/usr/local/bin/agent", "/opt/agent/bin/agent", "/work", "/work", 1000, false},
		{"wrapper shell script", "/work/agent.sh", "/usr/bin/bash", "/work", "/work", 1000, false},
		{"symlinked folder", "/opt/agent", "/opt/agent", "/home/me/project", "/mnt/projects/one", 1000, false},
		{"container numeric uid", "/opt/agent", "/opt/agent", "/work", "/work", 65532, true},
	}
	matched, separate, cannotTell := 0, 0, 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, f := recorded(), observed()
			r.Command, r.Folder, r.UID = []string{tt.command}, tt.folder, tt.uid
			switch tt.name {
			case "python script.py", "absolute Python script.py":
				r.Command = append(r.Command, "script.py")
			case "node cli.js", "absolute Node cli.js":
				r.Command = append(r.Command, "cli.js")
			case "npx":
				r.Command = append(r.Command, "@example/agent")
			}
			r.Verification, r.Tier, r.Ended = Verified, "landlock", true
			f.Command, f.Folder, f.UID = tt.program, tt.observedFolder, tt.uid
			rows := Resolve([]Found{f}, []Run{r}, nil)
			if len(rows) != 2 {
				t.Fatalf("ordinary layout merged evidence: %+v", rows)
			}
			separate++
			for _, row := range rows {
				if len(row.Found) == 0 {
					continue
				}
				related := strings.Contains(stage(t, row, RecordedStage).CannotTell, "may be the same program")
				if row.NextStep == "" {
					t.Error("ordinary layout lacks next step")
				}
				if related != tt.related {
					t.Errorf("relationship=%t want %t: %+v", related, tt.related, row)
				}
				if related {
					matched++
				} else {
					cannotTell++
				}
			}
		})
	}
	if matched != 3 || separate != 11 || cannotTell != 8 {
		t.Fatalf("layout totals: matched=%d separate=%d cannot-tell=%d", matched, separate, cannotTell)
	}
	t.Logf("ordinary layouts: textual possible relation=%d, separate=%d, cannot tell relation=%d", matched, separate, cannotTell)
}
