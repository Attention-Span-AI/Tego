// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

func TestMissingRecordRequiresEvidence(t *testing.T) {
	for _, evidence := range []string{"cached", "cached empty", "cached directory removed", "last refusal", "chain", "configured chain", "no surviving evidence", "new empty"} {
		t.Run(evidence, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "runs")
			id := "r-aaaaaaaa-0000000000002-harmxx"
			if evidence == "new empty" {
				if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				writeRun(t, root, id, line(id, "agent", 0, time.Now(), "ask", `"ask_id":"waiting","hold":"exec"`), line(id, "agent", 1, time.Now(), "refused", `"op":"exec","target":"curl"`))
			}
			if evidence == "cached empty" {
				if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			s := Open(root)
			if strings.HasPrefix(evidence, "cached") {
				if _, err := s.Snapshot(); err != nil {
					t.Fatal(err)
				}
			}
			if evidence == "last refusal" {
				if err := os.WriteFile(filepath.Join(root, id, ledger.LastRefusalFile), []byte(`{"seq":1}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if evidence == "chain" || evidence == "configured chain" {
				anchor := ledger.DefaultAnchorPath(filepath.Join(root, id))
				if evidence == "configured chain" {
					anchor = filepath.Join(t.TempDir(), "chosen-chain.log")
					s.SetAnchor(anchor)
				}
				if err := ledger.NewFileChainAnchor(anchor).Append(id, fmt.Sprintf("%064x", 2)); err != nil {
					t.Fatal(err)
				}
			}
			if evidence == "cached directory removed" {
				if err := os.RemoveAll(filepath.Join(root, id)); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(filepath.Join(root, id, "events.jsonl")); err != nil && !(evidence == "new empty" && os.IsNotExist(err)) {
				t.Fatal(err)
			}
			snap, err := s.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if evidence == "new empty" || evidence == "no surviving evidence" {
				if snap.ReadError != "" || len(snap.Runs) != 0 {
					t.Fatalf("new empty run: %+v", snap)
				}
				return
			}
			if !strings.Contains(snap.ReadError, "its record file is missing") {
				t.Fatalf("known record source became an empty run: %+v", snap)
			}
			r := snap.Find(id)
			if r == nil || !strings.Contains(r.ReadError, "its record file is missing") {
				t.Fatalf("recorded run disappeared: %+v", r)
			}
			if strings.HasPrefix(evidence, "cached") && evidence != "cached empty" && (r.Refusals != 1 || len(r.Pending) != 1) {
				t.Fatalf("lost the known prefix: %+v", r)
			}
			r, err = s.Run(id)
			if err != nil || r == nil || r.ReadError == "" {
				t.Fatalf("run page hid read failure: %v %v", r, err)
			}
		})
	}
}

func TestForeignAnchorCannotInventRunInAnotherRoot(t *testing.T) {
	id := "r-aaaaaaaa-0000000000002-harmxx"
	anchor := filepath.Join(t.TempDir(), "shared-chain.log")
	if err := ledger.NewFileChainAnchor(anchor).Append(id, fmt.Sprintf("%064x", 2)); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	s := Open(root)
	s.SetAnchor(anchor)
	if r, err := s.Run(id); !os.IsNotExist(err) {
		t.Fatalf("foreign anchor invented a run in this root: %+v %v", r, err)
	}
	snap, err := s.Snapshot()
	if err != nil || len(snap.Runs) != 0 {
		t.Fatalf("foreign run polluted snapshot: %+v %v", snap, err)
	}
}

func TestColdIndexedChainKeepsMissingRun(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, unreadable := range []bool{false, true} {
			t.Run(fmt.Sprintf("direct=%v/unreadable=%v", direct, unreadable), func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "runs")
				id := "r-aaaaaaaa-0000000000002-harmxx"
				if err := os.MkdirAll(filepath.Join(root, ".live"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, ".live", id), nil, 0600); err != nil {
					t.Fatal(err)
				}
				anchor := filepath.Join(t.TempDir(), "chain.log")
				if err := ledger.NewFileChainAnchor(anchor).Append(id, fmt.Sprintf("%064x", 2)); err != nil {
					t.Fatal(err)
				}
				if unreadable {
					if err := os.Remove(anchor); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(anchor, 0700); err != nil {
						t.Fatal(err)
					}
				}
				store := Open(root)
				store.SetAnchor(anchor)
				var run *Run
				if direct {
					var err error
					run, err = store.Run(id)
					if err != nil {
						t.Fatalf("indexed chain evidence lost the missing run: %v", err)
					}
				} else {
					snap, err := store.Snapshot()
					if err != nil {
						t.Fatal(err)
					}
					if snap.TotalRuns != 1 {
						t.Fatalf("indexed chain evidence shrank the run count: %d", snap.TotalRuns)
					}
					run = snap.Find(id)
				}
				if run == nil || !strings.Contains(run.ReadError, "its record file is missing") {
					t.Fatal("indexed chain evidence became an empty run")
				}
				if unreadable && !strings.Contains(run.ReadError, "could not check chain evidence") {
					t.Fatal("unreadable chain became positive recorded-line evidence")
				}
				before, err := store.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				after, err := store.Snapshot()
				if err != nil {
					t.Fatal(err)
				}
				if before.Rev != after.Rev || before.TotalRuns != after.TotalRuns {
					t.Fatal("unchanged indexed source failure churned its candidate or revision")
				}
			})
		}
	}
}
