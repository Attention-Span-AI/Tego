// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

func TestLoadExplainsOwnStateLimit(t *testing.T) {
	want := []string{
		"protects the saved scan and the list of remembered programs against ordinary writes",
		"even when a run was allowed to use the whole home folder",
		"worked out from the code, not tested on a real machine",
		"The stages shown for a run do not depend on this list.",
		"This list never proves that nothing else is running.",
		"A program run by the same user outside Tego can change both the saved scan and the remembered programs",
		"Tego does not work out a caution for each run about this, so none is shown.",
	}
	for _, state := range []string{"a", "missing", "invalid", "stale"} {
		t.Run(state, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			f.PutScan(t, state)
			v := fixtureService(t, f).Load(t.Context(), guidetest.CheckTime.Add(time.Minute))
			for _, w := range want {
				if !strings.Contains(v.Footer, w) {
					t.Fatalf("footer lacks own-state limit %q: %s", w, v.Footer)
				}
			}
			for _, bad := range []string{"landlock", "guest row", "anchor", "owner state"} {
				if strings.Contains(v.Footer, bad) {
					t.Fatalf("footer keeps the technical word %q: %s", bad, v.Footer)
				}
			}
		})
	}
}

func TestLoadUnsafeStateShowsRepairAndKeepsRecordedRows(t *testing.T) {
	for _, target := range []string{"scan/last.json", "agents/discoveries.json", "agents"} {
		for _, damage := range []string{"000", "0644", "link"} {
			t.Run(target+"/"+damage, func(t *testing.T) {
				f := guidetest.Make(t, guidetest.Finished)
				f.PutScan(t, "a")
				s := fixtureService(t, f)
				now := guidetest.CheckTime.Add(time.Minute)
				before := s.Load(t.Context(), now)
				recorded := func(v View) map[string]agentid.Agent {
					out := make(map[string]agentid.Agent)
					for _, row := range v.Rows {
						if row.Agent.RunID != "" {
							out[row.Agent.RunID] = row.Agent
						}
					}
					return out
				}
				want := recorded(before)
				if len(want) != len(f.Runs) || len(want) == 0 {
					t.Fatalf("fixture lacks every recorded row: %d / %d", len(want), len(f.Runs))
				}
				path := filepath.Join(f.Home, ".tego", target)
				mode := os.FileMode(0600)
				if target == "agents" {
					mode = 0700
				}
				switch damage {
				case "link":
					if err := os.Rename(path, path+".target"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+".target", path); err != nil {
						t.Fatal(err)
					}
				default:
					changed := os.FileMode(0)
					if damage == "0644" {
						changed = 0644
					}
					if err := os.Chmod(path, changed); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						if err := os.Chmod(path, mode); err != nil {
							t.Error(err)
						}
					})
				}
				damaged, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				got := s.Load(t.Context(), now)
				if !reflect.DeepEqual(recorded(got), want) {
					t.Fatalf("unsafe %s changed recorded rows", target)
				}
				notice := got.DiscoveryNotice
				if target == "scan/last.json" {
					notice = got.ScanNotice
					if got.ScanStatus != "unreadable" {
						t.Fatalf("unsafe scan status = %q", got.ScanStatus)
					}
				}
				for _, part := range []string{"could not be read", "mode", "link", "~/.tego/" + target, "tego scan"} {
					if !strings.Contains(notice, part) {
						t.Errorf("warning lacks %q: %s", part, notice)
					}
				}
				if damage == "link" {
					if !strings.Contains(notice, "Move") {
						t.Errorf("link repair missing: %s", notice)
					}
				} else if repair := fmt.Sprintf("chmod %o ~/.tego/%s", mode, target); !strings.Contains(notice, repair) {
					t.Errorf("mode repair %q missing: %s", repair, notice)
				}
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(damaged, after) || damaged.Mode() != after.Mode() {
					t.Fatal("reading the page changed the unsafe state")
				}
			})
		}
	}
}
