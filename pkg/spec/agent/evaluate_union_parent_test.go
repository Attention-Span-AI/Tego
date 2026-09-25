// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEvaluateNestedWriteUnderDenyRead: a write entry nested beneath an enforced deny_read carries the read
// set into its own subtree, and Landlock unions it with the target's access 0, so a read there succeeds.
// Evaluate answered refused at tier 1. Every tier now agrees: the root tiers' nearest-wins walk lets the
// nested write entry decide, and tier 1's union does the same. A read
// under the target but outside the nested entry is still refused everywhere.
func TestEvaluateNestedWriteUnderDenyRead(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "out", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	rt, _ := f.compile(f.load("version: 0\nname: nested\ncommand: [\"python\", \"agent.py\"]\nfs:\n  write: [\"out/sub/\"]\n  deny_read: [\"out/\"]\n"))
	p := func(rel string) string { return filepath.Join(f.project, rel) }
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		got := rt.Evaluate(Action{Kind: ActionFSRead, Path: p("out/sub/x")}, tier)
		if got.Verdict != VerdictAllow || got.Rule != "fs.write[out/sub/]" {
			t.Errorf("%s: read out/sub/x = %+v, want allow via fs.write[out/sub/]", tier, got)
		}
		got = rt.Evaluate(Action{Kind: ActionFSRead, Path: p("out/other")}, tier)
		if got.Verdict != VerdictRefused || got.Rule != "fs.deny_read[out/]" || got.Reason != record.ReasonReadDenied {
			t.Errorf("%s: read out/other = %+v, want refused by fs.deny_read[out/]", tier, got)
		}
	}
}

// TestEvaluateDeleteChecksParent: Landlock asks for REMOVE_FILE/REMOVE_DIR and REFER on the parent directory
// of the name removed or renamed, so a write entry's own path cannot be deleted or renamed away when nothing
// grants the directory above it. Evaluate answered allow. Tier 2 decides modifications with the same
// ruleset. Beneath the entry the parent is covered and it is allowed.
func TestEvaluateDeleteChecksParent(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.project, "report.md"), "r", 0o644)
	rt, _ := f.compile(f.load("version: 0\nname: parent\ncommand: [\"python\", \"agent.py\"]\nfs:\n  write: [\"out/\", \"report.md\"]\n"))
	p := func(rel string) string { return filepath.Join(f.project, rel) }
	cases := []struct {
		name    string
		action  Action
		verdict Verdict
		reason  record.Reason
	}{
		{"delete the write entry itself", Action{Kind: ActionFSDelete, Path: p("out")}, VerdictRefused, record.ReasonDeleteOutsideContract},
		{"delete a file entry itself", Action{Kind: ActionFSDelete, Path: p("report.md")}, VerdictRefused, record.ReasonDeleteOutsideContract},
		{"rename the write entry away", Action{Kind: ActionFSRename, Path: p("out"), DestPath: p("out/moved")}, VerdictRefused, record.ReasonRenameOutsideContract},
		{"rename onto a file entry", Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("report.md")}, VerdictRefused, record.ReasonRenameOutsideContract},
		{"delete beneath the entry", Action{Kind: ActionFSDelete, Path: p("out/a")}, VerdictAllow, ""},
		{"rename beneath the entry", Action{Kind: ActionFSRename, Path: p("out/a"), DestPath: p("out/b")}, VerdictAllow, ""},
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		for _, tc := range cases {
			got := rt.Evaluate(tc.action, tier)
			if got.Verdict != tc.verdict || got.Reason != tc.reason {
				t.Errorf("%s, %s: %+v, want %s %q", tier, tc.name, got, tc.verdict, tc.reason)
			}
		}
	}
}
