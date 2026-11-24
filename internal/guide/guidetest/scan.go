// SPDX-License-Identifier: Apache-2.0

package guidetest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

// ScanCases exercises the saved-file states through all guide surfaces.
var ScanCases = []string{"missing", "a", "b", "stale", "another-boot", "zero", "partial", "systemd-login", "partial-b", "partial-zero", "partial-limit", "failed", "unknown-boot", "forged-user", "invalid", "future", "settings-only", "project-only", "foreign-recipient", "wrong-mode"}

// PutScan writes fixture state to the actual reader's location, including invalid
// files a legitimate Save refuses. It returns whether the guide may tick find.
func (f *Fixture) PutScan(t testing.TB, state string) bool {
	t.Helper()
	dir := filepath.Join(f.Home, ".tego", "scan")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "last.json")
	if state == "missing" {
		if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
			t.Fatal(e)
		}
		return false
	}
	s := result.New(CheckTime, uint32(os.Getuid()), "dev")
	s.Status = "ok"
	s.Boot = result.Path(BootID)
	s.Rules = []result.Rule{{ID: "claude-native", Name: "claude", Origin: "catalog"}}
	source := result.Source{ID: "source-1", Kind: "A", State: "read", Read: 1, Reason: "none"}
	s.Counts.Running = 1
	s.Counts.Outside = 1
	s.Items = []result.Item{{ID: "item-1", Kind: "process", Name: "claude", Evidence: []result.Evidence{{RuleID: "claude-native", SourceID: "source-1", Fact: "exe-name"}}, Caveats: []string{"name-collision"}, Detail: result.Detail(result.Process{UID: uint32(os.Getuid()), PID: 10, PPID: 1, Start: "100", Exe: result.Path("/bin/claude"), Membership: "outside-run"})}}
	eligible := state == "a" || state == "b" || state == "partial" || state == "systemd-login" || state == "partial-b" || state == "partial-limit"
	switch state {
	case "b", "partial-b":
		s.Counts.Running = 0
		s.Counts.Outside = 0
		s.Counts.Installed = 1
		source.Kind = "B"
		source.Locator = result.Path("/bin/claude")
		s.Items[0].Kind = "program"
		s.Items[0].Evidence[0].Fact = "path"
		tm := CheckTime
		s.Items[0].Detail = result.Detail(result.File{Path: source.Locator, Mtime: &tm, Type: "executable"})
		if state == "partial-b" {
			s.Status = "partial"
			s.Sources = append(s.Sources, result.Source{ID: "source-2", Kind: "F", Locator: result.Path("/project/requirements.txt"), State: "not-read", NotRead: 1, Reason: "syntax"})
		}
	case "stale":
		s.Started = s.Started.Add(-24 * time.Hour)
		s.Finished = s.Started
	case "another-boot":
		s.Boot = result.Path("01234567-89ab-cdef-0123-456789abcdef")
	case "zero", "partial-zero":
		s.Counts = result.Counts{}
		s.Items = []result.Item{}
		if state == "partial-zero" {
			s.Status = "partial"
			s.Sources = append(s.Sources, result.Source{ID: "source-2", Kind: "F", Locator: result.Path("/project/requirements.txt"), State: "not-read", NotRead: 1, Reason: "syntax"})
		}
	case "partial":
		s.Status = "partial"
		s.Sources = append(s.Sources, result.Source{ID: "source-2", Kind: "F", Locator: result.Path("/project/requirements.txt"), State: "not-read", NotRead: 1, Reason: "syntax"})
	case "systemd-login":
		// Model the measured login: a readable Claude alongside systemd --user's
		// EACCES exe link. No hidden program name is retained in the saved scan.
		s.Status = "partial"
		s.Counts.UnreadablePrograms = 1
		s.UnreadableProgramPIDs = []int{3130}
		s.Sources = append(s.Sources, result.Source{ID: "source-2", Kind: "A", State: "unreadable-program", NotRead: 1, Reason: "permission"})
	case "partial-limit":
		s.Status = "partial"
		s.Limits = []string{"source-limit"}
		s.Sources = append(s.Sources, result.Source{ID: "source-2", Kind: "B", State: "not-read", NotRead: 1, Reason: "limit"})
	case "failed":
		s.Status = "failed"
	case "unknown-boot":
		s.Boot = nil
	case "forged-user":
		p := s.Items[0].Process()
		p.UID++
		s.Items[0].Detail = result.Detail(p)
	case "foreign-recipient":
		s.As.Recipient++
	case "future":
		s.Finished = CheckTime.Add(100 * 365 * 24 * time.Hour)
	case "settings-only":
		s.Counts = result.Counts{Settings: 1}
		source.Kind = "C"
		source.Locator = result.Path("/home/me/.claude")
		s.Items[0].Kind = "settings"
		s.Items[0].Evidence[0].Fact = "settings-path"
		tm := CheckTime
		s.Items[0].Detail = result.Detail(result.File{Path: source.Locator, Mtime: &tm, Type: "directory"})
		s.Items[0].Caveats = []string{"settings-only"}
	case "project-only":
		s.Counts = result.Counts{Project: 1}
		s.Rules = []result.Rule{{ID: "dep-langgraph", Name: "langgraph", Origin: "catalog"}}
		source.Kind = "F"
		source.Locator = result.Path("/home/me/requirements.txt")
		s.Items[0].Kind = "project"
		s.Items[0].Name = "langgraph"
		s.Items[0].Evidence[0].RuleID = "dep-langgraph"
		s.Items[0].Evidence[0].Fact = "dependency"
		s.Items[0].Detail = result.Detail(result.Project{Path: source.Locator, Dependency: result.Path("dep-langgraph")})
		s.Items[0].Caveats = []string{"declaration-only"}
	}
	s.Sources = append(s.Sources, source)
	if state != "invalid" && state != "forged-user" && state != "foreign-recipient" {
		if _, e := result.Encode(s); e != nil {
			t.Fatalf("invalid %s fixture: %v", state, e)
		}
	}
	b, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	if state == "invalid" {
		b = []byte(`{"command":"touch /bad"}`)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	if state == "wrong-mode" {
		if e = os.Chmod(path, 0644); e != nil {
			t.Fatal(e)
		}
	} else {
		if e = os.Chmod(path, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return eligible
}
