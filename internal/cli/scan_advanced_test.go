// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan"
	"github.com/attention-span-ai/tego/internal/scan/catalog"
	"github.com/attention-span-ai/tego/internal/scan/result"
	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
)

const advancedCanary = "ADVANCED_VALUE_CANARY_64"

// fixtureAdvancedCommand keeps kernel privilege changes behind CLI seams. The
// source parser tests exercise root source acquisition; this fixture exercises
// the resulting typed data through Main, output, privilege drop and storage.
func fixtureAdvancedCommand(t *testing.T) (scan.Options, func(context.Context, scan.Options) scan.Outcome) {
	t.Helper()
	o, _ := fixtureScanCommand(t)
	for name, content := range map[string]string{
		"advanced.service":                 "[Service]\nEnvironment=TOKEN=" + advancedCanary + "\nExecStart=/usr/bin/codex --token " + advancedCanary + "\n",
		"advanced.service.d/override.conf": "[Unit]\nDescription=" + advancedCanary + "\n[Service]\nEnvironment=TOKEN=" + advancedCanary + "\nExecStart=\nExecStart=/usr/bin/codex --token " + advancedCanary + "\n",
		"advanced.timer":                   "[Timer]\nUnit=advanced.service\nOnCalendar=" + advancedCanary + "\n",
	} {
		path := filepath.Join(o.Directory, ".config/systemd/user", name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, content)
	}
	oldCollect, oldPrivileged, oldDrop, oldSave := scanCollect, scanPrivileged, scanDrop, scanSave
	t.Cleanup(func() {
		scanCollect, scanPrivileged, scanDrop, scanSave = oldCollect, oldPrivileged, oldDrop, oldSave
	})
	collect := func(ctx context.Context, requested scan.Options) scan.Outcome {
		basic := requested
		basic.Advanced = false
		got := scan.Collect(ctx, basic)
		if !requested.Advanced {
			return got
		}
		s := &got.Snapshot
		advanced := result.NewAdvanced(s.Started, 0, uint32(os.Getuid()), s.Tego)
		s.Mode, s.Catalog, s.As, s.Exclusions = advanced.Mode, advanced.Catalog, advanced.As, advanced.Exclusions
		unitSources := map[string]bool{}
		for n, item := range s.Items {
			switch item.Kind {
			case "process":
				p := item.Process()
				if p.Container == nil {
					v := result.Detail(result.Container{Runtime: "docker", ID: strings.Repeat("abcdef01", 8)})
					p.Container = &v
					s.Items[n].Detail = result.Detail(p)
					s.Items[n].Caveats = append(s.Items[n].Caveats, "container-hint")
					s.Items[n].Evidence = append(s.Items[n].Evidence, result.Evidence{RuleID: item.Evidence[0].RuleID, SourceID: item.Evidence[0].SourceID, Fact: "cgroup"})
				}
			case "user_unit", "timer":
				v := item.Unit()
				v.UID = nil
				v.Path = result.Path("/etc/systemd/system/" + v.Name)
				s.Items[n].Detail = result.Detail(v)
				if item.Kind == "user_unit" {
					s.Items[n].Kind = "system_unit"
				}
				for _, evidence := range item.Evidence {
					unitSources[evidence.SourceID] = true
					for j := range s.Sources {
						if s.Sources[j].ID == evidence.SourceID {
							s.Sources[j].Locator = v.Path
						}
					}
				}
			}
		}
		for n := range s.Sources {
			if unitSources[s.Sources[n].ID] {
				s.Sources[n].Kind = "system"
			}
		}
		s.Counts.SystemUnits, s.Counts.Units = s.Counts.Units, 0
		uid := uint32(os.Getuid())
		cronPath := result.Path("/etc/cron.d/advanced")
		sourceID := fmt.Sprintf("source-%d", len(s.Sources)+1)
		s.Sources = append(s.Sources, result.Source{ID: sourceID, Kind: "cron", Locator: cronPath, State: "read", Read: 1, Reason: "none"})
		s.Rules = append(s.Rules, result.Rule{ID: "cron-codex", Name: "codex", Origin: "catalog"})
		s.Items = append(s.Items, result.Item{ID: fmt.Sprintf("item-%d", len(s.Items)+1), Kind: "cron", Name: "codex", Evidence: []result.Evidence{{RuleID: "cron-codex", SourceID: sourceID, Fact: "cron-command"}}, Detail: result.Detail(result.Cron{Path: cronPath, UID: &uid, Program: result.Path("codex-native")}), Caveats: []string{"configured-only"}})
		s.Counts.Cron++
		if requested.BeforeRecipient != nil {
			if err := requested.BeforeRecipient(got.Snapshot.As.Recipient, got.GID); err != nil {
				got.Snapshot.AddFailure("result", "privilege")
				return got
			}
		}
		return got
	}
	scanCollect = collect
	scanPrivileged = func() bool { return true }
	return o, collect
}

func advancedSeed(t *testing.T, o scan.Options, collect func(context.Context, scan.Options) scan.Outcome) []byte {
	t.Helper()
	o.Advanced, o.Rows = true, catalog.Rows()
	outcome := collect(context.Background(), o)
	if err := result.Save(outcome.Home, outcome.Snapshot.As.Recipient, outcome.Snapshot); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(o.Directory, ".tego/scan/last.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func scanAdvancedChannels(t *testing.T, out, errs string, saved []byte) {
	t.Helper()
	log, err := os.ReadFile(filepath.Join(testHome, ".tego/tego.log"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, channel := range []string{out, errs, string(saved), string(log)} {
		if strings.Contains(channel, advancedCanary) || strings.Contains(channel, scanCanary) {
			t.Fatal("canary in stdout, stderr, saved result or isolated own log")
		}
	}
}

func TestScanAdvancedEveryOutputChannel(t *testing.T) {
	t.Setenv("TEGO_HINTS", "off")
	for _, tc := range []struct {
		name  string
		args  []string
		check bool
		json  bool
	}{
		{"short", nil, false, false},
		{"verbose", []string{"-v"}, false, false},
		{"json", []string{"--json"}, false, true},
		{"all mine", []string{"--all-mine", "-v"}, false, false},
		{"check", []string{"--check"}, true, false},
		{"json check", []string{"--json", "--check"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, collect := fixtureAdvancedCommand(t)
			before := advancedSeed(t, o, collect)
			cache := filepath.Join(o.Directory, ".tego/scan/last.json")
			checkBeforeDrop := openTripwire(t, []string{filepath.Join(o.Directory, ".tego"), filepath.Dir(cache)})
			events := []string{}
			scanDrop = func(uid, gid uint32) error {
				checkBeforeDrop()
				if uid != uint32(os.Getuid()) || gid != 42 {
					t.Fatalf("drop to %d:%d", uid, gid)
				}
				events = append(events, "drop")
				return nil
			}
			scanSave = func(home string, uid uint32, s result.Snapshot) error {
				if len(events) != 1 || events[0] != "drop" {
					t.Fatal("destination opened before privilege drop")
				}
				events = append(events, "save")
				return result.Save(home, uid, s)
			}
			args := append([]string{"scan", "--advanced"}, tc.args...)
			code, out, errs := run(t, args...)
			want := 0
			if tc.check {
				want = 1
			}
			if code != want {
				t.Fatalf("exit %d: %s %s", code, out, errs)
			}
			if tc.check {
				if strings.Join(events, ",") != "drop" {
					t.Fatal("check must drop privilege without saving")
				}
				checkBeforeDrop()
			} else if strings.Join(events, ",") != "drop,save" {
				t.Fatalf("drop/save sequence %v", events)
			}
			saved, err := os.ReadFile(cache)
			if err != nil {
				t.Fatal(err)
			}
			if tc.check && !bytes.Equal(before, saved) {
				t.Fatal("check changed prior result")
			}
			scanAdvancedChannels(t, out, errs, saved)
			s, err := result.Decode(saved)
			if err != nil || s.Mode != "advanced" || s.Counts.SystemUnits != 2 || s.Counts.Cron != 1 {
				t.Fatalf("advanced result: %+v %v", s.Counts, err)
			}
			if !strings.Contains(errs, "cgroup suggestions only") || !strings.Contains(errs, "Not looked at:") {
				t.Fatal("advanced footer missing")
			}
			if tc.json {
				if _, err = result.Decode([]byte(out)); err != nil {
					t.Fatal(err)
				}
				var wire any
				if err = json.Unmarshal([]byte(out), &wire); err != nil {
					t.Fatal(err)
				}
				if err = jsonschema.Check("../../spec/scan/v1/schema.json", wire); err != nil {
					t.Fatal(err)
				}
				if !tc.check && !bytes.Equal([]byte(out), saved) {
					t.Fatal("JSON stdout differs from saved advanced result")
				}
			} else {
				for _, row := range []string{"System unit:", "System timer:", "Cron entry:", "Container cgroup suggestion:"} {
					if !strings.Contains(out, row) {
						t.Fatalf("missing %s", row)
					}
				}
			}
		})
	}
}

func TestScanAdvancedDropFailureDoesNotOpenDestination(t *testing.T) {
	o, collect := fixtureAdvancedCommand(t)
	before := advancedSeed(t, o, collect)
	cache := filepath.Join(o.Directory, ".tego/scan/last.json")
	checkNoOpen := openTripwire(t, []string{filepath.Join(o.Directory, ".tego"), filepath.Dir(cache), cache})
	dropped := false
	scanDrop = func(uint32, uint32) error {
		checkNoOpen()
		dropped = true
		return errors.New(advancedCanary)
	}
	scanSave = func(string, uint32, result.Snapshot) error {
		t.Fatal("save called after failed privilege drop")
		return nil
	}
	code, out, errs := run(t, "scan", "--advanced", "--json")
	if code != 125 || !dropped || !strings.Contains(errs, "could not drop privilege") {
		t.Fatalf("drop refusal %d %s %s", code, out, errs)
	}
	checkNoOpen()
	saved, err := os.ReadFile(cache)
	if err != nil || !bytes.Equal(before, saved) {
		t.Fatal("drop failure changed prior result")
	}
	scanAdvancedChannels(t, out, errs, saved)
	s, err := result.Decode([]byte(out))
	if err != nil || s.Mode != "advanced" || s.Status != "failed" {
		t.Fatalf("failure result lost scope: %v", err)
	}
	found := false
	for _, source := range s.Sources {
		found = found || source.Kind == "result" && source.Reason == "privilege" && source.State == "not-read"
	}
	if !found {
		t.Fatal("drop failure missing fixed result-source reason")
	}
}

func TestScanAdvancedUnprivilegedRefusesBeforeInputs(t *testing.T) {
	o, _ := fixtureScanCommand(t)
	oldPrivileged, oldInputs, oldCollect := scanPrivileged, scanInputs, scanCollect
	t.Cleanup(func() { scanPrivileged, scanInputs, scanCollect = oldPrivileged, oldInputs, oldCollect })
	scanPrivileged = func() bool { return false }
	inputs, collections := 0, 0
	scanInputs = func() scan.Options { inputs++; return o }
	scanCollect = func(ctx context.Context, requested scan.Options) scan.Outcome {
		collections++
		return scan.Collect(ctx, requested)
	}
	for _, args := range [][]string{{"--advanced"}, {"--advanced", "--json", "--check"}} {
		code, out, errs := run(t, append([]string{"scan"}, args...)...)
		if code != 125 || inputs != 0 || collections != 0 || !strings.Contains(errs, "--advanced needs root in the initial user namespace") || !strings.Contains(errs, "use tego scan for your own processes") || !strings.Contains(errs, "Not looked at:") {
			t.Fatalf("early refusal %d %s %s; inputs %d collections %d", code, out, errs, inputs, collections)
		}
		if strings.Contains(strings.Join(args, " "), "--json") {
			s, err := result.Decode([]byte(out))
			if err != nil || s.Mode != "advanced" || len(s.Items) != 0 {
				t.Fatalf("advanced refusal JSON: %v", err)
			}
		}
	}
	code, out, errs := run(t, "scan", "--check")
	if code != 1 || inputs != 1 || collections != 1 {
		t.Fatalf("ordinary scan stopped working: %d %s %s", code, out, errs)
	}
}

func TestScanAdvancedLateFailureKeepsScopeAndDropsValues(t *testing.T) {
	for _, failure := range []string{"panic", "invalid result"} {
		t.Run(failure, func(t *testing.T) {
			o, collect := fixtureAdvancedCommand(t)
			before := advancedSeed(t, o, collect)
			cache := filepath.Join(o.Directory, ".tego/scan/last.json")
			checkNoOpen := openTripwire(t, []string{filepath.Dir(cache), cache})
			scanCollect = func(ctx context.Context, requested scan.Options) scan.Outcome {
				got := collect(ctx, requested)
				if failure == "panic" {
					panic(advancedCanary)
				}
				got.Snapshot.Counts.Cron++
				return got
			}
			scanDrop = func(uint32, uint32) error { return nil }
			scanSave = func(string, uint32, result.Snapshot) error {
				t.Fatal("failed collection attempted save")
				return nil
			}
			code, out, errs := run(t, "scan", "--advanced", "--json")
			if code != 125 || strings.Contains(out+errs, "scan-not-performed") || strings.Contains(out+errs, "Read: none") {
				t.Fatalf("late failure report %d %s %s", code, out, errs)
			}
			checkNoOpen()
			saved, err := os.ReadFile(cache)
			if err != nil || !bytes.Equal(before, saved) {
				t.Fatal("late collection failure changed prior result")
			}
			scanAdvancedChannels(t, out, errs, saved)
			s, err := result.Decode([]byte(out))
			if err != nil || s.Mode != "advanced" || s.Status != "failed" || len(s.Items) != 0 {
				t.Fatalf("late failure lost advanced scope: %v", err)
			}
		})
	}
}

func TestScanAdvancedRecipientConfigAfterDrop(t *testing.T) {
	for _, check := range []bool{false, true} {
		t.Run(map[bool]string{false: "save", true: "check"}[check], func(t *testing.T) {
			o, _ := fixtureAdvancedCommand(t)
			writeTestFile(t, filepath.Join(o.ProcRoot, "20/cgroup"), "0::"+agentsRunCG+"\n")
			dropped, loaded := false, false
			scanDrop = func(uint32, uint32) error { dropped = true; return nil }
			scanLedgerRoot = func(home string, uid uint32) (string, error) {
				if !dropped {
					t.Fatal("recipient config loaded before privilege drop")
				}
				loaded = true
				return filepath.Join(home, "runs"), nil
			}
			args := []string{"scan", "--advanced", "--json"}
			if check {
				args = append(args, "--check")
			}
			code, out, errs := run(t, args...)
			if !dropped || !loaded || code == 125 {
				t.Fatalf("drop/config sequence: dropped=%t loaded=%t exit=%d %s %s", dropped, loaded, code, out, errs)
			}
		})
	}
}

func TestScanAdvancedRecordDiagnosticsKeepPartialEvidenceAtSourceLimit(t *testing.T) {
	for _, priorLimit := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior-limit-%t", priorLimit), func(t *testing.T) {
			o, collect := fixtureAdvancedCommand(t)
			scanDrop = func(uint32, uint32) error { return nil }
			scanCollect = func(ctx context.Context, requested scan.Options) scan.Outcome {
				got := collect(ctx, requested)
				s := &got.Snapshot
				var template result.Item
				for _, item := range s.Items {
					if item.Kind == "process" {
						template = item
						break
					}
				}
				if template.Kind == "" {
					t.Fatal("missing process fixture")
				}
				s.Items = nil
				s.Counts = result.Counts{}
				for n := 0; n < 64; n++ {
					item := template
					item.ID = fmt.Sprintf("item-%d", n+1)
					p := item.Process()
					p.PID, p.PPID, p.Membership = 1000+n, 0, "in-run"
					p.RunID = result.Path(fmt.Sprintf("r-0a1b2c3d-0123456789abc-%06d", n))
					item.Detail = result.Detail(p)
					s.Items = append(s.Items, item)
				}
				s.Counts.Running, s.Counts.InRun = 64, 64
				if priorLimit {
					s.Limits = append(s.Limits, "source-limit")
					s.Status = "partial"
				}
				for len(s.Sources) < 2020 {
					s.Sources = append(s.Sources, result.Source{ID: fmt.Sprintf("source-%d", len(s.Sources)+1), Kind: "meta", State: "read", Reason: "none"})
				}
				if _, err := result.Encode(*s); err != nil {
					t.Fatal("invalid capacity fixture", err)
				}
				return got
			}
			code, out, errs := run(t, "scan", "--advanced", "--json")
			if code != 0 {
				t.Fatalf("capacity discarded observations: exit%d %s", code, errs)
			}
			s, err := result.Decode([]byte(out))
			if err != nil || s.Status != "partial" || s.Counts.Running != 64 || len(s.Items) != 64 {
				t.Fatalf("partial evidence lost: items%d counts%+v status%s err%v", len(s.Items), s.Counts, s.Status, err)
			}
			if len(s.Sources) > 2030 {
				t.Fatalf("unbounded record diagnostics: %d", len(s.Sources))
			}
			last := s.Sources[len(s.Sources)-1]
			if last.Kind != "meta" || last.Reason != "limit" || last.Locator != nil {
				t.Fatalf("unknown record remainder missing: %+v", last)
			}
			saved, err := os.ReadFile(filepath.Join(o.Directory, ".tego/scan/last.json"))
			if err != nil || !bytes.Equal(saved, []byte(out)) {
				t.Fatal("partial result not saved", err)
			}
		})
	}
}

func TestScanAdvancedInvalidLedgerLocatorKeepsEvidence(t *testing.T) {
	for name, root := range map[string]string{"long": "/" + strings.Repeat("x", 4096), "control": "/PRIVATE_LEDGER_PATH_CANARY\nprivate", "invalid UTF-8": "/private\xff"} {
		t.Run(name, func(t *testing.T) {
			o, _ := fixtureAdvancedCommand(t)
			writeTestFile(t, filepath.Join(o.ProcRoot, "20/cgroup"), "0::"+agentsRunCG+"\n")
			scanDrop = func(uint32, uint32) error { return nil }
			scanLedgerRoot = func(string, uint32) (string, error) { return root, nil }
			code, out, errs := run(t, "scan", "--advanced", "--json")
			if code != 0 {
				t.Fatalf("invalid ledger path erased observations: exit%d %s", code, errs)
			}
			s, err := result.Decode([]byte(out))
			if err != nil || s.Status != "partial" || s.Counts.Running == 0 {
				t.Fatalf("evidence lost: %+v %v", s.Counts, err)
			}
			last := s.Sources[len(s.Sources)-1]
			if last.Kind != "meta" || last.State != "not-read" || last.Locator != nil || last.Reason != "syntax" {
				t.Fatalf("invalid locator not reduced to fixed diagnostic: %+v", last)
			}
			if strings.Contains(out+errs, "PRIVATE_LEDGER_PATH_CANARY") {
				t.Fatal("invalid path content retained")
			}
		})
	}
}
