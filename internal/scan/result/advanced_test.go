// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func advancedExample(t testing.TB) Snapshot {
	t.Helper()
	b, err := os.ReadFile("../../../spec/scan/v1/fixtures/advanced.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAdvancedContractRoundTrip(t *testing.T) {
	s := advancedExample(t)
	if s.Counts.Units != 2 || s.Counts.SystemUnits != 2 || s.Counts.Cron != 1 {
		t.Fatalf("counts: %+v", s.Counts)
	}
	for _, runtime := range []string{"docker", "podman", "containerd"} {
		t.Run(runtime, func(t *testing.T) {
			p := s.Items[0].Process()
			v := Detail(Container{Runtime: runtime, ID: strings.Repeat("abcdef01", 8)})
			p.Container = &v
			s.Items[0].Detail = Detail(p)
			b, err := Encode(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Decode(b); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdvancedCronSharesUnitProgramIDs(t *testing.T) {
	for _, tc := range []struct{ name, program string }{
		{"claude", "claude-native"}, {"claude", "claude-node"},
		{"codex", "codex-native"}, {"codex", "codex-node"},
		{"opencode", "opencode-native"}, {"opencode", "opencode-node"},
		{"gemini", "gemini-native"}, {"gemini", "gemini-node-bin"}, {"gemini", "gemini-node-dist"},
	} {
		t.Run(tc.program, func(t *testing.T) {
			s := advancedExample(t)
			s.Items[8].Name = tc.name
			s.Items[8].Evidence[0].RuleID = "cron-" + tc.name
			s.Rules[len(s.Rules)-1] = Rule{ID: "cron-" + tc.name, Name: tc.name, Origin: "catalog"}
			v := s.Items[8].Cron()
			v.Program = Path(tc.program)
			s.Items[8].Detail = Detail(v)
			if _, err := Encode(s); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdvancedDecoderRejectsInvalidScopeAndEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Snapshot)
	}{
		{"unprivileged collection", func(s *Snapshot) { s.As.UID, s.As.Root = 1000, false }},
		{"root claim missing", func(s *Snapshot) { s.As.Root = false }},
		{"old catalog", func(s *Snapshot) { s.Catalog = "c3" }},
		{"basic scope", func(s *Snapshot) { s.Mode, s.As.Recipient = "basic", 0 }},
		{"other uid G", func(s *Snapshot) { p := s.Items[3].Process(); p.UID = 1001; s.Items[3].Detail = Detail(p) }},
		{"user unit without uid", func(s *Snapshot) { v := s.Items[4].Unit(); v.UID = nil; s.Items[4].Detail = Detail(v) }},
		{"system unit with uid", func(s *Snapshot) {
			v := s.Items[6].Unit()
			uid := uint32(0)
			v.UID = &uid
			s.Items[6].Detail = Detail(v)
		}},
		{"system timer as user count", func(s *Snapshot) { s.Counts.SystemUnits--; s.Counts.Units++ }},
		{"system evidence from user source", func(s *Snapshot) { s.Sources[6].Kind = "E" }},
		{"cron count", func(s *Snapshot) { s.Counts.Cron++ }},
		{"cron source kind", func(s *Snapshot) { s.Sources[8].Kind = "E" }},
		{"cron fact", func(s *Snapshot) { s.Items[8].Evidence[0].Fact = "exec-start" }},
		{"cron rule", func(s *Snapshot) { s.Items[8].Evidence[0].RuleID = "unit-codex" }},
		{"cron path disagrees", func(s *Snapshot) {
			v := s.Items[8].Cron()
			v.Path = Path("/etc/cron.d/different")
			s.Items[8].Detail = Detail(v)
		}},
		{"cron uid missing", func(s *Snapshot) { v := s.Items[8].Cron(); v.UID = nil; s.Items[8].Detail = Detail(v) }},
		{"cron program is command", func(s *Snapshot) {
			v := s.Items[8].Cron()
			v.Program = Path("codex --token=secret-canary")
			s.Items[8].Detail = Detail(v)
		}},
		{"cron wrapper unsupported", func(s *Snapshot) {
			v := s.Items[8].Cron()
			v.Program = Path("shell-codex")
			s.Items[8].Detail = Detail(v)
		}},
		{"container no caveat", func(s *Snapshot) { s.Items[0].Caveats = []string{} }},
		{"container no cgroup evidence", func(s *Snapshot) { s.Items[0].Evidence = s.Items[0].Evidence[:1] }},
		{"container unsupported runtime", func(s *Snapshot) {
			p := s.Items[0].Process()
			v := Detail(Container{Runtime: "secret-canary", ID: strings.Repeat("a", 64)})
			p.Container = &v
			s.Items[0].Detail = Detail(p)
		}},
		{"container short id", func(s *Snapshot) {
			p := s.Items[0].Process()
			v := Detail(Container{Runtime: "docker", ID: strings.Repeat("a", 12)})
			p.Container = &v
			s.Items[0].Detail = Detail(p)
		}},
		{"container uppercase id", func(s *Snapshot) {
			p := s.Items[0].Process()
			v := Detail(Container{Runtime: "docker", ID: strings.Repeat("A", 64)})
			p.Container = &v
			s.Items[0].Detail = Detail(p)
		}},
		{"container unknown membership", func(s *Snapshot) {
			p := s.Items[0].Process()
			p.Membership = "unknown"
			s.Items[0].Detail = Detail(p)
			s.Status = "partial"
			s.Counts.Outside--
			s.Counts.Unknown++
			s.Sources = append(s.Sources, Source{ID: "a-gap", Kind: "A", State: "not-read", NotRead: 1, Reason: "permission"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := advancedExample(t)
			tc.edit(&s)
			b, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Decode(b)
			if !errors.Is(err, ErrInvalid) || got.Schema != "" {
				t.Fatalf("invalid object was retained: %v", err)
			}
		})
	}
}

func TestAdvancedRejectsCommandValueCanaries(t *testing.T) {
	const canary = "VALUE_CANARY_MUST_NOT_SURVIVE"
	s := advancedExample(t)
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ old, replacement string }{
		{`"runtime":"podman"`, `"runtime":"podman","token":"` + canary + `"`},
		{`"program":"codex-native"`, `"program":"codex-native","command":"` + canary + `"`},
		{`"program":"codex-native"`, `"program":"codex-native","schedule":"` + canary + `"`},
		{`"program":"codex-native"`, `"program":"codex-native","environment":{"TOKEN":"` + canary + `"}`},
	} {
		mut := bytes.Replace(b, []byte(tc.old), []byte(tc.replacement), 1)
		if bytes.Equal(mut, b) {
			t.Fatal("canary mutation did not apply")
		}
		got, err := Decode(mut)
		if err == nil || strings.Contains(err.Error(), canary) || got.Schema != "" {
			t.Fatalf("canary reached decoder result or diagnostic: %v", err)
		}
	}
}

func TestAdvancedRenderScopeAndLimits(t *testing.T) {
	s := advancedExample(t)
	for _, mode := range []string{"short", "verbose", "json"} {
		t.Run(mode, func(t *testing.T) {
			var out, errs bytes.Buffer
			if err := Render(&out, &errs, s, mode == "json", mode == "verbose", nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(errs.String(), "all users'") || !strings.Contains(errs.String(), "cgroup suggestions only") || !strings.Contains(errs.String(), "Result recipient uid 1000") {
				t.Fatal("advanced footer lost scope or container uncertainty: " + errs.String())
			}
			if mode == "json" {
				if _, err := Decode(out.Bytes()); err != nil {
					t.Fatal(err)
				}
				return
			}
			for _, want := range []string{"all users:", "cover recipient uid 1000 only", "observed uid 1001", "User unit:", "System unit:", "System timer:", "Cron entry:", "Container cgroup suggestion:", "runtime identity not checked", "uid 1002", "schedule and command omitted", "loaded state and firing time not checked"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q in %s", want, out.String())
				}
			}
			if strings.Contains(out.String(), "No match") {
				t.Fatal("advanced evidence printed a negative match summary")
			}
		})
	}
}

func TestAdvancedRefusalRetainsActualIdentityWithoutReads(t *testing.T) {
	s := NewAdvanced(example(t).Finished, 1000, 1000, "dev")
	s.Exclusions = append(s.Exclusions, "scan-not-performed")
	s.AddFailure("advanced", "privilege")
	if _, err := Encode(s); err != nil {
		t.Fatal(err)
	}
	s.Sources[0].Read = 1
	if _, err := Encode(s); err == nil {
		t.Fatal("unprivileged advanced refusal retained a read")
	}
}

func TestAdvancedSourceFailuresKeepProcessCheck(t *testing.T) {
	for _, kind := range []string{"system", "cron"} {
		s := NewAdvanced(example(t).Finished, 0, 1000, "dev")
		s.Boot = example(t).Boot
		s.Status, s.Check = "partial", "none-observed"
		s.Sources = []Source{{ID: "a", Kind: "A", State: "read", Read: 1, Reason: "none"}, {ID: "unresolved", Kind: kind, Locator: Path("/etc/example"), State: "not-read", NotRead: 1, Reason: "unresolved"}}
		if _, err := Encode(s); err != nil {
			t.Fatal(err)
		}
		if s.ExitCode() != 0 {
			t.Fatal("metadata failure changed process check")
		}
		var footer bytes.Buffer
		if err := Footer(&footer, s, false); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(footer.String(), "could not be read") {
			t.Fatal("unreadable source not disclosed")
		}
	}
}

func TestAdvancedExclusionsAndBasicCompatibility(t *testing.T) {
	s := NewAdvanced(example(t).Finished, 0, 1000, "dev")
	for _, absent := range []string{"other-users", "system-units", "containers-unattributed"} {
		if slices.Contains(s.Exclusions, absent) {
			t.Fatalf("advanced excluded selected scope %s", absent)
		}
	}
	for _, present := range []string{"other-user-settings", "unresolved-units", "unresolved-cron", "container-patterns", "unknown-names", "between-scans", "libraries", "remote-agents"} {
		if !slices.Contains(s.Exclusions, present) {
			t.Fatalf("advanced omitted exclusion %s", present)
		}
	}
	for _, fixture := range []string{"basic.json", "project.json", "configured.json"} {
		b, err := os.ReadFile("../../../spec/scan/v1/fixtures/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(b); err != nil {
			t.Fatalf("lost %s compatibility: %v", fixture, err)
		}
	}
}

func TestAdvancedFooterNamesOmittedSystemUnitRoots(t *testing.T) {
	s := advancedExample(t)
	var out bytes.Buffer
	if err := Footer(&out, s, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early", "/run/systemd/generator", "/run/systemd/generator.late", "/etc/systemd/system.attached", "/run/systemd/system.attached", "/usr/local/lib/systemd/system"} {
		if !strings.Contains(out.String(), path) {
			t.Errorf("advanced footer omits excluded system root %s", path)
		}
	}
}
