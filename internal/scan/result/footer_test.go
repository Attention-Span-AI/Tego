// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestVerboseSourceStates(t *testing.T) {
	s := Snapshot{Mode: "basic", Status: "partial", Check: "unknown", Sources: []Source{
		{ID: "read", Kind: "D", Locator: Path("/fixtures/read.json"), State: "read", Read: 1, Reason: "none"},
		{ID: "missing", Kind: "D", Locator: Path("/fixtures/missing.json"), State: "missing", Reason: "none"},
		{ID: "failed", Kind: "D", Locator: Path("/fixtures/bad.json"), State: "not-read", NotRead: 1, Reason: "syntax"},
		{ID: "partial", Kind: "E", Locator: Path("/fixtures/units"), State: "partial", Read: 1, NotRead: 1, Reason: "limit"},
	}}
	var out bytes.Buffer
	if err := Render(&out, &bytes.Buffer{}, s, false, true, nil); err != nil {
		t.Fatal(err)
	}
	var sourceLines strings.Builder
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, "Source ") {
			sourceLines.WriteString(line + "\n")
		}
	}
	want, err := os.ReadFile("testdata/verbose-sources.golden")
	if err != nil {
		t.Fatal(err)
	}
	if sourceLines.String() != string(want) {
		t.Fatalf("source rows:\n%s\nwant:\n%s", sourceLines.String(), want)
	}
}

func TestUnitCoverageNamesOmittedDefaultRoots(t *testing.T) {
	words := exclusionWords("unresolved-units")
	for _, path := range []string{"/etc/xdg/systemd/user", "/usr/local/lib/systemd/user", "/usr/share/systemd/user", "/usr/local/share/systemd/user", "~/.config/systemd/user.control"} {
		if !strings.Contains(words, path) {
			t.Errorf("unit exclusion omits default root %s", path)
		}
	}
}

func TestPartialSourcesDoNotPrintNegativeMatch(t *testing.T) {
	for _, source := range []Source{
		{ID: "unit", Kind: "E", Locator: Path("/fixtures/expand.service"), State: "not-read", NotRead: 1, Reason: "unresolved"},
		{ID: "settings", Kind: "D", Locator: Path("/fixtures/settings.json"), State: "not-read", NotRead: 1, Reason: "syntax"},
	} {
		t.Run(source.Kind, func(t *testing.T) {
			s := Snapshot{Status: "partial", Mode: "basic", Check: "none-observed", Sources: []Source{source}}
			var out, errs bytes.Buffer
			if err := Render(&out, &errs, s, false, false, nil); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String()+errs.String(), "No match") {
				t.Fatal("negative summary undercuts unresolved source: " + out.String())
			}
			if !strings.Contains(errs.String(), "Source "+source.ID) {
				t.Fatal("partial source warning lost")
			}
		})
	}
}

func TestUnresolvedUnitSourceContract(t *testing.T) {
	b, err := os.ReadFile("../../../spec/scan/v1/fixtures/configured.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	s.Status, s.Check = "partial", "none-observed"
	s.Sources = append(s.Sources, Source{ID: "unresolved-unit", Kind: "E", Locator: Path("/fixtures/expand.service"), State: "not-read", NotRead: 1, Reason: "unresolved"})
	b, err = Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(b); err != nil {
		t.Fatalf("unresolved unit source rejected: %v", err)
	}
	var out bytes.Buffer
	if err = Footer(&out, s, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"/fixtures/expand.service": not-read; read 0, not read 1; reason unresolved; could not be determined`) {
		t.Fatal("unresolved unit name and uncertainty missing: " + out.String())
	}
}

func TestClaudeLocalScopeContract(t *testing.T) {
	b, err := os.ReadFile("../../../spec/scan/v1/fixtures/configured.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	s.Items[0].Name = "claude"
	s.Items[0].Evidence[0].RuleID = "mcp-claude"
	v := s.Items[0].Config()
	v.Client, v.Scope, v.Path = "claude", "local", Path("/home/example/.claude.json")
	s.Items[0].Detail = Detail(v)
	s.Sources[0].Locator = v.Path
	b, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(b); err != nil {
		t.Fatalf("Claude local scope rejected: %v", err)
	}
	v.Client = "codex"
	s.Items[0].Name, s.Items[0].Evidence[0].RuleID = "codex", "mcp-codex"
	s.Items[0].Detail = Detail(v)
	b, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(b); err == nil {
		t.Fatal("local scope accepted for another client")
	}
}

// The CLI and the Agents page word the scan's limits from one table, so a code cannot get one wording without the other.
func TestFooterWordsCoverEveryCode(t *testing.T) {
	src, err := os.ReadFile("decode.go")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`const exclusions = "([^"]+)"`).FindSubmatch(src)
	if m == nil {
		t.Fatal("decoder's exclusion list not found")
	}
	codes := strings.Split(string(m[1]), "|")
	seen := map[string]string{}
	for _, code := range codes {
		w, ok := exclusionTable[code]
		if !ok || w.plain == "" {
			t.Errorf("exclusion %q has no plain wording", code)
			continue
		}
		if other, dup := seen[w.plain]; dup {
			t.Errorf("%q and %q share the wording %q", code, other, w.plain)
		}
		seen[w.plain] = code
		for _, tech := range []string{"uid", "pid", "cgroup", "NSS", "systemd", "XDG", "/etc", "/run", "/usr", "MCP", "unit", "cron", "(not read)", "(unresolved)", "namespace", "argv", "fd "} {
			if strings.Contains(w.plain, tech) {
				t.Errorf("plain wording of %q uses the technical word %q: %s", code, tech, w.plain)
			}
		}
	}
	if len(exclusionTable) != len(codes) {
		t.Errorf("table has %d codes, the decoder %d", len(exclusionTable), len(codes))
	}
	// the operator wording the CLI prints is unchanged
	if got := exclusionWords("project-parents"); got != "project parent folders (not walked)" {
		t.Errorf("CLI wording changed: %s", got)
	}
	if got := exclusionWords("remote-agents"); got != "remote-agents" {
		t.Errorf("a code without operator wording prints itself: %s", got)
	}
}

func TestPlainFooterSaysWhatEachLineMeans(t *testing.T) {
	s := New(time.Now(), 1000, "x")
	s.Status, s.Check = "partial", "unreadable-observed"
	s.Rules = []Rule{{ID: "R1", Name: "claude"}, {ID: "R2", Name: "codex"}}
	s.Sources = []Source{{ID: "a", Kind: "A", State: "read", Read: 4}, {ID: "b", Kind: "D", Locator: Path("/home/u/.claude.json"), State: "not-read", NotRead: 1, Reason: "mode"}}
	s.Counts.Exited, s.Counts.KernelThreads, s.Counts.UnreadablePrograms = 1, 2, 1
	s.UnreadableProgramPIDs = []int{3130}
	s.Limits = []string{"deadline"}
	p := PlainFooter(s)
	all := strings.Join(p.Lines, "\n")
	for _, want := range []string{
		"This scan looked at your own programs only.",
		"It found no agent running outside Tego, but some of your programs could not be checked.",
		"It looked for these agents: claude, codex.",
		"It read 4 places and could not read 1.",
		"1 program ended while the scan ran, so it was not checked. 2 tasks that belong to the operating system were left out; they are not agents.",
		"1 of your programs does not let its file be read (process numbers 3130). Tego cannot tell whether these are agents; any program can make itself unreadable.",
		`Could not read "/home/u/.claude.json". Other users are allowed to change it, so Tego will not trust it. Remove write access for the group and for everyone else. Tego cannot tell whether these are agents.`,
		"The scan stopped early, so the rest is unknown.",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("plain footer lacks %q in:\n%s", want, all)
		}
	}
	for _, bad := range []string{"Scope:", "uid ", "status ", "check ", "Sources:", "R1", "pids:", "chmod", "reason "} {
		if strings.Contains(all, bad) {
			t.Errorf("plain footer keeps operator wording %q", bad)
		}
	}
	if len(p.NotLooked) != len(s.Exclusions) {
		t.Errorf("%d not-looked-at lines for %d codes", len(p.NotLooked), len(s.Exclusions))
	}
	// the CLI footer is untouched
	var b bytes.Buffer
	if err := Footer(&b, s, false); err != nil || !strings.Contains(b.String(), "Scope: basic uid 1000; status partial; check unreadable-observed.") {
		t.Errorf("CLI footer changed: %v\n%s", err, b.String())
	}
}
