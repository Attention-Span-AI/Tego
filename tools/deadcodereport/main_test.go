// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	servePath = "github.com/attention-span-ai/tego/internal/serve"
	askPath   = "github.com/attention-span-ai/tego/internal/runtime/ask"
)

// writeProfile writes one profile's status and raw JSON.
func writeProfile(t *testing.T, dir, profile string, status int, packages []pkg) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, profile+".status"), []byte(strconv.Itoa(status)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(packages)
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		data = nil
	}
	if err := os.WriteFile(filepath.Join(dir, profile+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// reportFixture: every profile finds serve.Serve (classified) and ask.UnexpectedDeadAsk (not classified).
func reportFixture(t *testing.T, allowText string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	allow := filepath.Join(dir, "allow.txt")
	if err := os.WriteFile(allow, []byte(allowText), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		writeProfile(t, dir, p, 0, []pkg{
			{Path: servePath, Funcs: []function{{Name: "Serve", Position: position{File: "internal/serve/serve.go", Line: 10}}}},
			{Path: askPath, Funcs: []function{{Name: "UnexpectedDeadAsk", Position: position{File: "internal/runtime/ask/ask.go", Line: 20}}}},
		})
	}
	return dir, allow
}

const serveAllowed = servePath + ".Serve\tplaceholder\tADR 0015 deferred server\n"

// TestProfilesAreTheFourTagSetsOnBothArchitectures: plain, integration, tegobpf and both, on amd64 and arm64.
func TestProfilesAreTheFourTagSetsOnBothArchitectures(t *testing.T) {
	want := []string{
		"linux-amd64-plain", "linux-amd64-integration", "linux-amd64-tegobpf", "linux-amd64-integration-tegobpf",
		"linux-arm64-plain", "linux-arm64-integration", "linux-arm64-tegobpf", "linux-arm64-integration-tegobpf",
	}
	if strings.Join(profiles[:], " ") != strings.Join(want, " ") {
		t.Fatalf("profiles = %v; want %v", profiles, want)
	}
}

func TestReportRetainsClassifiedAndUnclassifiedFindings(t *testing.T) {
	dir, allow := reportFixture(t, serveAllowed)
	data, problems, err := render(dir, allow)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"2 unreachable functions (1 classified, 1 unclassified)", "serve.Serve` —", "placeholder: ADR 0015 deferred server", "ask.UnexpectedDeadAsk` —", "ask.go:20` (UNCLASSIFIED)"} {
		if strings.Count(string(data), text) != len(profiles) {
			t.Errorf("report missing per-profile %q: %s", text, data)
		}
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "unclassified "+askPath+".UnexpectedDeadAsk") {
		t.Fatalf("problems = %q; want the one unclassified function", problems)
	}
}

// TestRatchet: the gate fails on an unclassified finding in any one profile, on an unavailable profile and
// on a classification no profile finds; it passes when every finding is classified.
func TestRatchet(t *testing.T) {
	askAllowed := serveAllowed + askPath + ".UnexpectedDeadAsk\ttest-api\tfixture\n"
	t.Run("classified passes", func(t *testing.T) {
		dir, allow := reportFixture(t, askAllowed)
		data, problems, err := render(dir, allow)
		if err != nil || len(problems) != 0 {
			t.Fatalf("problems %q, err %v", problems, err)
		}
		if !strings.Contains(string(data), "Ratchet: PASS") {
			t.Fatalf("report does not say PASS: %s", data)
		}
	})
	t.Run("unclassified in one profile fails", func(t *testing.T) {
		dir, allow := reportFixture(t, askAllowed)
		writeProfile(t, dir, "linux-arm64-integration", 0, []pkg{
			{Path: servePath, Funcs: []function{{Name: "Serve", Position: position{File: "internal/serve/serve.go", Line: 10}}}},
			{Path: askPath, Funcs: []function{{Name: "UnexpectedDeadAsk", Position: position{File: "internal/runtime/ask/ask.go", Line: 20}}, {Name: "bridge", Position: position{File: "internal/runtime/ask/bridge.go", Line: 3}}}},
		})
		data, problems, err := render(dir, allow)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 1 || !strings.Contains(problems[0], "unclassified "+askPath+".bridge (linux-arm64-integration)") {
			t.Fatalf("problems = %q", problems)
		}
		if !strings.Contains(string(data), "Ratchet: FAIL") {
			t.Fatalf("report does not say FAIL: %s", data)
		}
	})
	t.Run("unavailable profile fails", func(t *testing.T) {
		dir, allow := reportFixture(t, askAllowed)
		writeProfile(t, dir, "linux-amd64-tegobpf", 124, nil)
		data, problems, err := render(dir, allow)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 1 || !strings.Contains(problems[0], "linux-amd64-tegobpf unavailable (tool exit 124)") {
			t.Fatalf("problems = %q", problems)
		}
		if !strings.Contains(string(data), "Unavailable (tool exit 124)") || strings.Count(string(data), "2 unreachable functions") != len(profiles)-1 {
			t.Fatalf("unavailable row: %s", data)
		}
	})
	t.Run("stale classification fails", func(t *testing.T) {
		dir, allow := reportFixture(t, askAllowed+servePath+".Gone\tplaceholder\tdeleted since\n")
		_, problems, err := render(dir, allow)
		if err != nil {
			t.Fatal(err)
		}
		if len(problems) != 1 || !strings.Contains(problems[0], "stale "+servePath+".Gone") {
			t.Fatalf("problems = %q", problems)
		}
	})
}

func TestSuccessMustBeReadableAndEveryProfilePresent(t *testing.T) {
	dir, allow := reportFixture(t, serveAllowed)
	if err := os.WriteFile(filepath.Join(dir, profiles[0]+".json"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := render(dir, allow); err == nil {
		t.Fatal("successful empty output accepted")
	}
	dir, allow = reportFixture(t, serveAllowed)
	if err := os.Remove(filepath.Join(dir, profiles[1]+".status")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := render(dir, allow); err == nil {
		t.Fatal("missing configuration accepted")
	}
}

func TestClassificationIsExactAndHasClassAndReason(t *testing.T) {
	for _, input := range []string{
		servePath + "\tplaceholder\tpackage-level form is gone",
		"github.com/attention-span-ai/tego/internal/*.Serve\tplaceholder\tx",
		servePath + ".Serve\tplaceholder\t",
		servePath + ".Serve\tplaceholder",
		servePath + ".Serve\tdead\tunknown class",
		"example.com/other.Serve\tplaceholder\tx",
		servePath + ".Serve\tplaceholder\tx\n" + servePath + ".Serve\tpublic-api\ty",
		// public-api is claimed only under pkg/: nothing outside this module can import internal/.
		servePath + ".Serve\tpublic-api\tno other module can import internal/",
	} {
		path := filepath.Join(t.TempDir(), "allow")
		if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := classifications(path); err == nil {
			t.Fatalf("accepted classification %q", input)
		}
	}
	path := filepath.Join(t.TempDir(), "allow")
	if err := os.WriteFile(path, []byte("# comment\n\n"+servePath+".FD.Close\tpending\tADR 0023\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := classifications(path)
	if err != nil || got[servePath+".FD.Close"].class != "pending" {
		t.Fatalf("method classification = %v, %v", got, err)
	}
	// Every class the allow file uses parses, each on the kind of path it may be claimed for.
	const specPath = "github.com/attention-span-ai/tego/pkg/spec/agent"
	every := specPath + ".Endpoint.Static\tpublic-api\tpkg/ API\n" +
		servePath + ".Fake\ttest-api\tinternal/cli tests\n" +
		servePath + ".Project\ttool-only\ttools/adoptiongen\n" +
		servePath + ".Fold\tcontrol-only\tinternal/control/rules\n" +
		servePath + ".T.UnmarshalJSON\treflection\tencoding/json through Usage\n" +
		servePath + ".Bridge\ttag-only\tintegration bridge\n"
	if err := os.WriteFile(path, []byte(every), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := classifications(path); err != nil || len(got) != 6 {
		t.Fatalf("every class = %v, %v", got, err)
	}
}

// TestRepositoryAllowFileParses: the checked-in classifications are well formed.
func TestRepositoryAllowFileParses(t *testing.T) {
	if _, err := classifications("../deadcode-allow.txt"); err != nil {
		t.Fatal(err)
	}
}

// TestGateExitStatus: the command's exit status is the gate. With one unclassified finding it exits 1
// under -gate and 0 without, and prints the ratchet problem on stderr in both modes; a clean report
// exits 0 either way; bad usage exits 2. Every run that reads the fixture writes report.md.
func TestGateExitStatus(t *testing.T) {
	const askAllowed = askPath + ".UnexpectedDeadAsk\tplaceholder\tADR 0015 deferred ask\n"
	cases := []struct {
		name    string
		allow   string
		gate    bool
		want    int
		problem bool
	}{
		{"unclassified, gated", serveAllowed, true, 1, true},
		{"unclassified, report only", serveAllowed, false, 0, true},
		{"clean, gated", serveAllowed + askAllowed, true, 0, false},
		{"clean, report only", serveAllowed + askAllowed, false, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, allow := reportFixture(t, c.allow)
			args := []string{"-dir", dir, "-allow", allow}
			if c.gate {
				args = append(args, "-gate")
			}
			var stderr strings.Builder
			if got := run(args, &stderr); got != c.want {
				t.Fatalf("run(%q) = %d; want %d (stderr %q)", args, got, c.want, stderr.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "report.md")); err != nil {
				t.Fatalf("report.md not written: %v", err)
			}
			printed := strings.Contains(stderr.String(), "deadcode ratchet: unclassified "+askPath+".UnexpectedDeadAsk")
			if printed != c.problem {
				t.Fatalf("stderr %q: ratchet problem printed = %v; want %v", stderr.String(), printed, c.problem)
			}
		})
	}
	for _, args := range [][]string{nil, {"-dir", t.TempDir()}, {"-dir", "d", "-allow", "a", "extra"}, {"-nosuchflag"}} {
		var stderr strings.Builder
		if got := run(args, &stderr); got != 2 {
			t.Errorf("run(%q) = %d; want 2 (usage)", args, got)
		}
	}
}
