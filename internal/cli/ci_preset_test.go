// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// These names carry CI authority or locate its services. Denying GITHUB_TOKEN is
// deliberate: even an explicit env.pass must not expose the receipt writer's token.
var ciDeniedEnv = []string{
	"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
	"ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL", "ACTIONS_CACHE_URL", "ACTIONS_RESULTS_URL",
	"ACTIONS_CACHE_SERVICE_V2", "GITHUB_TOKEN", "GH_TOKEN", "SIGSTORE_ID_TOKEN",
	"INPUT_TOKEN", "INPUT_GITHUB_TOKEN",
}

func ciContract(t *testing.T, extends, extra string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	for _, d := range []string{"src", ".github/workflows", ".github/actions/post", "extra"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// The contract is outside the project, so a broad write grant can be tested
	// without R10 refusing it for covering the contract itself.
	path := filepath.Join(t.TempDir(), "agent.yaml")
	body := "version: 0\nname: ci\nextends: " + extends + "\ncommand: [\"/bin/true\"]\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCIPresetCompileMerged(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	goldenDir, err := filepath.Abs(filepath.Join("testdata", "presets"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, extra, reason string }{
		{"ci", "", "on"},
		{"ci-off", "reason: {reads: off}\n", "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var latest string
			for _, ref := range []string{"tego/ci", "tego/ci@1"} {
				path := ciContract(t, ref, "fs:\n  write: [./src/]\n"+tc.extra)
				code, out, errs := run(t, "compile", path, "--offline", "--merged")
				if code != identity.ExitOK {
					t.Fatalf("%s: exit %d\n%s", ref, code, errs)
				}
				if !strings.Contains(out, "reason:\n  reads: \""+tc.reason+"\"\n") {
					t.Fatalf("reason.reads is not %s:\n%s", tc.reason, out)
				}
				if ref == "tego/ci" {
					latest = out
					continue
				}
				if out != strings.Replace(latest, "extends: tego/ci\n", "extends: tego/ci@1\n", 1) {
					t.Fatalf("the pin and newest revision merge differently:\n%s", out)
				}
				code, out, errs = run(t, "compile", path, "--offline")
				wantReason := "reads recorded at tier landlock (reason.reads: on)"
				if tc.reason == "off" {
					wantReason = "reason-reads-off (reason.reads: off)"
				}
				if code != identity.ExitOK || !strings.Contains(out, wantReason) {
					t.Fatalf("compiled read recording lacks %q: exit %d\n%s%s", wantReason, code, out, errs)
				}
			}
			golden := filepath.Join(goldenDir, tc.name+"-merged.golden")
			if *updateGolden {
				if err := os.WriteFile(golden, []byte(latest), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if latest != string(want) {
				t.Errorf("merged CI contract differs from %s:\n%s", golden, latest)
			}
		})
	}
}

func TestCIPresetKeepsDenialsAndGrants(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	for _, pass := range []string{"[]", "[" + strings.Join(ciDeniedEnv, ", ") + "]"} {
		t.Run(pass, func(t *testing.T) {
			path := ciContract(t, "tego/ci", "fs:\n  write: [./src/]\n  deny_write: [./extra/]\nnet: {allow: []}\nenv:\n  pass: "+pass+"\n  deny: [CUSTOM_STEP_TOKEN]\n")
			code, out, errs := run(t, "compile", path, "--offline", "--json")
			var table Table
			if code != identity.ExitOK || json.Unmarshal([]byte(out), &table) != nil {
				t.Fatalf("exit %d\n%s%s", code, out, errs)
			}
			for _, name := range append(slices.Clone(ciDeniedEnv), "CUSTOM_STEP_TOKEN") {
				if !slices.Contains(table.EnvDeny, name) {
					t.Errorf("%s is missing from env.deny: %v", name, table.EnvDeny)
				}
			}
			if pass != "[]" {
				for _, name := range ciDeniedEnv {
					if !strings.Contains(errs, "env.pass "+name+" is removed again by env.deny") {
						t.Errorf("passed denied name %s has no warning:\n%s", name, errs)
					}
				}
				if strings.Count(errs, "is removed again by env.deny [redundant-rule]") != len(ciDeniedEnv) {
					t.Errorf("want one redundant-rule warning per passed denied name:\n%s", errs)
				}
			}
			if pass == "[]" && (table.EnvPass == nil || len(table.EnvPass) != 0) {
				t.Errorf("preset widened the empty pass list: %v", table.EnvPass)
			}
			if table.NetUnrestricted || len(table.Net) != 0 {
				t.Errorf("preset widened the empty network allow list: %+v", table.Net)
			}
			code, out, errs = run(t, "compile", path, "--offline", "--merged")
			if code != identity.ExitOK || !strings.Contains(out, "    - ./extra/\n") || !strings.Contains(out, "    - ./.github/\n") {
				t.Errorf("preset lost a write refusal: exit %d\n%s%s", code, out, errs)
			}
		})
	}
	for _, name := range ciDeniedEnv {
		t.Run("set/"+name, func(t *testing.T) {
			path := ciContract(t, "tego/ci", "env:\n  deny: []\n  set: {"+name+": synthetic-canary}\n")
			code, out, errs := run(t, "compile", path, "--offline", "--merged")
			if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[contradiction]") {
				t.Errorf("env.set bypassed the preset: exit %d\n%s%s", code, out, errs)
			}
		})
	}
	t.Run("exact workflow write grant", func(t *testing.T) {
		path := ciContract(t, "tego/ci", "fs: {write: [./.github/]}\n")
		code, out, errs := run(t, "compile", path, "--offline", "--merged")
		if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "[contradiction]") {
			t.Fatalf("exact write grant bypassed the preset: exit %d\n%s%s", code, out, errs)
		}
	})
}

func TestCIPresetRefusesWorkflowWrites(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	for _, writes := range []string{"[./src/]", "[./]"} {
		t.Run(writes, func(t *testing.T) {
			path := ciContract(t, "tego/ci", "fs:\n  write: "+writes+"\n")
			if err := os.Symlink(".github", "workflow-alias"); err != nil {
				t.Fatal(err)
			}
			rows := `version: 0
tests:
  - {action: fs.write, path: src/result.txt, expect: allow}
  - {action: fs.write, path: .github/workflows/receipt.yml, expect: refused}
  - {action: fs.write, path: .github/actions/post/action.yml, expect: refused}
  - {action: fs.write, path: .github/new.yml, expect: refused}
  - {action: fs.write, path: workflow-alias/workflows/receipt.yml, expect: refused}
`
			if writes == "[./src/]" {
				rows += "  - {action: fs.write, path: unlisted.txt, expect: refused}\n"
			}
			if err := os.WriteFile("rows.yaml", []byte(rows), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "compile", path, "--offline", "--test", "rows.yaml", "--tier", "landlock", "--json")
			var rep TestReport
			if code != identity.ExitOK || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Rows) != strings.Count(rows, "- {action:") {
				t.Fatalf("exit %d\n%s%s", code, out, errs)
			}
			for _, row := range rep.Rows {
				if !row.Pass {
					t.Errorf("row failed: %+v", row)
				}
			}
		})
	}
}

// Profiles cannot require a path to exist (ADR 0071). This warning is a reason
// for the CI action to refuse launch; it must never be hidden as a clean compile.
func TestCIPresetMissingWorkflowDirectoryIsVisible(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	fixedEnviron(t) // no secret-env warning at the preset's env line from the caller's shell
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	for _, tc := range []struct {
		name, writes string
		warn         bool
	}{
		{"beneath write grant", "[./]", true},
		{"outside write grants", "[./src/]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := ciContract(t, "tego/ci", "fs: {write: "+tc.writes+"}\n")
			if err := os.RemoveAll(".github"); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "compile", path, "--offline", "--merged")
			if code != identity.ExitOK || out == "" {
				t.Fatalf("missing .github: exit %d\n%s%s", code, out, errs)
			}
			// The preset's own line: the contract's host_sockets line is [unenforced] too, at agent.yaml.
			warn := false
			for _, line := range strings.Split(errs, "\n") {
				if strings.Contains(line, "[unenforced]") && strings.Contains(line, "<builtin>/presets/v1/ci.yaml") {
					warn = true
				}
			}
			if warn != tc.warn {
				t.Fatalf("missing .github warning = %v, want %v:\n%s", warn, tc.warn, errs)
			}
		})
	}
}

func TestCIPresetIsListedInInitHelp(t *testing.T) {
	code, out, errs := run(t, "init", "--help")
	if code != identity.ExitOK || !strings.Contains(out+errs, "no-secrets, no-prod, repo-only-writes, ci") {
		t.Fatalf("CI is missing from init help: exit %d\n%s%s", code, out, errs)
	}
}

// A denial beneath a write grant needs a decision plane under kernel assurance.
// A deny outside every write/ask scope is redundant and is dropped before that check.
func TestCIPresetKernelAssuranceAtLandlock(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	for _, tc := range []struct {
		name, fs string
		code     int
	}{
		{"nested kernel denial", "write: [./]\n  assurance: kernel", identity.ExitFinding},
		{"outside writes", "write: [./src/]\n  assurance: kernel", identity.ExitOK},
		{"ask scope only", "write: [./src/]\n  ask: [./.github/]\n  assurance: kernel", identity.ExitOK},
		{"landlock pin alone", "write: [./]", identity.ExitOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := ciContract(t, "tego/ci", "tier: landlock\nfs:\n  "+tc.fs+"\n")
			code, out, errs := run(t, "compile", path, "--offline", "--merged")
			if code != tc.code {
				t.Fatalf("exit %d, want %d\n%s%s", code, tc.code, out, errs)
			}
			if tc.code == identity.ExitFinding && (out != "" || !strings.Contains(errs, "[unenforced]") ||
				!strings.Contains(errs, "fs.assurance: kernel needs a kernel decision plane") ||
				!strings.Contains(errs, "<builtin>/presets/v1/ci.yaml")) {
				t.Fatalf("nested denial did not explain the refusal:\n%s%s", out, errs)
			}
		})
	}
}

func TestCIPresetHyphenatedInputCannotBeDenied(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	path := ciContract(t, "tego/ci", "env: {deny: [INPUT_GITHUB-TOKEN]}\n")
	code, out, errs := run(t, "compile", path, "--offline", "--merged")
	// The entry is not a variable name, so it is called by its position and not echoed (identity envtext.go, (a)).
	if code != identity.ExitFinding || out != "" || !strings.Contains(errs, "env.deny.0: this entry is not an environment variable name") ||
		strings.Contains(errs, "INPUT_GITHUB-TOKEN") || !strings.Contains(errs, "^[A-Za-z_][A-Za-z0-9_]*$") {
		t.Fatalf("hyphenated input unexpectedly expressible in env.deny: exit %d\n%s%s", code, out, errs)
	}
}
