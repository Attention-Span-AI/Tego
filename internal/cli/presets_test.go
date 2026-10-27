// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// presetContract writes agent.yaml extending names into a fresh project directory, with the folders and host a
// contract under the presets names, and changes into it.
func presetContract(t *testing.T, extends string) string {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("src", 0o755); err != nil {
		t.Fatal(err)
	}
	body := "version: 0\nname: presets\nextends: " + extends + "\ncommand: [\"true\"]\nfs:\n  write: [./src/]\nnet:\n  allow: [\"127.0.0.1:8080\"]\n"
	if err := os.WriteFile("agent.yaml", []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return "agent.yaml"
}

// TestPresetCombinationsCompile: each preset loads and compiles, by its name and by its revision pin, alone and in
// all seven non-empty combinations, through the CLI's one profile source (profileSources registers the presets),
// with no error and no warning a preset caused.
func TestPresetCombinationsCompile(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	all := presets.List()
	for mask := 1; mask < 1<<len(all); mask++ {
		var names, pinned []string
		for i, p := range all {
			if mask&(1<<i) != 0 {
				names = append(names, p.Ref())
				pinned = append(pinned, p.Pinned(1))
			}
		}
		for _, list := range [][]string{names, pinned} {
			extends := "[" + strings.Join(list, ", ") + "]"
			t.Run(extends, func(t *testing.T) {
				f := presetContract(t, extends)
				code, _, errs := run(t, "compile", f, "--offline")
				if code != identity.ExitOK || strings.Contains(errs, "error:") || strings.Contains(errs, "<builtin>") {
					t.Fatalf("exit %d\n%s", code, errs)
				}
			})
		}
	}
}

// TestUnknownPresetListsTheKnownOnes: an unknown preset, or a revision that does not exist, is extends-not-found at
// its line, and the fix lists every preset name and pin the binary has.
func TestUnknownPresetListsTheKnownOnes(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	for _, name := range []string{"tego/no-secret", "tego/no-prod@2"} {
		f := presetContract(t, name)
		code, _, errs := run(t, "compile", f, "--offline")
		want := "the built-in profiles are tego/no-prod, tego/no-prod@1, tego/no-secrets, tego/no-secrets@1, tego/repo-only-writes, tego/repo-only-writes@1"
		if code != identity.ExitFinding || !strings.Contains(errs, "agent.yaml:3:") || !strings.Contains(errs, "[extends-not-found]") || !strings.Contains(errs, want) {
			t.Errorf("%s: exit %d\n%s", name, code, errs)
		}
	}
}

// TestPresetsPageExampleReachesItsModel: the contract docs/user/presets.md offers, copied verbatim, compiles with
// no error and keeps its harness's model reachable under the presets it extends: it declares the model under
// models: (with no entry no forwarder starts, and tego/no-prod refuses the model like any other host), the run
// captures through the forwarder, and env.pass names the provider's key, which tego/no-secrets would otherwise keep
// out. Review F1: the page's example declared no model and passed no key, so Claude Code under it reached nothing.
func TestPresetsPageExampleReachesItsModel(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	page, err := os.ReadFile(filepath.Join("..", "..", "docs", "user", "presets.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, block, ok := strings.Cut(string(page), "```yaml\n")
	block, _, closed := strings.Cut(block, "```")
	if !ok || !closed || !strings.Contains(block, "extends: [tego/no-secrets, tego/no-prod, tego/repo-only-writes]") {
		t.Fatalf("the page's first yaml block is not the three-preset example:\n%s", block)
	}
	// The example's command is claude, which a CI runner or a restricted PATH does not hold: a stand-in on PATH.
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Chdir(t.TempDir())
	for _, d := range []string{"src", "tests"} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("agent.yaml", []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}
	code, merged, errs := run(t, "compile", "agent.yaml", "--offline", "--merged")
	if code != identity.ExitOK || strings.Contains(errs, "error:") {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	if !strings.Contains(merged, "\nmodels:\n") || !strings.Contains(merged, "host: api.anthropic.com") {
		t.Errorf("the example declares no model, so no forwarder starts and tego/no-prod refuses it:\n%s", merged)
	}
	code, js, errs := run(t, "compile", "agent.yaml", "--offline", "--json")
	var table Table
	if code != identity.ExitOK || json.Unmarshal([]byte(js), &table) != nil {
		t.Fatalf("--json: exit %d\n%s", code, errs)
	}
	// The example pins no capture, so auto resolves to the highest this build reaches: forwarder in a build of tier
	// landlock alone, uprobe in a tegobpf build that reaches the root tiers, where the forwarder still starts beside the
	// probes and sets the model's base URL (capture.Select; agent's forwarding: uprobe reached through auto). Either way
	// the model is reached through the forwarder.
	if (table.Capture != "forwarder" && table.Capture != "uprobe") || !slices.Contains(table.EnvPass, "ANTHROPIC_API_KEY") || table.NetUnrestricted {
		t.Errorf("capture %s, env_pass %v, net_unrestricted %v", table.Capture, table.EnvPass, table.NetUnrestricted)
	}
}

// TestPresetAndItsPinMergeOnce: a contract naming a preset both by name and by its pin to the revision that name
// is, every preset so, merges each file once and gets one redundant-rule warning per second name, at its line in
// agent.yaml; none points into a built-in file, which the user cannot edit (it printed one warning per repeated
// entry inside <builtin>, 26 for the three presets).
func TestPresetAndItsPinMergeOnce(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	f := presetContract(t, "[tego/repo-only-writes, tego/repo-only-writes@1, tego/no-prod, tego/no-prod@1, tego/no-secrets, tego/no-secrets@1]")
	code, merged, errs := run(t, "compile", f, "--offline", "--merged")
	if code != identity.ExitOK || strings.Contains(errs, "<builtin>") || strings.Count(errs, "[redundant-rule]") != 3 ||
		strings.Count(errs, "agent.yaml:3:") != 3 || strings.Count(merged, "    - PATH\n") != 1 || strings.Count(merged, "/dev/null") != 1 {
		t.Errorf("exit %d\n%s%s", code, merged, errs)
	}
}

// TestCompileMerged: compile --merged prints the merged canonical contract, every preset laid in, which is the one
// rule file a run records as contract.yaml: its sha256 is the contract_hash compile --json reports, and it is held
// to the golden file. --merged is a way to print, so --json, --test and --exec beside it are usage errors.
func TestCompileMerged(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	golden, err := filepath.Abs(filepath.Join("testdata", "presets", "merged.golden"))
	if err != nil {
		t.Fatal(err)
	}
	f := presetContract(t, "[tego/no-secrets, tego/no-prod, tego/repo-only-writes@1]")
	code, out, errs := run(t, "compile", f, "--offline", "--merged")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	code, js, errs := run(t, "compile", f, "--offline", "--json")
	if code != identity.ExitOK {
		t.Fatalf("--json: exit %d\n%s", code, errs)
	}
	var table struct {
		ContractHash string `json:"contract_hash"`
	}
	if err := json.Unmarshal([]byte(js), &table); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256([]byte(out)); hex.EncodeToString(sum[:]) != table.ContractHash || table.ContractHash == "" {
		t.Errorf("sha256 of --merged %x, contract_hash %s", sum, table.ContractHash)
	}
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Errorf("--merged drifted from %s:\ngot:\n%s\nwant:\n%s", golden, out, want)
	}
	for _, extra := range [][]string{{"--json"}, {"--test", "t.yaml"}, {"--exec", "ls"}} {
		code, _, errs := run(t, append([]string{"compile", f, "--merged"}, extra...)...)
		if code != identity.ExitUsage || !strings.Contains(errs, "--merged") {
			t.Errorf("--merged %v: exit %d\n%s", extra, code, errs)
		}
	}
	// A contract that does not compile prints no rule file.
	if err := os.WriteFile("bad.yaml", []byte("version: 0\nname: bad\nextends: tego/none\ncommand: [\"true\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := run(t, "compile", "bad.yaml", "--offline", "--merged"); code != identity.ExitFinding || out != "" {
		t.Errorf("a contract that does not load: exit %d, printed %q", code, out)
	}
}

// TestPresetsAloneRefuse: a contract that writes no net:, fs: or env: of its own gets each preset's whole rule
// from the preset, so nothing the test contract states can stand in for the preset's. Under tego/no-prod the merged
// contract carries net: {} and its table refuses a connect and a datagram to any host (a net: section with no
// entry, SEMANTICS §1; were the section dropped, every IP would be allowed); under tego/repo-only-writes every write
// but /dev/null is refused; under tego/no-secrets env.pass is the preset's allow-list alone. Each preset is checked
// alone and with the other two, by name and by pin.
func TestPresetsAloneRefuse(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup)
	netRows := "  - name: a connect to a host no entry names\n    action: net.connect\n    host_port: 203.0.113.7:443\n    expect: refused\n    rule: unmatched\n" +
		"  - name: a datagram to a host no entry names\n    action: net.send\n    host_port: 198.51.100.9:53\n    expect: refused\n    rule: unmatched\n"
	fsRows := "  - name: a write in the project\n    action: fs.write\n    path: notes.md\n    expect: refused\n    rule: unmatched\n" +
		"  - name: the preset's one write entry\n    action: fs.write\n    path: /dev/null\n    expect: allow\n"
	for _, tc := range []struct {
		extends      string
		net, fs, env bool
	}{
		{"tego/no-prod", true, false, false},
		{"tego/repo-only-writes", false, true, false},
		{"tego/no-secrets", false, false, true},
		{"[tego/no-secrets, tego/no-prod, tego/repo-only-writes]", true, true, true},
		{"[tego/no-secrets@1, tego/no-prod@1, tego/repo-only-writes@1]", true, true, true},
	} {
		t.Run(tc.extends, func(t *testing.T) {
			t.Chdir(t.TempDir())
			if err := os.WriteFile("agent.yaml", []byte("version: 0\nname: alone\nextends: "+tc.extends+"\ncommand: [\"true\"]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			code, js, errs := run(t, "compile", "agent.yaml", "--offline", "--json")
			var table Table
			if code != identity.ExitOK || json.Unmarshal([]byte(js), &table) != nil {
				t.Fatalf("exit %d\n%s", code, errs)
			}
			if table.NetUnrestricted == tc.net || len(table.Net) != 0 {
				t.Errorf("net_unrestricted %v with %d entries; tego/no-prod merged: %v", table.NetUnrestricted, len(table.Net), tc.net)
			}
			if got := table.EnvPass != nil; got != tc.env || (tc.env && len(table.EnvPass) != 25) {
				t.Errorf("env_pass %v; tego/no-secrets merged: %v", table.EnvPass, tc.env)
			}
			code, merged, errs := run(t, "compile", "agent.yaml", "--offline", "--merged")
			if code != identity.ExitOK || strings.Contains(merged, "\nnet: {}\n") != tc.net || strings.Contains(merged, "\nnet:\n") {
				t.Errorf("--merged, tego/no-prod merged %v: exit %d\n%s%s", tc.net, code, merged, errs)
			}
			rows := ""
			if tc.net {
				rows += netRows
			}
			if tc.fs {
				rows += fsRows
			}
			if rows == "" {
				return
			}
			if err := os.WriteFile("rows.yaml", []byte("version: 0\ntests:\n"+rows), 0o644); err != nil {
				t.Fatal(err)
			}
			code, out, errs := run(t, "compile", "agent.yaml", "--test", "rows.yaml", "--tier", "landlock", "--offline", "--json")
			var rep TestReport
			if code != identity.ExitOK || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Rows) != strings.Count(rows, "- name:") {
				t.Fatalf("--test: exit %d\n%s%s", code, out, errs)
			}
			for _, r := range rep.Rows {
				if !r.Pass {
					t.Errorf("row %+v", r)
				}
			}
		})
	}
}
