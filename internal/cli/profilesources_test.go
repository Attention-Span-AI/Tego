// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/profilesrc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestProfileSourcesIsTheSharedChain: tego's profile source is exactly profilesrc.Chain, the one the dashboard's rule
// service compiles with . A built-in source registered in profileSources alone (a merge that keeps
// a branch's `c.WithBuiltin(...)` line there) would let tego resolve tego/ names the dashboard cannot, and the two
// write paths would part; register it in profilesrc.Chain instead.
func TestProfileSourcesIsTheSharedChain(t *testing.T) {
	m := config.Builtin()
	m.Profiles.Value = "/nonexistent/profiles"
	if got, want := profileSources(m), profilesrc.Chain(m); !reflect.DeepEqual(got, want) {
		t.Fatalf("profileSources is %#v, not profilesrc.Chain's %#v", got, want)
	}
}

// TestOneProfileSourceConstructor: every load site of the CLI takes its profile source from profileSources (ADR 0066
// D7), the one place built-in sources are registered, so a site that built its own dirProfiles would read a contract's
// extends without them, or serve a tego/ name from the profiles directory.
func TestOneProfileSourceConstructor(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	own := regexp.MustCompile(`dirProfiles\{|sealedProfiles\{\}|agent\.ProfileChain\{`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "profiles.go" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if own.MatchString(line) {
				t.Errorf("%s:%d builds its own profile source; take profileSources(m) or sealedSources(): %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// builtinFixture is a machine config whose profiles directory holds team.yaml and, under the reserved namespace,
// tego/base.yaml, and a project contract extending them.
func builtinFixture(t *testing.T, extends string) (contract string, m *config.Machine) {
	t.Helper()
	base := trustedDir(t)
	profiles := filepath.Join(base, "profiles")
	if err := os.MkdirAll(filepath.Join(profiles, "tego"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(profiles, "team.yaml"), "net:\n  allow: [\"api.github.com:443\"]\n")
	writeTestFile(t, filepath.Join(profiles, "tego", "base.yaml"), "fs:\n  write: [\"/tmp\"]\n")
	contract = filepath.Join(base, "agent.yaml")
	writeTestFile(t, contract, "version: 0\nname: tester\nextends: "+extends+"\ncommand: [\"/bin/true\"]\n")
	cfg := filepath.Join(base, "tego.yaml")
	writeTestFile(t, cfg, "ledger_root: "+filepath.Join(base, "runs")+"\nprofiles: "+profiles+"\n")
	t.Setenv("TEGO_CONFIG", cfg)
	m = config.Builtin()
	m.Profiles.Value = profiles
	return contract, m
}

// TestLoadSitesNeverReadABuiltinNameFromTheProfilesDirectory: compile and run read extends through profileSources, so
// a contract naming tego/base is refused shadowed-builtin while the profiles directory holds tego/base.yaml, and the
// file is never merged; the directory's other profiles still resolve.
func TestLoadSitesNeverReadABuiltinNameFromTheProfilesDirectory(t *testing.T) {
	contract, m := builtinFixture(t, "[tego/base, team]")
	code, _, errs := run(t, "compile", "--offline", contract)
	if code != identity.ExitFinding || !strings.Contains(errs, "[shadowed-builtin]") || !strings.Contains(errs, filepath.Join("tego", "base.yaml")) {
		t.Errorf("tego compile: exit %d, want %d with shadowed-builtin naming the file\n%s", code, identity.ExitFinding, errs)
	}
	var stderr bytes.Buffer
	rt, _, _, code := compileForRun(t.Context(), runOptions{contract: contract, offline: true}, m, &stderr)
	if rt != nil || code != identity.ExitLauncher || !strings.Contains(stderr.String(), "[shadowed-builtin]") {
		t.Errorf("compileForRun: exit %d\n%s", code, stderr.String())
	}

	contract, m = builtinFixture(t, "team")
	stderr.Reset()
	rt, _, _, code = compileForRun(t.Context(), runOptions{contract: contract, offline: true}, m, &stderr)
	if rt == nil || code != identity.ExitOK {
		t.Fatalf("compileForRun over a directory profile: exit %d\n%s", code, stderr.String())
	}
	if u := rt.Profiles; len(u) != 1 || u[0].Name != "team" || u[0].Source != agent.ProfileDir {
		t.Errorf("RuleTable.Profiles = %+v, want team from the directory", u)
	}
}

// TestSealedReloadServesBuiltinNames: the canonical contract.yaml of a run whose contract extended a built-in profile
// reloads with every name sealed, the built-in one included, and reproduces the run's contract_hash.
func TestSealedReloadServesBuiltinNames(t *testing.T) {
	builtin := mapProfiles{"tego/base": "fs:\n  write: [\"/tmp\"]\n", "team": "net:\n  allow: [\"api.github.com:443\"]\n"}
	chain := (&agent.ProfileChain{}).WithBuiltin(builtin).WithDir(builtin)
	c, ds, err := agent.LoadBytes("agent.yaml", []byte("version: 0\nname: tester\nextends: [tego/base, team]\ncommand: [\"/bin/true\"]\n"), chain)
	if err != nil {
		t.Fatalf("%v %v", err, ds)
	}
	canonical, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := c.Hash()
	path := writeCopy(t, canonical)
	again, ds, err := loadContractCopy(path, hex.EncodeToString(h[:]), profileSources(config.Builtin()))
	if err != nil {
		t.Fatalf("the canonical copy does not reload sealed: %v %v\n%s", err, ds, canonical)
	}
	if h2, _ := again.Hash(); h2 != h {
		t.Errorf("the sealed reload hashes %x, the run %x", h2, h)
	}
}

// mapProfiles serves profiles from memory.
type mapProfiles map[string]string

func (m mapProfiles) Resolve(name string) (string, []byte, error) {
	data, ok := m[name]
	if !ok {
		return "", nil, os.ErrNotExist
	}
	return "mem/" + name + ".yaml", []byte(data), nil
}

// TestDirProfilesHolds: the directory says it holds a name by an lstat beneath root, a link included, and holds
// nothing for a name that leaves root.
func TestDirProfilesHolds(t *testing.T) {
	root := trustedDir(t)
	if err := os.MkdirAll(filepath.Join(root, "tego"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "tego", "a.yaml"), "{}\n")
	if err := os.Symlink("a.yaml", filepath.Join(root, "tego", "b.yaml")); err != nil {
		t.Fatal(err)
	}
	s := dirProfiles{Root: root}
	for name, want := range map[string]bool{"tego/a": true, "tego/b": true, "tego/c": false, "../tego/a": false, "": false} {
		path, ok := s.Holds(name)
		if ok != want || (ok && path != s.Location(name)) {
			t.Errorf("Holds(%q) = %q, %v; want %v", name, path, ok, want)
		}
	}
	if _, ok := (dirProfiles{}).Holds("tego/a"); ok {
		t.Error("an empty root holds nothing")
	}
}
