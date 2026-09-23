// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestExtendsEmptyApprovalMappingsResetInheritedPolicy(t *testing.T) {
	profiles := mapSource{"base": `fs: {ask: [/work]}
ask: {hold: first_write, timeout: 1s, max_pending: 1}
gate: {rules: [{fs.write outside worktree: 90}]}
`}
	for _, tc := range []struct {
		name, suffix        string
		resetAsk, resetGate bool
	}{
		{"absent-inherits", "", false, false},
		{"empty-ask-resets", "ask: {}\n", true, false},
		{"empty-gate-resets", "gate: {}\n", false, true},
		{"both-reset", "ask: {}\ngate: {}\n", true, true},
		{"partial-ask-replaces", "ask: {max_pending: 64}\n", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: child\nextends: base\ncommand: [x]\n"+tc.suffix), profiles)
			if err != nil {
				t.Fatalf("load: %v\n%s", err, render(ds))
			}
			check := func(c *Contract) {
				t.Helper()
				cfg, err := CompileAskConfig(c)
				if err != nil || cfg == nil {
					t.Fatalf("ask: %+v %v", cfg, err)
				}
				if tc.resetAsk {
					if cfg.Hold != AskHoldConnect || time.Duration(cfg.Timeout) != 5*time.Minute || cfg.MaxPending != 64 {
						t.Errorf("explicit replacement retained inherited settings: %+v", cfg)
					}
				} else if cfg.Hold != AskHoldFirstWrite || time.Duration(cfg.Timeout) != time.Second || cfg.MaxPending != 1 {
					t.Errorf("absent ask lost inheritance: %+v", cfg)
				}
				gate, err := CompileGateConfig(c)
				if err != nil {
					t.Fatal(err)
				}
				if (gate == nil) != tc.resetGate {
					t.Errorf("gate presence=%v, reset=%v", gate != nil, tc.resetGate)
				}
			}
			check(c)
			// Serialize the merged values without reapplying the profile during reload.
			merged := *c
			merged.Extends = nil
			canonical, err := merged.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			reloaded, ds, err := LoadBytes("canonical.yaml", canonical, nil)
			if err != nil {
				t.Fatalf("canonical reload: %v\n%s", err, render(ds))
			}
			check(reloaded)
		})
	}
}

func TestExtendsApprovalReplacementPreservesValidationAndNestedReset(t *testing.T) {
	profiles := mapSource{
		"base":  "fs: {ask: [/work]}\nask: {hold: first_write, timeout: 1s, max_pending: 1}\ngate: {rules: [{fs.write outside worktree: 90}]}\n",
		"reset": "extends: base\nask: {}\ngate: {}\n",
	}
	base := "version: 0\nname: child\nextends: base\ncommand: [x]\n"
	for _, invalid := range []string{"ask: null", "ask: []", "ask: {timeout: 0s}", "gate: null", "gate: []", "gate: {thresholds: {allow: 90, ask: 80}}"} {
		if _, _, err := LoadBytes("invalid.yaml", []byte(base+invalid+"\n"), profiles); err == nil {
			t.Errorf("invalid replacement accepted: %s", invalid)
		}
	}
	c, ds, err := LoadBytes("child.yaml", []byte(strings.Replace(base, "extends: base", "extends: reset", 1)), profiles)
	if err != nil {
		t.Fatalf("nested reset: %v\n%s", err, render(ds))
	}
	ask, err := CompileAskConfig(c)
	if err != nil || ask == nil || ask.Hold != AskHoldConnect || time.Duration(ask.Timeout) != 5*time.Minute || ask.MaxPending != 64 {
		t.Fatalf("nested Ask reset: %+v %v", ask, err)
	}
	if gate, err := CompileGateConfig(c); err != nil || gate != nil {
		t.Fatalf("nested Gate reset: %+v %v", gate, err)
	}
}

// mapSource serves profiles from memory.
type mapSource map[string]string

func (m mapSource) Resolve(name string) (string, []byte, error) {
	data, ok := m[name]
	if !ok {
		return "", nil, os.ErrNotExist
	}
	return "profiles/" + name + ".yaml", []byte(data), nil
}

func TestExtendsMerge(t *testing.T) {
	profiles := mapSource{
		"base": `extends: root
fs:
  write: ["/p/write"]
  deny_read: ["/p/secret"]
  watch: ["/p/watch"]
net:
  allow: ["p.example:443"]
exec:
  allow: ["p-tool"]
env:
  pass: ["P_VAR"]
  deny: ["P_DENY"]
  set: {SHARED: profile, P_ONLY: p}
mcp:
  - {name: p-mcp, command: [p-mcp]}
models:
  - {provider: openai, host: api.openai.com, port: 443}
limits:
  memory: 2GiB
  pids: 100
record: full
tier: cgroup
capture: forwarder
io_uring: true
command: ["p-cmd"]
`,
		"root": `fs:
  deny_read: ["/root/secret"]
limits:
  wall: 1h
`,
	}
	contract := `version: 0
name: child
extends: base
command: ["c-cmd"]
fs:
  write: ["/c/write"]
  deny_read: []
net:
  allow: ["c.example:443"]
env:
  pass: ["C_VAR"]
  set: {SHARED: contract, C_ONLY: c}
limits:
  memory: 1GiB
record: off
`
	c, ds, err := LoadBytes("child.yaml", []byte(contract), profiles)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	join := func(s []string) string { return strings.Join(s, ",") }
	if join(c.Command) != "c-cmd" {
		t.Errorf("command: contract wins: %v", c.Command)
	}
	if join(c.FS.Write) != "/p/write,/c/write" || join(c.FS.Watch) != "/p/watch" {
		t.Errorf("lists concatenate profile first: %v %v", c.FS.Write, c.FS.Watch)
	}
	if join(c.FS.DenyRead) != "/root/secret,/p/secret" {
		t.Errorf("deny_read union, never removed by deny_read: []: %v", c.FS.DenyRead)
	}
	if join(c.Net.Allow) != "p.example:443,c.example:443" || join(c.Exec.Allow) != "p-tool" {
		t.Errorf("net/exec: %v %v", c.Net.Allow, c.Exec.Allow)
	}
	if join(c.Env.Pass) != "P_VAR,C_VAR" || join(c.Env.Deny) != "P_DENY" {
		t.Errorf("env lists: %v %v", c.Env.Pass, c.Env.Deny)
	}
	if c.Env.Set["SHARED"] != "contract" || c.Env.Set["P_ONLY"] != "p" || c.Env.Set["C_ONLY"] != "c" {
		t.Errorf("env.set key-wise, contract wins: %v", c.Env.Set)
	}
	if len(c.MCP) != 1 || len(c.Models) != 1 {
		t.Errorf("mcp/models: %v %v", c.MCP, c.Models)
	}
	if *c.Limits.Memory != 1<<30 || *c.Limits.Pids != 100 || *c.Limits.Wall != Duration(3600e9) {
		t.Errorf("limits: contract wins per field, else profile, else grandparent: %+v", c.Limits)
	}
	if c.Record != RecordOff || c.Tier != "cgroup" || c.Capture != CaptureForwarder || !c.IOUring {
		t.Errorf("scalars: %s %s %s %v", c.Record, c.Tier, c.Capture, c.IOUring)
	}
	// Origins follow entries into the profile they came from.
	if p, ok := c.Pos("fs.write.0"); !ok || p.File != "profiles/base.yaml" || p.Line != 3 {
		t.Errorf("origin of the profile's write entry: %+v %v", p, ok)
	}
	if p, ok := c.Pos("fs.write.1"); !ok || p.File != "child.yaml" || p.Line != 6 {
		t.Errorf("origin of the contract's write entry: %+v %v", p, ok)
	}
	if p, ok := c.Pos("fs.deny_read.0"); !ok || p.File != "profiles/root.yaml" {
		t.Errorf("origin of the root's deny_read: %+v", p)
	}
	if p, ok := c.Pos("env.set.SHARED"); !ok || p.File != "child.yaml" {
		t.Errorf("origin of a contract-won map key: %+v", p)
	}
	if p, ok := c.Pos("limits.pids"); !ok || p.File != "profiles/base.yaml" {
		t.Errorf("origin of a profile-won scalar: %+v", p)
	}
	// deny_read: [] in the contract still warns, and says what it did: the profiles declare
	// deny_read entries, so the merged list is populated and the built-in list stays on (R5, R6).
	// "disables" would be false here.
	var warned bool
	for _, d := range ds {
		if d.Code == CodeRedundantRule && d.File == "child.yaml" && d.Line == 7 && strings.Contains(d.Message, "deny_read: []") {
			warned = true
		}
	}
	if !warned || hasCode(ds, CodeDenyReadDisabled) {
		t.Errorf("deny_read: [] outvoted by the profiles' entries must warn redundant-rule at child.yaml:7, never deny-read-disabled:\n%s", render(ds))
	}
	// A profile's not-yet-supported field is reported at the profile's line.
	_, ds, err = LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"), mapSource{"p": "docker:\n  allow: [privileged]\n"})
	if !errors.Is(err, ErrInvalidContract) || len(ds) != 1 || ds[0].Code != CodeNotYetSupported || ds[0].File != "profiles/p.yaml" || ds[0].Line != 2 {
		t.Errorf("profile not-yet-supported: %v %v", err, ds)
	}
	// extends without a source.
	_, ds, err = LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"), nil)
	if !errors.Is(err, ErrProfileNotFound) || !hasCode(ds, CodeExtendsNotFound) {
		t.Errorf("nil source: %v %v", err, codes(ds))
	}
	// A source I/O error surfaces in Fix.
	_, ds, _ = LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"), errSource{})
	if !hasCode(ds, CodeExtendsNotFound) || !strings.Contains(render(ds), "permission denied") {
		t.Errorf("source error: %s", render(ds))
	}
}

// TestExtendsNotFoundFixWorks: the fix line told the author to run `tego init --profile <name>`, a flag init does
// not have. It names the file to create when the source can say where it reads profiles from, and never a command
// that does not exist.
func TestExtendsNotFoundFixWorks(t *testing.T) {
	src := []byte("version: 0\nname: a\nextends: py\ncommand: [x]\n")
	_, ds, err := LoadBytes("child.yaml", src, locatedSource{})
	if !errors.Is(err, ErrProfileNotFound) || !hasCode(ds, CodeExtendsNotFound) {
		t.Fatalf("%v %v", err, codes(ds))
	}
	if got := render(ds); !strings.Contains(got, "create /profiles/py.yaml, or remove extends:") || strings.Contains(got, "--profile") {
		t.Errorf("fix line: %s", got)
	}
	_, ds, _ = LoadBytes("child.yaml", src, mapSource{})
	if got := render(ds); !strings.Contains(got, "add a profile named py") || strings.Contains(got, "--profile") {
		t.Errorf("fix line without a location: %s", got)
	}
}

// locatedSource is an empty profile source that says where it would read a profile from.
type locatedSource struct{}

func (locatedSource) Resolve(name string) (string, []byte, error) {
	return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
}

func (locatedSource) Location(name string) string { return "/profiles/" + name + ".yaml" }

type errSource struct{}

func (errSource) Resolve(string) (string, []byte, error) { return "", nil, os.ErrPermission }

func TestFSPresence(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		nilFS    bool
		nilDeny  bool
		emptyDen bool
	}{
		{"absent", "", true, true, false},
		{"empty-map", "fs: {}\n", false, true, false},
		{"write-empty", "fs:\n  write: []\n", false, true, false},
		{"deny-empty", "fs:\n  deny_read: []\n", false, false, true},
	}
	for _, tc := range tests {
		c, _, err := LoadBytes("x.yaml", []byte("version: 0\nname: a\ncommand: [x]\n"+tc.yaml), nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if (c.FS == nil) != tc.nilFS {
			t.Errorf("%s: FS nil=%v", tc.name, c.FS == nil)
			continue
		}
		if c.FS != nil && (c.FS.DenyRead == nil) != tc.nilDeny {
			t.Errorf("%s: DenyRead nil=%v", tc.name, c.FS.DenyRead == nil)
		}
		if c.FS != nil && tc.emptyDen && len(c.FS.DenyRead) != 0 {
			t.Errorf("%s: DenyRead=%v", tc.name, c.FS.DenyRead)
		}
	}
}

// TestNonUTF8IsReportedWhereItIs: yaml.v3 reports a bad encoding with no position, and the loader put it at line 1
// whatever line held the byte.
func TestNonUTF8IsReportedWhereItIs(t *testing.T) {
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: t\ncommand: [\"true\"]\nfs:\n  write: [\"./o\xff\"]\n"), nil)
	if err == nil || len(ds) != 1 {
		t.Fatalf("%v %v", err, ds)
	}
	if d := ds[0]; d.Line != 5 || d.Col != 15 || !strings.Contains(d.Message, "UTF-8") {
		t.Errorf("diagnostic %+v, want line 5 col 15", d)
	}
	if line, col := invalidUTF8At([]byte("a\nb\xc3(\n")); line != 2 || col != 2 {
		t.Errorf("a truncated sequence at 2:2 is reported at %d:%d", line, col)
	}
	if line, col := invalidUTF8At([]byte("caf\xc3\xa9\n")); line != 0 || col != 0 {
		t.Errorf("valid UTF-8 reported at %d:%d", line, col)
	}
}

// TestTestTableNonUTF8IsReportedWhereItIs: a test table takes the same translation of yaml.v3's position-less
// encoding error as a contract, so an invalid byte on line 3 is not reported at line 1.
func TestTestTableNonUTF8IsReportedWhereItIs(t *testing.T) {
	_, ds, err := LoadTestTableBytes("t.yaml", []byte("# a table\n\ncases: [\"x\xff\"]\n"))
	if err == nil || len(ds) != 1 {
		t.Fatalf("%v %v", err, ds)
	}
	if d := ds[0]; d.Line != 3 || d.Col != 11 || !strings.Contains(d.Message, "UTF-8") {
		t.Errorf("diagnostic %+v, want line 3 col 11", d)
	}
}

// TestExtendsMergeCostIsLinear: merging a contract of n list entries and n env.set keys over a profile costs
// about n, not n² (E24): each entry's origins are found through an index, never by scanning every origin. By
// scan, 4,000 entries cost about 60 times what 500 do (seconds); indexed, about 8 times.
func TestExtendsMergeCostIsLinear(t *testing.T) {
	build := func(n int) (*Contract, *Contract) {
		p := &Contract{file: "profiles/base.yaml", Exec: &ExecSection{Allow: []string{"sh"}}, origins: origins{
			"exec": {File: "profiles/base.yaml", Line: 1}, "exec.allow": {File: "profiles/base.yaml", Line: 2},
			"exec.allow.0": {File: "profiles/base.yaml", Line: 3},
		}}
		c := &Contract{file: "c.yaml", Exec: &ExecSection{}, Env: EnvSection{Set: map[string]string{}}, origins: origins{
			"exec": {File: "c.yaml", Line: 1}, "exec.allow": {File: "c.yaml", Line: 2},
			"env": {File: "c.yaml", Line: 1}, "env.set": {File: "c.yaml", Line: 1},
		}}
		for i := range n {
			c.Exec.Allow = append(c.Exec.Allow, fmt.Sprintf("tool%d", i))
			c.origins[fmt.Sprintf("exec.allow.%d", i)] = Pos{File: "c.yaml", Line: 3 + i}
			k := fmt.Sprintf("K%d", i)
			c.Env.Set[k] = "v"
			c.origins["env.set."+k] = Pos{File: "c.yaml", Line: 3 + n + i}
		}
		return p, c
	}
	// merged returns a merge of n entries, which checks the positions it gives.
	merged := func(n int) func() time.Duration {
		p, c := build(n)
		return func() time.Duration {
			start := processCPU(t)
			r := merge(p, c)
			took := processCPU(t) - start
			if got, ok := r.Pos(fmt.Sprintf("exec.allow.%d", n)); !ok || got.File != "c.yaml" || got.Line != 3+n-1 {
				t.Fatalf("n=%d: exec.allow.%d at %+v, %v; want the contract's last entry", n, n, got, ok)
			}
			if got, ok := r.Pos("exec.allow.0"); !ok || got.File != "profiles/base.yaml" || got.Line != 3 {
				t.Fatalf("n=%d: exec.allow.0 at %+v, %v; want the profile's entry", n, got, ok)
			}
			if got, ok := r.Pos("env.set.K0"); !ok || got.Line != 3+n {
				t.Fatalf("n=%d: env.set.K0 at %+v, %v", n, got, ok)
			}
			return took
		}
	}
	// The least CPU time of five merges of each size (processCPU), the sizes interleaved, so a change in the machine's
	// load lands on both.
	small, large := bestInterleaved(5, merged(500), merged(4_000))
	t.Logf("merge: %v of CPU at 500 entries, %v at 4,000", small, large)
	if large > 24*small+20*time.Millisecond {
		t.Errorf("merge costs %v at 4,000 entries against %v at 500: it grows faster than the entries", large, small)
	}
}

// TestExtendsDoesNotSupplyVersion: version is required of the top file itself (R5 inherits none). A contract
// with no version: that extends a profile writing version: 0 loaded, because the merge carried the profile's
// origin of version and the required check asked only whether the merged contract had one.
func TestExtendsDoesNotSupplyVersion(t *testing.T) {
	_, ds, err := LoadBytes("child.yaml", []byte("name: a\nextends: p\ncommand: [x]\n"), mapSource{"p": "version: 0\n"})
	if err == nil || !hasCode(ds, CodeSchema) || !strings.Contains(render(ds), "version is required") {
		t.Fatalf("a contract with no version: extending a profile that writes one: err = %v\n%s", err, render(ds))
	}
	if _, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\n"), mapSource{"p": "version: 0\n"}); err != nil {
		t.Fatalf("a contract writing version: 0 over a profile that does: %v\n%s", err, render(ds))
	}
}
