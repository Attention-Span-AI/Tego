// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// fakeResolver answers from a table; unknown hosts fail like NXDOMAIN. A host's answers in next come first, one
// per lookup, before its table entry: a name whose two lookups disagree, as DNS round-robin answers.
type fakeResolver struct {
	table map[string][]netip.Addr
	calls atomic.Int32
	mu    sync.Mutex
	next  map[string][][]netip.Addr
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.mu.Lock()
	if q := r.next[host]; len(q) > 0 {
		r.next[host] = q[1:]
		r.mu.Unlock()
		return q[0], nil
	}
	r.mu.Unlock()
	if ips, ok := r.table[host]; ok {
		return ips, nil
	}
	return nil, fmt.Errorf("lookup %s: no such host", host)
}

// fixture is a throwaway world: a home with secrets, a project with a .env,
// a ledger root, a bin directory on PATH with crafted binaries.
type fixture struct {
	t        testing.TB
	root     string
	home     string
	project  string
	ledger   string
	bin      string
	resolver *fakeResolver
	machine  *config.Machine
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	// Resolved, because Compile resolves every entry (FSRule.Resolved, E8) and the expectations built from
	// root must name what it names: under a TMPDIR that is or holds a symlink, t.TempDir's spelling is not it.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, root: root,
		home: filepath.Join(root, "home"), project: filepath.Join(root, "project"),
		ledger: filepath.Join(root, "home", ".tego", "runs"), bin: filepath.Join(root, "bin")}
	for _, d := range []string{f.home, f.project, f.bin, filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".aws"),
		filepath.Join(f.project, "out"), filepath.Join(f.project, "config"), filepath.Join(f.project, "secrets"), filepath.Join(f.project, "node_modules", "x")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(f.home, ".netrc"), "machine x", 0o600)
	f.file(filepath.Join(f.project, ".env"), "SECRET=1", 0o600)
	f.file(filepath.Join(f.project, ".env.example"), "SECRET=", 0o644)
	f.file(filepath.Join(f.project, "node_modules", "x", ".env"), "SKIPPED=1", 0o644)
	f.file(filepath.Join(f.project, "secrets", "key.pem"), "---", 0o600)
	f.file(filepath.Join(f.bin, "python"), string(elf64("/lib64/ld-fake.so.2", 3)), 0o755)
	f.file(filepath.Join(f.bin, "static-tool"), string(elf64("", 2)), 0o755)
	// The #! names the fixture's env, which exec.allow lists by path: a same-named /usr/bin/env is another
	// inode and covers nothing at tiers 1 and 2 (SEMANTICS §4).
	f.file(filepath.Join(f.bin, "tool.sh"), "#!"+filepath.Join(f.bin, "env")+" python\nprint(1)\n", 0o755)
	f.file(filepath.Join(f.bin, "lonely.sh"), "#!/opt/none/ruby\nputs 1\n", 0o755)
	f.file(filepath.Join(f.bin, "env"), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
	f.file(filepath.Join(f.bin, "not-exec"), "data", 0o644)
	f.file(filepath.Join(f.bin, "broken"), string(elf64("/x", 3)[:100]), 0o755)
	f.file(filepath.Join(f.bin, "mcp-postgres"), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
	f.resolver = &fakeResolver{table: map[string][]netip.Addr{
		"mcp.internal":      {netip.MustParseAddr("10.0.0.5")},
		"api.anthropic.com": {netip.MustParseAddr("160.79.104.10"), netip.MustParseAddr("::ffff:160.79.104.10"), netip.MustParseAddr("2607:6bc0::10")},
	}}
	f.machine = machineWith(f.ledger, 8, 32<<30, 4096, 10_000_000, 200, 24*time.Hour, time.Hour, 20)
	return f
}

func (f *fixture) file(path, content string, mode os.FileMode) {
	f.t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		f.t.Fatal(err)
	}
}

// load writes a contract into the project and loads it.
func (f *fixture) load(yaml string) *Contract {
	f.t.Helper()
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, yaml, 0o644)
	c, ds, err := Load(path, f.profiles())
	if err != nil {
		f.t.Fatalf("load: %v\n%s", err, render(ds))
	}
	return c
}

// profiles is testdata/profiles copied under the fixture with "/tmp/"
// rewritten to a scratch directory, so the profile's write entry never
// contains the fixture itself (which lives under /tmp and would be an R10
// contradiction, correctly).
func (f *fixture) profiles() ProfileSource {
	f.t.Helper()
	dst := filepath.Join(f.root, "profiles")
	if _, err := os.Stat(dst); err == nil {
		return dirSource{root: dst}
	}
	scratch := filepath.Join(f.root, "scratch")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		f.t.Fatal(err)
	}
	err := filepath.WalkDir(filepath.Join("testdata", "profiles"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join("testdata", "profiles"), p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, []byte(strings.ReplaceAll(string(data), `"/tmp/"`, `"`+scratch+`"`)), 0o644)
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return dirSource{root: dst}
}

func (f *fixture) opts(extra ...CompileOption) []CompileOption {
	// The host-socket probe (R19) is rooted in the fixture, where no daemon socket exists unless a test
	// makes one, so no fixture's diagnostics depend on what runs on the machine the tests run on.
	base := []CompileOption{WithResolver(f.resolver), WithPATH(f.bin), WithCwd(f.project), WithHome(f.home), WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
		withHostSocketProbe(f.root, 4242)}
	return append(base, extra...)
}

func (f *fixture) compile(c *Contract, extra ...CompileOption) (*RuleTable, []Diagnostic) {
	f.t.Helper()
	rt, ds, err := Compile(c, f.machine, f.opts(extra...)...)
	if err != nil {
		f.t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	return rt, ds
}

const baseContract = `version: 0
name: retriever
command: ["python", "agent.py"]
mcp:
  - name: postgres
    command: ["mcp-postgres"]
fs:
  write: ["out/"]
  watch: ["config/"]
net:
  allow: ["mcp.internal:8080", "10.0.0.0/8:443", "127.0.0.1:5432", "unix:/run/pg.sock", "unix:@bus"]
exec:
  allow: ["python", "static-tool", "tool.sh", "%s"]
env:
  pass: ["PATH", "HOME"]
limits:
  cpu: "2.0"
  memory: 8GiB
  memory_high: 6GiB
  pids: 512
  wall: 2h
`

func codes(ds []Diagnostic) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Code)
	}
	return out
}

func hasCode(ds []Diagnostic, code string) bool {
	for _, d := range ds {
		if d.Code == code {
			return true
		}
	}
	return false
}

func findFS(rt *RuleTable, kind FSKind, path string) *FSRule {
	for i := range rt.FS {
		if rt.FS[i].Kind == kind && rt.FS[i].Path == path {
			return &rt.FS[i]
		}
	}
	return nil
}

func findExec(rt *RuleTable, base string) *ExecRule {
	for i := range rt.Exec {
		if rt.Exec[i].Basename == base {
			return &rt.Exec[i]
		}
	}
	return nil
}

func TestCompileHappyPath(t *testing.T) {
	f := newFixture(t)
	c := f.load(fmt.Sprintf(baseContract, f.bin+"/env"))
	rt, ds := f.compile(c)
	if HasErrors(ds) {
		t.Fatalf("errors:\n%s", render(ds))
	}
	// R9 implicit entries.
	for _, p := range []string{f.ledger, filepath.Join(f.project, "agent.yaml"), "/sys/fs/cgroup", "/sys/fs/bpf"} {
		if r := findFS(rt, FSImplicit, p); r == nil || r.Access != 0 {
			t.Errorf("implicit entry %s missing or writable", p)
		}
	}
	// R7 write resolved relative to cwd, watch exists.
	if r := findFS(rt, FSWrite, filepath.Join(f.project, "out")); r == nil || r.Access != AccessWriteSet || r.Missing {
		t.Errorf("write rule: %+v", r)
	}
	if r := findFS(rt, FSWatch, filepath.Join(f.project, "config")); r == nil {
		t.Error("watch rule missing")
	}
	// Built-in deny_read: existing home entries and the project's .env, not the example or node_modules.
	for _, p := range []string{filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".aws"), filepath.Join(f.home, ".netrc"), filepath.Join(f.project, ".env")} {
		if r := findFS(rt, FSDenyRead, p); r == nil || !r.BuiltIn {
			t.Errorf("built-in deny_read %s missing", p)
		}
	}
	for _, p := range []string{filepath.Join(f.home, ".gnupg"), filepath.Join(f.project, ".env.example"), filepath.Join(f.project, "node_modules", "x", ".env")} {
		if findFS(rt, FSDenyRead, p) != nil {
			t.Errorf("unexpected deny_read %s", p)
		}
	}
	// R8 exec: command, mcp, exec.allow, loaders, scripts.
	py := findExec(rt, "python")
	if py == nil || py.Interp != "/lib64/ld-fake.so.2" || !strings.Contains(py.Source, ExecSourceCommand) || !strings.Contains(py.Source, ExecSourceAllow) {
		t.Errorf("python rule: %+v", py)
	}
	if r := findExec(rt, "mcp-postgres"); r == nil || r.Source != "mcp:postgres" || r.Interp == "" {
		t.Errorf("mcp rule: %+v", r)
	}
	if r := findExec(rt, "static-tool"); r == nil || r.Interp != "" {
		t.Errorf("static rule: %+v", r)
	}
	if r := findExec(rt, "tool.sh"); r == nil || r.Interp != "" {
		t.Errorf("script rule: %+v", r)
	}
	if r := findExec(rt, "env"); r == nil || r.Raw != f.bin+"/env" {
		t.Errorf("path entry rule: %+v", r)
	}
	if hasCode(ds, CodeInterpreter) {
		t.Errorf("tool.sh's interpreter (env, python) is covered; got %v", codes(ds))
	}
	// Net: resolved host, static entries, TTL, unmapped and sorted addresses.
	if len(rt.Net) != 5 {
		t.Fatalf("net rules: %d", len(rt.Net))
	}
	host := rt.Net[0]
	if host.Static || host.Host != "mcp.internal" || host.Port != 8080 || host.Proto != ProtoInet || len(host.IPs) != 1 || host.TTL != DefaultDNSTTL || host.ResolvedAt.IsZero() || host.RuleName() != "net[mcp.internal:8080]" {
		t.Errorf("host rule: %+v", host)
	}
	if cidr := rt.Net[1]; !cidr.Static || cidr.CIDR == nil || cidr.CIDR.String() != "10.0.0.0/8" {
		t.Errorf("cidr rule: %+v", cidr)
	}
	if ip := rt.Net[2]; !ip.Static || len(ip.IPs) != 1 || ip.IPs[0].String() != "127.0.0.1" {
		t.Errorf("ip rule: %+v", ip)
	}
	if u := rt.Net[3]; u.Proto != ProtoUnix || u.UnixPath != "/run/pg.sock" || u.Abstract {
		t.Errorf("unix rule: %+v", u)
	}
	if u := rt.Net[4]; u.Proto != ProtoUnix || u.UnixPath != "bus" || !u.Abstract {
		t.Errorf("abstract rule: %+v", u)
	}
	if n := f.resolver.calls.Load(); n != 1 {
		t.Errorf("resolver called %d times; hosts are deduplicated", n)
	}
	// Limits within ceilings, memory_high kept, wall kept, others inherited.
	l := rt.Limits
	if l.CPU != "2.0" || l.MemoryB != 8<<30 || l.MemoryHigh != 6<<30 || l.Pids != 512 || l.Wall != 2*time.Hour || l.Tokens != 10_000_000 || l.Repeats != 20 || l.StallAfter != time.Hour {
		t.Errorf("limits: %+v", l)
	}
	if rt.Tier != backend.TierBPFLSM || rt.Capture != CaptureUprobe || rt.Record != RecordSummary {
		t.Errorf("tier/capture/record: %s %s %s", rt.Tier, rt.Capture, rt.Record)
	}
	if rt.PATH != f.bin || len(rt.Env) != 2 {
		t.Errorf("env: PATH=%q Env=%v", rt.PATH, rt.Env)
	}
	var buf bytes.Buffer
	if err := PrintRuleTable(&buf, rt); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tier      bpflsm", "/lib64/ld-fake.so.2", "net[mcp.internal:8080]", "10.0.0.5", "memory=8GiB", "built-in", "deny_read"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("print lacks %q:\n%s", want, buf.String())
		}
	}
}

// agent-contract.md R9: no fs: still yields the four implicit entries and no write entry.
func TestCompileFSDefaults(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name     string
		fs       string
		wantRoot bool // the deny-all-writes rule at /
		wantDeny bool // the built-in list
	}{
		// "absent" has no deny_read: either, so the built-in list applies to it as it does to
		// every other shape: the list is governed by deny_read's tri-state, not by the presence
		// of an fs: key (SEMANTICS §1, R6). Only `deny_read: []` turns it off, and that warns.
		{"absent", "", false, true},
		{"empty", "fs: {}\n", true, true},
		{"empty-write", "fs:\n  write: []\n", true, true},
		{"populated", "fs:\n  write: [out]\n", false, true},
		{"deny-read-disabled", "fs:\n  deny_read: []\n", true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\n" + tc.fs)
			rt, _ := f.compile(c)
			if got := findFS(rt, FSImplicit, "/") != nil; got != tc.wantRoot {
				t.Errorf("deny-all rule at /: %v want %v", got, tc.wantRoot)
			}
			if got := findFS(rt, FSDenyRead, filepath.Join(f.home, ".ssh")) != nil; got != tc.wantDeny {
				t.Errorf("built-in deny_read: %v want %v", got, tc.wantDeny)
			}
			if tc.name != "absent" {
				return
			}
			// R9: no fs: still adds exactly the four implicit entries and no write entry.
			implicit, writes := 0, 0
			for _, r := range rt.FS {
				switch r.Kind {
				case FSImplicit:
					implicit++
				case FSWrite:
					writes++
				}
			}
			if implicit != 4 || writes != 0 {
				t.Errorf("no fs: yielded %d implicit and %d write entries, want 4 and 0", implicit, writes)
			}
		})
	}
}

func TestCompilePathRules(t *testing.T) {
	f := newFixture(t)
	if err := os.Chmod(filepath.Join(f.project, "config"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(f.project, "config"), 0o755) })
	tests := []struct {
		name     string
		fs       string
		wantCode string
		wantErr  error
		check    func(t *testing.T, rt *RuleTable)
	}{
		{name: "write-leaf-missing-ok", fs: "fs:\n  write: [out/new]\n", check: func(t *testing.T, rt *RuleTable) {
			if r := findFS(rt, FSWrite, filepath.Join(f.project, "out", "new")); r == nil || !r.Missing {
				t.Errorf("missing leaf write dir: %+v", r)
			}
		}},
		{name: "write-parent-missing", fs: "fs:\n  write: [out/deep/nested]\n", wantCode: CodePathMissing, wantErr: ErrInvalidContract},
		// A write entry is no glob: marked missing, the run would mkdir a directory literally named "*".
		{name: "write-glob", fs: "fs:\n  write: [\"out/*\"]\n", wantCode: CodePathMissing, wantErr: ErrInvalidContract},
		{name: "write-glob-deeper", fs: "fs:\n  write: [\"out/sub?\"]\n", wantCode: CodePathMissing, wantErr: ErrInvalidContract},
		{name: "write-read-only-dir-no-uid-check", fs: "fs:\n  write: [config]\n"},
		{name: "watch-missing", fs: "fs:\n  watch: [nope]\n", wantCode: CodePathMissing, wantErr: ErrInvalidContract},
		{name: "deny-read-missing", fs: "fs:\n  deny_read: [~/.gnupg]\n", wantCode: CodePathMissing, wantErr: ErrInvalidContract},
		{name: "deny-read-glob", fs: "fs:\n  deny_read: [\"secrets/*.pem\"]\n", check: func(t *testing.T, rt *RuleTable) {
			if findFS(rt, FSDenyRead, filepath.Join(f.project, "secrets", "key.pem")) == nil {
				t.Error("glob match missing")
			}
		}},
		{name: "deny-read-glob-none", fs: "fs:\n  deny_read: [\"secrets/*.key\"]\n", wantCode: CodeGlobNoMatch},
		{name: "redundant-nested-write", fs: "fs:\n  write: [out, out/sub]\n", wantCode: CodeRedundantRule},
		{name: "contradiction-ledger", fs: "fs:\n  write: [~/.tego]\n", wantCode: CodeContradiction, wantErr: ErrContractOverlap},
		{name: "contradiction-contract-dir", fs: "fs:\n  write: [\".\"]\n", wantCode: CodeContradiction, wantErr: ErrContractOverlap},
		{name: "contradiction-root", fs: "fs:\n  write: [\"/\"]\n", wantCode: CodeContradiction, wantErr: ErrContractOverlap},
		{name: "unenforced-landlock", fs: "tier: landlock\nfs:\n  reads: direct\n  write: [secrets]\n  deny_read: [secrets/key.pem]\n", wantCode: CodeUnenforced, check: func(t *testing.T, rt *RuleTable) {
			if r := findFS(rt, FSDenyRead, filepath.Join(f.project, "secrets", "key.pem")); r == nil || !r.Unenforced {
				t.Errorf("unenforced flag: %+v", r)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.MkdirAll(filepath.Join(f.project, "out", "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
			c := f.load("version: 0\nname: a\ncommand: [python]\n" + tc.fs)
			rt, ds, err := Compile(c, f.machine, f.opts()...)
			if tc.wantCode != "" && !hasCode(ds, tc.wantCode) {
				t.Fatalf("want code %s, got %v\n%s", tc.wantCode, codes(ds), render(ds))
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || !errors.Is(err, ErrInvalidContract) || rt != nil {
					t.Fatalf("err=%v rt=%v", err, rt)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error %v\n%s", err, render(ds))
			}
			if tc.check != nil {
				tc.check(t, rt)
			}
		})
	}
}

// agent-contract.md E12 (a same-named directory earlier on PATH is skipped) and E14 (a truncated ELF warns malformed-elf).
func TestCompileExecResolution(t *testing.T) {
	f := newFixture(t)
	shadow := filepath.Join(f.root, "shadow")
	if err := os.MkdirAll(filepath.Join(shadow, "python"), 0o755); err != nil { // a directory named python earlier on PATH (E12)
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		yaml     string
		opts     []CompileOption
		wantCode string
		wantFix  string
		check    func(t *testing.T, rt *RuleTable)
	}{
		{name: "shadowed-by-dir", yaml: "exec:\n  allow: [python]\n", opts: []CompileOption{WithPATH(shadow + ":" + f.bin)}, check: func(t *testing.T, rt *RuleTable) {
			if r := findExec(rt, "python"); r == nil || r.Path != filepath.Join(f.bin, "python") {
				t.Errorf("shadowed resolution: %+v", r)
			}
		}},
		{name: "not-on-path", yaml: "exec:\n  allow: [ghost]\n", wantCode: CodeExecNotOnPath, wantFix: "searched: " + f.bin},
		{name: "not-executable", yaml: "exec:\n  allow: [not-exec]\n", wantCode: CodeExecNotOnPath},
		{name: "mcp-not-on-path", yaml: "mcp:\n  - name: ghost\n    command: [mcp-ghost]\n", wantCode: CodeExecNotOnPath, wantFix: "searched"},
		{name: "path-entry-missing", yaml: "exec:\n  allow: [/opt/none/bin/x]\n", wantCode: CodePathMissing},
		{name: "no-path-given", yaml: "", opts: []CompileOption{WithPATH("")}, wantCode: CodeExecNotOnPath, wantFix: "PATH is empty"},
		{name: "path-denied", yaml: "env:\n  deny: [PATH]\n", wantCode: CodeExecNotOnPath},
		{name: "path-not-passed", yaml: "env:\n  pass: [HOME]\n", wantCode: CodeExecNotOnPath},
		{name: "path-set", yaml: "env:\n  pass: [HOME]\n  set: {PATH: \"" + f.bin + "\"}\n", check: func(t *testing.T, rt *RuleTable) {
			if rt.PATH != f.bin || findExec(rt, "python") == nil {
				t.Errorf("env.set PATH not honoured: %q", rt.PATH)
			}
		}},
		{name: "malformed-elf", yaml: "exec:\n  allow: [broken]\n", wantCode: CodeMalformedELF, check: func(t *testing.T, rt *RuleTable) {
			if r := findExec(rt, "broken"); r == nil || r.Interp != "" {
				t.Errorf("broken rule: %+v", r)
			}
		}},
		{name: "script-interpreter-not-allowed", yaml: "exec:\n  allow: [lonely.sh]\n", wantCode: CodeInterpreter, wantFix: "ruby"},
		{name: "command-script-grants-interpreter", yaml: "", opts: []CompileOption{}, check: func(t *testing.T, rt *RuleTable) {
			if r := findExec(rt, "env"); r == nil || !strings.HasPrefix(r.Source, ExecSourceInterpreter) {
				t.Errorf("env not granted for the command's #!: %+v", r)
			}
			if r := findExec(rt, "python"); r == nil {
				t.Error("python (env's argument) not granted")
			}
		}},
		{name: "dir-entry", yaml: "exec:\n  allow: [\"" + f.bin + "\"]\n", check: func(t *testing.T, rt *RuleTable) {
			if r := findExec(rt, "bin"); r == nil || !r.IsDir {
				t.Errorf("dir entry: %+v", r)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := "command: [python]\n"
			if tc.name == "command-script-grants-interpreter" {
				cmd = "command: [tool.sh]\n"
			}
			c := f.load("version: 0\nname: a\n" + cmd + tc.yaml)
			rt, ds, err := Compile(c, f.machine, f.opts(tc.opts...)...)
			if tc.wantCode != "" {
				if !hasCode(ds, tc.wantCode) {
					t.Fatalf("want %s, got %v\n%s", tc.wantCode, codes(ds), render(ds))
				}
				if tc.wantFix != "" && !strings.Contains(render(ds), tc.wantFix) {
					t.Fatalf("want fix containing %q:\n%s", tc.wantFix, render(ds))
				}
				if err == nil && tc.check == nil {
					return
				}
			}
			if tc.check != nil {
				if err != nil {
					t.Fatalf("%v\n%s", err, render(ds))
				}
				tc.check(t, rt)
			}
		})
	}
}

// TestCompileShebangAsKernelReadsIt: compile asks for the interpreter binfmt_script would exec. A CRLF
// line keeps its '\r' in the name or the argument, and env gets the whole remainder as one argument, so
// none of these scripts can start: compile names that instead of granting /bin/env or python as if it
// could, and an exec.allow script's check warns that the interpreter it needs is covered by nothing.
func TestCompileShebangAsKernelReadsIt(t *testing.T) {
	f := newFixture(t)
	env := filepath.Join(f.bin, "env")
	f.file(filepath.Join(f.bin, "crlf-name.sh"), "#!"+env+"\r\npython\r\n", 0o755)
	f.file(filepath.Join(f.bin, "crlf-arg.sh"), "#!"+env+" python\r\nprint(1)\r\n", 0o755)
	f.file(filepath.Join(f.bin, "two-words.sh"), "#!"+env+" python -u\nprint(1)\n", 0o755)
	for _, tc := range []struct{ script, code, want string }{
		{"crlf-name.sh", CodePathMissing, strconv.Quote(env + "\r")},
		{"crlf-arg.sh", CodeExecNotOnPath, strconv.Quote("python\r")},
		{"two-words.sh", CodeExecNotOnPath, `"python -u"`},
	} {
		t.Run(tc.script, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [" + tc.script + "]\n")
			_, ds, err := Compile(c, f.machine, f.opts()...)
			if !errors.Is(err, ErrInvalidContract) || !hasCode(ds, tc.code) || !strings.Contains(render(ds), tc.want) {
				t.Fatalf("err=%v codes=%v, want %s naming %s\n%s", err, codes(ds), tc.code, tc.want, render(ds))
			}
		})
		t.Run(tc.script+"/exec.allow", func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [" + tc.script + ", " + env + ", python]\n")
			_, ds, err := Compile(c, f.machine, f.opts()...)
			if err != nil || !hasCode(ds, CodeInterpreter) {
				t.Fatalf("err=%v codes=%v, want a %s warning\n%s", err, codes(ds), CodeInterpreter, render(ds))
			}
		})
	}
}

// TestCompileExecSuggestsVersionedSibling: Debian and Ubuntu ship python3 with no python
// symlink, so a contract that grants python by its upstream name resolves nothing on those boxes.
// The fix line should point at the versioned sibling that does resolve, following the general rule
// (name+"3") rather than a hardcoded python special case, and stay silent when no sibling exists.
func TestCompileExecSuggestsVersionedSibling(t *testing.T) {
	f := newFixture(t)
	only3 := filepath.Join(f.root, "only3")
	if err := os.MkdirAll(only3, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(only3, "python3"), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)

	c := f.load("version: 0\nname: a\ncommand: [python3]\nexec:\n  allow: [python]\n")
	_, ds, err := Compile(c, f.machine, f.opts(WithPATH(only3))...)
	if !errors.Is(err, ErrInvalidContract) || !hasCode(ds, CodeExecNotOnPath) {
		t.Fatalf("err=%v codes=%v", err, codes(ds))
	}
	if !strings.Contains(render(ds), `did you mean "python3"?`) {
		t.Fatalf("fix line missing the python3 suggestion:\n%s", render(ds))
	}

	// A name with no versioned sibling on PATH keeps the plain "searched:" fix; nothing to suggest.
	c2 := f.load("version: 0\nname: a\ncommand: [python3]\nexec:\n  allow: [ghost]\n")
	_, ds2, err2 := Compile(c2, f.machine, f.opts(WithPATH(only3))...)
	if !errors.Is(err2, ErrInvalidContract) {
		t.Fatalf("err=%v", err2)
	}
	if strings.Contains(render(ds2), "did you mean") {
		t.Fatalf("unexpected suggestion for a name with no sibling:\n%s", render(ds2))
	}
	if !strings.Contains(render(ds2), "searched: "+only3) {
		t.Fatalf("fix line: %s", render(ds2))
	}
}

// TestCompileExecRelativePATHElement: a relative PATH element (node_modules/.bin, ./bin) names a
// directory under the compile's cwd, as the empty element does, so the rule comes out absolute and
// names the file under WithCwd, never one under the test process's own cwd (E12).
func TestCompileExecRelativePATHElement(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "rbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(f.project, "rbin", "mytool"), string(elf64("", 2)), 0o755)
	c := f.load("version: 0\nname: a\ncommand: [python]\nexec:\n  allow: [mytool]\n")
	rt, ds := f.compile(c, WithPATH("rbin:"+f.bin))
	r := findExec(rt, "mytool")
	if want := filepath.Join(f.project, "rbin", "mytool"); r == nil || r.Path != want {
		t.Fatalf("rule %+v, want Path %q\n%s", r, want, render(ds))
	}
}

// agent-contract.md E17 (a bare IP literal is Static, no DNS), E18 (host-unresolvable: error, warning with Offline) and E19 (a TTL below MinDNSTTL is floored).
func TestCompileNet(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nnet:\n  allow: [\"nope.invalid:443\", \"mcp.internal:80\"]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if !errors.Is(err, ErrInvalidContract) || rt != nil || !hasCode(ds, CodeHostUnresolvable) {
		t.Fatalf("online: err=%v codes=%v", err, codes(ds))
	}
	rt, ds, err = Compile(c, f.machine, f.opts(Offline(), WithDNSTTL(time.Second))...)
	if err != nil || !hasCode(ds, CodeHostUnresolvable) || HasErrors(ds) {
		t.Fatalf("offline: err=%v\n%s", err, render(ds))
	}
	if len(rt.Net[0].IPs) != 0 || rt.Net[0].TTL != MinDNSTTL || len(rt.Net[1].IPs) != 1 {
		t.Errorf("offline rules: %+v", rt.Net)
	}
	// Model bypass is a Load warning; the forwarder hosts still resolve.
	c = f.load("version: 0\nname: a\ncommand: [python]\nmodels: [{provider: anthropic, host: api.anthropic.com, port: 443}]\nnet:\n  allow: [\"api.anthropic.com:443\"]\n")
	rt, _ = f.compile(c)
	if got := rt.Net[0].IPs; len(got) != 2 || got[0].String() != "160.79.104.10" || got[1].String() != "2607:6bc0::10" {
		t.Errorf("addresses not unmapped/deduplicated/sorted: %v", got)
	}
}

func TestCompileManyHostsBoundedPool(t *testing.T) {
	f := newFixture(t)
	var sb strings.Builder
	sb.WriteString("version: 0\nname: a\ncommand: [python]\nnet:\n  allow:\n")
	for i := 0; i < 50; i++ {
		h := fmt.Sprintf("h%d.internal", i)
		f.resolver.table[h] = []netip.Addr{netip.MustParseAddr(fmt.Sprintf("10.1.0.%d", i+1))}
		fmt.Fprintf(&sb, "    - %s:443\n", h)
	}
	c := f.load(sb.String())
	slow := &slowResolver{inner: f.resolver, delay: 20 * time.Millisecond}
	// Serialized, 50 lookups of 20ms take a second; a bounded pool takes a fraction of that. The elapsed time
	// is the best of three compiles (a loaded box's stalls land on one run, a serialization on every one), and
	// the peak-concurrency check below is the load-independent half of the same claim.
	const serialized = 50 * 20 * time.Millisecond
	best := time.Duration(1<<63 - 1)
	rt, _ := f.compile(c, WithResolver(slow))
	for i := 0; i < 3 && best > serialized/2; i++ {
		start := time.Now()
		rt, _ = f.compile(c, WithResolver(slow))
		best = min(best, time.Since(start))
	}
	if best > serialized/2 {
		t.Errorf("lookups serialized: %v, the best of 3 compiles", best)
	}
	slow.mu.Lock()
	peak := slow.max
	slow.mu.Unlock()
	if peak > DefaultDNSParallel || peak < 2 {
		t.Errorf("peak concurrency %d, want 2..%d", peak, DefaultDNSParallel)
	}
	for _, r := range rt.Net {
		if len(r.IPs) != 1 {
			t.Errorf("%s unresolved", r.Host)
		}
	}
}

// slowResolver delays every lookup and records the peak concurrency.
type slowResolver struct {
	inner    Resolver
	delay    time.Duration
	mu       sync.Mutex
	inflight int
	max      int
}

func (s *slowResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	s.inflight++
	if s.inflight > s.max {
		s.max = s.inflight
	}
	s.mu.Unlock()
	time.Sleep(s.delay)
	s.mu.Lock()
	s.inflight--
	s.mu.Unlock()
	return s.inner.LookupNetIP(ctx, network, host)
}

// TestWriteEntryThatIsALinkToNothing: a dangling link stats as missing, and a missing write entry is created by the run,
// so it compiled, and the run stopped on "path vanished since compile" for a path that never existed.
func TestWriteEntryThatIsALinkToNothing(t *testing.T) {
	f := newFixture(t)
	link := filepath.Join(f.root, "out")
	if err := os.Symlink(filepath.Join(f.root, "absent"), link); err != nil {
		t.Fatal(err)
	}
	_, ds, err := f.compileErr(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"" + link + "/\"]\n"))
	if err == nil || !hasCode(ds, CodePathMissing) || !strings.Contains(render(ds), "symbolic link to nothing") {
		t.Errorf("compile: %v\n%s", err, render(ds))
	}
}

// TestLimitsBelowARunsStart: the child stage is a Go process under the run's limits from its first instruction, so a
// limit below what it takes never reaches the agent. pids 5 died with a Go stack dump on the user's terminal, memory
// 4 MiB with "child died before the fd handoff", and memory_high 1 MiB never started at all.
func TestLimitsBelowARunsStart(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, limits string
		refused      bool
		warned       bool
	}{
		{"pids below", "limits:\n  pids: 5\n", true, false},
		{"pids at", "limits:\n  pids: 6\n", false, false},
		{"memory below", "limits:\n  memory: 4MiB\n", false, true},
		{"memory at", "limits:\n  memory: 8MiB\n", false, false},
		{"memory_high below", "limits:\n  memory_high: 1MiB\n", false, true},
		{"unset", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ds, err := f.compileErr(f.load("version: 0\nname: a\ncommand: [python]\n" + tc.limits))
			if (err != nil) != tc.refused {
				t.Errorf("compile: %v, want refused=%v\n%s", err, tc.refused, render(ds))
			}
			if got := hasCode(ds, CodeLimitBelowStart); got != (tc.refused || tc.warned) {
				t.Errorf("limit-below-start reported: %v\n%s", got, render(ds))
			}
		})
	}
}

// TestCeilingsBelowARunsStart: the floor holds the value a run gets, not only the contract's. A machine ceiling of pids
// 3 compiled every contract clean, so every run died the way TestLimitsBelowARunsStart's contracts did, and the
// limit-above-machine fix said "lower limits.pids to 3", a value the floor refuses. The ceiling stays enforced as
// written (E12), so this is a warning naming the ceiling's line.
func TestCeilingsBelowARunsStart(t *testing.T) {
	f := newFixture(t)
	etc := config.Provenance{File: "/etc/tego/config.yaml", Line: 4, Layer: config.LayerEtc}
	for _, tc := range []struct {
		name, limits string
		pids         config.Ceiling[int]
		memory       config.Ceiling[config.ByteSize]
		refused      bool
		want         string // a limit-below-start message
	}{
		{"pids ceiling, contract above it", "limits:\n  pids: 10\n", config.Ceiling[int]{Value: 3, Bounded: true, Source: etc}, config.Ceiling[config.ByteSize]{}, false,
			"the machine's pids ceiling 3 from /etc/tego/config.yaml:4 is below what a run's start takes (6)"},
		{"pids ceiling, no contract limit", "", config.Ceiling[int]{Value: 3, Bounded: true, Source: etc}, config.Ceiling[config.ByteSize]{}, false,
			"the machine's pids ceiling 3 from /etc/tego/config.yaml:4"},
		{"pids ceiling and a contract below the floor", "limits:\n  pids: 4\n", config.Ceiling[int]{Value: 3, Bounded: true, Source: etc}, config.Ceiling[config.ByteSize]{}, true,
			"limits.pids 4 cannot start a run"},
		{"memory ceiling", "", config.Ceiling[int]{}, config.Ceiling[config.ByteSize]{Value: 4 << 20, Bounded: true, Source: etc}, false,
			"the machine's memory ceiling 4MiB from /etc/tego/config.yaml:4"},
		{"pids ceiling at the floor", "", config.Ceiling[int]{Value: 6, Bounded: true, Source: etc}, config.Ceiling[config.ByteSize]{}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := *f.machine
			m.Limits.Pids, m.Limits.Memory, m.Limits.MemoryHigh = tc.pids, tc.memory, config.Ceiling[config.ByteSize]{}
			_, ds, err := Compile(f.load("version: 0\nname: a\ncommand: [python]\n"+tc.limits), &m, f.opts()...)
			if (err != nil) != tc.refused {
				t.Fatalf("compile: %v, want refused=%v\n%s", err, tc.refused, render(ds))
			}
			below := 0
			for _, d := range ds {
				if d.Code == CodeLimitBelowStart {
					below++
					if tc.want == "" || !strings.Contains(d.Message, tc.want) {
						t.Errorf("limit-below-start %q, want one containing %q", d.Message, tc.want)
					}
				}
				if d.Code == CodeLimitAboveMachine && strings.Contains(d.Fix, "lower limits.pids to 3") {
					t.Errorf("the fix suggests a value below the floor: %s", d.Fix)
				}
			}
			if want := map[bool]int{true: 1, false: 0}[tc.want != ""]; below != want {
				t.Errorf("%d limit-below-start diagnostics, want %d\n%s", below, want, render(ds))
			}
		})
	}
}

// agent-contract.md R11 (ceiling precedence) and I2 (Limits never exceed the machine ceiling).
func TestCompileLimitsCeilings(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name   string
		limits string
		want   func(l ResolvedLimits) bool
		warn   bool
	}{
		{"below", "limits:\n  memory: 4GiB\n  cpu: \"1\"\n  pids: 10\n  tokens: 5\n  cost_usd: 1.5\n  wall: 1h\n  stall_after: 1m\n  repeats: 2\n",
			func(l ResolvedLimits) bool {
				return l.MemoryB == 4<<30 && l.CPU == "1" && l.Pids == 10 && l.Tokens == 5 && l.CostUSD == 1.5 && l.Wall == time.Hour && l.StallAfter == time.Minute && l.Repeats == 2
			}, false},
		{"equal", "limits:\n  memory: 32GiB\n  cpu: \"8.0\"\n  pids: 4096\n", func(l ResolvedLimits) bool { return l.MemoryB == 32<<30 && l.CPU == "8.0" && l.Pids == 4096 }, false},
		{"above", "limits:\n  memory: 64GiB\n  cpu: \"16\"\n  pids: 9999\n  tokens: 99999999\n  cost_usd: 1000\n  wall: 48h\n  stall_after: 2h\n  repeats: 50\n",
			func(l ResolvedLimits) bool {
				return l.MemoryB == 32<<30 && l.CPU == "8" && l.Pids == 4096 && l.Tokens == 10_000_000 && l.CostUSD == 200 && l.Wall == 24*time.Hour && l.StallAfter == time.Hour && l.Repeats == 20
			}, true},
		{"inherit", "", func(l ResolvedLimits) bool {
			return l.MemoryB == 32<<30 && l.CPU == "8" && l.MemoryHigh == 0 && l.CPUWeight == 0
		}, false},
		{"memory-high-clamped", "limits:\n  memory: 64GiB\n  memory_high: 48GiB\n  cpu_weight: 50\n", func(l ResolvedLimits) bool { return l.MemoryB == 32<<30 && l.MemoryHigh == 32<<30 && l.CPUWeight == 50 }, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\n" + tc.limits)
			rt, ds := f.compile(c)
			if !tc.want(rt.Limits) {
				t.Errorf("limits: %+v\n%s", rt.Limits, render(ds))
			}
			if got := hasCode(ds, CodeLimitAboveMachine); got != tc.warn {
				t.Errorf("limit-above-machine warning %v want %v:\n%s", got, tc.warn, render(ds))
			}
			if HasErrors(ds) {
				t.Errorf("a ceiling must never be an error:\n%s", render(ds))
			}
		})
	}
	// Unbounded ceilings keep the contract's value and never invent a default (R11).
	c := f.load("version: 0\nname: a\ncommand: [python]\nlimits:\n  memory: 64GiB\n")
	rt, ds, err := Compile(c, &config.Machine{LedgerRoot: config.Setting[string]{Value: f.ledger}}, f.opts()...)
	if err != nil || rt.Limits.MemoryB != 64<<30 || rt.Limits.Pids != 0 || rt.Limits.CPU != "" || hasCode(ds, CodeLimitAboveMachine) {
		t.Errorf("unbounded ceilings: %+v %v", rt.Limits, err)
	}
}

// agent-contract.md R14: auto/"" resolve to the highest ceiling value.
func TestCompileTierAndCapture(t *testing.T) {
	f := newFixture(t)
	tests := []struct {
		name        string
		machineTier backend.Tier
		machineCap  string
		pin         string
		wantTier    backend.Tier
		wantCapture CaptureMode
		warn        bool
	}{
		{"auto-auto", backend.TierAuto, "auto", "", backend.TierBPFLSM, CaptureUprobe, false},
		{"machine-landlock", backend.TierLandlock, "auto", "", backend.TierLandlock, CaptureForwarder, false},
		{"pin-below", backend.TierBPFLSM, "auto", "tier: landlock\n", backend.TierLandlock, CaptureForwarder, false},
		{"pin-above", backend.TierLandlock, "auto", "tier: bpflsm\n", backend.TierLandlock, CaptureForwarder, true},
		{"capture-off", backend.TierAuto, "off", "", backend.TierBPFLSM, CaptureOff, false},
		{"capture-pin-above", backend.TierAuto, "forwarder", "capture: uprobe\n", backend.TierBPFLSM, CaptureForwarder, true},
		{"capture-pin-below", backend.TierAuto, "auto", "capture: off\n", backend.TierBPFLSM, CaptureOff, false},
		{"landlock-uprobe-pin", backend.TierAuto, "auto", "tier: landlock\ncapture: uprobe\n", backend.TierLandlock, CaptureForwarder, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := *f.machine
			m.Tier, m.Capture = tierCeil(tc.machineTier), capCeil(tc.machineCap)
			c := f.load("version: 0\nname: a\ncommand: [python]\n" + tc.pin)
			rt, ds, err := Compile(c, &m, f.opts()...)
			if err != nil {
				t.Fatalf("%v\n%s", err, render(ds))
			}
			if rt.Tier != tc.wantTier || rt.Capture != tc.wantCapture {
				t.Errorf("tier=%s capture=%s want %s %s", rt.Tier, rt.Capture, tc.wantTier, tc.wantCapture)
			}
			if got := hasCode(ds, CodeLimitAboveMachine); got != tc.warn {
				t.Errorf("warning %v want %v:\n%s", got, tc.warn, render(ds))
			}
		})
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nio_uring: true\n")
	if _, ds := f.compile(c); !hasCode(ds, CodeIOUring) {
		t.Errorf("io_uring under landlock must warn: %v", codes(ds))
	}
}

// TestSharedWritableExecAndKernelFSWriteWarn: exec.allow of a directory every user can write (/tmp), or of
// one holding such a directory (/), makes whatever anyone drops there executable, and fs.write on /proc or
// /dev writes to the kernel, other processes and devices; all four compiled without a word. A single device
// file and /dev/shm are not warned about.
func TestSharedWritableExecAndKernelFSWriteWarn(t *testing.T) {
	f := newFixture(t)
	shared := filepath.Join(f.root, "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o1777); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(f.root, "private")
	if err := os.Mkdir(private, 0o755); err != nil {
		t.Fatal(err)
	}
	c := f.load(fmt.Sprintf("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  allow: [%q, %q]\nfs:\n  write: [\"/proc/self/oom_score_adj\", \"/dev\", \"/dev/null\"]\n", shared, private))
	_, ds := f.compile(c)
	got := render(ds)
	for _, want := range []string{
		"exec.allow " + shared + " is writable by every user: anything any process drops there is executable",
		"fs.write \"/proc/self/oom_score_adj\"",
		"reaches procfs",
		"fs.write \"/dev\" grants writes to every device node this uid can open",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("diagnostics lack %q:\n%s", want, got)
		}
	}
	for _, not := range []string{"exec.allow " + private, "fs.write \"/dev/null\" grants", "fs.write \"/dev/null\" reaches"} {
		if strings.Contains(got, not) {
			t.Errorf("diagnostics warn about %q:\n%s", not, got)
		}
	}
	if !worldWritable("/tmp") {
		t.Skip("/tmp is not world-writable here, so / holds no shared writable directory to warn about")
	}
	c = f.load("version: 0\nname: t\ncommand: [\"python\"]\nexec:\n  allow: [\"/\"]\n")
	if _, ds := f.compile(c); !strings.Contains(render(ds), "exec.allow / holds /tmp, which every user can write") {
		t.Errorf("exec.allow / did not warn:\n%s", render(ds))
	}
}

// TestEnvScanCoversTheProjectRoot: the built-in .env scan was rooted at the working
// directory, so a run started from a subdirectory of the project left the project root's .env readable.
// The scan starts at the contract's directory as well, and still covers the working directory when that
// lies elsewhere.
func TestEnvScanCoversTheProjectRoot(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: t\ncommand: [\"python\"]\n")
	sub := filepath.Join(f.project, "out")
	f.file(filepath.Join(sub, ".env.local"), "SECRET=2", 0o600)
	elsewhere := filepath.Join(f.root, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(elsewhere, ".env"), "SECRET=3", 0o600)
	for _, tc := range []struct {
		cwd  string
		want []string
	}{
		{sub, []string{filepath.Join(f.project, ".env"), filepath.Join(sub, ".env.local")}},
		{elsewhere, []string{filepath.Join(f.project, ".env"), filepath.Join(elsewhere, ".env")}},
	} {
		rt, _ := f.compile(c, WithCwd(tc.cwd))
		for _, p := range tc.want {
			if r := findFS(rt, FSDenyRead, p); r == nil || !r.BuiltIn {
				t.Errorf("cwd %s: %s is not a built-in deny_read entry", tc.cwd, p)
			}
		}
		n := 0
		for _, r := range rt.FS {
			if r.Kind == FSDenyRead && r.Path == filepath.Join(sub, ".env.local") {
				n++
			}
		}
		if n > 1 {
			t.Errorf("cwd %s: a directory under both roots was scanned twice into %d rules", tc.cwd, n)
		}
	}
}

func TestCompileEnvRules(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\ncapture: forwarder\nenv:\n  pass: [PATH, TEGO_RUN_ID, HTTPS_PROXY, ANTHROPIC_BASE_URL, LANG]\n  deny: [LANG, TERM]\n  set: {TEGO_TIER: x, OPENAI_BASE_URL: y, KEEP: z}\n")
	rt, ds := f.compile(c)
	if got := strings.Join(rt.Env, ","); got != "PATH,HTTPS_PROXY" {
		t.Errorf("pass list %q", got)
	}
	if len(rt.Set) != 3 || rt.Set["TEGO_TIER"] != "x" {
		t.Errorf("set must keep every value: %v", rt.Set)
	}
	if strings.Join(rt.Deny, ",") != "LANG,TERM" {
		t.Errorf("deny %v", rt.Deny)
	}
	reserved, proxy := 0, 0
	for _, d := range ds {
		switch d.Code {
		case CodeEnvRuntimeReserved:
			reserved++
		case CodeProxyEnv:
			proxy++
		}
	}
	if reserved != 4 || proxy != 1 {
		t.Errorf("reserved=%d proxy=%d:\n%s", reserved, proxy, render(ds))
	}
}

// TestCompileHashMachineIndependent asserts I3: the hash depends on the
// merged contract alone, never on the compiling machine.
func TestCompileHashMachineIndependent(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nlimits:\n  memory: 64GiB\n")
	small := *f.machine
	small.Limits.Memory = bounded(config.ByteSize(1 << 30))
	a, _, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Compile(c, &small, f.opts()...)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash || a.Hash == [32]byte{} {
		t.Errorf("hash differs across machines")
	}
	if a.Limits.MemoryB == b.Limits.MemoryB {
		t.Errorf("ceiling not applied")
	}
}

func TestCompilePreconditions(t *testing.T) {
	f := newFixture(t)
	if _, _, err := Compile(&Contract{}, f.machine); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("hand-built contract: %v", err)
	}
	if _, _, err := Compile(nil, f.machine); !errors.Is(err, ErrNotLoaded) {
		t.Errorf("nil contract: %v", err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\n")
	if _, _, err := Compile(c, nil); err == nil {
		t.Error("nil machine accepted")
	}
	// Evaluate has no error return (§4): an empty table decides, it never fails.
	if got := (&RuleTable{}).Evaluate(Action{Kind: ActionFSRead, Path: "/x"}, backend.TierLandlock); got.Verdict != VerdictAllow || got.Rule != UnmatchedRule {
		t.Errorf("Evaluate on an empty table: %+v", got)
	}
	if got := (*RuleTable)(nil).Evaluate(Action{Kind: ActionFSRead, Path: "/x"}, backend.TierLandlock); got.Verdict != VerdictRefused || got.Rule != InvalidActionRule {
		t.Errorf("Evaluate on a nil table: %+v", got)
	}
	if err := PrintRuleTable(&bytes.Buffer{}, nil); err == nil {
		t.Error("nil table printed")
	}
}

// TestCompileExample compiles examples/agents/retriever.yaml against a
// synthetic machine: only warnings.
func TestCompileExample(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(filepath.Join(f.home, ".gnupg"), 0o700); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "agents", "retriever.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// The example names /work paths and PATH binaries; rewrite them into the fixture. It takes PATH from
	// examples/profiles/base/python-dev, which this fixture's profile of the same name does not pass.
	y := strings.NewReplacer(`"/work/out/"`, `"out/"`, `"/work/config/"`, `"config/"`,
		`"make"`, `"static-tool"`, `"go"`, `"tool.sh"`, "\nenv:\n", "\nenv:\n  pass: [\"PATH\"]\n").Replace(string(src))
	f.file(filepath.Join(f.bin, "python3"), string(elf64("/lib64/ld-fake.so.2", 3)), 0o755)
	for _, h := range []string{"pypi.org", "files.pythonhosted.org"} {
		f.resolver.table[h] = []netip.Addr{netip.MustParseAddr("151.101.0.223")}
	}
	f.file(filepath.Join(f.bin, "pip"), string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
	c := f.load(y)
	rt, ds := f.compile(c)
	if HasErrors(ds) {
		t.Fatalf("example compiled with errors:\n%s", render(ds))
	}
	if findFS(rt, FSDenyRead, filepath.Join(f.home, ".gnupg")) == nil {
		t.Error("profile deny_read entry lost in the merge")
	}
	if rt.Record != RecordSummary || rt.Limits.Pids != 512 || rt.Limits.Wall != 2*time.Hour {
		t.Errorf("contract must win scalars over the profile: %+v record=%s", rt.Limits, rt.Record)
	}
	var buf bytes.Buffer
	if err := PrintRuleTable(&buf, rt); err != nil {
		t.Fatal(err)
	}
	t.Logf("\n%s%s", render(ds), buf.String())
}
