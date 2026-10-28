// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// updateLiveOff rewrites testdata/live_off_golden. It is its own flag, not -update, so refreshing another golden
// never rewrites this one: the files were written at the commit before the live: section existed (ADR 0125 R1).
var updateLiveOff = flag.Bool("update-live-off", false, "rewrite testdata/live_off_golden (only at a commit whose compile is the reference)")

// liveOffGolden is where each contract's compiled table and diagnostics were written before ADR 0125.
const liveOffGolden = "testdata/live_off_golden"

// goldenResolver answers every host with one documentation address, so no golden depends on DNS.
type goldenResolver struct{}

func (goldenResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

// hostFields are the RuleTable fields whose value is the host's, not the contract's: the device, link count and
// mount facts of a path. The golden drops them, so it holds on another machine with the same layout.
var hostFields = map[string]bool{
	"Device": true, "Nlink": true, "Mount": true, "Filesystem": true, "IsMountPoint": true, "Overlay": true,
	"Btrfs": true, "FileMountPoint": true, "DirCaseExact": true,
}

// stripHost removes hostFields from a decoded JSON value, at any depth.
func stripHost(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if hostFields[k] {
				delete(x, k)
				continue
			}
			x[k] = stripHost(e)
		}
	case []any:
		for i, e := range x {
			x[i] = stripHost(e)
		}
	}
	return v
}

// goldenContract is one contract the golden covers: its name in the golden directory and its file.
type goldenContract struct {
	name, path string
}

// liveKey finds a top-level live: key, which takes a contract out of the live-off set.
var liveKey = regexp.MustCompile(`(?m)^live:`)

// liveOffContracts lists every contract under pkg/spec/agent/testdata/good and examples/, and tego
// init's starter (written to dir with its name filled in).
func liveOffContracts(t *testing.T, dir string) []goldenContract {
	t.Helper()
	var out []goldenContract
	add := func(root, prefix string) {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || (filepath.Ext(p) != ".yaml" && filepath.Ext(p) != ".yml") {
				return nil
			}
			if strings.Contains(filepath.ToSlash(p), "/profiles/") {
				return nil // a profile is compiled through the contracts that extend it
			}
			if body, err := os.ReadFile(p); err == nil && liveKey.Match(body) {
				return nil // a contract that sets live: is not a live-off contract (examples/live-modes-demo)
			}
			rel, _ := filepath.Rel(root, p)
			abs, err := filepath.Abs(p) // Compile places the contract as the kernel walks it, so never a relative "..".
			if err != nil {
				return err
			}
			out = append(out, goldenContract{name: prefix + strings.ReplaceAll(filepath.ToSlash(rel), "/", "__"), path: abs})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	add(filepath.Join("testdata", "good"), "testdata__good__")
	add(filepath.Join(repoRoot, "examples"), "examples__")
	starter, err := os.ReadFile(filepath.Join(repoRoot, "internal", "cli", "agent.starter.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(p, bytes.ReplaceAll(starter, []byte("__NAME__"), []byte("starter")), 0o600); err != nil {
		t.Fatal(err)
	}
	out = append(out, goldenContract{name: "internal__cli__agent.starter.yaml", path: p})
	for name, body := range liveOffVariants {
		vd := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Join(vd, "secret"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(vd, "secret", "key"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		vp := filepath.Join(vd, "agent.yaml")
		if err := os.WriteFile(vp, []byte("version: 0\nname: "+name+"\ncommand: [python3, agent.py]\nenv: {pass: [PATH, HOME]}\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, goldenContract{name: "variant__" + name, path: vp})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// liveOffVariants are contract shapes the fence touches (deny_read, net.allow, exec allow and deny, fs.reads, each
// tier), beside the repository's contracts, most of which are templates that compile only once filled in.
var liveOffVariants = map[string]string{
	"cgroup-all": "tier: cgroup\nfs: {write: [./out/], deny_read: [./secret/], reads: held}\n" +
		"net: {allow: [api.example.com:443, \"10.0.0.0/8:5432\"]}\nexec: {allow: [python3, git, \"git status\"], deny: [\"git push\", curl]}\n",
	"bpflsm-open":    "tier: bpflsm\nfs: {write: [./out/]}\n",
	"landlock-unix":  "tier: landlock\nfs: {write: [./out/], deny_read: [./secret/key]}\nnet: {allow: [\"unix:/run/user/1000/bus\"]}\n",
	"deny-list-exec": "fs: {write: [./out/], deny_read: []}\nexec: {deny: [psql, \"rm -r\"]}\nnet: {allow: []}\n",
	"reads-direct":   "tier: cgroup\nfs: {write: [./out/], deny_read: [./secret/], reads: direct}\n",
}

// compileGolden compiles one contract hermetically: a fixed home, PATH, clock and resolver, no mount probe, every
// tier built. It returns the table's JSON with the host's fields dropped and the diagnostics, every temporary and
// repository path replaced by a placeholder; "" when the file is not a contract (verdicts, a profile).
func compileGolden(t *testing.T, c goldenContract, home, bin string, subst *strings.Replacer) string {
	t.Helper()
	data, err := os.ReadFile(c.path)
	if err != nil {
		t.Fatal(err)
	}
	var ct *Contract
	var loadDs []Diagnostic
	for _, src := range []ProfileSource{dirSource{root: filepath.Join(repoRoot, "examples", "profiles")}, testProfiles()} {
		if ct, loadDs, err = LoadBytes(c.path, data, src); err == nil {
			break
		}
	}
	if err != nil {
		return ""
	}
	machine, mds, err := config.LoadSources(config.Sources{}, home, 1000, config.TrustAbort)
	if err != nil {
		t.Fatalf("machine: %v %v", err, mds)
	}
	rt, ds, err := Compile(ct, machine, WithCwd(filepath.Dir(c.path)), WithHome(home), WithPATH(bin), WithMountInfo(""),
		WithResolver(goldenResolver{}), WithTiers(backend.Tiers()...), WithChainAnchor(filepath.Join(home, ".tego", "chain.log")),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }))
	var b strings.Builder
	b.WriteString("load:\n" + render(loadDs) + "compile:\n" + render(ds))
	if err != nil {
		b.WriteString("error: " + err.Error() + "\n")
	}
	if rt != nil {
		// ExecCommands holds the host's file identities and the tool rows' matchers (funcs): only its entries are
		// the contract's.
		cp := *rt
		var cmds []ExecCommandEntry
		if cp.ExecCommands != nil {
			for _, e := range cp.ExecCommands.Entries {
				p := *e.Pattern
				p.Row = nil // the tool row's matchers are code, not the contract
				p.Opts = append([]execmatch.PatOpt(nil), p.Opts...)
				for i := range p.Opts {
					p.Opts[i].Opt = nil
				}
				e.Pattern = &p
				cmds = append(cmds, e)
			}
		}
		cp.ExecCommands = nil
		cp.AskDenyWrite = dropCheckoutAbove(cp.AskDenyWrite)
		raw, err := json.Marshal(struct {
			Table        any // *RuleTable with ExecCommands, whose matchers are funcs, set nil above
			ExecCommands any // []ExecCommandEntry with the tool rows and their matchers taken out above
		}{&cp, cmds})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		out, err := json.MarshalIndent(stripHost(v), "", " ")
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("table:\n")
		b.Write(out)
		b.WriteString("\n")
	}
	return subst.Replace(b.String())
}

// dropCheckoutAbove drops the built-in deny_write rows fsAsk adds for a protected directory (.claude) at or above the
// checkout itself: they exist only where the checkout lies inside such a directory, as a linked worktree under the
// main checkout's .claude does, so a golden that kept them held in that one place and failed in a plain clone and on
// CI. Rows inside the checkout are the contract's and stay. An emptied list is nil, as a plain clone
// compiles it.
func dropCheckoutAbove(rows []FSRule) []FSRule {
	root, err := filepath.Abs(repoRoot)
	if err != nil || rows == nil {
		return rows
	}
	var out []FSRule
	for _, r := range rows {
		if r.BuiltIn && r.Pos == (Pos{}) && isAncestorOrSelf(r.Path, root) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// goldenBin is a PATH holding a stub for every program name a contract under test runs, so no exec entry is the
// host's: each stub is neither ELF nor a #! script, so no loader or interpreter of the host is granted from it.
func goldenBin(t *testing.T, dir string) {
	t.Helper()
	for _, n := range []string{"python3", "python", "node", "npm", "npx", "git", "claude", "codex", "sh", "bash",
		"ls", "cat", "env", "pip", "pip3", "uv", "make", "go", "curl", "jq", "rg", "grep", "sed", "awk", "true",
		"psql", "agent", "fixture", "tego", "sleep", "echo", "find", "head", "tail", "wc", "sort", "diff", "mkdir",
		"rm", "cp", "mv", "touch", "chmod", "pytest", "ruff", "black", "tsc", "yarn", "pnpm", "deno", "bun", "cargo",
		"rustc", "java", "mvn", "gradle", "docker", "kubectl", "ssh", "scp", "rsync", "wget", "tar", "gzip", "unzip",
		"zip", "less", "more", "vim", "nano", "code", "gh", "aws", "gcloud", "az", "terraform", "helm", "openssl", "tr", "date",
		"mcp-postgres"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("stub\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// goldenHome makes the credential files the example contracts name in deny_read, so they compile to a table.
func goldenHome(t *testing.T, home string) {
	t.Helper()
	for _, d := range []string{".ssh", ".aws", ".codex/sessions"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{".netrc", ".pypirc", ".team-token", ".codex/auth.json", ".codex/config.toml", ".codex/history.jsonl"} {
		if err := os.WriteFile(filepath.Join(home, f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLiveOffGolden is ADR 0125 R1: every contract with no live: key compiles to the table and diagnostics it
// compiled to before the live: section existed, byte for byte. The golden was written at that commit
// (-update-live-off); only an x86-64 host shares its loader paths.
func TestLiveOffGolden(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the golden names x86-64 loader paths")
	}
	tmp := t.TempDir()
	home, bin, starter := filepath.Join(tmp, "home"), filepath.Join(tmp, "bin"), filepath.Join(tmp, "starter")
	for _, d := range []string{home, bin, starter} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	goldenBin(t, bin)
	goldenHome(t, home)
	root, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	pairs := []string{home, "$HOME", bin, "$BIN", starter, "$STARTER", root, "$REPO", tmp, "$TMP"}
	// In a linked worktree the repository's own state (its .claude, the git directory) lies in the main checkout:
	// it is $REPO too, as it is in a plain checkout. The worktree's root comes first, since it begins with the main one.
	if g, err := os.ReadFile(filepath.Join(root, ".git")); err == nil {
		if main, _, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(string(g)), "gitdir: "), "/.git/worktrees/"); ok {
			pairs = append(pairs, main, "$REPO")
		}
	}
	subst := strings.NewReplacer(pairs...)
	n := 0
	for _, c := range liveOffContracts(t, starter) {
		got := compileGolden(t, c, home, bin, subst)
		if got == "" {
			continue
		}
		n++
		file := filepath.Join(liveOffGolden, c.name+".golden")
		if *updateLiveOff {
			if err := os.MkdirAll(liveOffGolden, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if string(want) != got {
			t.Errorf("%s: the compiled table or its diagnostics changed with no live: key\n%s", c.name, firstDiff(string(want), got))
		}
	}
	if n < 15 {
		t.Fatalf("compiled %d contracts: too few to prove anything", n)
	}
}

// firstDiff shows the first line where two goldens differ.
func firstDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return "line " + strconv.Itoa(i+1) + ":\n-" + a + "\n+" + b
		}
	}
	return ""
}

// liveFixture is a fixture whose resolver answers the fence's hosts.
func liveFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.resolver.table["api.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	f.resolver.table["api.stripe.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.30")}
	f.resolver.table["localhost"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	return f
}

// liveContract is a cgroup contract with a write entry, a deny_read entry, net and exec allow-lists and an exec.deny
// entry, plus the live: section given.
func liveContract(f *fixture, live string) string {
	return "version: 0\nname: fence\ncommand: [python, agent.py]\ntier: cgroup\n" +
		"fs:\n  write: [out/]\n  deny_read: [secrets/]\n" +
		"net:\n  allow: [\"api.example.com:443\"]\n" +
		"exec:\n  allow: [python]\n  deny: [static-tool]\n" +
		"env: {pass: [PATH, HOME]}\n" + live
}

// compileLiveErr compiles yaml and returns the diagnostics, failing unless compile refused it.
func compileLiveErr(t *testing.T, f *fixture, yaml string, extra ...CompileOption) []Diagnostic {
	t.Helper()
	c := f.load(yaml)
	rt, ds, err := Compile(c, f.machine, f.opts(extra...)...)
	if err == nil || rt != nil {
		t.Fatalf("compile accepted it:\n%s", render(ds))
	}
	return ds
}

// hasLiveCode reports whether ds holds a diagnostic of code and severity whose message holds every one of words.
func hasLiveCode(ds []Diagnostic, code, severity string, words ...string) bool {
	for _, d := range ds {
		if d.Code != code || d.Severity != severity {
			continue
		}
		ok := true
		for _, w := range words {
			ok = ok && strings.Contains(d.Message+" "+d.Fix, w)
		}
		if ok {
			return true
		}
	}
	return false
}

// TestLiveFenceMergesPerKind: an Adjustable fence compiles into the kernel layers' entries, each kind its own way,
// and RuleTable.Live names every entry as the live overlay does (ADR 0125 decision 2).
func TestLiveFenceMergesPerKind(t *testing.T) {
	f := liveFixture(t)
	c := f.load(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    read: [secrets/]\n"+
		"    net: [\"API.Stripe.com.:443\", \"[2001:db8::1]:8443\", \"192.0.2.40:22\"]\n"+
		"    exec: ["+filepath.Join(f.bin, "static-tool")+", "+filepath.Join(f.bin, "env")+"]\n"))
	rt, ds := f.compile(c)
	if !rt.Adjustable() {
		t.Fatalf("table is not Adjustable: %+v", rt.Live)
	}
	secrets := filepath.Join(f.project, "secrets")
	want := []LiveEntry{
		{Kind: LiveKindRead, Value: secrets, Source: LiveSourceDeny, Raw: "secrets/"},
		{Kind: LiveKindNet, Value: "api.stripe.com:443", Source: LiveSourceNew, Raw: "API.Stripe.com.:443"},
		{Kind: LiveKindNet, Value: "[2001:db8::1]:8443", Source: LiveSourceNew, Raw: "[2001:db8::1]:8443"},
		{Kind: LiveKindNet, Value: "192.0.2.40:22", Source: LiveSourceNew, Raw: "192.0.2.40:22"},
		{Kind: LiveKindExec, Value: filepath.Join(f.bin, "static-tool"), Source: LiveSourceDeny, Raw: filepath.Join(f.bin, "static-tool")},
		{Kind: LiveKindExec, Value: filepath.Join(f.bin, "env"), Source: LiveSourceNew, Raw: filepath.Join(f.bin, "env")},
	}
	if len(rt.Live.Entries) != len(want) {
		t.Fatalf("entries %+v", rt.Live.Entries)
	}
	for i, w := range want {
		g := rt.Live.Entries[i]
		if g.Kind != w.Kind || g.Value != w.Value || g.Source != w.Source || g.Raw != w.Raw || g.Pos.Line == 0 {
			t.Errorf("entry %d = %+v, want %+v", i, g, w)
		}
	}
	// Read: the deny_read entry is gone from the table, the built-in list stays on, and reads are held.
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.Path == secrets {
			t.Errorf("deny_read %s still compiled: %+v", secrets, r)
		}
	}
	if !builtInRefused(rt, filepath.Join(f.home, ".ssh")) {
		t.Error("~/.ssh is no longer refused")
	}
	if rt.Reads.Mode != ReadsHeld {
		t.Errorf("reads %s, want held", rt.Reads.Mode)
	}
	if !hasLiveCode(ds, CodeHeldReads, SeverityWarning, "live.fence has read entries", "fs.reads: held") {
		t.Errorf("no held-reads finding:\n%s", render(ds))
	}
	// Net: each entry is a TCP-only net.allow rule named after the fence entry: only a TCP connect is relayed, so a
	// UDP datagram to a fence destination stays refused by the kernel rows.
	for _, v := range []string{"api.stripe.com:443", "[2001:db8::1]:8443", "192.0.2.40:22"} {
		found := false
		for _, r := range rt.Net {
			if r.Raw == "tcp://"+v {
				found = true
				if !r.Fence || r.RuleName() != LiveFenceRule(LiveKindNet, v) || r.Proto != ProtoTCP {
					t.Errorf("net rule %s: fence %v name %s proto %s", v, r.Fence, r.RuleName(), r.Proto)
				}
			}
		}
		if !found {
			t.Errorf("no net rule for %s", v)
		}
	}
	// Exec: the deny entry is gone, and both programs are allow rules named after the fence entry.
	if rt.ExecCommands != nil {
		for _, e := range rt.ExecCommands.Entries {
			if e.Pattern.Entry == "static-tool" && e.Pattern.List != execmatch.ListAllow {
				t.Errorf("exec.deny static-tool still compiled")
			}
		}
	}
	for _, p := range []string{filepath.Join(f.bin, "static-tool"), filepath.Join(f.bin, "env")} {
		found := false
		for _, r := range rt.Exec {
			if r.Path == p {
				found = true
				if !r.Fence || r.RuleName() != LiveFenceRule(LiveKindExec, p) {
					t.Errorf("exec rule %s: fence %v name %s", p, r.Fence, r.RuleName())
				}
			}
		}
		if !found {
			t.Errorf("no exec rule for %s", p)
		}
	}
	// The contract as written, and its hash, are untouched.
	if got := rt.Contract.FS.DenyRead; len(got) != 1 || got[0] != "secrets/" {
		t.Errorf("RuleTable.Contract's deny_read changed: %v", got)
	}
	if len(rt.Contract.Net.Allow) != 1 || len(rt.Contract.Exec.Allow) != 1 || len(rt.Contract.Exec.Deny) != 1 {
		t.Errorf("RuleTable.Contract changed: %+v %+v", rt.Contract.Net, rt.Contract.Exec)
	}
	if h, _ := c.Hash(); h != rt.Hash {
		t.Error("contract_hash is not the written contract's")
	}
	// The print names the mode, the fence and the held reads.
	var b strings.Builder
	if err := PrintRuleTable(&b, rt); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"adjustable (live both ways)", "fence     6 entries, sha256 " + rt.Live.SHA256, "api.stripe.com:443", "best effort", "held at every tier"} {
		if !strings.Contains(b.String(), w) {
			t.Errorf("print lacks %q:\n%s", w, b.String())
		}
	}
}

// builtInRefused reports whether a built-in deny_read rule, compiled or absent at compile, covers p.
func builtInRefused(rt *RuleTable, p string) bool {
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.BuiltIn && isAncestorOrSelf(r.Path, p) {
			return true
		}
	}
	for _, a := range rt.AbsentDenyRead {
		if isAncestorOrSelf(a.Path, p) {
			return true
		}
	}
	return false
}

// TestLiveFenceKeepsBuiltInDenyRead is the deny_read nil trap: a fence that takes out the only deny_read entry the
// person wrote leaves the list nil, the built-in credential list, never [] (which turns it off).
func TestLiveFenceKeepsBuiltInDenyRead(t *testing.T) {
	f := liveFixture(t)
	rt, ds := f.compile(f.load(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    read: [secrets/]\n")))
	for _, p := range []string{filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".aws"), filepath.Join(f.home, ".netrc")} {
		if !builtInRefused(rt, p) {
			t.Errorf("%s is no longer refused", p)
		}
	}
	if hasLiveCode(ds, CodeDenyReadDisabled, SeverityWarning) {
		t.Errorf("the built-in list was turned off:\n%s", render(ds))
	}
}

// TestLiveRuleNamesMatchEntries: every rule the fence added is named exactly as its LiveEntry, and no other rule is.
func TestLiveRuleNamesMatchEntries(t *testing.T) {
	f := liveFixture(t)
	rt, _ := f.compile(f.load(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    net: [\"api.stripe.com:443\"]\n    exec: ["+filepath.Join(f.bin, "env")+"]\n")))
	names := map[string]bool{}
	for _, e := range rt.Live.Entries {
		names[e.Rule()] = true
	}
	fenced := 0
	for _, r := range rt.Net {
		if r.Fence != names[r.RuleName()] {
			t.Errorf("net rule %s: fence %v", r.RuleName(), r.Fence)
		}
		if r.Fence {
			fenced++
		}
	}
	for _, r := range rt.Exec {
		if r.Fence != names[r.RuleName()] {
			t.Errorf("exec rule %s: fence %v", r.RuleName(), r.Fence)
		}
		if r.Fence {
			fenced++
		}
	}
	if fenced < 2 {
		t.Errorf("%d fence rules, want one per entry", fenced)
	}
	if (FSRule{Path: "/a", Fence: true}).RuleName() != "live.fence[read:/a]" {
		t.Error("FSRule fence name")
	}
}

// TestLiveDigestIsStable: the fence's digest is the sha256 of its kind, value and source triples in order, the same
// on every compile, and it changes with any of them.
func TestLiveDigestIsStable(t *testing.T) {
	es := []LiveEntry{{Kind: LiveKindNet, Value: "a.example:443", Source: LiveSourceNew, Raw: "A.example:443", Pos: Pos{Line: 3}}}
	const want = `[{"Kind":"net","Value":"a.example:443","Source":"new"}]`
	sum := sha256.Sum256([]byte(want))
	if got := liveDigest(es); got != hex.EncodeToString(sum[:]) {
		t.Errorf("digest %s, want sha256(%s)", got, want)
	}
	es2 := []LiveEntry{{Kind: LiveKindNet, Value: "a.example:443", Source: LiveSourceNew, Raw: "other", Pos: Pos{Line: 9}}}
	if liveDigest(es) != liveDigest(es2) {
		t.Error("digest depends on Raw or Pos")
	}
	es2[0].Source = LiveSourceDeny
	if liveDigest(es) == liveDigest(es2) {
		t.Error("digest ignores Source")
	}
	empty := sha256.Sum256([]byte("[]"))
	if liveDigest(nil) != hex.EncodeToString(empty[:]) {
		t.Error("an empty fence's digest is not sha256([])")
	}
	f := liveFixture(t)
	yaml := liveContract(f, "live:\n  mode: adjustable\n  fence:\n    net: [\"api.stripe.com:443\"]\n")
	a, _ := f.compile(f.load(yaml))
	b, _ := f.compile(f.load(yaml))
	if a.Live.SHA256 != b.Live.SHA256 || a.Live.SHA256 == "" {
		t.Errorf("digest differs between compiles: %s %s", a.Live.SHA256, b.Live.SHA256)
	}
}

// TestHoldsFSNotificationsOnlyAdjustable: an Adjustable table keeps every fs notification with the supervisor (ADR
// 0125 decision 6); Locked, explicit or absent, does not.
func TestHoldsFSNotificationsOnlyAdjustable(t *testing.T) {
	f := liveFixture(t)
	for _, tc := range []struct {
		live string
		want bool
	}{
		{"", false},
		{"live: {mode: locked}\n", false},
		{"live: {mode: adjustable}\n", true},
		{"live:\n  mode: adjustable\n  fence: {net: [\"api.stripe.com:443\"]}\n", true},
	} {
		rt, _ := f.compile(f.load(liveContract(f, tc.live)))
		if got := rt.HoldsFSNotifications(); got != tc.want {
			t.Errorf("%q: HoldsFSNotifications %v, want %v", tc.live, got, tc.want)
		}
		if got := rt.Adjustable(); got != tc.want {
			t.Errorf("%q: Adjustable %v", tc.live, got)
		}
		if !tc.want && rt.Live != nil {
			t.Errorf("%q: Live %+v, want nil", tc.live, rt.Live)
		}
	}
}

// TestLiveTierCheckMessages: Adjustable is allowed at cgroup and bpflsm only.
func TestLiveTierCheckMessages(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if err := LiveTierCheck(tier, false); err != nil {
			t.Errorf("%s: %v", tier, err)
		}
	}
	const landlock = "live.mode: adjustable needs tier cgroup or bpflsm. At tier landlock Tego keeps Adjustable off by policy: its live refusals would rest on the supervisor alone, while at cgroup and bpflsm they can move into kernel checks Tego already runs there (ADR 0125). Use live.mode: locked, or tier: cgroup (needs root)"
	err := LiveTierCheck(backend.TierLandlock, false)
	if err == nil || err.Error() != landlock || !errors.Is(err, ErrLiveTier) {
		t.Errorf("landlock: %v", err)
	}
	if err := LiveTierCheck(backend.TierCgroup, true); err == nil || !errors.Is(err, ErrLiveTier) || !strings.Contains(err.Error(), "--observe") {
		t.Errorf("observe: %v", err)
	}
	if err := LiveTierCheck(backend.TierObserve, false); err == nil {
		t.Error("tier observe allowed")
	}
}

// TestLiveDiagnostics: each refusal compile makes of a live: section, and the local-destination warning.
func TestLiveDiagnostics(t *testing.T) {
	f := liveFixture(t)
	adj := func(fence string) string { return "live:\n  mode: adjustable\n  fence:\n" + fence }
	for _, tc := range []struct {
		name, live, yaml string
		code             string
		words            []string
		opts             []CompileOption
	}{
		{name: "mode", live: "live: {mode: loose}\n", code: CodeLiveMode, words: []string{`"loose"`}},
		{name: "locked fence", live: "live:\n  mode: locked\n  fence: {net: [\"api.stripe.com:443\"]}\n", code: CodeLiveLockedFence},
		{name: "no mode fence", live: "live:\n  fence: {net: [\"api.stripe.com:443\"]}\n", code: CodeLiveLockedFence},
		{name: "tier landlock", yaml: strings.Replace(liveContract(f, "live: {mode: adjustable}\n"), "tier: cgroup", "tier: landlock", 1),
			code: CodeLiveTier, words: []string{"At tier landlock Tego keeps Adjustable off by policy"}},
		{name: "observe", live: "live: {mode: adjustable}\n", code: CodeLiveTier, words: []string{"--observe"}, opts: []CompileOption{WithObserve()}},
		{name: "too many", live: adj("    net: [" + manyHosts(65) + "]\n"), code: CodeLiveTooMany},
		{name: "read allowed", live: adj("    read: [config/]\n"), code: CodeLiveFenceAllowed, words: []string{"tego block --for"}},
		{name: "net allowed", live: adj("    net: [\"API.example.com:443\"]\n"), code: CodeLiveFenceAllowed, words: []string{"tego block --for"}},
		{name: "exec allowed", live: adj("    exec: [" + filepath.Join(f.bin, "python") + "]\n"), code: CodeLiveFenceAllowed},
		{name: "read write", live: adj("    read: [out/]\n"), code: CodeLiveFenceWrite, words: []string{"renamed out from under it", "ADR 0125"}},
		{name: "read above write", live: adj("    read: [.]\n"), code: CodeLiveFenceWrite},
		{name: "own state", live: adj("    read: [~/.tego]\n"), code: CodeLiveFenceEntry, words: []string{"Tego's own state"}},
		{name: "read without exec allow", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "exec:\n  allow: [python]\n  deny: [static-tool]\n", "", 1),
			code: CodeLiveFenceEntry, words: []string{"needs an exec.allow list"}},
		{name: "read under an exec deny-list", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "  allow: [python]\n", "", 1),
			code: CodeLiveFenceEntry, words: []string{"needs an exec.allow list"}},
		{name: "exec allow above", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "allow: [python]", "allow: [python, \""+f.project+"/\"]", 1),
			code: CodeLiveFenceEntry, words: []string{"lies inside exec.allow", "be read"}},
		{name: "exec allow at", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "allow: [python]", "allow: [python, \""+filepath.Join(f.project, "secrets")+"/\"]", 1),
			code: CodeLiveFenceEntry, words: []string{"lies inside exec.allow"}},
		{name: "exec allow beneath", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "allow: [python]", "allow: [python, \""+filepath.Join(f.project, "secrets", "tool")+"\"]", 1),
			code: CodeLiveFenceEntry, words: []string{"holds exec.allow"}},
		{name: "exec pattern beneath", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "allow: [python]", "allow: [python, \""+filepath.Join(f.project, "secrets", "tool")+" --x\"]", 1),
			code: CodeLiveFenceEntry, words: []string{"holds exec.allow"}},
		{name: "builtin", yaml: strings.Replace(liveContract(f, adj("    read: [~/.ssh]\n")), "deny_read: [secrets/]", "deny_read: [secrets/, ~/.ssh]", 1),
			code: CodeLiveFenceEntry, words: []string{"built-in"}},
		{name: "inside deny_read", live: adj("    read: [secrets/key.pem]\n"), code: CodeLiveFenceEntry, words: []string{"name that deny_read entry itself"}},
		{name: "unix", live: adj("    net: [\"unix:/run/user/1000/bus\"]\n"), code: CodeLiveFenceEntry, words: []string{"the user bus, systemd, docker, tmux"}},
		{name: "abstract", live: adj("    net: [\"@bus\"]\n"), code: CodeLiveFenceEntry, words: []string{"the user bus"}},
		{name: "no port", live: adj("    net: [api.stripe.com]\n"), code: CodeLiveFenceEntry, words: []string{"names no port"}},
		{name: "range", live: adj("    net: [\"10.0.0.0/8:443\"]\n"), code: CodeLiveFenceEntry},
		{name: "no net section", yaml: strings.Replace(liveContract(f, adj("    net: [\"api.stripe.com:443\"]\n")), "net:\n  allow: [\"api.example.com:443\"]\n", "", 1),
			code: CodeLiveFenceEntry, words: []string{"no net: section"}},
		{name: "exec relative", live: adj("    exec: [bin/tool]\n"), code: CodeLiveFenceEntry, words: []string{"not an absolute program path"}},
		{name: "exec dir", live: adj("    exec: [" + f.bin + "/]\n"), code: CodeLiveFenceEntry},
		{name: "exec missing", live: adj("    exec: [" + filepath.Join(f.bin, "nope") + "]\n"), code: CodeLiveFenceEntry, words: []string{"names no program file"}},
		{name: "twice", live: adj("    net: [\"api.stripe.com:443\", \"api.stripe.com:443\"]\n"), code: CodeLiveFenceEntry, words: []string{"twice"}},
		{name: "io_uring", yaml: strings.Replace(liveContract(f, adj("    net: [\"api.stripe.com:443\"]\n")), "tier: cgroup", "tier: cgroup\nio_uring: true", 1),
			code: CodeSchema, words: []string{"requires io_uring disabled"}},
		{name: "reads direct", yaml: strings.Replace(liveContract(f, adj("    read: [secrets/]\n")), "deny_read: [secrets/]", "deny_read: [secrets/]\n  reads: direct", 1),
			code: CodeLiveReadsDirect},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := tc.yaml
			if yaml == "" {
				yaml = liveContract(f, tc.live)
			}
			ds := compileLiveErr(t, f, yaml, tc.opts...)
			if !hasLiveCode(ds, tc.code, SeverityError, tc.words...) {
				t.Errorf("no [%s] error with %q:\n%s", tc.code, tc.words, render(ds))
			}
		})
	}
	t.Run("in profile", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("version: 0\nname: p\nlive: {mode: adjustable}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, ds, err := LoadBytes(filepath.Join(f.project, "agent.yaml"), []byte(liveContract(f, "extends: p\n")), dirSource{root: dir})
		if err == nil || !hasLiveCode(ds, CodeLiveInProfile, SeverityError, "live") {
			t.Errorf("a profile's live: was not refused: %v\n%s", err, render(ds))
		}
	})
	t.Run("local", func(t *testing.T) {
		_, ds := f.compile(f.load(liveContract(f, adj("    net: [\"127.0.0.1:8080\", \"localhost:9000\"]\n"))))
		n := 0
		for _, d := range ds {
			if d.Code == CodeLiveFenceLocal && d.Severity == SeverityWarning && strings.Contains(d.Message, "a local service may run commands outside the run; Tego cannot tell") {
				n++
			}
		}
		if n != 2 {
			t.Errorf("%d local warnings, want 2:\n%s", n, render(ds))
		}
	})
}

// manyHosts is n distinct net fence entries.
func manyHosts(n int) string {
	hs := make([]string, n)
	for i := range hs {
		hs[i] = `"h` + strconv.Itoa(i) + `.example:443"`
	}
	return strings.Join(hs, ", ")
}

// TestLiveNetValueMatchesLiveblock: a net fence entry's value is what internal/liveblock.Normalize names the same
// destination (a copy of its rules, since pkg/spec imports nothing from internal): a run is refused at start whose
// fence value is not in that form.
func TestLiveNetValueMatchesLiveblock(t *testing.T) {
	for raw, want := range map[string]string{
		"API.Stripe.com:443":   "api.stripe.com:443",
		"api.stripe.com.:443":  "api.stripe.com:443",
		"192.0.2.1:22":         "192.0.2.1:22",
		"[2001:DB8::1]:8443":   "[2001:db8::1]:8443",
		"[::ffff:192.0.2.1]:5": "192.0.2.1:5",
		"my-host-1.internal:1": "my-host-1.internal:1",
	} {
		got, msg, _ := liveNetValue(raw)
		if got != want || msg != "" {
			t.Errorf("%q: %q %q, want %q", raw, got, msg, want)
		}
	}
	for _, raw := range []string{"api.stripe.com", "192.0.2.1", "host:0", "host:65536", "host:08", "300.1.2.3:4", "tcp://h:1", "unix:/x", "/run/x", "@x", "10.0.0.0/8:1", "-h:1", "my_host.internal:1"} {
		if got, msg, _ := liveNetValue(raw); msg == "" {
			t.Errorf("%q accepted as %q", raw, got)
		}
	}
}

// TestLiveFenceReadLinks: a fence read entry that is or passes through a link is refused, a deny_read
// entry spelled through a link is matched by where it leads, and a write entry spelled through a link onto the
// fenced path's parent is refused like the same entry spelled directly.
func TestLiveFenceReadLinks(t *testing.T) {
	f := liveFixture(t)
	vault := filepath.Join(f.project, "vault")
	data := filepath.Join(f.project, "data", "secrets")
	for _, d := range []string{vault, data} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(vault, "key"), "k", 0o600)
	f.file(filepath.Join(data, "key.pem"), "k", 0o600)
	if err := os.Symlink("vault", filepath.Join(f.project, "vlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.project, "data"), filepath.Join(f.root, "projlink")); err != nil {
		t.Fatal(err)
	}
	adj := func(fence string) string { return "live:\n  mode: adjustable\n  fence:\n" + fence }
	t.Run("entry is a link", func(t *testing.T) {
		yaml := strings.Replace(liveContract(f, adj("    read: [vlink]\n")), "deny_read: [secrets/]", "deny_read: [vlink]", 1)
		ds := compileLiveErr(t, f, yaml)
		if !hasLiveCode(ds, CodeLiveFenceEntry, SeverityError, "names a link", vault) {
			t.Errorf("a link fence entry was not refused:\n%s", render(ds))
		}
	})
	t.Run("entry passes through a link", func(t *testing.T) {
		yaml := strings.Replace(liveContract(f, adj("    read: [vlink/key]\n")), "deny_read: [secrets/]", "deny_read: [vlink/key]", 1)
		ds := compileLiveErr(t, f, yaml)
		if !hasLiveCode(ds, CodeLiveFenceEntry, SeverityError, "names a link", filepath.Join(vault, "key")) {
			t.Errorf("a fence entry through a link was not refused:\n%s", render(ds))
		}
	})
	t.Run("deny_read through a link", func(t *testing.T) {
		yaml := strings.Replace(liveContract(f, adj("    read: [vault]\n")), "deny_read: [secrets/]", "deny_read: [vlink]", 1)
		rt, _ := f.compile(f.load(yaml))
		if len(rt.Live.Entries) != 1 || rt.Live.Entries[0].Value != vault || rt.Live.Entries[0].Source != LiveSourceDeny {
			t.Fatalf("entries %+v", rt.Live.Entries)
		}
		for _, r := range rt.FS {
			if r.Kind == FSDenyRead && !r.BuiltIn && (r.Resolved == vault || r.Path == vault) {
				t.Errorf("deny_read %s still compiled: %+v", vault, r)
			}
		}
		if e, ok := rt.Live.Covering(filepath.Join(vault, "key")); !ok || e.Value != vault {
			t.Errorf("the vault's key is not covered: %+v %v", e, ok)
		}
	})
	t.Run("write through a link above the entry", func(t *testing.T) {
		yaml := strings.Replace(liveContract(f, adj("    read: [data/secrets]\n")), "deny_read: [secrets/]", "deny_read: [data/secrets]", 1)
		yaml = strings.Replace(yaml, "write: [out/]", "write: [\""+filepath.Join(f.root, "projlink")+"/\"]", 1)
		ds := compileLiveErr(t, f, yaml)
		if !hasLiveCode(ds, CodeLiveFenceWrite, SeverityError, "projlink", "renamed out from under it") {
			t.Errorf("a write entry linked above the fence was not refused:\n%s", render(ds))
		}
	})
}

// liveProfileContract loads the fixture's contract extending a profile p whose body is given, with the top-level
// contract's text edited by edit.
func liveProfileContract(t *testing.T, f *fixture, profile string, edit func(string) string) (*RuleTable, []Diagnostic, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("version: 0\nname: p\n"+profile), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.project, "agent.yaml")
	body := edit(liveContract(f, "extends: p\n"))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	c, ds, err := Load(path, dirSource{root: dir})
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	return Compile(c, f.machine, f.opts()...)
}

// TestLiveFenceKeepsProfileRefusals: a fence takes out only the top-level contract's own refusals; a
// deny_read or exec.deny entry a profile declares stays a floor, whether or not the contract repeats it.
func TestLiveFenceKeepsProfileRefusals(t *testing.T) {
	f := liveFixture(t)
	secrets := filepath.Join(f.project, "secrets")
	fence := func(s string) func(string) string {
		return func(y string) string { return y + "live:\n  mode: adjustable\n  fence:\n" + s }
	}
	for _, tc := range []struct {
		name, profile string
		edit          func(string) string
		words         []string
	}{
		{name: "deny_read only in the profile", profile: "fs: {deny_read: [\"" + secrets + "\"]}\n",
			edit: func(y string) string {
				return fence("    read: [secrets]\n")(strings.Replace(y, "  deny_read: [secrets/]\n", "", 1))
			}, words: []string{"profile", "p.yaml", "never part of a fence"}},
		{name: "deny_read in both", profile: "fs: {deny_read: [\"" + secrets + "\"]}\n",
			edit: fence("    read: [secrets]\n"), words: []string{"profile", "p.yaml"}},
		{name: "exec.deny in the profile", profile: "exec: {deny: [env]}\n",
			edit: fence("    exec: [" + filepath.Join(f.bin, "env") + "]\n"), words: []string{"exec.deny", "profile", "p.yaml"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, ds, err := liveProfileContract(t, f, tc.profile, tc.edit)
			if err == nil || rt != nil || !hasLiveCode(ds, CodeLiveFenceEntry, SeverityError, tc.words...) {
				t.Errorf("a profile's refusal was taken out: %v\n%s", err, render(ds))
			}
		})
	}
	// Without the fence, the same profile compiles, and its refusal stands.
	rt, ds, err := liveProfileContract(t, f, "fs: {deny_read: [\""+secrets+"\"]}\n", func(y string) string { return y })
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	refused := false
	for _, r := range rt.FS {
		refused = refused || r.Kind == FSDenyRead && r.Path == secrets
	}
	if !refused {
		t.Error("the profile's deny_read is not compiled")
	}
}

// TestLiveFenceExecByName: an exec entry that took out an exec.deny entry naming a program by its
// bare name carries that name, its digest says so, LiveTable.For reaches every program of that name, and a link entry
// is refused.
func TestLiveFenceExecByName(t *testing.T) {
	f := liveFixture(t)
	other := filepath.Join(f.root, "other")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(other, "static-tool"), "x", 0o755)
	tool := filepath.Join(f.bin, "static-tool")
	rt, _ := f.compile(f.load(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    exec: ["+tool+"]\n")))
	if len(rt.Live.Entries) != 1 {
		t.Fatalf("entries %+v", rt.Live.Entries)
	}
	e := rt.Live.Entries[0]
	if e.Name != "static-tool" || e.Source != LiveSourceDeny {
		t.Errorf("entry %+v, want Name static-tool", e)
	}
	if rt.Live.SHA256 != liveDigest([]LiveEntry{{Kind: LiveKindExec, Value: tool, Source: LiveSourceDeny, Name: "static-tool"}}) ||
		rt.Live.SHA256 == liveDigest([]LiveEntry{{Kind: LiveKindExec, Value: tool, Source: LiveSourceDeny}}) {
		t.Error("the digest does not carry the entry's name")
	}
	for _, p := range []string{tool, filepath.Join(other, "static-tool")} {
		if got, ok := rt.Live.For(Action{Kind: ActionExec, Path: p}); !ok || got.Value != tool {
			t.Errorf("For(exec %s) = %+v %v, want the fence entry", p, got, ok)
		}
	}
	if _, ok := rt.Live.For(Action{Kind: ActionExec, Path: filepath.Join(f.bin, "env")}); ok {
		t.Error("For reaches a program the fence does not name")
	}
	var b strings.Builder
	if err := PrintRuleTable(&b, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "refused by name static-tool at start") {
		t.Errorf("print lacks the by-name refusal:\n%s", b.String())
	}
	// A link is refused.
	if err := os.Symlink("static-tool", filepath.Join(f.bin, "st-link")); err != nil {
		t.Fatal(err)
	}
	ds := compileLiveErr(t, f, liveContract(f, "live:\n  mode: adjustable\n  fence:\n    exec: ["+filepath.Join(f.bin, "st-link")+"]\n"))
	if !hasLiveCode(ds, CodeLiveFenceEntry, SeverityError, "names a link", tool) {
		t.Errorf("a link exec entry was not refused:\n%s", render(ds))
	}
}

// TestLiveTableFor: the fence entry each kind of action reaches.
func TestLiveTableFor(t *testing.T) {
	lt := &LiveTable{Mode: LiveAdjustable, Entries: []LiveEntry{
		{Kind: LiveKindRead, Value: "/srv/vault"},
		{Kind: LiveKindNet, Value: "api.stripe.com:443"},
		{Kind: LiveKindNet, Value: "[2001:db8::1]:8443"},
		{Kind: LiveKindNet, Value: "192.0.2.1:22"},
		{Kind: LiveKindExec, Value: "/usr/bin/psql"},
	}}
	for _, tc := range []struct {
		a    Action
		want string
	}{
		{Action{Kind: ActionFSRead, Path: "/srv/vault/key"}, "/srv/vault"},
		{Action{Kind: ActionFSRead, Path: "/srv/vaulted"}, ""},
		{Action{Kind: ActionFSWrite, Path: "/srv/vault/key"}, ""},
		{Action{Kind: ActionNetConnect, Host: "API.Stripe.com.", Port: 443}, "api.stripe.com:443"},
		{Action{Kind: ActionNetConnect, Host: "api.stripe.com", Port: 443, Proto: "udp"}, ""},
		{Action{Kind: ActionNetConnect, Host: "2001:db8::1", Port: 8443, Proto: "tcp"}, "[2001:db8::1]:8443"},
		{Action{Kind: ActionNetConnect, Host: "::ffff:192.0.2.1", Port: 22}, "192.0.2.1:22"},
		{Action{Kind: ActionNetConnect, Host: "192.0.2.1", Port: 23}, ""},
		{Action{Kind: ActionExec, Path: "/usr/bin/psql"}, "/usr/bin/psql"},
		{Action{Kind: ActionExec, Path: "/opt/pg/bin/psql"}, ""},
	} {
		e, ok := lt.For(tc.a)
		if got := map[bool]string{true: e.Value}[ok]; got != tc.want {
			t.Errorf("For(%+v) = %q, want %q", tc.a, got, tc.want)
		}
	}
	if _, ok := (*LiveTable)(nil).For(Action{Kind: ActionFSRead, Path: "/srv/vault"}); ok {
		t.Error("a nil table reaches an entry")
	}
}

// TestLiveFenceExecHelperImages: a fenced git is granted with its helper images (git's exec-path
// git, another inode than the PATH one, and its dashed helpers, ADR 0048 (2)). Each is marked as the fence's, named
// after the fence entry, and listed on the entry, so the live layer refuses git by every path until the lift, and the
// ledger never names a helper exec[...].
func TestLiveFenceExecHelperImages(t *testing.T) {
	f := commandFixture(t)
	f.resolver.table["api.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	core := filepath.Join(f.root, "lib", "git-core")
	git := filepath.Join(f.bin, "git")
	rt, ds := f.compile(f.load(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    exec: ["+git+"]\n")))
	if rt == nil || len(rt.Live.Entries) != 1 {
		t.Fatalf("compile:\n%s", render(ds))
	}
	e := rt.Live.Entries[0]
	helpers := []string{filepath.Join(core, "git"), filepath.Join(core, "git-remote-https")}
	for _, h := range helpers {
		if !slices.Contains(e.Images, h) {
			t.Errorf("entry images %v lack %s", e.Images, h)
		}
		found := false
		for _, r := range rt.Exec {
			if r.Path != h {
				continue
			}
			found = true
			if !r.Fence || r.RuleName() != e.Rule() {
				t.Errorf("helper row %s: Fence %v, rule %s, want %s", h, r.Fence, r.RuleName(), e.Rule())
			}
		}
		if !found {
			t.Errorf("helper image %s not granted", h)
		}
		if got, ok := rt.Live.For(Action{Kind: ActionExec, Path: h}); !ok || got.Value != git {
			t.Errorf("For(exec %s) = %+v %v, want the git entry", h, got, ok)
		}
	}
	if rt.Live.SHA256 != liveDigest([]LiveEntry{{Kind: LiveKindExec, Value: git, Source: LiveSourceNew}}) {
		t.Error("the helper images changed the fence's digest")
	}
	var b strings.Builder
	if err := PrintRuleTable(&b, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "so are its helper images "+filepath.Join(core, "git")) {
		t.Errorf("print does not name the helper images:\n%s", b.String())
	}
	for _, r := range rt.Exec {
		if r.Fence && r.Path != git && !slices.Contains(helpers, r.Path) && r.Resolved != git {
			t.Errorf("row %s is marked as the fence's", r.Path)
		}
	}
	// A contract that already grants git, even constrained, has no git to fence: the helper rows stay its own.
	y := strings.Replace(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    exec: ["+git+"]\n"), "allow: [python]", "allow: [python, git status]", 1)
	if ds := compileLiveErr(t, f, y); !hasLiveCode(ds, CodeLiveFenceAllowed, SeverityError, "already grants it") {
		t.Errorf("a fence entry for a git the contract grants was not refused:\n%s", render(ds))
	}
}

// TestLiveFenceExecInsideWrite: an exec fence entry at or beneath a write or ask entry is refused, by its declared and
// its resolved spelling: the agent could rewrite the program in place, keeping its EXECUTE grant, and rename it past
// the live layer's name check.
func TestLiveFenceExecInsideWrite(t *testing.T) {
	f := liveFixture(t)
	tool := filepath.Join(f.project, "out", "bin", "tool")
	if err := os.MkdirAll(filepath.Dir(tool), 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(tool, string(elf64("", 2)), 0o755)
	ds := compileLiveErr(t, f, liveContract(f, "live:\n  mode: adjustable\n  fence:\n    exec: ["+tool+"]\n"))
	if !hasLiveCode(ds, CodeLiveFenceWrite, SeverityError, "fs.write", "rewrite the program") {
		t.Errorf("an exec entry inside fs.write was not refused:\n%s", render(ds))
	}
	// The write entry spelled through a link onto the program's folder is the same write entry.
	if err := os.Symlink(filepath.Join(f.project, "out"), filepath.Join(f.project, "outlink")); err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    exec: ["+tool+"]\n"), "write: [out/]", "write: [outlink/]", 1)
	if ds := compileLiveErr(t, f, y); !hasLiveCode(ds, CodeLiveFenceWrite, SeverityError, "fs.write") {
		t.Errorf("an exec entry inside a linked fs.write was not refused:\n%s", render(ds))
	}
}

// TestLiveFenceExecInsideARead: an exec fence entry at or beneath one of the fence's own read entries
// is refused, as an exec.allow entry there is: the fence takes the folder's deny_read out of the kernel
// layers and grants the program, so lifting the program alone would let it run inside the refused folder, and be
// read. So is an entry whose helper images lie there. The same program outside the read entry compiles.
func TestLiveFenceExecInsideARead(t *testing.T) {
	f := liveFixture(t)
	inside := filepath.Join(f.project, "secrets", "tool")
	outside := filepath.Join(f.project, "tools", "tool")
	for _, p := range []string{inside, outside} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(p, string(elf64("/lib64/ld-fake.so.2", 1)), 0o755)
	}
	fence := func(tool string) string {
		return liveContract(f, "live:\n  mode: adjustable\n  fence:\n    read: [secrets/]\n    exec: ["+tool+"]\n")
	}
	if ds := compileLiveErr(t, f, fence(inside)); !hasLiveCode(ds, CodeLiveFenceEntry, SeverityError,
		"live.fence.exec \""+inside+"\" lies at or inside live.fence.read \"secrets/\"") {
		t.Errorf("an exec entry inside the fence's read entry was not refused:\n%s", render(ds))
	}
	rt, ds := f.compile(f.load(fence(outside)))
	if rt == nil || hasCode(ds, CodeLiveFenceEntry) {
		t.Fatalf("an exec entry outside the read entry was refused:\n%s", render(ds))
	}

	// git's helper images lie in its exec-path, lib/git-core: a read entry there meets the fenced git through them.
	g := commandFixture(t)
	g.resolver.table["api.example.com"] = []netip.Addr{netip.MustParseAddr("192.0.2.20")}
	core := filepath.Join(g.root, "lib", "git-core")
	git := filepath.Join(g.bin, "git")
	y := strings.Replace(liveContract(g, "live:\n  mode: adjustable\n  fence:\n    read: ["+core+"]\n    exec: ["+git+"]\n"),
		"deny_read: [secrets/]", "deny_read: [secrets/, "+core+"]", 1)
	if ds := compileLiveErr(t, g, y); !hasLiveCode(ds, CodeLiveFenceEntry, SeverityError,
		"runs "+filepath.Join(core, "git")+", which lies at or inside live.fence.read") {
		t.Errorf("an exec entry whose helper images lie inside a read entry was not refused:\n%s", render(ds))
	}
}

// TestLiveFenceNetByAddress: the supervisor matches an agent's connect by address, so a connect to an
// address a host fence entry resolved to is not found by For, which looks up the destination as given; ForNet finds
// it through the rule the connect matched, which is how a live layer must refuse it.
func TestLiveFenceNetByAddress(t *testing.T) {
	f := liveFixture(t)
	rt, ds := f.compile(f.load(liveContract(f, "live:\n  mode: adjustable\n  fence:\n    net: [\"api.stripe.com:443\"]\n")))
	if rt == nil {
		t.Fatalf("compile:\n%s", render(ds))
	}
	addr := netip.MustParseAddr("192.0.2.30")
	if _, ok := rt.Live.For(Action{Kind: ActionNetConnect, Host: addr.String(), Port: 443}); ok {
		t.Error("For found a host entry from an address; its doc says it does not")
	}
	var matched *NetRule
	for i := range rt.Net {
		if r := &rt.Net[i]; r.Port == 443 && slices.Contains(r.IPs, addr) {
			matched = r
		}
	}
	if matched == nil {
		t.Fatalf("no net rule holds %s: %+v", addr, rt.Net)
	}
	if e, ok := rt.Live.ForNet(*matched); !ok || e.Value != "api.stripe.com:443" || matched.RuleName() != e.Rule() {
		t.Errorf("ForNet(%s) = %+v %v, rule %s", matched.Raw, e, ok, matched.RuleName())
	}
	for _, r := range rt.Net {
		if !r.Fence {
			if _, ok := rt.Live.ForNet(r); ok {
				t.Errorf("ForNet reaches the contract's rule %s", r.Raw)
			}
		}
	}
}
