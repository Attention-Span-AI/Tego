// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func baselineMachine(t *testing.T, f *fixture, body string) *config.Machine {
	t.Helper()
	if err := os.Chmod(f.root, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.root, "baseline.yaml")
	f.file(p, "baseline:\n"+body, 0o600)
	m, ds, err := config.LoadSources(config.Sources{User: p}, f.home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("baseline: %v %v", err, ds)
	}
	m.LedgerRoot = f.machine.LedgerRoot
	return m
}

func TestBaselineNullAllowPreservesRestrictedMode(t *testing.T) {
	for _, section := range []string{"exec: {}", "exec: {allow: []}", "exec:\n  allow: # all entries commented out", "exec: {assurance: best-effort}"} {
		t.Run(section, func(t *testing.T) {
			f := newFixture(t)
			c := f.load("version: 0\nname: mode\ncommand: [python]\n" + section + "\n")
			m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
			before, _, err := Compile(c, f.machine, f.opts()...)
			if err != nil {
				t.Fatal(err)
			}
			after, ds, err := Compile(c, m, f.opts()...)
			if err != nil {
				t.Fatalf("%v %s", err, render(ds))
			}
			if before.ExecUnrestricted() || after.ExecUnrestricted() || after.EffectiveContract.Exec.Allow == nil {
				t.Fatal("restricted exec mode changed")
			}
			for _, image := range []string{"unlisted", "git", "curl"} {
				for _, rt := range []*RuleTable{before, after} {
					if rt.Evaluate(Action{Kind: ActionExec, Path: filepath.Join(f.bin, image)}, rt.Tier).Verdict == VerdictAllow {
						t.Fatalf("unlisted image %s allowed", image)
					}
				}
			}
		})
	}
}

func TestBaselineOnlyExecVisible(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: visible\ncommand: [python]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	var out bytes.Buffer
	if err := PrintRuleTable(&out, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "exec deny  git push") || !strings.Contains(out.String(), "images unrestricted") {
		t.Fatal(out.String())
	}
	if c.Exec != nil || rt.Hash == rt.EffectiveHash || !rt.ExecUnrestricted() {
		t.Fatal("source or effective mode/hash is wrong")
	}
}

func TestBaselineCoveragePrinted(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: coverage-print\ncommand: [python]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n  env: {deny: [TOKEN]}\n")
	for _, observe := range []bool{false, true} {
		opts := f.opts()
		if observe {
			opts = append(opts, WithObserve())
		}
		rt, ds, err := Compile(c, m, opts...)
		if err != nil {
			t.Fatalf("%v %s", err, render(ds))
		}
		var out bytes.Buffer
		if err := PrintRuleTable(&out, rt); err != nil {
			t.Fatal(err)
		}
		text := out.String()
		for _, required := range []string{"effective ", "modeled coverage", "baseline.exec.deny", "baseline.env.deny", "source user", "owner uid"} {
			if !strings.Contains(text, required) {
				t.Fatalf("missing %q: %s", required, text)
			}
		}
		for _, e := range rt.Baseline.Entries {
			for _, cell := range e.Coverage {
				if !strings.Contains(text, string(cell.Tier)+"/"+cell.Plane+": "+cell.Held) {
					t.Fatalf("missing modeled coverage cell: %+v", cell)
				}
			}
		}
		if observe && !strings.Contains(text, "not-applied") || !observe && (!strings.Contains(text, "best-effort") || !strings.Contains(text, "final exec environment delivery")) {
			t.Fatalf("missing conditions/limits or recording-only state: %s", text)
		}
	}
}

func TestBaselineImmutableAndAppliedOnce(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: once\ncommand: [python]\nexec: {deny: ['git push']}\nenv: {deny: [TOKEN, TOKEN]}\n")
	before, _ := c.Canonical()
	hash, _ := c.Hash()
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n  env: {deny: [TOKEN]}\n")
	for range 3 {
		rt, ds, err := Compile(c, m, f.opts()...)
		if err != nil {
			t.Fatalf("%v %s", err, render(ds))
		}
		if !slices.Equal(rt.EffectiveContract.Exec.Deny, []string{"git push", "git push"}) || !slices.Equal(rt.EffectiveContract.Env.Deny, []string{"TOKEN", "TOKEN", "TOKEN"}) {
			t.Fatal("baseline deduplicated source or applied twice")
		}
		after, _ := c.Canonical()
		if !bytes.Equal(before, after) || rt.Hash != hash {
			t.Fatal("source changed")
		}
		if _, _, err := Compile(rt.EffectiveContract, m, f.opts()...); err == nil {
			t.Fatal("effective copy was rematerialized")
		}
	}
}

func TestBaselineOriginsShiftNestedAndClass(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: origins\ncommand: [python]\nexec: {deny: ['git push']}\n")
	c.origins["exec.deny.0.nested"] = Pos{File: "profile.yaml", Line: 31, Col: 4}
	m := baselineMachine(t, f, "  exec: {deny: ['git commit']}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	p, ok := rt.EffectiveContract.Pos("exec.deny.1.nested")
	if !ok || p.File != "profile.yaml" || p.Line != 31 {
		t.Fatal(p)
	}
	if _, ok := rt.EffectiveContract.Pos("exec.deny.0.nested"); ok {
		t.Fatal("stale nested origin")
	}
	k := compiler{c: rt.EffectiveContract, rt: rt, top: c.file}
	if k.baselineMember("exec.deny.0") == nil || k.baselineMember("exec.deny.1") != nil {
		t.Fatal("membership confused with source position")
	}
	if k.declaredByProfile("exec.deny.0") == "" {
		t.Fatal("baseline became top-file exception")
	}
}

func TestBaselineWithoutDecodedOrigins(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: originless\ncommand: [python]\n")
	c.origins = nil // Public library callers can construct a source directly.
	m := baselineMachine(t, f, "  env: {deny: [TOKEN]}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	if _, class, ok := rt.EffectiveContract.Origin("env.deny.0"); !ok || class != OriginBaseline || c.origins != nil {
		t.Fatal("missing baseline origin or mutated source origins")
	}
}

func TestBaselineReplayVerifiedAndIndependent(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: replay\ncommand: [python]\n")
	m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
	rt, ds, err := Compile(c, m, f.opts()...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	effective, _ := rt.EffectiveContract.Canonical()
	replay, err := VerifyBaselineReplay(c, rt.Baseline, rt.Hash, rt.EffectiveHash, effective)
	if err != nil {
		t.Fatal(err)
	}
	for _, machine := range []*config.Machine{config.Builtin(), baselineMachine(t, f, "  exec: {deny: [python]}\n")} {
		got, ds, err := replay.Compile(c, machine, f.opts(WithHome(filepath.Join(f.root, "different-replayer-home")))...)
		if err != nil {
			t.Fatalf("%v %s", err, render(ds))
		}
		b, _ := got.EffectiveContract.Canonical()
		if !bytes.Equal(b, effective) || got.EffectiveHash != rt.EffectiveHash || !got.Replayed() || got.Home != rt.Home || len(got.Baseline.Entries[0].Rules) != len(rt.Baseline.Entries[0].Rules) {
			t.Fatal("replay used current baseline or inserted twice")
		}
	}
	if _, err := VerifyBaselineReplay(c, rt.Baseline, rt.Hash, rt.Hash, effective); err == nil {
		t.Fatal("bad effective hash verified")
	}
	for _, home := range []string{f.home, "relative"} {
		for _, uid := range []int{0, 1000, 2147483000, -1, int(^uint32(0))} {
			snapshot := cloneBaseline(rt.Baseline)
			snapshot.Owner = config.BaselineOwner{UID: uid, Home: home}
			_, err := VerifyBaselineReplay(c, snapshot, rt.Hash, rt.EffectiveHash, effective)
			if valid := uid >= 0 && uint64(uid) < uint64(^uint32(0)) && filepath.IsAbs(home); (err == nil) != valid {
				t.Fatalf("recorded owner uid=%d home=%q: %v", uid, home, err)
			}
		}
	}
	unknown, _, err := UnknownBaselineReplay().Compile(c, m, f.opts()...)
	if err != nil || unknown.Hash != unknown.EffectiveHash || unknown.Baseline != nil {
		t.Fatal("unknown record borrowed current baseline")
	}
}

func TestBaselineExplicitCommandUsesItsOwnImage(t *testing.T) {
	f := newFixture(t)
	left, right := filepath.Join(f.root, "left"), filepath.Join(f.root, "right")
	for _, dir := range []string{left, right} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(left, "tool"), string(elf64("", 2)), 0o755)
	f.file(filepath.Join(right, "tool"), "#!"+filepath.Join(f.bin, "python")+" -E\n", 0o755)
	rt := &RuleTable{Exec: []ExecRule{{Path: filepath.Join(left, "tool"), Basename: "tool"}}, Workdir: right}
	facts, err := rt.baselineCommandFacts([]string{filepath.Join(right, "tool")})
	if err != nil {
		t.Fatal(err)
	}
	if facts.Form != 1 || len(facts.Interp) != 1 || facts.Interp[0].Image != "python" {
		t.Fatalf("explicit command borrowed unrelated same-name image: %+v", facts)
	}
	facts, err = rt.baselineCommandFacts([]string{"./tool"})
	if err != nil || len(facts.Interp) != 1 {
		t.Fatalf("relative explicit command lost governed cwd: %+v %v", facts, err)
	}
}

func TestBaselineObserveKeepsSourceHash(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: observe\ncommand: [python]\nhost_sockets: true\n")
	m := baselineMachine(t, f, "  exec: {deny: [python]}\n  fs: {deny_read: [/absent/target]}\n")
	rt, ds, err := Compile(c, m, f.opts(WithObserve())...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	if rt.Hash != rt.EffectiveHash || rt.EffectiveContract != c || rt.Baseline.Applied || len(rt.Baseline.Entries) != 2 {
		t.Fatal("observe materialized baseline")
	}
}

func TestBaselineFilesystemAndSocketConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, baseline, body string
		conflict             bool
	}{
		{"nested read write", "fs:\n    deny_read: [REPO]", "fs: {write: [REPO/out]}", true},
		{"equal write", "fs:\n    deny_write: [REPO/out]", "fs: {write: [REPO/out]}", true},
		{"nested write reopening", "fs:\n    deny_write: [REPO]", "fs: {write: [REPO/out]}", true},
		{"host sockets", "env: {deny: [TOKEN]}", "host_sockets: true", true},
		{"container socket", "env: {deny: [TOKEN]}", "net: {allow: ['unix:/run/docker.sock']}", true},
		{"ordinary socket", "env: {deny: [TOKEN]}", "net: {allow: ['unix:/run/ordinary.sock']}", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			r := strings.NewReplacer("REPO", f.project)
			m := baselineMachine(t, f, "  "+r.Replace(tc.baseline)+"\n")
			c := f.load("version: 0\nname: conflicts\ncommand: [python]\n" + r.Replace(tc.body) + "\n")
			rt, ds, err := Compile(c, m, f.opts()...)
			if tc.conflict {
				if rt != nil || err == nil || !strings.Contains(render(ds), CodeBaselineConflict) {
					t.Fatalf("missing conflict: %v %s", err, render(ds))
				}
			} else if err != nil {
				t.Fatalf("ordinary input refused: %v %s", err, render(ds))
			}
		})
	}
}

func FuzzBaselineMerge(f *testing.F) {
	for _, text := range []string{"exec: {}", "exec: {allow: null}", "exec: {allow: []}", "exec: {deny: []}", ""} {
		for _, baseline := range []string{"exec: {deny: ['git push']}", "fs: {deny_read: [/machine/read], deny_write: [/machine/write]}\nenv: {deny: [TOKEN]}", "fs: {deny_read: []}\nexec: {deny: []}"} {
			f.Add(text, baseline)
		}
	}
	f.Fuzz(func(t *testing.T, section, baselineText string) {
		c, _, err := LoadBytes("agent.yaml", []byte("version: 0\nname: fuzz\ncommand: [python]\n"+section+"\n"), nil)
		if err != nil {
			return
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(path, []byte("baseline:\n  "+strings.ReplaceAll(baselineText, "\n", "\n  ")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		m, _, err := config.LoadSources(config.Sources{User: path}, dir, os.Getuid(), config.TrustAbort)
		if err != nil {
			return
		}
		baseline, _ := m.BaselineSnapshot()
		if baseline.Empty() {
			return // Compile's no-transformation path is covered by the corpus matrix.
		}
		before, _ := c.Canonical()
		b := &BaselineTable{Applied: true}
		for _, e := range baseline.Entries() {
			b.Entries = append(b.Entries, BaselineRule{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: e, Expanded: e.Value}})
		}
		cp, err := prependBaseline(c, b)
		if err != nil {
			t.Fatal(err)
		}
		after, _ := c.Canonical()
		if !bytes.Equal(before, after) || cp.ExecUnrestricted() != c.ExecUnrestricted() {
			t.Fatal("source or mode changed")
		}
	})
}

func TestBaselineCombinedCommandBound(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: combined-bound\ncommand: [python]\nexec: {deny: [contract-denied]}\n")
	var body strings.Builder
	body.WriteString("  exec:\n    deny:\n")
	for i := 0; i < 512; i++ {
		fmt.Fprintf(&body, "      - blocked%d\n", i)
	}
	m := baselineMachine(t, f, body.String())
	if _, ds, err := Compile(c, m, f.opts()...); err == nil || !strings.Contains(render(ds), "513 command patterns") {
		t.Fatalf("combined bound: %v %s", err, render(ds))
	}
}

func TestBaselineCrossOwnerEffectiveBytes(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: owners\ncommand: [python]\n")
	home2 := filepath.Join(f.root, "other-home")
	for _, home := range []string{f.home, home2} {
		if err := os.MkdirAll(filepath.Join(home, "machine-secret"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	m := baselineMachine(t, f, "  fs: {deny_read: ['~/machine-secret']}\n")
	a, ds, err := Compile(c, m, f.opts(WithOwnerUID(1001))...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	b, ds, err := Compile(c, m, f.opts(WithHome(home2), WithOwnerUID(1002))...)
	if err != nil {
		t.Fatalf("%v %s", err, render(ds))
	}
	if a.Hash != b.Hash || a.EffectiveHash == b.EffectiveHash || a.Baseline.Owner.UID == b.Baseline.Owner.UID {
		t.Fatal("owner context collapsed into source hash or same effective hash")
	}
}

func TestBaselineOwnerUIDContexts(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: owner-uids\ncommand: [python]\n")
	m := baselineMachine(t, f, "  env: {deny: [TOKEN]}\n")
	for _, uid := range []int{0, 1000, 2147483000, -1, int(^uint32(0))} {
		rt, ds, err := Compile(c, m, f.opts(WithOwnerUID(uid))...)
		if uid < 0 || uint64(uid) >= uint64(^uint32(0)) {
			if err == nil || rt != nil || !strings.Contains(render(ds), CodeBaselinePlacement) {
				t.Fatalf("invalid owner%d accepted: %v %s", uid, err, render(ds))
			}
		} else if err != nil || rt.Baseline.Owner.UID != uid {
			t.Fatalf("valid owner%d refused: %v %s", uid, err, render(ds))
		}
	}
}

func TestBaselineCommandAllowAndOwnConflicts(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		argv       []string
		bad        bool
	}{
		{"disjoint command", "exec: {allow: ['git status']}", nil, false},
		{"overlapping command", "exec: {allow: ['git push --dry-run']}", nil, true},
		{"bare image", "exec: {allow: [git]}", nil, false},
		{"own command", "command: [git, push]", nil, true},
		{"mcp command", "mcp: [{name: git-server, command: [git, push]}]", nil, true},
		{"CLI command", "", []string{"git", "push", "--dry-run"}, true},
		{"anonymous restricted images", "exec: {allow: [git], anonymous: true}", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.file(filepath.Join(f.bin, "git"), string(elf64("", 2)), 0o755)
			m := baselineMachine(t, f, "  exec: {deny: ['git push']}\n")
			head := "version: 0\nname: command-conflicts\ncommand: [python]\n"
			if strings.HasPrefix(tc.body, "command:") {
				head = "version: 0\nname: command-conflicts\n"
			}
			c := f.load(head + tc.body + "\n")
			rt, ds, err := Compile(c, m, f.opts(WithRunArgv(tc.argv))...)
			if tc.bad {
				if rt != nil || err == nil || !strings.Contains(render(ds), CodeBaselineConflict) {
					t.Fatalf("missing conflict: %v %s", err, render(ds))
				}
			} else if err != nil {
				t.Fatalf("ordinary command refused: %v %s", err, render(ds))
			}
		})
	}
}
