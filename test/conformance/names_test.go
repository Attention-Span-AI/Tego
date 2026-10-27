// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// builtinNames is the built-in .env pair a contract whose deny_read is not [] carries, scoped to the project (ADR
// 0043 Terms, D10), as a table's model writes it.
var builtinNames = []NameEntry{
	{Exact: ".env", Scopes: []string{"."}},
	{Prefix: ".env.", Except: []string{".env.example", ".env.sample", ".env.template", ".env.dist"}, Scopes: []string{"."}},
}

// TestNameInvariant: ADR 0043 D1 from the model's name entries. Where the tier enforces them (tier cgroup and the
// plane), a read or a change of a covered file that succeeded is a fail-open; tier landlock (the expansion only), a
// name no entry matches, an exception, a dependency directory between the scope and the file, a write entry at the
// file's own place (D3), a directory op and a metadata op are not.
func TestNameInvariant(t *testing.T) {
	m := Model{Write: []string{"w", ".env.test"}, DenyRead: []string{"secrets"}, Names: builtinNames}
	ok := Outcome{OK: true}
	for _, tc := range []struct {
		name string
		c    Cell
		tier Tier
		bad  bool
	}{
		{"read-exact", Cell{Op: OpRead, Path: "w/.env"}, TierBPFLSM, true},
		{"read-exact-cgroup", Cell{Op: OpRead, Path: "w/.env"}, TierCgroup, true},
		{"read-exact-landlock", Cell{Op: OpRead, Path: "w/.env"}, TierLandlock, false},
		{"read-prefix-folded", Cell{Op: OpRead, Path: "w/deep/.ENV.Prod"}, TierBPFLSM, true},
		{"read-exception", Cell{Op: OpRead, Path: "w/.env.example"}, TierBPFLSM, false},
		{"read-exception-folded", Cell{Op: OpRead, Path: "w/.Env.Sample"}, TierBPFLSM, false},
		{"read-plain", Cell{Op: OpRead, Path: "w/env"}, TierBPFLSM, false},
		{"read-beneath-dependency", Cell{Op: OpRead, Path: "w/node_modules/p/.env"}, TierBPFLSM, false},
		{"dependency-compared-exactly", Cell{Op: OpRead, Path: "w/Node_Modules/p/.env"}, TierBPFLSM, true},
		{"read-exempt", Cell{Op: OpRead, Path: ".env.test"}, TierBPFLSM, false},
		{"exempt-is-by-place", Cell{Op: OpRead, Path: "w/.env.test"}, TierBPFLSM, true},
		{"write-open", Cell{Op: OpWriteOpen, Path: "w/.env.local"}, TierCgroup, true},
		{"create", Cell{Op: OpCreate, Path: "w/.env"}, TierBPFLSM, true},
		{"unlink", Cell{Op: OpUnlink, Path: "w/.env.u"}, TierBPFLSM, true},
		{"symlink-new-name", Cell{Op: OpSymlink, Path: "w/.env.s", Dest: "plain"}, TierBPFLSM, true},
		{"symlink-to-covered", Cell{Op: OpSymlink, Path: "w/s", Dest: ".env"}, TierBPFLSM, false},
		{"link-new-name", Cell{Op: OpLink, Path: "w/b", Dest: "w/.env.l"}, TierBPFLSM, true},
		{"link-from-covered", Cell{Op: OpLink, Path: "w/.env", Dest: "w/b"}, TierBPFLSM, true},
		{"rename-onto", Cell{Op: OpRename, Path: "w/a", Dest: "w/.env.m"}, TierBPFLSM, true},
		{"rename-from", Cell{Op: OpRename, Path: "w/.env.m", Dest: "w/a"}, TierBPFLSM, true},
		{"rename-landlock", Cell{Op: OpRename, Path: "w/a", Dest: "w/.env.m"}, TierLandlock, false},
		{"mkdir", Cell{Op: OpMkdir, Path: "w/.env.d"}, TierBPFLSM, false},
		{"chmod", Cell{Op: OpChmod, Path: "w/.env"}, TierBPFLSM, false},
	} {
		got := Invariant(m, &tc.c, tc.tier, ok)
		if (got != "") != tc.bad {
			t.Errorf("%s at %s: invariant %q, want a violation %v", tc.name, tc.tier, got, tc.bad)
		}
		if v := Invariant(m, &tc.c, tc.tier, Outcome{Errno: 13}); v != "" {
			t.Errorf("%s at %s: a refusal broke %q", tc.name, tc.tier, v)
		}
		if v := Invariant(Model{Write: m.Write, DenyRead: m.DenyRead}, &tc.c, tc.tier, ok); v != "" {
			t.Errorf("%s at %s: a model with no name entry broke %q", tc.name, tc.tier, v)
		}
	}
}

// TestNoCellMeetsAnUnmodelledNameEntry holds the condition under which the invariants may leave a fixture's name
// entries out (ADR 0043 C9: the generator avoids .env names until its invariants learn them): every contract whose
// deny_read is not [] carries the built-in .env pair, so a fixture whose model declares no name entry names no path
// the pair would cover, in its tree or its cells, handwritten or generated, and declares no deny_read glob (a
// declared glob can be a name entry too).
func TestNoCellMeetsAnUnmodelledNameEntry(t *testing.T) {
	for _, sp := range Spaces() {
		for _, fx := range sp.Fixtures() {
			if len(fx.Model.Names) > 0 {
				continue
			}
			paths := append(append([]string{}, fx.Dirs...), fx.Fifos...)
			for _, set := range []map[string]string{fx.Files, fx.Scripts, fx.Links, fx.HardLinks, fx.Later} {
				for p := range set {
					paths = append(paths, p)
				}
			}
			for _, c := range fx.Cells {
				paths = append(paths, c.Path, c.Dest, c.Canon)
			}
			for _, p := range paths {
				for _, part := range strings.Split(p, "/") {
					if nameMatches(builtinNames, part) {
						t.Errorf("%s/%s: %q names %q, which the built-in .env pair covers, and the model declares no name entry", sp.Name, fx.Name, p, part)
					}
				}
			}
			for _, d := range fx.Model.DenyRead {
				if strings.ContainsAny(d, "*?[") {
					t.Errorf("%s/%s: deny_read %q is a glob, which can be a name entry, and the model declares none", sp.Name, fx.Name, d)
				}
			}
		}
	}
}

// TestLaterAndNamesAreChecked: a table's later files and model names load as written, and each way they can be wrong
// is refused.
func TestLaterAndNamesAreChecked(t *testing.T) {
	good := strings.Replace(goodTable, "model:\n  write: [out]\n", "dirs: [w]\nlater:\n  w/.env: s\nmodel:\n  write: [out]\n"+
		"  names:\n    - {exact: .env, scopes: [.]}\n    - {prefix: .env., except: [.env.example], scopes: [.]}\n", 1)
	fx, _, _, err := parseTable([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if fx.Later["w/.env"] != "s" || len(fx.Model.Names) != 2 || fx.Model.Names[1].Prefix != ".env." || fx.Model.Names[1].Except[0] != ".env.example" {
		t.Fatalf("later %v names %+v", fx.Later, fx.Model.Names)
	}
	for name, edit := range map[string][2]string{
		"later in an undeclared directory": {"  w/.env: s", "  v/.env: s"},
		"later not clean":                  {"  w/.env: s", "  w/../w/.env: s"},
		"later with mounts":                {"dirs: [w]", "dirs: [w]\nmounts:\n  - {kind: tmpfs, at: w}"},
		"name both exact and prefix":       {"{exact: .env, scopes", "{exact: .env, prefix: .env., scopes"},
		"name with no scope":               {"{exact: .env, scopes: [.]}", "{exact: .env}"},
		"exceptions of an exact name":      {"{exact: .env, scopes", "{exact: .env, except: [.envx], scopes"},
		"a directory under a covered name": {"dirs: [w]", "dirs: [w, w/.env.d/x]"},
	} {
		src := strings.Replace(good, edit[0], edit[1], 1)
		if src == good {
			t.Fatalf("%s: the edit does not apply", name)
		}
		if _, _, _, err := parseTable([]byte(src)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

// TestRunAwaitingWritesLaterFilesBetween is the await handshake without a run: later is called once the command
// printed AwaitReady, and the command goes on only after later wrote the file it waits for; a command that exits
// before the line never calls later.
func TestRunAwaitingWritesLaterFilesBetween(t *testing.T) {
	dir := t.TempDir()
	goFile := filepath.Join(dir, AwaitGo)
	cmd := exec.Command("sh", "-c", `echo '`+AwaitReady+`'; while [ ! -e "$1" ]; do sleep 0.01; done; cat "$2"`, "sh", goFile, filepath.Join(dir, "later"))
	out := newAwaitWriter()
	cmd.Stdout = out
	called := false
	later := func() {
		called = true
		if err := os.WriteFile(filepath.Join(dir, "later"), []byte("written-later\n"), 0o644); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(goFile, nil, 0o644); err != nil {
			t.Error(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- runAwaiting(cmd, out, later) }()
	select {
	case err := <-done:
		if err != nil || !called || !strings.HasSuffix(out.String(), "written-later\n") {
			t.Fatalf("err %v, later called %v, stdout %q", err, called, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the handshake did not finish")
	}
	quit := exec.Command("sh", "-c", "exit 3")
	out = newAwaitWriter()
	quit.Stdout = out
	if err := runAwaiting(quit, out, func() { t.Error("later was called for a command that never waited") }); err == nil {
		t.Error("the command's exit status was lost")
	}
}
