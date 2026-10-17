// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// execMode names a contract's exec mode as the ADR 0048 (1) table does.
func execMode(c *Contract) string {
	switch {
	case c.Exec == nil:
		return "no section"
	case c.Exec.DenyList():
		return "deny-list"
	}
	return "restricted"
}

// loadExec loads a contract with the given exec: section.
func loadExec(t *testing.T, section string) *Contract {
	t.Helper()
	c, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: m\ncommand: [true]\n"+section), nil)
	if err != nil {
		t.Fatalf("%q: %v\n%s", section, err, render(ds))
	}
	return c
}

// TestExecModeByKeyPresence is ADR 0048 (1)'s mode table: the mode is which keys are present, never whether a list
// is empty.
func TestExecModeByKeyPresence(t *testing.T) {
	cases := map[string]string{
		"":                                      "no section",
		"exec: {allow: []}\n":                   "restricted",
		"exec: {allow: [ls]}\n":                 "restricted",
		"exec: {allow: [], deny: [git push]}\n": "restricted",
		"exec: {deny: [git push]}\n":            "deny-list",
		"exec: {deny: []}\n":                    "deny-list",
		"exec: {ask: []}\n":                     "deny-list",
		"exec: {ask: [npm install]}\n":          "deny-list",
		"exec: {}\n":                            "restricted",
		"exec: {anonymous: true}\n":             "restricted",
	}
	for section, want := range cases {
		c := loadExec(t, section)
		if got := execMode(c); got != want {
			t.Errorf("%q: %s, want %s", section, got, want)
		}
		unrestricted := want != "restricted"
		if got := c.ExecUnrestricted(); got != unrestricted {
			t.Errorf("%q: ExecUnrestricted %v", section, got)
		}
	}
	// A deny or ask key left with nothing under it (its last entry commented out) is refused with the fix, never
	// read as absent: absent would turn the deny-list into a section that restricts every image.
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: m\ncommand: [true]\nexec:\n  deny:\n    # - git push\n"), nil)
	if err == nil || !strings.Contains(render(ds), "write `deny: []`") {
		t.Errorf("a null deny key: %v\n%s", err, render(ds))
	}
	// An allow key left with nothing under it is refused where its absence makes a deny-list: beside a deny or ask
	// key it made the section a deny-list, where every image may run, though an allow key, even allow: [], restricts
	// images. The message says so, at the allow key's line.
	for _, section := range []string{
		"exec:\n  allow:\n    # - /usr/bin/git\n  deny: [git push]\n",
		"exec:\n  allow:\n  ask: [npm install]\n",
	} {
		_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: m\ncommand: [true]\n"+section), nil)
		if out := render(ds); err == nil || !strings.Contains(out, "write `allow: []`") || !strings.Contains(out, "deny-list") || !strings.Contains(out, "c.yaml:5") {
			t.Errorf("a null allow key in %q: %v\n%s", section, err, out)
		}
	}
	// Alone, a null allow reads as absent, as it did before ADR 0048: `exec: {}`, which restricts every image. A
	// contract that loaded then loads now, with the same mode and contract_hash.
	empty, _ := loadExec(t, "exec: {}\n").Hash()
	for _, section := range []string{
		"exec:\n  allow:\n",
		"exec:\n  allow:\n    # - /usr/bin/git\n",
		"exec:\n  allow:\n  anonymous: true\n",
	} {
		c := loadExec(t, section)
		if execMode(c) != "restricted" {
			t.Errorf("%q: %s, want restricted", section, execMode(c))
		}
		if h, _ := c.Hash(); h != empty && !strings.Contains(section, "anonymous") {
			t.Errorf("%q: hashes unlike exec: {}", section)
		}
	}
}

// TestExecNullAllowAcrossExtends: whether a null allow flips the mode depends on the merged section, so the check
// runs after the merge. A null allow under a profile's deny-list is refused at the allow key; a null allow in a
// profile under a child that writes allow entries is not.
func TestExecNullAllowAcrossExtends(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("denylist.yaml", "exec:\n  deny: [git push]\n")
	write("nullallow.yaml", "exec:\n  allow:\n")
	src := dirSource{root: dir}
	_, ds, err := LoadBytes("top.yaml", []byte("version: 0\nname: m\ncommand: [true]\nextends: denylist\nexec:\n  allow:\n"), src)
	if out := render(ds); err == nil || !strings.Contains(out, "top.yaml:6") || !strings.Contains(out, "write `allow: []`") {
		t.Errorf("a null allow over a deny-list profile: %v\n%s", err, out)
	}
	_, ds, err = LoadBytes("top.yaml", []byte("version: 0\nname: m\ncommand: [true]\nextends: nullallow\nexec:\n  deny: [rm -r]\n"), src)
	if out := render(ds); err == nil || !strings.Contains(out, "nullallow.yaml:2") {
		t.Errorf("a profile's null allow under a child's deny: %v\n%s", err, out)
	}
	c, ds, err := LoadBytes("top.yaml", []byte("version: 0\nname: m\ncommand: [true]\nextends: nullallow\nexec:\n  allow: [ls]\n  deny: [rm -r]\n"), src)
	if err != nil {
		t.Fatalf("a profile's null allow under a child's allow: %v\n%s", err, render(ds))
	}
	if execMode(c) != "restricted" {
		t.Errorf("merged: %s, want restricted", execMode(c))
	}
}

// TestExecModeCanonical: Canonical keeps the mode through a reload (R13), and the two sections the mode separates
// hash differently.
func TestExecModeCanonical(t *testing.T) {
	sections := []string{
		"exec: {allow: [], deny: [git push]}\n",
		"exec: {deny: [git push]}\n",
		"exec: {deny: []}\n",
		"exec: {ask: []}\n",
		"exec: {allow: [], ask: [npm install]}\n",
		"exec: {allow: [git status], deny: [git push], ask: [npm install]}\n",
	}
	hashes := map[[32]byte]string{}
	for _, s := range sections {
		c := loadExec(t, s)
		b, err := c.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		back, ds, err := LoadBytes("contract.yaml", b, nil)
		if err != nil {
			t.Fatalf("%q: canonical does not load back: %v\n%s\n%s", s, err, b, render(ds))
		}
		if execMode(back) != execMode(c) {
			t.Errorf("%q: mode %s after a reload of\n%s", s, execMode(back), b)
		}
		b2, _ := back.Canonical()
		if !bytes.Equal(b, b2) {
			t.Errorf("%q: canonical not stable:\n%s\n---\n%s", s, b, b2)
		}
		h, _ := c.Hash()
		hashes[h] = s
	}
	a, _ := loadExec(t, "exec: {allow: [], deny: [git push]}\n").Hash()
	b, _ := loadExec(t, "exec: {deny: [git push]}\n").Hash()
	if a == b {
		t.Error("exec: {allow: [], deny: [git push]} and exec: {deny: [git push]} hash alike")
	}
}

// TestExecModeExtends: extends concatenates deny and ask as it does allow, keeps a present empty list present, and a
// child that adds allow to a deny-list profile makes the merged section restricted; the mode's source is the file
// whose key set it.
func TestExecModeExtends(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("base.yaml", "exec:\n  deny: [git push]\n")
	src := dirSource{root: dir}
	c, ds, err := LoadBytes("top.yaml", []byte("version: 0\nname: m\ncommand: [true]\nextends: base\nexec:\n  deny: [rm -r]\n"), src)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if execMode(c) != "deny-list" || strings.Join(c.Exec.Deny, ",") != "git push,rm -r" {
		t.Errorf("merged: %s %v", execMode(c), c.Exec.Deny)
	}
	if file, _ := c.ExecModeSource(); filepath.Base(file) != "base.yaml" && filepath.Base(file) != "top.yaml" {
		t.Errorf("mode source %q", file)
	}
	c, ds, err = LoadBytes("top.yaml", []byte("version: 0\nname: m\ncommand: [true]\nextends: base\nexec:\n  allow: [ls]\n"), src)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if execMode(c) != "restricted" {
		t.Errorf("a child's allow on a deny-list profile: %s", execMode(c))
	}
	if file, key := c.ExecModeSource(); filepath.Base(file) != "top.yaml" || key != "allow" {
		t.Errorf("mode source %q %q, want top.yaml allow", file, key)
	}
	write("base.yaml", "exec:\n  allow: []\n")
	c, ds, err = LoadBytes("top.yaml", []byte("version: 0\nname: m\ncommand: [true]\nextends: base\nexec:\n  deny: [git push]\n"), src)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	if execMode(c) != "restricted" || c.Exec.Allow == nil {
		t.Errorf("a profile's allow: [] keeps the merged section restricted: %s %#v", execMode(c), c.Exec.Allow)
	}
	if file, key := c.ExecModeSource(); filepath.Base(file) != "base.yaml" || key != "allow" {
		t.Errorf("mode source %q %q, want base.yaml allow", file, key)
	}
}

// TestExecRuleLoadErrors: an exec entry the pattern grammar refuses is an exec-rule error at Load, with the fix.
func TestExecRuleLoadErrors(t *testing.T) {
	cases := map[string]string{
		"exec: {deny: [/usr/bin/git push]}\n":     `a deny entry matches every file of a name`,
		"exec: {ask: [/usr/bin/npm]}\n":           `an ask entry matches every file of a name`,
		"exec: {deny: [git push && git tag]}\n":   `"&&" is shell syntax`,
		"exec: {deny: ['Bash(git push:*)']}\n":    `Bash(...:*)`,
		"exec: {allow: [git log --frobnicate]}\n": `does not list the option`,
		"exec: {deny: [git * push]}\n":            `lone *`,
	}
	for section, want := range cases {
		_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: m\ncommand: [true]\n"+section), nil)
		if err == nil {
			t.Errorf("%q loaded", section)
			continue
		}
		found := false
		for _, d := range ds {
			if d.Code == CodeExecRule && d.Severity == SeverityError && strings.Contains(d.Message, want) && d.Fix != "" {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: want an exec-rule error holding %q with a fix:\n%s", section, want, render(ds))
		}
	}
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: m\ncommand: [true]\nexec: {deny: []}\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasFinding(ds, CodeExecRule, SeverityWarning) {
		t.Errorf("an empty deny-list section restricts nothing and warns:\n%s", render(ds))
	}
	_, ds, err = LoadBytes("c.yaml", []byte("version: 0\nname: m\ncommand: [true]\nexec: {deny: [mytool $HOME]}\n"), nil)
	if err != nil || !hasFinding(ds, CodeExecRule, SeverityWarning) {
		t.Errorf("$ in a word warns: %v\n%s", err, render(ds))
	}
}

// hasFinding reports whether ds holds a finding of code at severity.
func hasFinding(ds []Diagnostic, code, severity string) bool {
	for _, d := range ds {
		if d.Code == code && d.Severity == severity {
			return true
		}
	}
	return false
}

// TestExecModeOneSpelling is ADR 0048 (1)'s source test: outside pkg/spec/agent no code reads the exec mode off the
// Contract's fields (Exec == nil, Exec != nil, Exec.Anonymous). Each enforcer asks RuleTable.ExecUnrestricted and
// ExecAnonymous, so a deny-only section cannot read as restricted to one and unrestricted to another.
func TestExecModeOneSpelling(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	fset := token.NewFileSet()
	var found []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", "testdata", "node_modules":
				return filepath.SkipDir
			}
			if filepath.ToSlash(p) == filepath.ToSlash(filepath.Join(root, "pkg", "spec", "agent")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Anonymous" {
				if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Exec" {
					if id, ok := inner.X.(*ast.SelectorExpr); ok && id.Sel.Name == "Contract" || isContractVar(inner.X) {
						found = append(found, fset.Position(sel.Pos()).String())
					}
				}
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			be, ok := n.(*ast.BinaryExpr)
			if !ok || (be.Op != token.EQL && be.Op != token.NEQ) {
				return true
			}
			for _, side := range []ast.Expr{be.X, be.Y} {
				if sel, ok := side.(*ast.SelectorExpr); ok && sel.Sel.Name == "Exec" {
					if id, ok := sel.X.(*ast.SelectorExpr); ok && id.Sel.Name == "Contract" || isContractVar(sel.X) {
						found = append(found, fset.Position(be.Pos()).String())
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range found {
		t.Errorf("%s reads the exec mode off the contract's fields; ask RuleTable.ExecUnrestricted or ExecAnonymous", f)
	}
}

// isContractVar reports whether an expression is a variable conventionally holding a *agent.Contract (c, ct).
func isContractVar(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && (id.Name == "ct" || id.Name == "c" || id.Name == "contract")
}
