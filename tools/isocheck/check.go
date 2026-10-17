// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// finding is one rule a file breaks.
type finding struct {
	File string // slash-separated, relative to the root
	Line int
	Rule string
	Msg  string
}

func (f finding) String() string { return fmt.Sprintf("%s:%d: %s: %s", f.File, f.Line, f.Rule, f.Msg) }

// skipDirs are directories no rule looks into: version control, the owner's working notes, the
// prose (docs), build output and the paths agents' worktrees and caches live under.
var skipDirs = map[string]bool{
	".git": true, ".claude": true, "docs": true, "node_modules": true,
	"bin": true, "testdata": true, "LICENSES": true,
}

// shellExempt are the directory prefixes whose scripts the shell rules leave alone, and why.
var shellExempt = []string{
	// test/vm's scripts run inside the KVM guests (run-matrix-row.sh, doctor-refusal.sh, tier2-pairs.sh ...), whose
	// home is the guest's own; the ones that run on the host only start and read the guest, but for shellChecked's.
	"test/vm/",
	// this tool's own fixtures.
	"tools/isocheck/",
	// the demo kit's demo.sh is a presenter's script: it runs the presenter's own tego on purpose, with their
	// own ~/.tego and XDG_RUNTIME_DIR. Its test (examples/demo/demo_test.go) runs it under an isolated config
	// and a tegotesthooks build.
	"examples/demo/",
	// the supply-chain demo's demo.sh is the same kind of script, for the same reason: the presenter's own tego, with
	// their ~/.tego chain log, on purpose. Its tests (examples/supply-chain-demo/demo_test.go) run it under a
	// tegotesthooks build, a config, a ledger, a HOME and an XDG_RUNTIME_DIR of their own.
	"examples/supply-chain-demo/",
	// the container image's entrypoint and smoke.sh run inside the image as its own `tego` user, whose ~/.tego is the
	// state volume, on purpose; smoke.sh refuses any other user unless told the caller isolated it. Their tests
	// (examples/container) source the entrypoint's cgroup functions over a stand-in tree and never run tego.
	"examples/container/",
	// the Adjustable-mode demo's demo.sh is the same kind of script: it runs the presenter's own tego, as root through
	// sudo for run, lift, restore and proof (Adjustable needs tier cgroup), with a config and ledger of its own but the
	// presenter's chain log and runtime directory, on purpose. No test runs it; its rehearsal is in its README.
	"examples/live-modes-demo/",
}

// shellChecked are the scripts under a shellExempt prefix that the shell rules still read: root-suites.sh, whose
// VM_HOST=sudo runs every suite and `tego doctor` as root on this host, not in a guest. SH-5 sees that doctor as the
// $0 of the `/bin/sh -c "$doctor_script" "$doctor_bin"` line (runsThroughShell); like every SH rule it asks only that
// the file set the isolation variables somewhere, so which doctor that mode runs, and with which variables, is
// test/vm/root-suites_test.sh's check.
var shellChecked = map[string]bool{"test/vm/root-suites.sh": true}

// goBuildExempt are the Go files that name cmd/tego without running it: a test that reads the build commands
// for the shipped binary, the dead-code report, which analyses the build, and the link gates of ADR 0100 (1a),
// which read the shipped builds' `go list -deps` and build nothing.
var goBuildExempt = map[string]bool{
	"internal/runtime/enforce/shipbuild_test.go": true,
	"tools/deadcodereport/main.go":               true,
	"internal/control/linkgate_test.go":          true,
}

// setters are the helpers that call t.Setenv for TEGO_TEST_CHAIN_ANCHOR and TEGO_TEST_OWN_LOG_HOME.
var setters = map[string]bool{"writeMachineConfig": true, "writeMachineConfigWith": true}

// check runs every rule over the files under root.
func check(root string) ([]finding, error) {
	var out []finding
	mod, err := modulePath(root)
	if err != nil {
		return nil, err
	}
	var facts []*goFacts
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".go":
			fnd, gf, err := checkGo(path, rel, mod)
			if err != nil {
				return err
			}
			out = append(out, fnd...)
			if gf != nil {
				facts = append(facts, gf)
			}
		case ".sh", ".bash", ".py":
			for _, p := range shellExempt {
				if strings.HasPrefix(rel, p) && !shellChecked[rel] {
					return nil
				}
			}
			fnd, err := checkScript(path, rel)
			if err != nil {
				return err
			}
			out = append(out, fnd...)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return append(out, checkGuards(facts)...), nil
}

// checkGo applies GO-1 to GO-3 and GO-5 to one Go file and, when the module path is known, returns what GO-4
// needs of it.
func checkGo(path, rel, mod string) ([]finding, *goFacts, error) {
	if strings.HasPrefix(rel, "tools/isocheck/") {
		return nil, nil, nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", rel, err)
	}
	var gf *goFacts
	if mod != "" {
		if gf, err = factsOf(f, fset, src, rel, mod); err != nil {
			return nil, nil, err
		}
	}
	var out []finding
	at := func(p token.Pos) int { return fset.Position(p).Line }

	// The string literals of the file, unquoted, with their lines.
	type lit struct {
		s    string
		line int
	}
	var lits []lit
	ast.Inspect(f, func(n ast.Node) bool {
		if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if s, err := strconv.Unquote(b.Value); err == nil {
				lits = append(lits, lit{s, at(b.Pos())})
			}
		}
		return true
	})
	has := func(pred func(string) bool) bool {
		for _, l := range lits {
			if pred(l.s) {
				return true
			}
		}
		return false
	}
	text := string(src)

	// GO-2: a TEGO_CONFIG= environment entry comes with the isolation.
	cfgLine := 0
	for _, l := range lits {
		if strings.HasPrefix(l.s, "TEGO_CONFIG=") {
			cfgLine = l.line
			break
		}
	}
	if cfgLine > 0 && !strings.Contains(text, "TEGO_TEST_CHAIN_ANCHOR") && !strings.Contains(text, "TegoEnv(") &&
		!strings.Contains(text, "writeMachineConfig") {
		out = append(out, finding{rel, cfgLine, "GO-2", "a tego subprocess gets TEGO_CONFIG here and nothing in the file sets " +
			"TEGO_TEST_CHAIN_ANCHOR (use testutil.TegoEnv): the run would anchor in the invoking user's own ~/.tego/chain.log"})
	}

	// GO-3: a build of cmd/tego carries the test hooks.
	if !goBuildExempt[rel] {
		buildLine := 0
		for _, l := range lits {
			if l.s == "github.com/attention-span-ai/tego/cmd/tego" || l.s == "./cmd/tego" {
				buildLine = l.line
				break
			}
		}
		if buildLine > 0 && !has(func(s string) bool { return strings.Contains(s, "tegotesthooks") }) {
			out = append(out, finding{rel, buildLine, "GO-3", "builds cmd/tego without -tags tegotesthooks: the binary anchors " +
				"in the invoking user's own ~/.tego/chain.log whatever the test sets"})
		}
	}

	// GO-1: in a function, an os.Environ() that goes into a TEGO_CONFIG= entry comes after the helpers that set the
	// isolation variables.
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		var setAt []token.Pos
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && setters[id.Name] {
					setAt = append(setAt, c.Pos())
				}
			}
			return true
		})
		if len(setAt) == 0 {
			continue
		}
		var stack []ast.Node
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return true
			}
			stack = append(stack, n)
			c, ok := n.(*ast.CallExpr)
			if !ok || !isSel(c.Fun, "os", "Environ") {
				return true
			}
			var stmt ast.Stmt
			for i := len(stack) - 1; i >= 0; i-- {
				if s, ok := stack[i].(ast.Stmt); ok {
					stmt = s
					break
				}
			}
			if stmt == nil || !mentionsConfigEntry(stmt) {
				return true
			}
			for _, s := range setAt {
				if s > c.Pos() {
					out = append(out, finding{rel, at(c.Pos()), "GO-1", "os.Environ() is read before the call at line " +
						strconv.Itoa(at(s)) + " that sets TEGO_TEST_CHAIN_ANCHOR and TEGO_TEST_OWN_LOG_HOME with t.Setenv: " +
						"the environment holds neither, and the run anchors in the invoking user's own ~/.tego/chain.log"})
					break
				}
			}
			return true
		})
	}

	// GO-5: a command that runs the tego binary gets an environment of its own.
	for _, decl := range f.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
			out = append(out, inheritedTegoEnv(fd.Body, fset, rel)...)
		}
	}
	return out, gf, nil
}

// tegoSubcommands are the tego commands GO-4, GO-5 and SH-5 know a run of the binary by.
var tegoSubcommands = strings.Split(strings.TrimSuffix(strings.TrimPrefix(subcommands, "(?:"), ")"), "|")

// notRuns are the commands internal/cli registers that the rules do not count as a run of the binary, each with why
// it cannot reach a ledger, an anchor or the own log.
var notRuns = map[string]string{
	// scripts/install.sh runs the product build's version where it was downloaded, to see that it runs at all.
	"version": "it prints the build's versions from the binary itself and opens no config, ledger, anchor or log",
}

// tegoCommand reports the subcommand of an exec.Command or exec.CommandContext call that runs the tego binary: the
// program is an expression that is not a string literal (bin, e.bin, filepath.Join(dir, "tego")) or a literal whose
// last element is tego, and the first argument is one of tegoSubcommands. Another program ("go" "run", "git"
// "status") and a call with no subcommand are not one.
func tegoCommand(c *ast.CallExpr) (string, bool) {
	first := 0
	switch {
	case isSel(c.Fun, "exec", "Command"):
	case isSel(c.Fun, "exec", "CommandContext"):
		first = 1
	default:
		return "", false
	}
	if len(c.Args) < first+2 {
		return "", false
	}
	if b, ok := c.Args[first].(*ast.BasicLit); ok {
		v, err := strconv.Unquote(b.Value)
		if b.Kind != token.STRING || err != nil || (v != "tego" && !strings.HasSuffix(v, "/tego")) {
			return "", false
		}
	}
	b, ok := c.Args[first+1].(*ast.BasicLit)
	if !ok || b.Kind != token.STRING {
		return "", false
	}
	sub, err := strconv.Unquote(b.Value)
	if err != nil || !contains(tegoSubcommands, sub) {
		return "", false
	}
	return sub, true
}

// exprKey is the dotted spelling of a name or a selector chain (cmd, r.launcher), "" for any other expression.
func exprKey(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return ""
		}
		return e.Name
	case *ast.SelectorExpr:
		if x := exprKey(e.X); x != "" {
			return x + "." + e.Sel.Name
		}
	}
	return ""
}

// inheritsOnly reports whether an Env value is the inherited environment with no isolation of its own:
// os.Environ(), or an append to it, that names neither a TEGO_CONFIG= nor a TEGO_TEST_CHAIN_ANCHOR= entry. A
// TEGO_CONFIG= entry is the test's machine config, and GO-1 and GO-2 hold the anchor that goes with it (a
// writeMachineConfig before the os.Environ() sets the anchor with t.Setenv).
func inheritsOnly(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	base := c
	for {
		id, ok := base.Fun.(*ast.Ident)
		if !ok || id.Name != "append" || len(base.Args) == 0 {
			break
		}
		inner, ok := base.Args[0].(*ast.CallExpr)
		if !ok {
			return false
		}
		base = inner
	}
	if !isSel(base.Fun, "os", "Environ") {
		return false
	}
	return !namesIsolation(c)
}

// envState is what a command's Env holds at a point of GO-5's walk.
type envState int

const (
	envNone      envState = iota // never set: the command inherits the environment
	envInherited                 // os.Environ(), an append to it, or nil, naming no isolation
	envOwn                       // an environment of its own
)

// stmtList is the statement list a block-like node holds, nil for any other node.
func stmtList(n ast.Node) []ast.Stmt {
	switch n := n.(type) {
	case *ast.BlockStmt:
		return n.List
	case *ast.CaseClause:
		return n.Body
	case *ast.CommClause:
		return n.Body
	}
	return nil
}

// envAfter walks the statements that follow the one making the command held in key, in that statement's own block,
// and returns what its Env holds when the command leaves the function's view: the first statement that starts it
// (key.Run, Start, Output or CombinedOutput), passes it to a call, uses it as a value of its own (c2 := key, return
// key, &key: the command goes on under another name) or makes a new command in key, or the block's end. Only an Env
// set by a statement of that block makes it the command's own (key.Env = ...; one inside an if or a closure is set
// on its condition, or not at all); one set there to anything but an environment of its own (os.Environ(), nil, a
// truncation) leaves the command with the inherited one, whatever the block set. An Env of nil is the inherited
// environment, and an append to key.Env keeps what key.Env held unless it names the isolation (an append to an
// unset Env is an environment of its own) or appends os.Environ() after it.
func envAfter(rest []ast.Stmt, key string) envState {
	state := envNone
	for _, st := range rest {
		top, _ := st.(*ast.AssignStmt)
		if top != nil {
			for i, l := range top.Lhs {
				k := exprKey(l)
				if k == key {
					return state
				}
				if k != key+".Env" {
					continue
				}
				if len(top.Lhs) != len(top.Rhs) {
					state = envOwn
					continue
				}
				state = envValue(top.Rhs[i], key, state)
			}
		}
		leaves := false
		var stack []ast.Node
		ast.Inspect(st, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if leaves {
				return false
			}
			var parent ast.Node
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, n)
			switch n := n.(type) {
			case *ast.AssignStmt:
				if n == top || len(n.Lhs) != len(n.Rhs) {
					break
				}
				for i, l := range n.Lhs {
					if exprKey(l) == key+".Env" && envValue(n.Rhs[i], key, state) != envOwn {
						state = envInherited // set on a condition, or in a closure, to the inherited environment
					}
				}
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && exprKey(sel.X) == key {
					switch sel.Sel.Name {
					case "Run", "Start", "Output", "CombinedOutput":
						leaves = true
					}
				}
				for _, arg := range n.Args {
					if exprKey(arg) == key {
						leaves = true
					}
				}
			case *ast.Ident, *ast.SelectorExpr:
				// the command itself as a value, not the X of one of its fields (key.Env, key.Stdout, key.Process)
				if exprKey(n.(ast.Expr)) != key {
					break
				}
				if sel, ok := parent.(*ast.SelectorExpr); ok && sel.X == n {
					break
				}
				if as, ok := parent.(*ast.AssignStmt); ok && slices.Contains(as.Lhs, n.(ast.Expr)) {
					break // key = ... (handled above when top-level), not a use of the command
				}
				leaves = true
			}
			return !leaves
		})
		if leaves {
			return state
		}
	}
	return state
}

// envValue is what key.Env holds after key.Env = e, when it held prev.
func envValue(e ast.Expr, key string, prev envState) envState {
	if id, ok := e.(*ast.Ident); ok && id.Name == "nil" {
		return envInherited
	}
	if inheritsOnly(e) {
		return envInherited
	}
	if c, ok := e.(*ast.CallExpr); ok && len(c.Args) > 0 {
		if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "append" && exprKey(c.Args[0]) == key+".Env" {
			environ, iso := -1, -1
			for i, a := range c.Args[1:] {
				if namesIsolation(a) {
					iso = i
				} else if callsEnviron(a) {
					environ = i
				}
			}
			switch {
			case environ > iso:
				return envInherited // os.Environ() appended after the isolation: exec keeps the last entry of a name
			case iso >= 0 || prev == envNone:
				return envOwn
			}
			return prev
		}
	}
	if mentions(e, key+".Env") && !namesIsolation(e) {
		return envInherited // key.Env[:0], or what a call makes of it: the isolation it held is not kept for sure
	}
	return envOwn
}

// callsEnviron reports whether n calls os.Environ().
func callsEnviron(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && isSel(c.Fun, "os", "Environ") {
			found = true
		}
		return !found
	})
	return found
}

// mentions reports whether n holds the name or selector chain key.
func mentions(n ast.Node, key string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if e, ok := n.(ast.Expr); ok && exprKey(e) == key {
			found = true
		}
		return !found
	})
	return found
}

// namesIsolation reports whether n holds a string literal that begins a TEGO_CONFIG= or TEGO_TEST_CHAIN_ANCHOR=
// entry.
func namesIsolation(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if v, err := strconv.Unquote(b.Value); err == nil && (strings.HasPrefix(v, "TEGO_TEST_CHAIN_ANCHOR=") ||
				strings.HasPrefix(v, "TEGO_CONFIG=")) {
				found = true
			}
		}
		return !found
	})
	return found
}

// inheritedTegoEnv applies GO-5 to one function body (its closures included): each command that runs the tego
// binary (tegoCommand) is assigned to a name or field by a statement of a block, and a later statement of that
// block sets its Env to something other than the bare inherited environment before the command starts, is passed
// to a call or the name gets another command (envAfter); or the command is passed straight to a call (a helper such
// as privpathCase.exec that sets the environment; GO-5 does not follow it). A command run straight from the call
// (exec.Command(bin, "doctor").Run()), returned, made in an if's or a for's header, or never given an Env of its
// own is flagged: in a test build it meets the refusal of the invoking user's built-in ~/.tego/runs
// (identity-config.md R27), and in a product build it reads and writes the real ~/.tego.
func inheritedTegoEnv(body *ast.BlockStmt, fset *token.FileSet, rel string) []finding {
	var out []finding
	var stack []ast.Node
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		c, ok := n.(*ast.CallExpr)
		if !ok || len(stack) < 2 {
			return true
		}
		sub, ok := tegoCommand(c)
		if !ok {
			return true
		}
		holder := ""
		var stmt ast.Node // the statement that makes the command, in the block envAfter walks
		blockAt := -1
		switch p := stack[len(stack)-2].(type) {
		case *ast.CallExpr: // an argument: the callee runs it
			return true
		case *ast.AssignStmt:
			for i, r := range p.Rhs {
				if r == c && len(p.Lhs) == len(p.Rhs) {
					holder = exprKey(p.Lhs[i])
				}
			}
			stmt, blockAt = p, len(stack)-3
		case *ast.ValueSpec:
			for i, v := range p.Values {
				if v == c && len(p.Names) == len(p.Values) {
					holder = exprKey(p.Names[i])
				}
			}
			if len(stack) >= 5 {
				if _, ok := stack[len(stack)-4].(*ast.DeclStmt); ok {
					stmt, blockAt = stack[len(stack)-4], len(stack)-5
				}
			}
		}
		if holder != "" && blockAt >= 0 {
			list := stmtList(stack[blockAt])
			for i, st := range list {
				if st == stmt && envAfter(list[i+1:], holder) == envOwn {
					return true
				}
			}
		}
		out = append(out, finding{rel, fset.Position(c.Pos()).Line, "GO-5", "runs tego " + sub + " with the inherited " +
			"environment (no Env of its own set before it starts, or os.Environ() or nil with neither TEGO_CONFIG nor " +
			"TEGO_TEST_CHAIN_ANCHOR): a test build refuses the invoking user's built-in ~/.tego/runs, so the command " +
			"fails on that and not on what it tests, and a product build reads and writes the real ~/.tego; give it " +
			"testutil.TegoEnv with the test's own TEGO_CONFIG"})
		return true
	})
	return out
}

// isSel reports whether e is the selector pkg.name.
func isSel(e ast.Expr, pkg, name string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != name {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// mentionsConfigEntry reports whether the statement holds a string literal that begins a TEGO_CONFIG= entry.
func mentionsConfigEntry(s ast.Stmt) bool {
	found := false
	ast.Inspect(s, func(n ast.Node) bool {
		if b, ok := n.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if v, err := strconv.Unquote(b.Value); err == nil && strings.HasPrefix(v, "TEGO_CONFIG=") {
				found = true
			}
		}
		return !found
	})
	return found
}

var (
	// assignsConfig matches a script that sets TEGO_CONFIG: VAR=, export VAR=, env VAR=, a Python dict key or an
	// os.environ item.
	assignsConfig = regexp.MustCompile(`(?:^|[\s;&(|"'])TEGO_CONFIG=|["']TEGO_CONFIG["']\s*(?::|\]\s*=)`)
	opensPty      = regexp.MustCompile(`\bpty\.(?:fork|spawn|openpty)\b`)
	interactive   = regexp.MustCompile(`\b(?:bash|zsh|sh|dash|ksh)\b[^\n]*(?:\s|")-i\b`)
	histNull      = regexp.MustCompile(`HISTFILE["']?\s*[=:,]\s*["']?/dev/null`)
	helperSetsAll = regexp.MustCompile(`\b(?:kt_config|lib_init)\b`)

	// buildsTego matches a Go build, install or run of the tego command in a script.
	buildsTego = regexp.MustCompile(`\bgo\s+(?:build|install|run)\b[^\n]*(?:\./|github\.com/attention-span-ai/tego/)cmd/tego\b`)

	// subcommands are the tego commands that read or write a ledger, an anchor, the own log or a project's .tego/:
	// every command internal/cli registers but those notRuns names (TestTheSubcommandsAreTheCLIsCommands), and detect,
	// which older scripts spelled. `agents --adopt` starts ledgered runs, `alternate` answers one as approve and deny
	// do, `rule` reads the run whose event it turns into a rule, `dns` and every other command append to the own log on
	// an error or a panic, and `init` writes the .tego/ of the directory it is given. The nouns tego hands to
	// tego-control (serve to alert, ADR 0100 (2)) are commands like these, and tego-control's services will keep their
	// state under the state directory. `block` and `unblock` reach a running run's live control under ledger_root, and
	// `test` starts tego runs of its own; `route` writes a running run's model-routes.json under ledger_root.
	subcommands = `(?:run|watch|gc|stop|events|status|ask|approve|deny|alternate|doctor|drift|learn|adopt|agents|measure|receipt|detect|compile|rule|block|unblock|pause|resume|lift|grant|restore|test|dns|init|serve|control|inbox|people|role|access|whoami|alert|mcp|vault|route)`
	// launches are the subcommands that start a run (agents with --adopt): each launch makes <XDG_RUNTIME_DIR>/tego
	// and first removes the directories there whose launcher's lock is free (SH-7).
	launches = `(?:run|watch|adopt|agents)`
	// assignsRuntimeDir matches an assignment of XDG_RUNTIME_DIR and captures the start of its value: a shell
	// assignment (VAR=, export VAR=, env VAR=) or a Python keyword argument (group 1), a Python dict key ("VAR": v) or
	// item assignment (env["VAR"] = v) (group 2). A comparison (env["VAR"] == v) captures "=" and is no assignment.
	// A quoted mention alone (a check that the caller set it, a print) assigns nothing.
	assignsRuntimeDir = regexp.MustCompile(`(?:^|[\s;&(|"'{,])XDG_RUNTIME_DIR=(\S*)|["']XDG_RUNTIME_DIR["']\s*(?::|\]\s*=)[ \t]*(\S*)`)
	// shellAssign and pyAssign match an assignment to another name, for a value copied through it (rt=$XDG_RUNTIME_DIR;
	// XDG_RUNTIME_DIR=$rt): the shell's value up to a blank, Python's to the end of the line.
	shellAssign = regexp.MustCompile(`(?:^|[\s;&(|])([A-Za-z_]\w*)=(\S*)`)
	pyAssign    = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z_]\w*)[ \t]*=([^=].*)$`)
	identStart  = regexp.MustCompile(`^[A-Za-z_]\w*`)
	// inheritedStart matches a value that is the inherited runtime directory or the login session's: $XDG_RUNTIME_DIR,
	// ${XDG_RUNTIME_DIR...}, os.environ or os.getenv, or a path under /run/user/ (any uid's spelling: $(id -u), $UID,
	// {os.getuid()}, digits), quotes and a Python f prefix removed first.
	inheritedStart = regexp.MustCompile(`^(?:\$\{?XDG_RUNTIME_DIR\b|os\.(?:environ|getenv)\b|/run/user/)`)
	// refusesLoginRuntimeDir matches a Python check that refuses the login session's directory, as the watch demo's
	// drivers do (os.path.realpath(os.environ["XDG_RUNTIME_DIR"]) == os.path.realpath(f"/run/user/{os.getuid()}")): with
	// it, a script that requires the caller's XDG_RUNTIME_DIR by naming it gives tego the caller's own directory.
	refusesLoginRuntimeDir = regexp.MustCompile(`XDG_RUNTIME_DIR[^\n]*==[^\n]*/run/user/`)
	quotedRuntimeDir       = regexp.MustCompile(`["']XDG_RUNTIME_DIR["']`)
	// execsTego matches a logical line (backslash continuations joined) that runs a tego binary: execsTegoWith with
	// no wrapper of the script's own.
	execsTego = execsTegoWith(nil, nil)
	// definesFunc matches a shell function definition, `name() {` or `function name`: a wrapper the script may run the
	// binary through (`wrap "$tego" run`).
	definesFunc = regexp.MustCompile(`(?m)^[ \t]*(?:function[ \t]+([A-Za-z_][\w-]*)|([A-Za-z_][\w-]*)[ \t]*\([ \t]*\))`)
	// pyExecsTego matches a Python argument list whose first element is an expression (a name, an attribute, a call or
	// a subscript: tego, self.bin, str(binpath), os.environ["TEGO"]) or a literal ending in tego, and whose second is
	// a tego subcommand, in a file that names tego anywhere (pyNamesTego). A literal first element that does not
	// end in tego (["git", "status"]) is another program.
	pyExecsTego = pyExecsTegoWith(subcommands)
	// pyLaunchesTego is pyExecsTego for a subcommand that starts a run (SH-7).
	pyLaunchesTego = pyExecsTegoWith(launches)
	pyNamesTego    = regexp.MustCompile(`(?:tego|Tego|TEGO)(?:[^rR]|$)`) // not category (ADR 0060)
	// readsTegoBin matches a script that takes the binary it runs from its caller: $TEGO_BIN, os.environ["TEGO_BIN"],
	// or a --tego option.
	readsTegoBin = regexp.MustCompile(`TEGO_BIN|["']--tego["']|\s--tego[\s=)]`)
	// refusesProductBuild matches a script that checks the binary it was handed is a test build: the shared helpers, or
	// a search of the file for the variable only a test build contains.
	refusesProductBuild = regexp.MustCompile(`\b(?:kt_require_testhooks|kt_ensure_tego)\b|grep\s+-\w*a\w*[^\n]*TEGO_TEST_CHAIN_ANCHOR|(?:\bb)?["']TEGO_TEST_CHAIN_ANCHOR["']\s+(?:not\s+)?in\b`)
)

// The pieces of execsTegoWith.
const (
	// startsCommand is the start of a line or of a command: after ; & | ( { $( and any of then, do, else, if, while,
	// until, elif or ! there.
	startsCommand = `(?:^|[;&|({]|\$\()\s*(?:(?:then|do|else|if|while|until|elif|!)\s+)*`
	// runsNext are the programs that run the command their arguments name, wherever they stand: setsid, script, sudo,
	// doas, setpriv, runuser, exec, eval, env, timeout, nohup, time, nice, ionice, chrt, taskset, unshare, stdbuf,
	// systemd-run, xargs, command or a shell.
	runsNext = `\b(?:setsid|script|sudo|doas|setpriv|runuser|exec|eval|env|timeout|nohup|time|nice|ionice|chrt|taskset|unshare|stdbuf|systemd-run|xargs|command|bash|sh|dash|zsh)\b`
	// optionWords are the options and values after one of those or a wrapper: plain words, an option word of any
	// characters (--reuid=1000), or a quoted word (-u "$SUDO_USER").
	optionWords = `(?:\s+(?:-\S+|"[^"\n]*"|'[^'\n]*'|[-\w.=/]+))*`
	// quote is a quote around the binary or the subcommand, escaped where it stands inside a string that a shell or
	// eval runs (eval "\"$tego\" run").
	quote = `(?:\\?["'])`
	// tegoWord is the binary: a path ending in /tego, which may hold quoted segments and command substitutions
	// ("$TMPDIR/tego", ./tego, "$W"/tego, "$(go env GOPATH)/bin/tego") and whose last segment may be quoted
	// ("$bindir"/"tego", "$W/"'tego'), the word tego, or a $var or ${var:-default} that is one letter, has bin or exe
	// in its name, or has tego, Tego or TEGO in it not followed by r ($tego, $bin, $E, $tego_bin, $qtego, $realtego,
	// "${TEGO_BIN:-tego}"; not "${GO:-go}", "$LINT" or "$gh", which the repository's scripts run with `run` too, and
	// not $category or $updateGolden, which hold the letters of the name inside another word: ADR 0060).
	tegoWord = `(?:(?:"[^"\n]*"|'[^'\n]*'|\$\([^()\n]*\)|[^\s"';&|()<>])*(?:/["']{0,2}|"[^"\n]*/"["']?|'[^'\n]*/'["']?)tego|tego|\$\{?(?:[A-Za-z]|\w*(?i:bin|exe)\w*|\w*(?:tego|Tego|TEGO)(?:[^\WrR]\w*)?)(?::-[^}\s]*)?\}?)`
	// globalOptions are options between the binary and its subcommand ("$tego" --tier landlock run): an option word,
	// with its value after = or as the next word.
	globalOptions = `(?:\s+-[-\w]+(?:=\S+|\s+[^\s-]\S*)?)*`
	// forwardsArgs is a function body's "$@", $*, "${@}" or ${1+"$@"}: the arguments of the function's call.
	forwardsArgs = `(?:["']?\$\{?[@*]|\$\{1\+["']?\$@)`
)

// repoWrappers are the shell functions of the repository's harnesses that run the command their arguments name:
// test/e2e/lib.sh's kt_run and test/vm/run-matrix-row.sh's as_user.
var repoWrappers = []string{"kt_run", "as_user"}

// tegoHead is the pattern up to the binary and its global options: tegoWord, or one of binFuncs (functions that
// wrap the binary itself), as the command word where a command starts (startsCommand), or there after a wrapper
// (repoWrappers, or the given functions the script defines) and its options, or anywhere after one of runsNext and its
// options; past any VAR=value words and quotes.
func tegoHead(wrappers, binFuncs []string) string {
	word := tegoWord
	if len(binFuncs) > 0 {
		word = `(?:` + tegoWord + `|\b(?:` + alternation(binFuncs) + `))`
	}
	return headOf(wrappers, word)
}

// headOf is tegoHead with word as the binary.
func headOf(wrappers []string, word string) string {
	wrap := `(?:(?:` + alternation(append(append([]string{}, repoWrappers...), wrappers...)) + `)\b` + optionWords + `)?`
	return `(?:` + startsCommand + wrap + `|` + runsNext + optionWords + `)\s*(?:[A-Za-z_]\w*=\S*\s+)*` + quote + `{0,2}` +
		word + quote + `?` + globalOptions
}

var (
	// shellDashC matches a shell run with a script on its command line (sh -c, /bin/sh -ec, bash -c): the words after
	// it are the script and then $0, $1 ... of the script.
	shellDashC = regexp.MustCompile(`(?:^|[\s;&|(/])(?:ba|da|k|z)?sh\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c[A-Za-z]*\s+`)
	// shellWord is one word of a command line: quoted and plain segments, up to a space or an operator.
	shellWord = regexp.MustCompile(`^(?:"(?:[^"\\\n]|\\.)*"|'[^'\n]*'|[^\s"';&|()<>])+`)
	// isTegoWord is a whole word that names the binary (tegoWord), quoted or not.
	isTegoWord = regexp.MustCompile(`^` + quote + `?` + tegoWord + quote + `?$`)
	// scriptVar is a script word that is a variable's value ("$doctor_script", ${s}).
	scriptVar = regexp.MustCompile(`^"?\$\{?([A-Za-z_]\w*)\}?"?$`)
)

// runsThroughShell reports whether the logical line s hands a tego binary to a shell's -c script that runs it with
// a subcommand: sh -c '"$0" doctor' "$tego", sh -c '"$1" run x' sh "$bin", or sh -c "$script" "$doctor_bin" where
// text assigns script='... "$0" doctor ...'. A script in a variable that text does not assign is searched for in the
// whole of text.
func runsThroughShell(s, text string) bool {
	for _, loc := range shellDashC.FindAllStringIndex(s, -1) {
		var words []string
		for rest := s[loc[1]:]; ; {
			w := shellWord.FindString(rest)
			if w == "" {
				break
			}
			words = append(words, w)
			rest = strings.TrimLeft(rest[len(w):], " \t")
		}
		if len(words) < 2 {
			continue
		}
		var pos []string
		for i, w := range words[1:] {
			if i < 10 && isTegoWord.MatchString(w) {
				pos = append(pos, strconv.Itoa(i))
			}
		}
		if len(pos) == 0 {
			continue
		}
		body := scriptText(words[0], text)
		runs := regexp.MustCompile(headOf(nil, `\\?\$\{?(?:`+strings.Join(pos, "|")+`)\}?`) + `\s+` + quote + `?` + subcommands + `\b`)
		for _, l := range strings.Split(body, "\n") {
			if runs.MatchString(l) {
				return true
			}
		}
	}
	return false
}

// scriptText is the text of a shell's -c script word: the inside of its quotes (a double-quoted one unescaped), the
// value text assigns to the variable it names, or, when text assigns none, all of text.
func scriptText(word, text string) string {
	if m := scriptVar.FindStringSubmatch(word); m != nil {
		assign := regexp.MustCompile(`(?:^|[\s;&])(?:(?:local|export|readonly|declare)\s+)?` + regexp.QuoteMeta(m[1]) +
			`=('[^']*'|"(?:[^"\\]|\\.)*")`)
		if a := assign.FindStringSubmatch(text); a != nil {
			return scriptText(a[1], "")
		}
		return text
	}
	switch {
	case len(word) >= 2 && word[0] == '\'' && word[len(word)-1] == '\'':
		return word[1 : len(word)-1]
	case len(word) >= 2 && word[0] == '"' && word[len(word)-1] == '"':
		return strings.NewReplacer(`\"`, `"`, `\$`, `$`, `\\`, `\`, "\\`", "`").Replace(word[1 : len(word)-1])
	}
	return word
}

// alternation is the names, quoted for a regular expression, joined with |.
func alternation(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(q, "|")
}

// execsTegoWith matches a logical line that runs a tego binary: tegoHead, then one of the subcommands, which may
// be quoted. A wrapper or a function counts only where a command starts, so a function named in prose is not one. The
// pattern does not parse quoting: prose in an echo's quotes is not reported when the binary follows a quote or a space
// ("tego run is what the demo shows"), but is when it follows a ( or ; there ("== x (tego doctor as root)"). That
// errs toward a finding, and the tests of the shapes that must be reported do not rest on it.
func execsTegoWith(wrappers, binFuncs []string) *regexp.Regexp {
	return runsTegoWith(wrappers, binFuncs, subcommands)
}

// runsTegoWith is execsTegoWith for the given subcommands (launches for SH-7).
func runsTegoWith(wrappers, binFuncs []string, subs string) *regexp.Regexp {
	return regexp.MustCompile(tegoHead(wrappers, binFuncs) + `\s+` + quote + `?` + subs + `\b`)
}

// pyExecsTegoWith is pyExecsTego for the given subcommands.
func pyExecsTegoWith(subs string) *regexp.Regexp {
	return regexp.MustCompile(`\[\s*(?:"[^"\n]*tego"|'[^'\n]*tego'|[A-Za-z_][\w.]*(?:\([^()\n]*\))?(?:\[[^\]\n]*\])*)\s*,\s*["']` + subs + `["']`)
}

// forwardsToTego matches a line of a function body that runs the binary with the function's arguments
// ("$tego" "$@"): the function is then the binary at its call site (ey run x).
var forwardsToTego = regexp.MustCompile(tegoHead(nil, nil) + `\s+` + forwardsArgs)

// scriptFuncs are the names of the functions the script defines (wrappers), and of those among them whose body runs
// the binary with the function's arguments (binFuncs). A body is the rest of the definition's line when that line
// holds its closing }, or else the lines up to the first one that starts with }.
func scriptFuncs(text string) (wrappers, binFuncs []string) {
	for _, m := range definesFunc.FindAllStringSubmatchIndex(text, -1) {
		name := ""
		if m[2] >= 0 {
			name = text[m[2]:m[3]]
		} else {
			name = text[m[4]:m[5]]
		}
		wrappers = append(wrappers, name)
		first, after, _ := strings.Cut(text[m[1]:], "\n")
		body := []string{first}
		if !strings.Contains(first, "}") {
			for _, l := range strings.Split(after, "\n") {
				if strings.HasPrefix(strings.TrimSpace(l), "}") {
					break
				}
				body = append(body, l)
			}
		}
		for _, l := range body {
			if forwardsToTego.MatchString(l) {
				binFuncs = append(binFuncs, name)
				break
			}
		}
	}
	return wrappers, binFuncs
}

// runtimeDirAssignments returns the start of each value XDG_RUNTIME_DIR is assigned on a line, quotes and a Python
// f prefix removed; a comparison is none.
func runtimeDirAssignments(line string) []string {
	var vals []string
	for _, m := range assignsRuntimeDir.FindAllStringSubmatch(line, -1) {
		v := m[1] + m[2]
		if strings.HasPrefix(v, "=") {
			continue
		}
		vals = append(vals, unquoteStart(v))
	}
	return vals
}

// unquoteStart removes a value's leading quotes and Python f, r or b prefix.
func unquoteStart(v string) string {
	if len(v) > 1 && strings.ContainsRune("fFrRbB", rune(v[0])) && (v[1] == '"' || v[1] == '\'') {
		v = v[1:]
	}
	return strings.TrimLeft(v, `"'`)
}

// inheritedRuntimeDirLine returns the index of the first line that assigns XDG_RUNTIME_DIR the inherited value or the
// login session's directory, directly or through names assigned one (rt=$XDG_RUNTIME_DIR; XDG_RUNTIME_DIR=$rt, to any
// depth), or -1. A shell name is read as $name or ${name; a Python one bare.
func inheritedRuntimeDirLine(lines []string, py bool) int {
	tainted := map[string]bool{}
	inherited := func(v string) bool {
		if inheritedStart.MatchString(v) {
			return true
		}
		name := v
		if !py {
			if !strings.HasPrefix(v, "$") {
				return false
			}
			name = strings.TrimPrefix(strings.TrimPrefix(v, "$"), "{")
		}
		return tainted[identStart.FindString(name)]
	}
	// The names that hold an inherited value, to a fixed point (each pass adds one or ends).
	for changed := true; changed; {
		changed = false
		for _, l := range lines {
			var ms [][]string
			if py {
				ms = pyAssign.FindAllStringSubmatch(l, -1)
			} else {
				ms = shellAssign.FindAllStringSubmatch(l, -1)
			}
			for _, m := range ms {
				name, v := m[1], unquoteStart(strings.TrimSpace(m[2]))
				if name == "XDG_RUNTIME_DIR" || tainted[name] {
					continue
				}
				// A Python value read from the environment holds the runtime directory only when it names it (env =
				// os.environ.copy() is the whole environment).
				if py && strings.HasPrefix(v, "os.") && !strings.Contains(v, "XDG_RUNTIME_DIR") {
					continue
				}
				if inherited(v) {
					tainted[name], changed = true, true
				}
			}
		}
	}
	for i, l := range lines {
		for _, v := range runtimeDirAssignments(l) {
			if inherited(v) {
				return i
			}
		}
	}
	return -1
}

// checkScript applies SH-1 to SH-7 to one shell or Python script.
func checkScript(path, rel string) ([]finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Comment lines carry neither an assignment nor an isolation: they are removed, keeping the line numbers.
	lines := strings.Split(string(raw), "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			lines[i] = ""
		}
	}
	text := strings.Join(lines, "\n")
	// A command split with a trailing backslash is one logical line, numbered by its first physical line.
	type logical struct {
		n int
		s string
	}
	var ll []logical
	for i := 0; i < len(lines); i++ {
		l := logical{i + 1, lines[i]}
		for strings.HasSuffix(strings.TrimRight(l.s, " \t"), "\\") && i+1 < len(lines) {
			l.s = strings.TrimSuffix(strings.TrimRight(l.s, " \t"), "\\") + " " + lines[i+1]
			i++
		}
		ll = append(ll, l)
	}
	lineOf := func(re *regexp.Regexp) int {
		for _, l := range ll {
			if re.MatchString(l.s) {
				return l.n
			}
		}
		return 0
	}
	// lineOfText is lineOf over the whole text, for a pattern that spans lines (a Python list written over several).
	lineOfText := func(re *regexp.Regexp) int {
		loc := re.FindStringIndex(text)
		if loc == nil {
			return 0
		}
		return strings.Count(text[:loc[0]], "\n") + 1
	}
	var out []finding

	helper := helperSetsAll.MatchString(text)
	if n := lineOf(assignsConfig); n > 0 {
		if !strings.Contains(text, "TEGO_TEST_CHAIN_ANCHOR") && !helper {
			out = append(out, finding{rel, n, "SH-1", "assigns TEGO_CONFIG and never sets TEGO_TEST_CHAIN_ANCHOR: a run here " +
				"anchors in the invoking user's own ~/.tego/chain.log (tego's home is the passwd entry's, so HOME does not help)"})
		}
		if !strings.Contains(text, "TEGO_TEST_OWN_LOG_HOME") && !helper {
			out = append(out, finding{rel, n, "SH-1", "assigns TEGO_CONFIG and never sets TEGO_TEST_OWN_LOG_HOME: tego's own " +
				"log would be the invoking user's ~/.tego/tego.log"})
		}
	}
	if filepath.Ext(rel) == ".py" {
		if n := lineOf(opensPty); n > 0 && !histNull.MatchString(text) {
			out = append(out, finding{rel, n, "SH-2", "opens a pseudo-terminal and never sets HISTFILE=/dev/null: a shell " +
				"on it appends what was typed to the invoking user's ~/.bash_history on exit"})
		}
	}
	// SH-4: a script that builds the tego command builds it with the test hooks.
	if n := lineOf(buildsTego); n > 0 && !strings.Contains(text, "tegotesthooks") {
		out = append(out, finding{rel, n, "SH-4", "builds cmd/tego without tegotesthooks: the binary ignores " +
			"TEGO_TEST_CHAIN_ANCHOR and anchors every run in the invoking user's own ~/.tego/chain.log"})
	}
	// SH-5: a script that runs a tego binary sets the isolation itself or through the helper that does.
	runsRe, launchRe := execsTego, runsTegoWith(nil, nil, launches)
	if w, f := scriptFuncs(text); len(w) > 0 && filepath.Ext(rel) != ".py" {
		runsRe, launchRe = execsTegoWith(w, f), runsTegoWith(w, f, launches)
	}
	runs := lineOf(runsRe)
	if runs == 0 && filepath.Ext(rel) != ".py" {
		// the binary handed to a shell's -c script as $0 or $1 (root-suites.sh's doctor).
		for _, l := range ll {
			if runsThroughShell(l.s, text) {
				runs = l.n
				break
			}
		}
	}
	if runs == 0 && filepath.Ext(rel) == ".py" && pyNamesTego.MatchString(text) {
		runs = lineOfText(pyExecsTego)
	}
	if runs > 0 {
		if !helper && !(strings.Contains(text, "TEGO_TEST_CHAIN_ANCHOR") && strings.Contains(text, "TEGO_TEST_OWN_LOG_HOME")) {
			out = append(out, finding{rel, runs, "SH-5", "runs a tego binary and neither sets TEGO_TEST_CHAIN_ANCHOR and " +
				"TEGO_TEST_OWN_LOG_HOME nor calls kt_config or lib_init: the run would anchor in the invoking user's own ~/.tego/chain.log"})
		}
		// SH-6: and, taking the binary from its caller, refuses one that is not a test build.
		if n := lineOf(readsTegoBin); n > 0 && !refusesProductBuild.MatchString(text) {
			out = append(out, finding{rel, n, "SH-6", "runs the tego binary its caller names and never checks that it is a test build " +
				"(kt_require_testhooks, or grep -aq TEGO_TEST_CHAIN_ANCHOR on it): a product build ignores the anchor variable"})
		}
	}
	// SH-7: a script that starts a run gives tego an XDG_RUNTIME_DIR of its own, and never the inherited one.
	launch := 0
	if filepath.Ext(rel) == ".py" {
		if pyNamesTego.MatchString(text) {
			launch = lineOfText(pyLaunchesTego)
		}
	} else {
		launch = lineOf(launchRe)
	}
	if launch > 0 {
		py := filepath.Ext(rel) == ".py"
		texts := make([]string, len(ll))
		for i, l := range ll {
			texts[i] = l.s
		}
		owns := false
		for _, l := range texts {
			if len(runtimeDirAssignments(l)) > 0 {
				owns = true
				break
			}
		}
		if py && !owns {
			owns = quotedRuntimeDir.MatchString(text) && refusesLoginRuntimeDir.MatchString(text)
		}
		if i := inheritedRuntimeDirLine(texts, py); i >= 0 {
			out = append(out, finding{rel, ll[i].n, "SH-7", "starts a run and hands tego the inherited XDG_RUNTIME_DIR or the login session's " +
				"/run/user/<uid>: the launch makes <XDG_RUNTIME_DIR>/tego and removes the directories the invoking user's crashed runs left there; " +
				"give it a 0700 directory of the script's own"})
		} else if !helper && !owns {
			out = append(out, finding{rel, launch, "SH-7", "starts a run and never sets XDG_RUNTIME_DIR nor calls kt_config or lib_init: the launch " +
				"makes the invoking user's /run/user/<uid>/tego and removes the directories their crashed runs left there"})
		}
	}
	if n := lineOf(interactive); n > 0 && !histNull.MatchString(text) {
		out = append(out, finding{rel, n, "SH-3", "starts an interactive shell and never sets HISTFILE=/dev/null: what is typed " +
			"into it is appended to the invoking user's ~/.bash_history on exit"})
	}
	return out, nil
}
