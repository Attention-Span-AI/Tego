// SPDX-License-Identifier: Apache-2.0

// Command checkexits checks the two exit-code rules limits-check-doctor-cli.md states as CI checks, on the Go
// syntax tree rather than with a grep, so an import alias, a dot import, a call split across lines or os.Exit
// taken as a value is caught.
//
//	I6: nothing but cmd/ uses os.Exit (or syscall.Exit, unix.Exit, log.Fatal*, a *log.Logger, flag.Parse,
//	    flag.ExitOnError): every command returns its code to cli.Main, which returns it to cmd/tego's main, so
//	    any command is callable in-process from a test. Test files,
//	    tools/ (developer programs), test/perf/cmd, test/conformance/cmd, the guest helpers under test/vm/cmd, the
//	    test workloads under test/workloads and the stand-in Claude Code under test/e2e/reason-claude/fakeclaude
//	    (programs of their own, not tego) are exempt.
//	I9: internal/cli returns no bare non-zero integer: an exit code is a named identity.Exit* value, or the
//	    return's line carries a comment citing the rule it comes from.
//
// The files are the ones git lists in the checkout, tracked or untracked but not ignored
// (`git ls-files -co --exclude-standard`), filtered here: git's exclude pathspecs, which the grep this replaces
// used, emptied the list on git 2.51 when combined with a directory-prefixed pattern, and I9 then checked nothing.
// An empty list is itself a failure.
//
// Usage: go run ./tools/checkexits [root]   (root defaults to the working directory)
// Exit: 0 when both hold; 1 when either does not; 2 on a read or parse error.
//
// Imports: standard library only.
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// exitPkgs are the import paths whose Exit ends the process.
var exitPkgs = map[string]bool{"os": true, "syscall": true, "golang.org/x/sys/unix": true}

// fatalPkgs are the import paths whose Fatal, Fatalf and Fatalln end the process through os.Exit(1) (log), or
// whose flag parsing does (flag).
var fatalPkgs = map[string]bool{"log": true, "flag": true}

func isFatal(sel string) bool { return sel == "Fatal" || sel == "Fatalf" || sel == "Fatalln" }

// endsProcess is whether pkg's sel ends the process, or hands out something that can: Exit of an exitPkgs
// package; Fatal* of log, and log.New and log.Default, whose *Logger's Fatal* methods end it too (a method call
// on a local variable is invisible to a syntax check, so the loggers are refused where they are made); flag.Parse
// and flag.ExitOnError, since the default flag set and any ExitOnError one os.Exit(2) on a bad flag.
func endsProcess(pkg, sel string) bool {
	if exitPkgs[pkg] {
		return sel == "Exit"
	}
	switch pkg {
	case "log":
		return isFatal(sel) || sel == "New" || sel == "Default"
	case "flag":
		return sel == "Parse" || sel == "ExitOnError"
	}
	return false
}

// Finding is one violation.
type Finding struct {
	Rule string // "I6" or "I9"
	Pos  string // file:line
	What string
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	findings, err := Check(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "checkexits:", err)
		os.Exit(2)
	}
	if len(findings) == 0 {
		return
	}
	for _, f := range findings {
		switch f.Rule {
		case "I6":
			fmt.Printf("checkexits: %s: %s outside cmd/ (limits-check-doctor-cli.md I6: return the code to cli.Main instead)\n", f.Pos, f.What)
		default:
			fmt.Printf("checkexits: %s: %s in internal/cli (limits-check-doctor-cli.md I9: use identity.Exit*, or cite the rule in a comment on the line)\n", f.Pos, f.What)
		}
	}
	os.Exit(1)
}

// listGo lists the checkout's Go files, relative to root with forward slashes.
func listGo(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "-co", "--exclude-standard", "--", "*.go")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, filepath.ToSlash(f))
		}
	}
	sort.Strings(files)
	return files, nil
}

// exemptI6 is whether a file may end the process itself.
func exemptI6(f string) bool {
	return strings.HasSuffix(f, "_test.go") || strings.HasPrefix(f, "cmd/") || strings.HasPrefix(f, "tools/") ||
		strings.HasPrefix(f, "test/workloads/") || strings.HasPrefix(f, "test/conformance/cmd/") ||
		strings.HasPrefix(f, "test/perf/cmd/") || strings.HasPrefix(f, "test/vm/cmd/") ||
		strings.HasPrefix(f, "test/e2e/reason-claude/fakeclaude/")
}

// inCLI is whether I9 covers a file: internal/cli's own non-test files, not its subpackages'.
func inCLI(f string) bool {
	return !strings.HasSuffix(f, "_test.go") && filepath.ToSlash(filepath.Dir(f)) == "internal/cli"
}

// Check checks every Go file under root that git lists.
func Check(root string) ([]Finding, error) {
	files, err := listGo(root)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("git listed no Go file under %s; nothing was checked", root)
	}
	var out []Finding
	cli := 0
	for _, f := range files {
		i6, i9 := !exemptI6(f), inCLI(f)
		if !i6 && !i9 {
			continue
		}
		if i9 {
			cli++
		}
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			if os.IsNotExist(err) {
				continue // listed but deleted in the working tree
			}
			return nil, err
		}
		fs, err := CheckFile(f, src, i6, i9)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	if cli == 0 {
		return nil, fmt.Errorf("no file under internal/cli was listed; I9 checked nothing")
	}
	return out, nil
}

// CheckFile checks one file's source: I6 when i6, I9 when i9.
func CheckFile(name string, src []byte, i6, i9 bool) ([]Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []Finding
	pos := func(p token.Pos) string {
		position := fset.Position(p)
		return fmt.Sprintf("%s:%d", name, position.Line)
	}
	if i6 {
		// names are the file's identifiers for an exit package; dot is whether one is dot-imported.
		names, dots := map[string]string{}, []string{}
		logImported := false
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || !(exitPkgs[path] || fatalPkgs[path]) {
				continue
			}
			name := filepath.Base(path)
			logImported = logImported || path == "log"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			switch name {
			case "_":
			case ".":
				dots = append(dots, path)
			default:
				names[name] = path
			}
		}
		var visit func(n ast.Node) bool
		visit = func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				id, ok := x.X.(*ast.Ident)
				isPkg := false
				if ok {
					var path string
					if path, isPkg = names[id.Name]; isPkg && endsProcess(path, x.Sel.Name) {
						out = append(out, Finding{"I6", pos(x.Pos()), path + "." + x.Sel.Name})
					}
				}
				// A Fatal* method of anything but the package, in a file that imports log: a *log.Logger's.
				if logImported && !isPkg && isFatal(x.Sel.Name) {
					out = append(out, Finding{"I6", pos(x.Pos()), "(*log.Logger)." + x.Sel.Name})
				}
				if !ok {
					// X is an expression (a call chain, a literal): walk it, but never Sel, which is no free
					// identifier.
					ast.Inspect(x.X, visit)
				}
				return false
			case *ast.Ident:
				for _, dot := range dots {
					if endsProcess(dot, x.Name) {
						out = append(out, Finding{"I6", pos(x.Pos()), dot + "." + x.Name + " (dot import)"})
					}
				}
			}
			return true
		}
		ast.Inspect(file, visit)
	}
	if i9 {
		commented := map[int]bool{}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				commented[fset.Position(c.Pos()).Line] = true
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok || len(ret.Results) != 1 {
				return true
			}
			if v, ok := intLit(ret.Results[0]); ok && v != 0 {
				line := fset.Position(ret.Pos()).Line
				end := fset.Position(ret.End()).Line
				for l := line; l <= end; l++ {
					if commented[l] {
						return true
					}
				}
				out = append(out, Finding{"I9", pos(ret.Pos()), fmt.Sprintf("return %d", v)})
			}
			return true
		})
	}
	return out, nil
}

// intLit is the value of an integer literal, through parentheses and a sign.
func intLit(e ast.Expr) (int64, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return intLit(x.X)
	case *ast.UnaryExpr:
		if x.Op == token.SUB || x.Op == token.ADD {
			v, ok := intLit(x.X)
			if x.Op == token.SUB {
				v = -v
			}
			return v, ok
		}
	case *ast.BasicLit:
		if x.Kind == token.INT {
			v, err := strconv.ParseInt(strings.ReplaceAll(x.Value, "_", ""), 0, 64)
			return v, err == nil
		}
	}
	return 0, false
}
