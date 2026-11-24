// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// moduleRoot is the directory that holds go.mod, from this package's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}

// productFiles walks the module's Go files that are no tests, outside the folders that are not the product's
// source (the archive, notes, vendored and generated trees).
func productFiles(t *testing.T, root string, visit func(rel string, src []byte)) {
	t.Helper()
	skip := map[string]bool{".git": true, "archive": true, "node_modules": true, "testdata": true, "rust": true}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		visit(filepath.ToSlash(rel), src)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// inOrdinaryBuild reports whether an ordinary build (no build tag) compiles the file.
func inOrdinaryBuild(t *testing.T, root, rel string) bool {
	t.Helper()
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.BuildTags, ctx.CgoEnabled = "linux", "amd64", nil, false
	ok, err := ctx.MatchFile(filepath.Join(root, filepath.Dir(rel)), filepath.Base(rel))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return ok
}

// The names of the gate's two switches: whoever can flip one must name one of these.
var (
	switchNames = []string{"SetWSLRuleForTest", "TEGO_TEST_WSL_RULE", "SetNestedRuleForTest", "TEGO_TEST_NESTED_RULE"}
	switchVars  = map[string]bool{"wslRule": true, "nestedRule": true}
	switchFuncs = []string{"wslRuleOn", "nestedRuleOn"}
	// switchConstants is the constant each switch's ordinary definition returns.
	switchConstants = map[string]string{"wslRuleOn": "true", "nestedRuleOn": "false"}
)

// TestOrdinaryBuildCannotTurnTheWSLRuleOn: the rule's use on WSL is on in an ordinary build (ADR 0100, amended when it
// was switched on) and outside WSL beyond the first cgroup namespace, where it is not proven, off; and such a build has
// no way to change either. Its one definition of each switch is a function whose whole body is a constant ("return
// true" for WSL's, "return false" for the nested one); the variables, their setters and the environment variables that
// drive the setters exist only in files an ordinary build leaves out (the tegotesthooks tag), in this package and in
// every other.
func TestOrdinaryBuildCannotTurnTheWSLRuleOn(t *testing.T) {
	root := moduleRoot(t)
	definitions, named := map[string]int{}, 0
	productFiles(t, root, func(rel string, src []byte) {
		ordinary := inOrdinaryBuild(t, root, rel)
		text := string(src)
		for _, name := range switchNames {
			if strings.Contains(text, name) {
				named++
				if ordinary {
					t.Errorf("%s names %s and is part of an ordinary build", rel, name)
				}
			}
		}
		if filepath.ToSlash(filepath.Dir(rel)) != "internal/platform/peer" {
			return
		}
		f, err := parser.ParseFile(token.NewFileSet(), rel, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if switchVars[x.Name] && ordinary {
					t.Errorf("%s names the switch variable %s and is part of an ordinary build", rel, x.Name)
				}
			case *ast.FuncDecl:
				name := x.Name.Name
				if !slices.Contains(switchFuncs, name) || !ordinary {
					return true
				}
				definitions[name]++
				if x.Body == nil || len(x.Body.List) != 1 {
					t.Errorf("%s: the ordinary build's %s is not a single return", rel, name)
					return true
				}
				ret, ok := x.Body.List[0].(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					t.Errorf("%s: the ordinary build's %s is not a single return", rel, name)
					return true
				}
				if id, ok := ret.Results[0].(*ast.Ident); !ok || id.Name != switchConstants[name] || x.Type.Params.NumFields() != 0 {
					t.Errorf("%s: the ordinary build's %s does not return the constant %s", rel, name, switchConstants[name])
				}
			}
			return true
		})
	})
	for _, name := range switchFuncs {
		if definitions[name] != 1 {
			t.Errorf("an ordinary build has %d definitions of %s; want one", definitions[name], name)
		}
	}
	if named == 0 {
		t.Error("no file names the switch's setter or its environment variable: the proof builds have no switch to check")
	}
}

// TestProbeReadsNothingElseOfThePeer: the rule's code opens three files beneath the anchored /proc and no more
// (this process's cgroup, pid 1's cgroup and the listener's cgroup, with the pidfd's fdinfo of this process), opens
// no namespace link of another process, never opens a pidfd on a pid number, and neither writes to nor reads from
// the manager's socket.
func TestProbeReadsNothingElseOfThePeer(t *testing.T) {
	src, err := os.ReadFile("self.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "self.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var anchored []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if x.Name.Name == "pathExists" {
				return false // the gate's look at WSL's own marks, which are no file of the peer
			}
		case *ast.CallExpr:
			text := func(e ast.Expr) string {
				return string(src[fset.Position(e.Pos()).Offset:fset.Position(e.End()).Offset])
			}
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "anchoredRead" && len(x.Args) == 2 {
				anchored = append(anchored, text(x.Args[1]))
			}
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				switch sel.Sel.Name {
				case "Openat2": // every open beneath the anchor that is not anchoredRead's own
					if a := text(x.Args[0]); a != "rel" {
						anchored = append(anchored, a)
					}
				case "Open", "Openat":
					if a := text(x.Args[0]); a != "path" {
						t.Errorf("self.go:%d opens %s outside the anchor", fset.Position(x.Pos()).Line, a)
					}
				}
				switch sel.Sel.Name {
				case "PidfdOpenProcessFD", "PidfdOpenProcess", "PidfdOpen", "PidfdOpenThreadFD", "PidfdOpenThread":
					t.Errorf("self.go:%d opens a pidfd on a pid number (%s): the rule has no such fallback", fset.Position(x.Pos()).Line, sel.Sel.Name)
				case "Write", "Sendmsg", "Sendto", "Send", "Recvmsg", "Recvfrom", "Readlink", "Stat", "Lstat", "Fstatat", "Statx":
					t.Errorf("self.go:%d calls %s: the probe sends and reads nothing on the socket and stats no file of the peer",
						fset.Position(x.Pos()).Line, sel.Sel.Name)
				}
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING && strings.Contains(x.Value, "/ns/") && x.Value != `"/proc/self/ns/cgroup"` {
				t.Errorf("self.go:%d names a namespace link other than this process's own cgroup namespace: %s", fset.Position(x.Pos()).Line, x.Value)
			}
		}
		return true
	})
	want := []string{`"self/cgroup"`, `"1/cgroup"`, `"self/fdinfo/"+strconv.Itoa(n)`, `strconv.Itoa(pid)+"/cgroup"`}
	// The two opens by absolute path are of constants of this process alone (selfHost: its namespace file and /proc).
	if strings.Join(anchored, " | ") != strings.Join(want, " | ") {
		t.Errorf("the rule's anchored reads are %v; want %v", anchored, want)
	}
}

// TestUnshareThreadsAreNeverHandedBack: the proof of a cgroup namespace stays true for the life of the process only
// while no thread of it enters or makes another. tego calls unshare in two places, for a mount namespace
// (CLONE_NEWNS) and a private fs_struct (CLONE_FS), never for a cgroup namespace, and never setns; each of the two
// runs on a thread locked to its goroutine that is not unlocked after the unshare, so the runtime ends the thread
// with the goroutine and no probe can run on it.
func TestUnshareThreadsAreNeverHandedBack(t *testing.T) {
	root := moduleRoot(t)
	sites := map[string]string{
		"internal/doctor/planeknown.go":           "unix.CLONE_NEWNS",
		"internal/runtime/supervisor/ask_open.go": "unix.CLONE_FS",
	}
	seen := map[string]bool{}
	productFiles(t, root, func(rel string, src []byte) {
		if strings.HasPrefix(rel, "tools/") {
			return
		}
		text := string(src)
		if strings.Contains(text, "unix.Setns(") || strings.Contains(text, "SYS_SETNS,") {
			t.Errorf("%s calls setns: a thread that enters another namespace would outlive the proof's premise", rel)
		}
		for _, call := range []string{"unix.Unshare(", "syscall.Unshare("} {
			for rest := text; ; {
				i := strings.Index(rest, call)
				if i < 0 {
					break
				}
				rest = rest[i+len(call):]
				arg, _, _ := strings.Cut(rest, ")")
				if sites[rel] != arg {
					t.Errorf("%s calls unshare(%s): only %v are reviewed, and none makes a cgroup namespace", rel, arg, sites)
					continue
				}
				seen[rel] = true
				if strings.Contains(rest, "UnlockOSThread") {
					t.Errorf("%s unlocks its thread after unshare(%s): the thread would go back to the runtime", rel, arg)
				}
			}
		}
		if strings.Contains(text, "CLONE_NEWCGROUP") && (strings.Contains(text, "Cloneflags") || strings.Contains(text, "Unshareflags")) {
			t.Errorf("%s starts a process in a new cgroup namespace", rel)
		}
	})
	for rel := range sites {
		if !seen[rel] {
			t.Errorf("%s no longer calls unshare: update this test's list of the reviewed sites", rel)
		}
	}
}
