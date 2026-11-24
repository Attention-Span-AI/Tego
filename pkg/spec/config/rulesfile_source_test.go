// SPDX-License-Identifier: Apache-2.0

package config

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// rulesSource is where the bytes one place in the tree compiles as rules come from: the functions that read them from
// a file (each must read them through ReadRulesFile itself), or, when they come from no file, why.
type rulesSource struct {
	readers  []string
	notAFile string
}

// rulesLoadSites is every function outside pkg/spec/agent that hands rules text to the loader (agent.Load,
// agent.LoadBytes, agent.LoadBytesBounded, agent.LoadTestTable, agent.LoadTestTableBytes), keyed
// "<file>:<function>" (a method as "(<receiver>).<name>"), with where its bytes come from. A new loader fails
// TestRulesFilesAreReadThroughOneFunction until it is listed here, with the readers it reads through.
var rulesLoadSites = map[string]rulesSource{
	// tego compile, test, print and run by path: agent.Load reads through readCapped; standard input directly.
	"internal/cli/compile.go:loadContract":   {readers: []string{"pkg/spec/agent/load.go:readCapped", "internal/cli/compile.go:loadContract"}},
	"internal/cli/compile.go:runCompileTest": {readers: []string{"pkg/spec/agent/load.go:readCapped"}},
	// tego run <name>, tego rules, the guide: a registry entry (the project's agent.yaml, .tego/agents, the user
	// registry), read by readEntry.
	"internal/cli/contractref.go:(contractRef).load": {readers: []string{"internal/registry/registry.go:readEntry"}},
	// A run's recorded copy of its contract.
	"internal/cli/contractcopy.go:loadContractCopy": {readers: []string{"internal/cli/contractcopy.go:readCopy"}},
	"internal/cli/mcp.go:mcpRunContract":            {readers: []string{"internal/cli/contractcopy.go:readCopy"}},
	// tego rules edit and tego start check the text a person's rules file holds, or their edit of it, read by
	// readRulesPath.
	"internal/cli/rules_edit.go:checkRules": {readers: []string{"internal/cli/rulesread.go:readRulesPath"}},
	"internal/cli/learn.go:saveProposal":    {notAFile: "the proposal tego learn made, in memory, before it is saved"},
	// The dashboard's contract list: a file the catalog opens through rulefile.Read, or a registry entry.
	"internal/contracts/catalog.go:(*Catalog).checkSource": {readers: []string{"internal/rulefile/guard.go:(*pinned).read",
		"internal/registry/registry.go:readEntry"}},
	// The general policy layers (system and user), read by config.ReadPolicySource.
	"internal/contractsrc/general.go:readGeneral": {readers: []string{"pkg/spec/config/policysource.go:readPolicySourceAt"}},
	// The next run's compile: a registry entry, a rule change to a file rulefile.Read read, or a dashboard request.
	"internal/nextrun/nextrun.go:Compile": {readers: []string{"internal/registry/registry.go:readEntry",
		"internal/rulefile/guard.go:(*pinned).read"}},
	"internal/control/rulesview/inforce.go:checkSource":  {readers: []string{"internal/control/rulesview/rulesview.go:readRegularNoFollow"}},
	"internal/control/rulesview/rulesview.go:loadCopy":   {readers: []string{"internal/control/rulesview/rulesview.go:readRegularNoFollow"}},
	"internal/control/draftcompile/compile.go:compile":   {notAFile: "the draft text of a dashboard request"},
	"internal/setup/check.go:CheckFile":                  {notAFile: "the contract tego start composes, in memory"},
	"internal/setup/compose.go:CheckReviewFile":          {notAFile: "the review contract tego start composes, in memory"},
	"internal/testutil/contracttest/contract.go:BuildAt": {readers: []string{"pkg/spec/agent/load.go:readCapped"}},
	"test/vm/cmd/adoptprobe/main.go:table":               {notAFile: "a contract literal the guest probe writes"},
	"test/vm/cmd/adoptprobe/main.go:phasePlane":          {notAFile: "a contract literal the guest probe writes"},
	"tools/baselinefixture/main.go:run":                  {notAFile: "contract literals the fixture builder holds in memory"},
}

// profileSources is every ProfileSource (a Resolve(name string) (string, []byte, error) method) outside tests, with
// where the profile bytes it returns come from.
var profileSources = map[string]rulesSource{
	"internal/profilesrc/dir.go:(Dir).Resolve":                 {readers: []string{"internal/profilesrc/dir.go:(Dir).resolve"}},
	"internal/cli/contractcopy.go:(sealedProfiles).Resolve":    {notAFile: "a run's sealed copy extends nothing"},
	"internal/control/rulesview/rulesview.go:(sealed).Resolve": {notAFile: "a run's sealed copy extends nothing"},
	"pkg/spec/presets/presets.go:(Source).Resolve":             {notAFile: "the presets built into the binary"},
	"pkg/spec/agent/profilechain.go:(*ProfileChain).Resolve":   {notAFile: "it asks the sources it chains, each listed here"},
}

// rawReadAllowed is each listed function whose body calls a raw read that reads no file on a disk, with why. A listed
// reader reads rules content only through config.ReadRulesFile, in every branch.
var rawReadAllowed = map[string]bool{
	// The presets are embedded in the binary (embed.FS), not read from a file.
	"pkg/spec/presets/presets.go:(Source).Resolve": true,
}

// otherRulesReaders are rules files read outside a loader: to show, edit or save them, or a registry entry rewritten.
var otherRulesReaders = []string{
	"internal/registry/write.go:ReadIdentityAt",
	"internal/rulefile/journal.go:(*journal).readBlob",
}

// privateOnlyFiles are the files of the tables above that the public export leaves out (tools/oss/manifest.txt's "!"
// lines), so a public tree does not hold them.
var privateOnlyFiles = map[string]bool{
	"tools/baselinefixture/main.go": true,
}

// absentFromTree reports whether the file of a "<file>:<function>" key is one of privateOnlyFiles and this tree does
// not hold it (the public cut). Their entries stay in the tables above for the private tree. Any other entry whose file
// is gone is stale and fails, in either tree: a deleted file with no replacement must not pass (review F2); a listed
// function that is gone from a file the tree holds fails too (tools/rulecheck's baseline_readers_test.go treats its
// inventory the same way).
func absentFromTree(root, key string) bool {
	file, _, _ := strings.Cut(key, ":")
	if !privateOnlyFiles[file] {
		return false
	}
	_, err := os.Stat(filepath.Join(root, file))
	return os.IsNotExist(err)
}

// TestAbsentFromTreeSkipsOnlyPrivateOnlyFiles pins that the public cut's missing file is tolerated for the private-only
// list and for nothing else (review F2).
func TestAbsentFromTreeSkipsOnlyPrivateOnlyFiles(t *testing.T) {
	root := t.TempDir()
	if !absentFromTree(root, "tools/baselinefixture/main.go:run") {
		t.Error("a private-only file the tree does not hold must be skipped")
	}
	if absentFromTree(root, "tools/doesnotexist/main.go:run") {
		t.Error("a table entry whose file is gone and is not private-only must not be skipped")
	}
	if err := os.MkdirAll(filepath.Join(root, "tools", "baselinefixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tools", "baselinefixture", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if absentFromTree(root, "tools/baselinefixture/main.go:run") {
		t.Error("a private-only file the tree holds is looked for, not skipped")
	}
}

// TestRulesFilesAreReadThroughOneFunction (ADR 0059, amended 2026-11-19, round 5; review F3): every read of a rules file
// goes through ReadRulesFile, which checks the file system of the descriptor it reads. It holds the tree to that by
// its source: every place that hands rules text to the loader, and every profile source, is listed with the functions
// its bytes are read by, and each of those calls ReadRulesFile; no function outside it reads under the rules file
// cap (io.LimitReader with MaxContractSize+1), and no listed reader (nor a loader site that is not one) reads content
// another way in any branch (os.ReadFile, io.ReadAll, a Read method, a bufio reader). A loader named but not called
// (load := agent.LoadBytes) is a loader site too (round 6, review G2: both bypasses the reviewer built passed before).
func TestRulesFilesAreReadThroughOneFunction(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s: %v", root, err)
	}
	type fn struct {
		readsRules bool
		// rawReads is every call in the body that reads content another way (os.ReadFile, io.ReadAll, a Read method,
		// a bufio reader): none of a listed reader's reads may bypass ReadRulesFile, in any branch.
		rawReads []string
	}
	funcs := map[string]fn{}
	sites := map[string]bool{}
	sources := map[string]bool{}
	var capped []string
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "archive", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := goparser.ParseFile(fset, p, nil, goparser.SkipObjectResolution)
		if err != nil {
			return err
		}
		agentName, configName := importName(f, "github.com/attention-span-ai/tego/pkg/spec/agent"), importName(f, "github.com/attention-span-ai/tego/pkg/spec/config")
		inConfig := strings.HasPrefix(rel, "pkg/spec/config/")
		inAgent := strings.HasPrefix(rel, "pkg/spec/agent/")
		if agentName == "." {
			t.Errorf("%s dot-imports pkg/spec/agent: the loaders cannot be told from its other functions", rel)
		}
		for _, decl := range f.Decls {
			if gd, ok := decl.(*ast.GenDecl); ok && !inAgent && agentName != "" {
				// A loader named at package level (var load = agent.LoadBytes) is a function value.
				ast.Inspect(gd, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && isLoaderRef(sel, agentName) {
						sites[rel+":(package level)"] = true
					}
					return true
				})
			}
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			key := rel + ":" + funcName(fd)
			if fd.Recv != nil && fd.Name.Name == "Resolve" && isProfileResolve(fd.Type) {
				sources[key] = true
			}
			var info fn
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				// A loader named but not called (load := agent.LoadBytes, passed as an argument) is a loader site
				// too: the call through the value is not seen.
				if sel, ok := n.(*ast.SelectorExpr); ok && !inAgent && isLoaderRef(sel, agentName) {
					sites[key] = true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				pkg, name := callee(call)
				switch {
				case name == "ReadRulesFile" && (pkg == configName && configName != "" || inConfig && pkg == ""):
					info.readsRules = true
				case pkg == "io" && name == "LimitReader" && len(call.Args) == 2 && capPlusOne(call.Args[1]):
					capped = append(capped, fset.Position(call.Pos()).String())
				case isRawRead(pkg, name):
					info.rawReads = append(info.rawReads, fset.Position(call.Pos()).String()+" "+callText(pkg, name))
				}
				return true
			})
			funcs[key] = info
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	checkReaders := func(what, key string, s rulesSource) {
		if len(s.readers) == 0 && s.notAFile == "" {
			t.Errorf("%s %s: name the functions that read its bytes, or say why they come from no file", what, key)
		}
		// The place that hands the bytes to the loader reads nothing itself, unless it is one of the listed readers (then
		// the check below holds it to ReadRulesFile): a loader that reads its own bytes another way is a bypass.
		if own, ok := funcs[key]; ok && len(own.rawReads) > 0 && !slices.Contains(s.readers, key) && !rawReadAllowed[key] {
			t.Errorf("%s %s reads content itself, yet lists no reader that is itself: %s", what, key, strings.Join(own.rawReads, ", "))
		}
		for _, r := range s.readers {
			info, ok := funcs[r]
			switch {
			case !ok:
				t.Errorf("%s %s: its reader %s is not in the tree", what, key, r)
			case !info.readsRules:
				t.Errorf("%s %s: its reader %s does not read through config.ReadRulesFile", what, key, r)
			case len(info.rawReads) > 0 && !rawReadAllowed[r]:
				t.Errorf("%s %s: its reader %s also reads content another way, so its bytes may bypass config.ReadRulesFile "+
					"in some branch: %s", what, key, r, strings.Join(info.rawReads, ", "))
			}
		}
	}
	for _, key := range sortedKeys(sites) {
		s, ok := rulesLoadSites[key]
		if !ok {
			t.Errorf("rules loader %s is not listed in rulesLoadSites: name the functions that read its bytes (each through "+
				"config.ReadRulesFile), or why they come from no file", key)
			continue
		}
		checkReaders("rules loader", key, s)
	}
	for key := range rulesLoadSites {
		if !sites[key] && !absentFromTree(root, key) {
			t.Errorf("rulesLoadSites lists %s, which loads no rules any more", key)
		}
	}
	for _, key := range sortedKeys(sources) {
		s, ok := profileSources[key]
		if !ok {
			t.Errorf("profile source %s is not listed in profileSources", key)
			continue
		}
		checkReaders("profile source", key, s)
	}
	for key := range profileSources {
		if !sources[key] && !absentFromTree(root, key) {
			t.Errorf("profileSources lists %s, which is no profile source any more", key)
		}
	}
	for _, r := range otherRulesReaders {
		checkReaders("rules reader", r, rulesSource{readers: []string{r}})
	}
	for _, at := range capped {
		t.Errorf("%s reads under the rules file cap (MaxContractSize) itself: read the rules file through config.ReadRulesFile", at)
	}
}

// importName is the name a file refers to the package at path by, "" when it does not import it.
func importName(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return path[strings.LastIndexByte(path, '/')+1:]
	}
	return ""
}

// funcName is a function's name, a method's as "(<receiver type>).<name>".
func funcName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	recv := ""
	switch t := fd.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			recv = "*" + id.Name
		}
	case *ast.Ident:
		recv = t.Name
	}
	return "(" + recv + ")." + fd.Name.Name
}

// callee is a call's package (or receiver) name and function name: "", name for a plain call.
func callee(call *ast.CallExpr) (pkg, name string) {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return "", f.Name
	case *ast.SelectorExpr:
		if id, ok := f.X.(*ast.Ident); ok {
			return id.Name, f.Sel.Name
		}
		return "?", f.Sel.Name
	}
	return "?", ""
}

// capPlusOne reports whether a read limit is the rules file cap plus one (MaxContractSize+1), the limit a rules file's
// own read takes to tell a file past the cap apart.
func capPlusOne(e ast.Expr) bool {
	b, ok := e.(*ast.BinaryExpr)
	if !ok || b.Op != token.ADD {
		return false
	}
	one, ok := b.Y.(*ast.BasicLit)
	return ok && one.Value == "1" && mentions(b.X, "MaxContractSize")
}

// mentions reports whether an expression names ident (as an identifier or a selector's name).
func mentions(e ast.Expr, ident string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			found = found || x.Name == ident
		case *ast.SelectorExpr:
			found = found || x.Sel.Name == ident
		}
		return !found
	})
	return found
}

// isProfileResolve reports whether a method type is ProfileSource's Resolve: (string) (string, []byte, error).
func isProfileResolve(t *ast.FuncType) bool {
	if t.Params == nil || t.Results == nil || len(t.Params.List) != 1 || len(t.Results.List) != 3 {
		return false
	}
	_, isSlice := t.Results.List[1].Type.(*ast.ArrayType)
	return isSlice
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// loaderNames are the functions of pkg/spec/agent that parse rules text.
var loaderNames = []string{"Load", "LoadBytes", "LoadBytesBounded", "LoadTestTable", "LoadTestTableBytes"}

// isLoaderRef reports whether sel names one of the agent package's loaders, called or not.
func isLoaderRef(sel *ast.SelectorExpr, agentName string) bool {
	id, ok := sel.X.(*ast.Ident)
	return ok && agentName != "" && id.Name == agentName && slices.Contains(loaderNames, sel.Sel.Name)
}

// isRawRead reports whether a call reads file content other than through ReadRulesFile: os.ReadFile and the io, ioutil
// and bufio readers, or any method named like a read (Read, ReadAt, ReadFrom, ReadAll, ReadString, ReadBytes, ...).
func isRawRead(pkg, name string) bool {
	switch pkg {
	case "os", "ioutil":
		return name == "ReadFile" || name == "ReadAll"
	case "io":
		return slices.Contains([]string{"ReadAll", "ReadFull", "ReadAtLeast", "Copy", "CopyN", "CopyBuffer"}, name)
	case "bufio":
		return strings.HasPrefix(name, "New")
	case "":
		return false
	}
	return strings.HasPrefix(name, "Read") && name != "ReadRulesFile" && name != "ReadDir" && name != "ReadDirNames" && name != "Readdir" && name != "Readdirnames"
}

func callText(pkg, name string) string {
	if pkg == "" {
		return name
	}
	return pkg + "." + name
}
