// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This deliberately over-approximates readers: construction sites, generic byte
// offsets and baseline summary fields are inventoried too. Parse every build tag,
// like isocheck, so an inactive platform cannot hide a new ingress. Counts catch
// added sites within an already inventoried function as well as new functions.
func TestBaselineReaderInventory(t *testing.T) {
	root := "../.."
	sites, tests, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open("baseline_readers.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	inventory := map[string]bool{}
	sc := bufio.NewScanner(file)
	for sc.Scan() {
		row := strings.TrimSpace(sc.Text())
		if row == "" || strings.HasPrefix(row, "#") {
			continue
		}
		fields := strings.Split(row, "\t")
		if len(fields) != 3 {
			t.Fatalf("invalid inventory row: %s", row)
		}
		site, count, route := fields[0], fields[1], fields[2]
		if inventory[site] {
			t.Errorf("duplicate inventory entry %s", site)
		}
		inventory[site] = true
		n, err := strconv.Atoi(count)
		if err != nil || n < 1 {
			t.Fatalf("bad count: %s", row)
		}
		if !tests[route] {
			t.Errorf("inventory route test does not exist: %s", route)
		}
		if found, ok := sites[site]; ok {
			if found != n {
				t.Errorf("reader sites changed: %s count=%d want=%d; exercise the new route and update baseline_readers.txt", site, found, n)
			}
		} else {
			// Private source files are absent from the public export. An existing file
			// losing its sites is stale inventory and must still fail.
			source := strings.Split(site, ":")[0]
			if _, err := os.Stat(filepath.Join(root, source)); err == nil || !os.IsNotExist(err) {
				t.Errorf("stale reader inventory: %s", site)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	for site, n := range sites {
		if !inventory[site] {
			t.Errorf("unregistered reader: %s\t%d; add an exercised route test and its mapping to tools/rulecheck/baseline_readers.txt", site, n)
		}
	}
}

func receiverName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return receiverName(e.X)
	case *ast.IndexExpr:
		return receiverName(e.X)
	case *ast.IndexListExpr:
		return receiverName(e.X)
	default:
		return fmt.Sprintf("%T", e)
	}
}

// Propagate named aliases, structs carrying evidence, evidence-returning helpers
// and global destinations. Names are intentionally over-approximated across
// packages, so an alias or helper cannot hide a reader from syntax discovery.

func baselineImports(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		for _, marker := range []string{"/internal/", "/pkg/"} {
			if at := strings.Index(path, marker); at >= 0 {
				rel := path[at+1:]
				name := filepath.Base(rel)
				if imp.Name != nil {
					name = imp.Name.Name
				}
				out[name] = rel
			}
		}
	}
	return out
}

func baselineCarriers(root string) (map[string]bool, error) {
	carriers := map[string]bool{}
	for _, name := range []string{"Baseline", "BaselineSource", "BaselineRule", "BaselineOrigin", "RunStartPayload"} {
		carriers["pkg/spec/record:"+name] = true
	}
	type source struct {
		file    *ast.File
		pkg     string
		imports map[string]string
	}
	var files []source
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "archive", "vendor", "testdata", ".claude", "rust":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		files = append(files, source{f, filepath.ToSlash(rel), baselineImports(f)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	has := func(node ast.Node, f source) bool {
		found := false
		if node != nil {
			ast.Inspect(node, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.Field:
					if baselineJSONTag(n.Tag) {
						found = true
					}
				case *ast.Ident:
					if carriers[f.pkg+":"+n.Name] {
						found = true
					}
				case *ast.SelectorExpr:
					if id, ok := n.X.(*ast.Ident); ok && f.imports[id.Name] != "" && carriers[f.imports[id.Name]+":"+n.Sel.Name] {
						found = true
					}
				}
				return true
			})
		}
		return found
	}
	for _, f := range files {
		if f.imports["."] == "pkg/spec/record" {
			for _, name := range []string{"Baseline", "BaselineSource", "BaselineRule", "BaselineOrigin", "RunStartPayload"} {
				carriers[f.pkg+":"+name] = true
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			add := func(name string) {
				key := f.pkg + ":" + name
				if !carriers[key] {
					carriers[key] = true
					changed = true
				}
			}
			for _, d := range f.file.Decls {
				switch d := d.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						switch spec := spec.(type) {
						case *ast.TypeSpec:
							if has(spec.Type, f) {
								add(spec.Name.Name)
							}
						case *ast.ValueSpec:
							carries := has(spec.Type, f)
							for _, value := range spec.Values {
								carries = carries || has(value, f)
							}
							if carries {
								for _, id := range spec.Names {
									add(id.Name)
								}
							}
						}
					}
				case *ast.FuncDecl:
					if d.Type.Results != nil && has(d.Type.Results, f) {
						add(d.Name.Name)
					}
				}
			}
		}
	}
	return carriers, nil
}

func baselineJSONTag(tag *ast.BasicLit) bool {
	if tag == nil {
		return false
	}
	value, err := strconv.Unquote(tag.Value)
	if err != nil {
		return false
	}
	for _, key := range []string{"baseline", "effective_hash", "contract_hash", "source_contract", "effective_contract", "evidence_sha256", "fact_sha256"} {
		if strings.Contains(strings.ToLower(value), `json:"`+key) {
			return true
		}
	}
	return false
}

// Unknown destinations include generic receivers, local any values and function
// literals. Their declarations and calls are conservative sites even when no
// baseline type is spelled there. JSON decoder selectors are inventoried in all
// contexts, including the codec itself; there is no destination-type guess.
// Follow unknown destination types and decoder values across declarations and
// imports. Like evidence carriers, names are conservative within each package;
// local declarations are included so moving an alias into a function cannot hide it.
func baselineIndirectContexts(root string) (map[string]bool, error) {
	type source struct {
		file    *ast.File
		pkg     string
		imports map[string]string
	}
	var files []source
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "archive", "vendor", "testdata", ".claude", "rust":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filepath.Dir(path))
		if err != nil {
			return err
		}
		files = append(files, source{f, filepath.ToSlash(rel), baselineImports(f)})
		return nil
	})
	if err != nil {
		return nil, err
	}

	types, decoders := map[string]bool{}, map[string]bool{}
	has := func(node ast.Node, f source, names map[string]bool, typeContext bool) bool {
		found := false
		if b, typed := node.(*ast.BlockStmt); node == nil || typed && b == nil {
			return false // no node, or the nil body of a function the assembler provides
		}
		ast.Inspect(node, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.Ident:
				found = found || typeContext && n.Name == "any" || names[f.pkg+":"+n.Name]
			case *ast.InterfaceType:
				found = found || typeContext
			case *ast.SelectorExpr:
				if !typeContext {
					switch n.Sel.Name {
					case "Unmarshal", "UnmarshalRead", "UnmarshalDecode", "Decode":
						found = true
					}
				}
				if id, ok := n.X.(*ast.Ident); ok && f.imports[id.Name] != "" {
					found = found || names[f.imports[id.Name]+":"+n.Sel.Name]
				}
			}
			return true
		})
		return found
	}
	valueHas := func(expr ast.Expr, f source) bool {
		for {
			if p, ok := expr.(*ast.ParenExpr); ok {
				expr = p.X
			} else {
				break
			}
		}
		switch expr.(type) {
		case *ast.Ident, *ast.SelectorExpr, *ast.FuncLit:
			return has(expr, f, decoders, false)
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			add := func(names map[string]bool, name string) {
				key := f.pkg + ":" + name
				if !names[key] {
					names[key] = true
					changed = true
				}
			}
			ast.Inspect(f.file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncDecl:
					// Named decoding helpers can be assigned to function values.
					// Seed their names and iterate so aliases and forwarding
					// helpers retain decoder context without destination syntax.
					if has(n.Body, f, nil, false) || baselineUnknownContext(n.Type) && has(n.Body, f, decoders, false) {
						add(decoders, n.Name.Name)
					}
				case *ast.TypeSpec:
					_, iface := n.Type.(*ast.InterfaceType)
					// Imported interface types may come from dependencies outside
					// this syntax walk. Treat every alias conservatively.
					if n.Assign.IsValid() || iface && has(n.Type, f, types, true) {
						add(types, n.Name.Name)
					}
				case *ast.ValueSpec:
					found := false
					for _, v := range n.Values {
						found = found || valueHas(v, f)
					}
					if found {
						for _, id := range n.Names {
							add(decoders, id.Name)
						}
					}
				case *ast.AssignStmt:
					found := false
					for _, v := range n.Rhs {
						found = found || valueHas(v, f)
					}
					if found {
						for _, v := range n.Lhs {
							if id, ok := v.(*ast.Ident); ok {
								add(decoders, id.Name)
							}
						}
					}
				}
				return true
			})
		}
	}
	indirect := types
	for key := range decoders {
		indirect[key] = true
	}

	return indirect, nil
}

func baselineUnknownContext(decl ast.Node) bool {
	unknown := false
	if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
		ast.Inspect(fn.Recv, func(n ast.Node) bool {
			switch n.(type) {
			case *ast.IndexExpr, *ast.IndexListExpr:
				unknown = true
			}
			return true
		})
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncType:
			if n.TypeParams != nil {
				unknown = true
			}
		case *ast.TypeSpec:
			if n.TypeParams != nil {
				unknown = true
			}
		case *ast.Ident:
			if n.Name == "any" {
				unknown = true
			}
		case *ast.InterfaceType:
			unknown = true
		}
		return true
	})
	return unknown
}

func TestBaselineUntypedDecodingHelpers(t *testing.T) {
	root := t.TempDir()
	source := `package probe
import "encoding/json"
func decodeAgain[T any](raw []byte, dst *T) error { return json.Unmarshal(raw,dst) }
func decodeUntyped(raw []byte, dst any) error { return json.Unmarshal(raw,dst) }
var decodeValue = func(raw []byte,dst any) error {return decodeUntyped(raw,dst)}
func carrier(v any) {}
func ordinary(raw []byte, dst *string) error { return json.Unmarshal(raw,dst) }
func localAny(raw []byte) (any,error) { var dst any; err:=json.Unmarshal(raw,&dst); return dst,err }
type decoder[T any] struct{}
func (d decoder[T]) decode(raw []byte,dst *T) error {return json.Unmarshal(raw,dst)}
func forward[T any](raw []byte,dst *T) error {return decodeAgain(raw,dst)}
`
	if err := os.WriteFile(filepath.Join(root, "probe.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	sites, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"decodeAgain", "decodeUntyped", "ordinary", "localAny", "decoder.decode"} {
		if sites["probe.go:"+name+":json-decode"] != 1 {
			t.Errorf("JSON helper %s was not inventoried", name)
		}
	}
	if sites["probe.go:carrier:untyped-context"] != 1 || sites["probe.go:declarations:untyped-context"] < 2 || sites["probe.go:declarations:evidence-call"] != 1 {
		t.Error("untyped declarations and function values were not inventoried")
	}
	if sites["probe.go:forward:untyped-context"] != 1 {
		t.Error("forwarding generic helper was not inventoried")
	}
}

func baselineReaderSites(root string) (map[string]int, map[string]bool, error) {
	carriers, err := baselineCarriers(root)
	if err != nil {
		return nil, nil, err
	}
	indirect, err := baselineIndirectContexts(root)
	if err != nil {
		return nil, nil, err
	}
	sites := map[string]int{}
	tests := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "archive", "vendor", "testdata", ".claude", "rust":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		isTest := strings.HasSuffix(rel, "_test.go")
		aliases := map[string]bool{}
		imports := baselineImports(f)
		for _, imp := range f.Imports {
			name, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if strings.HasSuffix(name, "/pkg/spec/record") {
				alias := "record"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				aliases[alias] = true
			}
		}
		for _, decl := range f.Decls {
			name := "declarations"
			if fn, ok := decl.(*ast.FuncDecl); ok {
				name = fn.Name.Name
				if isTest {
					if fn.Recv == nil && name != "TestMain" && strings.HasPrefix(name, "Test") {
						tests[rel+":"+name] = true
					}
					continue
				}
				if fn.Recv != nil {
					name = receiverName(fn.Recv.List[0].Type) + "." + name
				}
			} else if isTest {
				continue
			}

			unknown := baselineUnknownContext(decl)
			ast.Inspect(decl, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && indirect[filepath.ToSlash(filepath.Dir(rel))+":"+id.Name] {
					unknown = true
				}
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && imports[id.Name] != "" && indirect[imports[id.Name]+":"+sel.Sel.Name] {
						unknown = true
					}
				}
				return true
			})
			ast.Inspect(decl, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if node.Kind == token.STRING {
						value, _ := strconv.Unquote(node.Value)
						switch value {
						case "run_start":
							sites[rel+":"+name+":run-start-kind"]++
						case "events.jsonl":
							sites[rel+":"+name+":ledger-file"]++
						}
					}
				case *ast.IndexExpr:
					if key, ok := node.Index.(*ast.BasicLit); ok && key.Kind == token.STRING {
						value, _ := strconv.Unquote(key.Value)
						switch value {
						case "baseline", "effective_hash", "contract_hash", "baseline_sha256", "baseline_evidence_sha256":
							sites[rel+":"+name+":evidence-map"]++
						}
					}
				case *ast.Field:
					if baselineJSONTag(node.Tag) {
						sites[rel+":"+name+":evidence-tag"]++
					}
				case *ast.Ident:
					if node.Name == "controlScan" {
						sites[rel+":"+name+":offset-helper"]++
					}
					if filepath.Dir(rel) == "internal/ledger" && node.Name == "EventsFile" {
						sites[rel+":"+name+":ledger-file"]++
					}
				}
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				kind := ""
				if id, ok := sel.X.(*ast.Ident); ok && aliases[id.Name] {
					switch sel.Sel.Name {
					case "Baseline", "BaselineSource", "BaselineRule", "BaselineOrigin":
						kind = "typed-evidence"
					case "RunStartPayload":
						kind = "run-start-payload"
					case "KindRunStart":
						kind = "run-start-kind"
					}
				}
				switch sel.Sel.Name {
				case "EventsFile":
					kind = "ledger-file"
				case "Baseline", "BaselineSHA256", "EffectiveHash", "SourceContract", "EffectiveContract", "EvidenceSHA256", "FactSHA256":
					if kind == "" {
						kind = "evidence-field"
					}
				case "AllEvents", "loadWindow", "lineOffset":
					kind = "offset-helper"
				case "ReadAt", "Pread", "Preadv", "Preadv2", "Seek", "NewSectionReader", "LinesFrom", "Backward":
					kind = "offset-read"
				}
				if kind != "" {
					sites[rel+":"+name+":"+kind]++
				}
				return true
			})
			ast.Inspect(decl, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && carriers[filepath.Dir(rel)+":"+id.Name] {
					sites[rel+":"+name+":carrier-reference"]++
				}
				if sel, ok := n.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && imports[id.Name] != "" && carriers[imports[id.Name]+":"+sel.Sel.Name] {
						sites[rel+":"+name+":carrier-reference"]++
					}
				}
				return true
			})
			if unknown {
				sites[rel+":"+name+":untyped-context"]++
			}
			relevant := sites[rel+":"+name+":carrier-reference"] > 0 || sites[rel+":"+name+":typed-evidence"] > 0 || sites[rel+":"+name+":run-start-payload"] > 0 || sites[rel+":"+name+":evidence-field"] > 0
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if relevant {
					switch sel.Sel.Name {
					case "V", "Mode", "SHA256", "OwnerUID", "Home", "OwnerKnown", "Sources", "ProtectedOwnerLayer", "Rules", "SourceContract", "EffectiveContract", "Replay", "FactSHA256", "EvidenceSHA256", "Layer", "File", "State", "Bytes", "ID", "Key", "Value", "Expanded", "Rule", "EmptyReason", "Tier", "Plane", "Held", "ImageMode", "Operations", "Conditions", "Limits", "Line":
						sites[rel+":"+name+":evidence-member"]++

					}
				}
				// A JSON decoder's destination may be hidden behind a type
				// parameter, alias or any. Inventory its selector regardless
				// of whether this declaration already names evidence.
				switch sel.Sel.Name {
				case "Unmarshal", "UnmarshalRead", "UnmarshalDecode", "Decode":
					sites[rel+":"+name+":json-decode"]++
				}
				if sel.Sel.Name == "DecodePayload" {
					sites[rel+":"+name+":payload-decode"]++
				}
				return true
			})
			// Shared offset helpers also create reread sites without another I/O call.
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				// Every call in an evidence-bearing or unknown-type context
				// is a potential decode, including inferred, parenthesized,
				// method and function-value calls. No callee inference can
				// hide an additional call at an already inventoried reader.
				if relevant || unknown {
					sites[rel+":"+name+":evidence-call"]++
				}
				fun := call.Fun
			unwrap:
				for {
					switch f := fun.(type) {
					case *ast.ParenExpr:
						fun = f.X
					case *ast.IndexExpr:
						fun = f.X
					case *ast.IndexListExpr:
						fun = f.X
					default:
						break unwrap
					}
				}

				if id, ok := fun.(*ast.Ident); ok {
					switch id.Name {
					case "headAt", "lineAt", "WindowBefore", "newLineReader", "eachReverseLine":
						sites[rel+":"+name+":offset-helper"]++
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return sites, tests, nil
}

// This is the inferred-generic inventory escape from the confirm review: the
// destination already exists, so the added call has no baseline-type syntax.
func TestBaselineInferredGenericNegativeControl(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "probe.go")
	before := `package probe
import "github.com/attention-span-ai/tego/pkg/spec/record"
func existing(raw []byte, b *record.Baseline) { }
`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	old, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	after := strings.Replace(before, "import ", "import \"encoding/json\"\nimport ", 1)
	after = strings.Replace(after, " { }", " { _ = decodeAgain(raw,b); _ = decodeUntyped(raw,b); _ = (decodeAgain[record.Baseline])(raw,b); _ = decodeForward(raw,b); _ = decodeForwardAny(raw,b) }", 1)
	after += `func decodeAgain[T any](raw []byte,dst *T) error {return json.Unmarshal(raw,dst)}
func decodeUntyped(raw []byte,dst any) error {return json.Unmarshal(raw,dst)}
func decodeForward[T any](raw []byte,dst *T) error {return decodeAgain(raw,dst)}
func decodeForwardAny(raw []byte,dst any) error {return decodeUntyped(raw,dst)}
`
	if err := os.WriteFile(path, []byte(after), 0600); err != nil {
		t.Fatal(err)
	}
	next, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"probe.go:decodeAgain:untyped-context", "probe.go:decodeAgain:json-decode", "probe.go:decodeUntyped:untyped-context", "probe.go:decodeUntyped:json-decode", "probe.go:decodeForward:untyped-context", "probe.go:decodeForwardAny:untyped-context", "probe.go:existing:evidence-call"} {
		if next[site] == 0 || old[site] != 0 {
			t.Errorf("unmodified inventory would miss %s: before=%d after=%d", site, old[site], next[site])
		}
	}
	if next["probe.go:existing:evidence-call"] != 5 {
		t.Error("inferred, parenthesized and forwarded calls were not all inventoried")
	}
}

func TestBaselineAliasFunctionValueNegativeControl(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "probe.go")
	before := `package probe
import "encoding/json"
import "io"
type opaque = any
type named interface{ Marker() }
type iface = named
type again = opaque
type external = io.Reader
type failure = error
var unpack = json.Unmarshal
var forwarding = unpack
`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	old, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	after := before + `
func missed(raw []byte, dst opaque) error { return unpack(raw,dst) }
func caller(raw []byte, dst again) error { return missed(raw,dst) }
func viaInterface(raw []byte, dst iface) error { return forwarding(raw,dst) }
func typed(raw []byte, dst *string) error { return forwarding(raw,dst) }
func viaExternal(raw []byte, dst external) error { return unpack(raw,dst) }
func viaError(raw []byte, dst failure) error { return unpack(raw,dst) }
`
	if err := os.WriteFile(path, []byte(after), 0600); err != nil {
		t.Fatal(err)
	}
	next, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missed", "caller", "viaInterface", "typed", "viaExternal", "viaError"} {
		site := "probe.go:" + name + ":evidence-call"
		if next[site] != 1 || old[site] != 0 {
			t.Errorf("unmodified inventory would miss %s: before=%d after=%d", site, old[site], next[site])
		}
	}
}

// A named decoding helper must seed function-value discovery even when its
// caller's destination has no baseline, generic or interface type syntax.
func TestBaselineNamedDecoderValueNegativeControl(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "probe.go")
	before := `package probe
import "encoding/json"
func decode(raw []byte, dst any) error { return json.Unmarshal(raw, dst) }
var unpack = decode
`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	old, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	after := before + `
func missed(raw []byte, dst map[string]json.RawMessage) error { return unpack(raw, &dst) }
`
	if err := os.WriteFile(path, []byte(after), 0600); err != nil {
		t.Fatal(err)
	}
	next, _, err := baselineReaderSites(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"untyped-context", "evidence-call"} {
		site := "probe.go:missed:" + kind
		if old[site] != 0 || next[site] != 1 {
			t.Errorf("unmodified inventory misses named decoder value %s: before=%d after=%d", site, old[site], next[site])
		}
	}
}
