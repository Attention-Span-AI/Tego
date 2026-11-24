// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var schemaPath = filepath.Join("..", "..", "..", "spec", "receipt", "receipt-v1.schema.json")

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// objectOf finds the object schema a property's schema stands for: itself, a $ref into $defs, a nullable one (anyOf with
// null), or the items of an array or the values of a map. nil when it stands for no object.
func objectOf(root, node map[string]any) map[string]any {
	if ref, ok := node["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		d, _ := root["$defs"].(map[string]any)
		def, _ := d[name].(map[string]any)
		return def
	}
	if alts, ok := node["anyOf"].([]any); ok {
		for _, a := range alts {
			if m, ok := a.(map[string]any); ok && m["type"] != "null" {
				return objectOf(root, m)
			}
		}
	}
	if items, ok := node["items"].(map[string]any); ok {
		return objectOf(root, items)
	}
	if ap, ok := node["additionalProperties"].(map[string]any); ok {
		return objectOf(root, ap)
	}
	if node["properties"] != nil {
		return node
	}
	return nil
}

// jsonKeys is the keys a struct writes and the ones it always writes (no omitempty), embedded structs flattened.
func jsonKeys(t reflect.Type) (all, required []string) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if !f.IsExported() || tag == "-" {
			continue
		}
		if f.Anonymous && tag == "" {
			a, r := jsonKeys(f.Type)
			all, required = append(all, a...), append(required, r...)
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			name = f.Name
		}
		all = append(all, name)
		if !slices.Contains(parts[1:], "omitempty") && !slices.Contains(parts[1:], "omitzero") {
			required = append(required, name)
		}
	}
	return all, required
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// TestSchemaMatchesTypes: spec/receipt/receipt-v1.schema.json and these types write the same keys at every depth: each
// struct's JSON keys are the schema's properties for it, its always-written keys are the required ones, and the
// schema refuses a key the types do not write. A key added to a type with no row in the schema, or a row with no field,
// fails here (C163).
func TestSchemaMatchesTypes(t *testing.T) {
	root := loadSchema(t)
	seen := map[reflect.Type]bool{}
	var check func(path string, typ reflect.Type, node map[string]any)
	check = func(path string, typ reflect.Type, node map[string]any) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ == reflect.TypeOf(time.Time{}) {
			return
		}
		obj := objectOf(root, node)
		if obj == nil {
			t.Errorf("%s: no object schema for %s", path, typ)
			return
		}
		props, _ := obj["properties"].(map[string]any)
		keys, required := jsonKeys(typ)
		var inSchema []string
		for k := range props {
			inSchema = append(inSchema, k)
		}
		sort.Strings(inSchema)
		sorted := slices.Sorted(slices.Values(keys))
		if !slices.Equal(sorted, inSchema) {
			t.Errorf("%s (%s): the type writes %v, the schema has %v", path, typ, sorted, inSchema)
		}
		var req []string
		if r, ok := obj["required"]; ok {
			req = strs(r)
		}
		if !slices.Equal(slices.Sorted(slices.Values(required)), slices.Sorted(slices.Values(req))) {
			t.Errorf("%s (%s): the type always writes %v, the schema requires %v", path, typ, required, req)
		}
		if obj["additionalProperties"] != false {
			t.Errorf("%s: the schema does not refuse a key the type does not write", path)
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		var walk func(t2 reflect.Type)
		walk = func(t2 reflect.Type) {
			for i := 0; i < t2.NumField(); i++ {
				f := t2.Field(i)
				tag := f.Tag.Get("json")
				if !f.IsExported() || tag == "-" {
					continue
				}
				if f.Anonymous && tag == "" {
					walk(f.Type)
					continue
				}
				name := strings.Split(tag, ",")[0]
				if name == "" {
					name = f.Name
				}
				if p, ok := props[name].(map[string]any); ok {
					check(path+"."+name, f.Type, p)
				}
			}
		}
		walk(typ)
	}
	check("receipt", reflect.TypeOf(Receipt{}), root)
	if v, _ := root["properties"].(map[string]any)["receipt_v"].(map[string]any); v["const"] != float64(Version) {
		t.Errorf("receipt_v is %v in the schema, %d in the types", v["const"], Version)
	}
}

// constsNamed is the string values of the package's top-level constants whose names start with prefix, read from the
// source (a constant declared as another constant's name is followed one step through value).
func constsNamed(t *testing.T, prefix string, value map[string]string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	out := map[string]string{}
	{
		for _, f := range files {
			for _, d := range f.Decls {
				g, ok := d.(*ast.GenDecl)
				if !ok || g.Tok != token.CONST {
					continue
				}
				for _, s := range g.Specs {
					vs := s.(*ast.ValueSpec)
					for i, n := range vs.Names {
						if !strings.HasPrefix(n.Name, prefix) || i >= len(vs.Values) {
							continue
						}
						switch v := vs.Values[i].(type) {
						case *ast.BasicLit:
							u, _ := strconv.Unquote(v.Value)
							out[n.Name] = u
						case *ast.SelectorExpr:
							out[n.Name] = value[v.Sel.Name]
						}
					}
				}
			}
		}
	}
	return out
}

// TestCodesAreTheSchemasAndTheTables: every Code* constant has a row in the table of codes (a level and one sentence),
// the table has no other, and the schema's enums for the codes, the levels, the limits and the binding versions are the
// constants'.
func TestCodesAreTheSchemasAndTheTables(t *testing.T) {
	root := loadSchema(t)
	consts := constsNamed(t, "Code", map[string]string{"GapNoPriceTable": "no-price-table"})
	if len(consts) < 17 {
		t.Fatalf("found %d Code constants: %v", len(consts), consts)
	}
	var want []string
	for _, v := range consts {
		want = append(want, v)
	}
	sort.Strings(want)
	var table []string
	seen := map[string]bool{}
	for _, c := range Codes() {
		if seen[c.Code] {
			t.Errorf("code %q is in the table twice", c.Code)
		}
		seen[c.Code] = true
		table = append(table, c.Code)
		if c.Means == "" || (c.Level != LevelPartial && c.Level != LevelNone) {
			t.Errorf("code %q has level %q and sentence %q", c.Code, c.Level, c.Means)
		}
	}
	sort.Strings(table)
	if !slices.Equal(want, table) {
		t.Errorf("the constants are %v, the table %v", want, table)
	}
	defs := root["$defs"].(map[string]any)
	enum := func(def, prop string) []any {
		return defs[def].(map[string]any)["properties"].(map[string]any)[prop].(map[string]any)["enum"].([]any)
	}
	if got := slices.Sorted(slices.Values(strs(enum("CoverageGap", "code")))); !slices.Equal(got, want) {
		t.Errorf("the schema's coverage codes are %v, the constants %v", got, want)
	}
	if got := strs(enum("CoverageGap", "level")); !slices.Equal(got, []string{LevelPartial, LevelNone}) {
		t.Errorf("the schema's levels are %v", got)
	}
	limits := constsNamed(t, "Limit", nil)
	delete(limits, "Limit") // the type is no constant
	var wantLimits []string
	for n, v := range limits {
		if n != "Limit" {
			wantLimits = append(wantLimits, v)
		}
	}
	if got := slices.Sorted(slices.Values(strs(enum("Limit", "code")))); !slices.Equal(got, slices.Sorted(slices.Values(wantLimits))) {
		t.Errorf("the schema's limit codes are %v, the constants %v", got, wantLimits)
	}
	var versions []float64
	for _, v := range enum("Binding", "v") {
		versions = append(versions, v.(float64))
	}
	if !slices.Equal(versions, []float64{1, BindingVersion, BaselineBindingVersion}) {
		t.Errorf("the schema's binding versions are %v, the constants 1, %d, %d", versions, BindingVersion, BaselineBindingVersion)
	}
}

// TestLevelsNeverReadBetterThanTheCode: a gap is never taken for better than its code says (the receipt of an older tego
// has no level; one of a newer tego may carry a code this one does not know).
func TestLevelsNeverReadBetterThanTheCode(t *testing.T) {
	for _, c := range []struct {
		gap  CoverageGap
		want string
	}{
		{CoverageGap{Code: CodeCaptureOff, Level: LevelNone}, LevelNone},
		{CoverageGap{Code: CodeCaptureOff}, LevelNone},                             // an older receipt: the code's own
		{CoverageGap{Code: CodeCaptureOff, Level: LevelPartial}, LevelNone},        // edited to better: the code wins
		{CoverageGap{Code: CodeMissedActions, Level: LevelNone}, LevelNone},        // worse than the code: kept
		{CoverageGap{Code: CodeMissedActions}, LevelPartial},                       // an older receipt
		{CoverageGap{Code: CodeMissedActions, Level: LevelComplete}, LevelPartial}, // no gap is complete
		{CoverageGap{Code: "a-code-from-the-future", Level: LevelPartial}, LevelNone},
		{CoverageGap{Code: "a-code-from-the-future"}, LevelNone},
	} {
		if got := c.gap.EffectiveLevel(); got != c.want {
			t.Errorf("%+v is read as %q, want %q", c.gap, got, c.want)
		}
	}
}
