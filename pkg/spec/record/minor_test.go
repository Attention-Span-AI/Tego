// SPDX-License-Identifier: Apache-2.0

package record

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// declaredAheadMinors are the reserved record revisions, declared before their writers (ADR 0100): above Minor no ledger holds them yet, so they open no gap a reader could misread. TestRecordMinorsHaveNoGap
// and TestRecordMinorsAreContiguous admit them above Minor, and no other constant.
var declaredAheadMinors = map[string]int{"MinorStoppedBy": 35, "MinorDeployment": 32, "MinorSecrets": 33, "MinorShares": 34}

// TestRecordMinorsAreContiguous holds the rule that numbers a revision (spec/record/v1/README.md, "Revisions"): a
// revision is the next free number in the build that holds it, so the revisions a build writes are 1 to Minor, each
// once. A reader decides what a ledger holds by comparing record_minor with a revision ("absent at 17 or later means
// ..."), and a build that wrote 19 while holding neither 17 nor 18 would make every such rule a later build adds for
// 17 or 18 misread its ledgers. Two lanes that chose one number fail here when merged,
// and so does a lane that kept a planned number past a gap: each Minor<Name> constant names one revision, every
// revision from 1 to Minor has one, and the Minor doc lists them in order.
func TestRecordMinorsAreContiguous(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "record.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	named := map[int][]string{}
	var doc string
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			v := s.(*ast.ValueSpec)
			for i, n := range v.Names {
				if n.Name == "Minor" {
					doc = g.Doc.Text()
					continue
				}
				if !strings.HasPrefix(n.Name, "Minor") || i >= len(v.Values) {
					continue
				}
				lit, ok := v.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					t.Errorf("%s is not an integer literal; a revision constant names its number", n.Name)
					continue
				}
				num, err := strconv.Atoi(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				named[num] = append(named[num], n.Name)
			}
		}
	}
	for r := 1; r <= Minor; r++ {
		if len(named[r]) != 1 {
			t.Errorf("revision %d is named by %q; every revision from 1 to Minor (%d) is named by exactly one constant", r, named[r], Minor)
		}
	}
	for r, names := range named {
		if len(names) == 1 && r > Minor && declaredAheadMinors[names[0]] == r {
			continue
		}
		if r < 1 || r > Minor {
			t.Errorf("%q name revision %d, outside 1 to Minor (%d)", names, r, Minor)
		}
	}
	var listed []int
	for _, m := range regexp.MustCompile(`(?m)^\t(\d+)\s`).FindAllStringSubmatch(doc, -1) {
		n, _ := strconv.Atoi(m[1])
		listed = append(listed, n)
	}
	want := make([]int, Minor)
	for i := range want {
		want[i] = i + 1
	}
	if !slices.Equal(listed, want) {
		t.Errorf("Minor's doc lists revisions %v, want %v", listed, want)
	}
}
