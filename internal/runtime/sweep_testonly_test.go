// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"embed"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Compile the source into the test so go test -overlay also exercises the source
// used for the production build, rather than reading a different on-disk file.
//
//go:embed rundir.go sweep.go
var sweepProductionSources embed.FS

// Production cleanup uses the checked helpers: these older wrappers discard the
// identity-read error and are retained only for tests of descriptor lookups.
func TestSweepErrorDiscardingHelpersStayTestOnly(t *testing.T) {
	for _, name := range []string{"rundir.go", "sweep.go"} {
		source, err := sweepProductionSources.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if function.Name.Name == "runCgroupID" && function.Recv == nil {
				t.Errorf("%s: runCgroupID discards errors and must remain in a test file", name)
			}
			if function.Name.Name == "ownerUID" && function.Recv != nil {
				if receiver, ok := function.Recv.List[0].Type.(*ast.Ident); ok && receiver.Name == "runDir" {
					t.Errorf("%s: runDir.ownerUID discards errors and must remain in a test file", name)
				}
			}
		}
	}
}
