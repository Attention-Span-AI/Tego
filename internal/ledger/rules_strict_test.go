// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bufio"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// makeSkewedRun writes an ended run whose id carries idAt and whose events are stamped from tsAt, so the two
// clocks a run has (the id's time36 and the events' ts) disagree.
func makeSkewedRun(t *testing.T, root string, idAt, tsAt time.Time, rand6 string) record.RunRef {
	t.Helper()
	ref := record.RunRef{ID: runID(idAt, rand6), Agent: "retriever"}
	w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(&memAnchor{}),
		WithClock(newStepClock(tsAt, 1_000_000_000, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 2)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	return ref
}

// TestGCAgeFromRunIDNotTS is record-ledger.md R16 and E30: gc's retention age comes from the run id's time36,
// never from a stored ts, so a run whose events carry a skewed ts is judged by its id. A run minted long ago
// whose ts says "just now" (a clock stepped back) is still deleted; a run minted just now whose ts says "long
// ago" (a clock stepped forward then corrected) is still kept.
func TestGCAgeFromRunIDNotTS(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	keep := 30 * 24 * time.Hour
	oldIDFreshTS := makeSkewedRun(t, root, fixedStart, now.Add(-time.Hour), "s00001")
	freshIDOldTS := makeSkewedRun(t, root, now.Add(-time.Hour), fixedStart, "s00002")

	for _, dry := range []bool{true, false} {
		rep, err := GC(context.Background(), root, keep, dry, WithNow(func() time.Time { return now }),
			WithWriterOptions(WithAnchor(&memAnchor{})))
		if err != nil {
			t.Fatal(err)
		}
		if !sameSet(rep.Deleted, []string{oldIDFreshTS.ID}) || !sameSet(rep.Kept, []string{freshIDOldTS.ID}) {
			t.Fatalf("dry=%v: deleted %v kept %v, want the run with the old id deleted and the run with the fresh id kept",
				dry, rep.Deleted, rep.Kept)
		}
	}
	if _, err := os.Stat(filepath.Join(root, oldIDFreshTS.ID)); !os.IsNotExist(err) {
		t.Errorf("the run with the old id was not removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, freshIDOldTS.ID)); err != nil {
		t.Errorf("the run with the fresh id was removed: %v", err)
	}
}

// TestStoppedHolderStaysRunning is record-ledger.md E15: a run whose lock holder is SIGSTOPped keeps its flock,
// so RunState reads running for as long as it is stopped (indistinguishable from alive-but-slow by design) and
// gc neither sweeps nor deletes it, even with a retention of zero; once continued and ended it reads ended.
func TestStoppedHolderStaysRunning(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, testRef.ID)
	cmd := helper(t, "hold", dir)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGCONT)
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("helper: %q %v", line, err)
	}
	if err := cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if s := stateOf(t, dir); s != StateRunning {
			t.Fatalf("state %s while the holder is stopped, want running", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
	rep, err := GC(context.Background(), root, 0, false, WithNow(func() time.Time { return fixedStart.Add(1000 * 24 * time.Hour) }),
		WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Deleted) != 0 || len(rep.Swept) != 0 {
		t.Fatalf("gc touched a run whose holder is stopped: %+v", rep)
	}
	if s := stateOf(t, dir); s != StateRunning {
		t.Fatalf("state %s after gc, want running", s)
	}
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v", err)
	}
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("state %s after the holder was continued and ended, want ended", s)
	}
}

// TestExportedErrorsAreSentinelsWrappedWithW is record-ledger.md I10: every exported error the package offers
// is a sentinel `var Err…` built once with errors.New (or fmt.Errorf), and no fmt.Errorf in the package
// takes an error operand without a %w verb, which would cut the chain errors.Is walks.
func TestExportedErrorsAreSentinelsWrappedWithW(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sentinels := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.VAR {
				continue
			}
			for _, sp := range g.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if !strings.HasPrefix(id.Name, "Err") || !id.IsExported() {
						continue
					}
					sentinels++
					if i >= len(vs.Values) {
						t.Errorf("%s: %s has no initialiser", name, id.Name)
						continue
					}
					// A sentinel is built once, or re-exports another package's sentinel (record.ErrX).
					built := false
					switch v := vs.Values[i].(type) {
					case *ast.CallExpr:
						fn := exprString(v.Fun)
						built = fn == "errors.New" || fn == "fmt.Errorf"
					case *ast.SelectorExpr:
						built = strings.HasPrefix(v.Sel.Name, "Err")
					}
					if !built {
						t.Errorf("%s: %s is not built by errors.New/fmt.Errorf or re-exported from another Err var", name, id.Name)
					}
				}
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 || exprString(call.Fun) != "fmt.Errorf" {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			format, _ := strconv.Unquote(lit.Value)
			if strings.Contains(format, "%w") {
				return true
			}
			for _, a := range call.Args[1:] {
				if id, ok := a.(*ast.Ident); ok && (id.Name == "err" || strings.HasSuffix(id.Name, "Err")) {
					t.Errorf("%s: fmt.Errorf(%s) carries the error %s with no %%w", fset.Position(call.Pos()), lit.Value, id.Name)
				}
			}
			return true
		})
	}
	if sentinels < 5 {
		t.Fatalf("found only %d exported Err sentinels; the scan is not reading the package", sentinels)
	}
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	}
	return ""
}
