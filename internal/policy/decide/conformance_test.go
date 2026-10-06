// SPDX-License-Identifier: Apache-2.0

package decide_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/test/conformance"
)

// coreAction is the decide core's action for a table cell's filesystem op, as compile --test's row for it is
// (test/conformance compileAction); ok is false for an op the tables check elsewhere: exec, a mapping and a
// connect through compile --test and the kernel runner, and an exchange, which no core action names.
func coreAction(op string) (agent.ActionKind, bool) {
	switch op {
	case conformance.OpRead:
		return agent.ActionFSRead, true
	case conformance.OpWriteOpen, conformance.OpCreate, conformance.OpCreat, conformance.OpOpenTrunc, conformance.OpTruncate, conformance.OpSymlink,
		conformance.OpMknod:
		return agent.ActionFSWrite, true
	case conformance.OpUnlink, conformance.OpRmdir:
		return agent.ActionFSDelete, true
	case conformance.OpMkdir:
		return agent.ActionFSMkdir, true
	case conformance.OpRename:
		return agent.ActionFSRename, true
	case conformance.OpLink:
		return agent.ActionFSLink, true
	case conformance.OpChmod, conformance.OpChown, conformance.OpSetxattr, conformance.OpSetfacl:
		return agent.ActionFSAttr, true
	}
	return "", false
}

// ADR0028 S6: every table in spec/policy/conformance, the bytes the kernel conformance runner also reads, is held
// to the decide core: each filesystem cell's expectation per tier against the indexed evaluator, the reference
// Evaluate and, for the plane column, the plane evaluator. The expectations and citations are authored from the
// contract, independently of every evaluator.
func TestSharedSpecificationTables(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	actor, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	loader, err := conformance.Loader()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, fx := range conformance.Fixtures() {
		t.Run(fx.Name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			subst := strings.NewReplacer("{{P}}", root, "{{PORT}}", "40001", "{{PORT2}}", "40002", "{{LOADER}}", loader).Replace
			if err := conformance.Layout(root, &fx, actor, subst); err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{"home", "ledger"} {
				if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(root, "agent.yaml")
			data := []byte(subst(fx.Contract))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			c, ds, err := agent.LoadBytes(path, data, nil)
			if err != nil {
				t.Fatalf("load: %v %v", err, ds)
			}
			m := config.Builtin()
			m.LedgerRoot.Value = filepath.Join(root, "ledger")
			rt, ds, err := agent.Compile(c, m, agent.WithCwd(root), agent.WithHome(filepath.Join(root, "home")), agent.WithMountInfo(""), agent.Offline())
			if err != nil {
				t.Fatalf("compile: %v %v", err, ds)
			}
			model := decide.NewEvaluator(rt)
			plane := decide.NewPlaneEvaluator(rt)
			if err := plane.Err(); err != nil {
				t.Fatal(err)
			}
			for _, cell := range fx.Cells {
				kind, ok := coreAction(cell.Op)
				if !ok || cell.NoCompile != "" {
					continue
				}
				// The row's paths spelled as the agent's syscall spells them, uncleaned, and landed with the run's own
				// walk, as compile --test lands its rows (RunResolved, supervisor.Land).
				a := agent.Action{Kind: kind, Path: root + "/" + cell.Path}
				if cell.Op == conformance.OpRename || cell.Op == conformance.OpLink {
					a.DestPath = root + "/" + cell.Dest
				}
				a, _ = agent.ResolveAction(a, agent.Landers{Path: supervisor.Land, Unix: supervisor.LandUnix})
				for key, want := range cell.Want {
					tier := backend.Tier(key.Tier)
					rule := subst(want.Rule)
					got := model.Evaluate(a, tier)
					if ref := decide.Evaluate(rt, a, tier); got != ref {
						t.Fatalf("%s %s: indexed %+v, reference %+v", cell.Name, tier, got, ref)
					}
					if got.Verdict != agent.Verdict(want.Verdict) || rule != "" && got.Rule != rule {
						t.Errorf("%s %s (%s): got %+v want %+v", cell.Name, tier, cell.Source, got, want)
					}
					if tier == backend.TierBPFLSM {
						if p := plane.Evaluate(a, decide.Env{}); p.Verdict != got.Verdict || rule != "" && p.Rule != rule {
							t.Errorf("%s: plane %+v want %+v", cell.Name, p, want)
						}
					}
					checked++
				}
			}
		})
	}
	if checked == 0 {
		t.Fatal("no table cell reached the decide core")
	}
	t.Logf("%d expectations checked against the decide core", checked)
}
