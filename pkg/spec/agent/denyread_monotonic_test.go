// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// denyReadContract is a contract writing out/ with deny as its deny_read list.
func denyReadContract(deny []string) string {
	quoted := make([]string, len(deny))
	for i, d := range deny {
		quoted[i] = fmt.Sprintf("%q", d)
	}
	return "version: 0\nname: qa\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  deny_read: [" + strings.Join(quoted, ", ") + "]\nnet: {}\n"
}

// TestDenyReadIsMonotonic is a property of deny_read: adding entries never turns a refused action into an
// allowed one, in any tier, for any filesystem or exec action. A contract the added entries make fail to
// compile (a contradiction) is not a relaxation and is skipped. The entries and the actions are drawn from a
// fixed seed over the fixture's project, home and root, so a failure reproduces.
func TestDenyReadIsMonotonic(t *testing.T) {
	f := newFixture(t)
	comps := []string{"out", "secrets", "config", ".env", "x", "..", ".", "node_modules", "key.pem", ".ssh", "home"}
	roots := []string{f.project, f.home, f.root, "/etc", "/"}
	// A deny_read entry naming nothing is path-missing, an error, so the tree the entries are drawn from
	// exists two levels deep beneath each of the fixture's roots.
	for _, r := range roots[:3] {
		for _, a := range comps {
			for _, b := range comps {
				// The fixture's own files (project/secrets/key.pem) stay files; a directory beneath one is not made.
				_ = os.MkdirAll(filepath.Join(r, a, b), 0o755)
			}
		}
	}
	base, _ := f.compile(f.load(denyReadContract([]string{"secrets/"})))
	rng := rand.New(rand.NewSource(1))
	tiers := []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM}
	kinds := []ActionKind{ActionFSRead, ActionFSWrite, ActionFSDelete, ActionFSMkdir, ActionExec}
	compiled := 0
	for trial := 0; trial < 40; trial++ {
		var extra []string
		for k := 0; k < 1+rng.Intn(3); k++ {
			p := roots[rng.Intn(3)]
			for d := 0; d < 1+rng.Intn(3); d++ {
				p = filepath.Join(p, comps[rng.Intn(len(comps))])
			}
			extra = append(extra, p)
		}
		c, _, err := LoadBytes(filepath.Join(f.project, "agent.yaml"), []byte(denyReadContract(append([]string{"secrets/"}, extra...))), nil)
		if err != nil {
			continue
		}
		more, _, err := Compile(c, f.machine, f.opts()...)
		if err != nil {
			continue // a contradiction: not a relaxation
		}
		compiled++
		for q := 0; q < 300; q++ {
			p := roots[rng.Intn(len(roots))]
			for d := 0; d < rng.Intn(4); d++ {
				p += "/" + comps[rng.Intn(len(comps))]
			}
			a := Action{Kind: kinds[rng.Intn(len(kinds))], Path: p}
			for _, tier := range tiers {
				before, after := base.Evaluate(a, tier), more.Evaluate(a, tier)
				if before.Verdict == VerdictRefused && after.Verdict == VerdictAllow {
					t.Errorf("tier %s %s %s: refused (%s) with deny_read [secrets/], allowed (%s) with %v added",
						tier, a.Kind, p, before.Rule, after.Rule, extra)
				}
			}
		}
	}
	if compiled < 10 {
		t.Fatalf("only %d of 40 contracts compiled: the property was barely checked", compiled)
	}
}
