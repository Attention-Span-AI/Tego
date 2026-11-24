// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Built-in command rows contain function-typed grammar fields. A full RuleTable
// JSON marshal fails even for a nil callback in a sh rule; the snapshot must
// represent built-in code explicitly rather than discard command authority.
func TestBuilderReviewedCommandRulesSave(t *testing.T) {
	for _, mode := range []string{"new", "existing"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			f.s.Compile, f.s.Check = nil, nil
			f.s.Machine = config.Builtin()
			f.s.Machine.Home = f.s.Home
			f.s.PATH = "/usr/bin:/bin"
			head := "version: 0\nname: tester\ncommand: [sh]\nexec:\n  allow: [sh]\n  deny: ['sh -c']\n"
			if mode == "new" {
				dir := f.newProject(t, "command-rules")
				req := NewReq{Dir: dir, Name: "tester", Text: []byte(head)}
				p, err := f.s.PlanNew(t.Context(), req)
				if err != nil || !p.OK {
					t.Fatalf("command-rule preview: %+v %v", p, err)
				}
				if _, err := f.s.CreateNew(t.Context(), req, p.Base); err != nil {
					t.Fatal(err)
				}
				got, err := os.ReadFile(filepath.Join(dir, NewFile))
				if err != nil || string(got) != head {
					t.Fatalf("saved command rules: %q %v", got, err)
				}
			} else {
				writeFile(t, f.contract, head)
				c := f.ref(t, f.contract)
				req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(head + "limits: {wall: 2h}\n")}
				p, err := f.s.PlanRaw(t.Context(), req)
				if err != nil || p.Err != "" {
					t.Fatalf("command-rule preview: %+v %v", p, err)
				}
				req.Ack = p.Ack
				if _, err := f.s.ApplyRaw(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if got := f.text(t); got != string(req.Text) {
					t.Fatalf("saved command rules: %q", got)
				}
			}
		})
	}
}
