// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/nextrun"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/agentdiff"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The export pins the distribution's exact credential refusal. Empty here
// requires the credential-capable compiler path; arbitrary errors never qualify.
const credentialComparisonRefusal = "credentials: Tego does not support this section"

// Real compiler output, rather than a hand-built table, reaches the service's
// warning and acknowledgement path. The original comparison omitted net.limits
// and ask, and had no exhaustive family registry.
func TestCompiledComparisonReviewsOmittedFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, old, new, want string
		classified           bool
	}{
		{"network limits", "net:\n  allow: []\n  limits: {connections: 0}\n", "net:\n  allow: []\n  limits: {connections: 100}\n", "Network connections", true},
		{"approval configuration", "net:\n  ask: ['192.0.2.1:443']\nask: {timeout: 1m, max_pending: 1}\n", "net:\n  ask: ['192.0.2.1:443']\nask: {timeout: 2m, max_pending: 2}\n", "Pending approval requests", true},
		{"credentials", "capture: forwarder\nmodels: [{provider: openai, host: api.example, port: 443}]\n", "capture: forwarder\nmodels: [{provider: openai, host: api.example, port: 443}]\ncredentials: [{name: provider, env: PROVIDER_KEY, allow: [api.example]}]\n", "Use credential provider through PROVIDER_KEY at api.example:443", true},
		{"unclassified listener", "net:\n  allow: []\n", "net:\n  allow: []\n  listen: ['tcp://127.0.0.1:8080']\n", "Also review: listeners changed and Tego cannot tell whether it allows more", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.s.Compile = nil
			f.s.Machine = config.Builtin()
			f.s.Machine.Home = f.s.Home
			f.s.PATH = "/usr/bin:/bin"
			f.s.Anchor = filepath.Join(f.dir, "state", "chain.log")
			if err := os.MkdirAll(filepath.Join(f.dir, "state", "vault"), 0700); err != nil {
				t.Fatal(err)
			}
			// The contract recorded by the fixture is writable by the service.
			head := "version: 0\nname: tester\ntier: cgroup\ncommand: [sh]\nexec:\n  allow: [sh]\n"
			writeFile(t, f.contract, head+tc.old)
			c := f.ref(t, f.contract)
			req := RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(head + tc.new)}
			p, err := f.s.PlanRaw(t.Context(), req)
			if tc.name == "credentials" && credentialComparisonRefusal != "" {
				if err != nil || p == nil || !strings.Contains(p.Err, credentialComparisonRefusal) {
					t.Fatalf("distribution must refuse unsupported credentials: %+v %v", p, err)
				}
				if p.ReviewID != "" || p.Ack != "" || p.Compiled != "" || len(p.NewlyAllows) != 0 {
					t.Fatalf("refused credentials minted a review or compiled authority: %+v", p)
				}
				if _, err := f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrNeedsAck) {
					t.Fatalf("refused credential save without review: %v", err)
				}
				req.Ack = "unreviewed-credentials"
				if _, err := f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrReviewGone) {
					t.Fatalf("refused credential save with forged review: %v", err)
				}
				control := req
				control.Ack = ""
				control.Text = []byte(head + tc.old + "limits: {wall: 1h}\n")
				allowed, err := f.s.PlanRaw(t.Context(), control)
				if err != nil || allowed == nil || allowed.Err != "" || allowed.ReviewID == "" || allowed.Ack == "" {
					t.Fatalf("the same context without credentials must compile and retain a review: %+v %v", allowed, err)
				}
				req.Ack = allowed.Ack
				if _, err := f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrAckMismatch) {
					t.Fatalf("refused credentials reused an unrelated valid review: %v", err)
				}
			} else {
				if err != nil || p.Err != "" {
					t.Fatalf("preview: %+v %v", p, err)
				}
				items := p.ComparisonReview
				if tc.classified {
					items = p.NewlyAllows
				}
				if !strings.Contains(strings.Join(items, " "), tc.want) {
					t.Fatalf("missing %q in %+v", tc.want, p)
				}
				if !p.NeedsAck {
					t.Fatal("changed authority needs no explicit confirmation")
				}
				if _, err := f.s.ApplyRaw(t.Context(), req); !errors.Is(err, ErrNeedsAck) {
					t.Fatalf("save without confirmation: %v", err)
				}
			}
			if b, err := os.ReadFile(filepath.Join(f.proj, "agent.yaml")); err != nil || string(b) != head+tc.old {
				t.Fatalf("unconfirmed write: %s %v", b, err)
			}
		})
	}
}

func TestCompiledSimpleFamilies(t *testing.T) {
	for _, tc := range []struct{ name, old, new, family string }{
		{"remove write", "fs:\n  write: [./out/]\n", "fs:\n  write: []\n", "filesystem"},
		{"remove program", "exec:\n  allow: [sh, cat]\n", "exec:\n  allow: [sh]\n", "programs"},
		{"remove destination", "net:\n  allow: ['192.0.2.1:443']\n", "net:\n  allow: []\n", "destinations"},
		{"remove approval", "net:\n  ask: ['192.0.2.1:443']\n", "net:\n  ask: []\n", "destination approvals"},
		{"shorter wall", "limits: {wall: 2h}\n", "limits: {wall: 1h}\n", "run limits"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.s.Compile = nil
			f.s.Machine = config.Builtin()
			f.s.Machine.Home = f.s.Home
			f.s.PATH = "/usr/bin:/bin"
			if err := os.Mkdir(filepath.Join(f.proj, "out"), 0700); err != nil {
				t.Fatal(err)
			}
			head := "version: 0\nname: tester\ncommand: [sh]\ntier: landlock\n"
			cc := CheckContext{Contract: f.contract, Cwd: f.proj, Tier: "landlock"}
			a, err := nextrun.Compile(t.Context(), f.s.Machine, f.s.nextrunContext(cc), []byte(head+tc.old))
			if err != nil {
				t.Fatal(err)
			}
			b, err := nextrun.Compile(t.Context(), f.s.Machine, f.s.nextrunContext(cc), []byte(head+tc.new))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range agentdiff.Compare(a, b) {
				if r.Family != tc.family {
					continue
				}
				found = true
				if r.Direction != agentdiff.Narrowed {
					// The compiler inventories this host's live IPC protection.
					// If that boundary changes between compiles it must be reviewed,
					// even when the only YAML edit removes a write. The pure package
					// separately proves the stable last-write sentinel case.
					if tc.family == "filesystem" && r.Direction == agentdiff.CannotClassify && !reflect.DeepEqual(nonWriteFacts(a.FS), nonWriteFacts(b.FS)) {
						continue
					}
					t.Fatalf("simple family not narrowed: %+v", r)
				}
			}
			if !found {
				t.Fatalf("comparison omitted family %q", tc.family)
			}
		})
	}
}

func nonWriteFacts(rows []agent.FSRule) []agent.FSRule {
	var out []agent.FSRule
	for _, r := range rows {
		r.Raw, r.Pos, r.Mount, r.Filesystem = "", agent.Pos{}, "", ""
		if r.Kind != agent.FSWrite && !reflect.DeepEqual(r, agent.FSRule{Kind: agent.FSImplicit, Path: "/", Resolved: "/"}) {
			out = append(out, r)
		}
	}
	return out
}
