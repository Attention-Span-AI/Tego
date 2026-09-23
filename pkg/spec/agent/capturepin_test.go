// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestPinnedUprobeKeepsTheBaseURL is the compile half of kill test 7 (b): a contract that pins capture: uprobe
// runs no forwarder (PinsUprobe, capture.Select), so ANTHROPIC_BASE_URL is the contract's own to pass, the way
// examples/agents/anthropic-sdk-python.yaml passes it for a gateway or a private CA. Compile used to reserve it
// under uprobe as under forwarder, warn env-runtime-reserved and drop it from env.pass: the SDK then never
// reached the endpoint it was given. uprobe reached through auto runs the forwarder beside the probes, so there
// the variable is still the forwarder's, as it is under capture: forwarder (SEMANTICS §9).
func TestPinnedUprobeKeepsTheBaseURL(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name     string
		capture  string
		want     CaptureMode
		pinned   bool
		reserved bool
	}{
		{"pinned uprobe", "capture: uprobe\n", CaptureUprobe, true, false},
		{"auto resolved to uprobe", "capture: auto\n", CaptureUprobe, false, true},
		{"capture unset", "", CaptureUprobe, false, true},
		{"forwarder", "capture: forwarder\n", CaptureForwarder, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\ntier: cgroup\n" + tc.capture +
				"env:\n  pass: [PATH, ANTHROPIC_BASE_URL]\n")
			rt, ds := f.compile(c)
			if rt.Tier != backend.TierCgroup || rt.Capture != tc.want {
				t.Fatalf("tier=%s capture=%s, want cgroup %s", rt.Tier, rt.Capture, tc.want)
			}
			if rt.PinsUprobe() != tc.pinned {
				t.Errorf("PinsUprobe = %v, want %v", rt.PinsUprobe(), tc.pinned)
			}
			passed := slices.Contains(rt.Env, "ANTHROPIC_BASE_URL")
			if warned := hasCode(ds, CodeEnvRuntimeReserved); warned != tc.reserved || passed == tc.reserved {
				t.Errorf("env-runtime-reserved %v and ANTHROPIC_BASE_URL passed %v, want reserved %v:\n%s",
					warned, passed, tc.reserved, render(ds))
			}
		})
	}
}

// TestEveryForwarderVarIsReserved: every variable the forwarder may set (identity.ForwarderVarNames: each
// provider's base-URL variables and CODEX_HOME) draws env-runtime-reserved under capture: forwarder, in env.pass and
// in env.set. Compile's own list held the Anthropic and OpenAI names alone, so a contract passing
// GOOGLE_GEMINI_BASE_URL or CODE_ASSIST_ENDPOINT was silently overridden by identity.Env.Apply. A base-URL
// variable leaves the pass list; CODEX_HOME stays in it, since the launcher reads the contract's value to find the
// user's Codex config.toml it copies into the run's.
// agent-contract.md R12: env-runtime-reserved on ANTHROPIC_BASE_URL-and-peers wherever the forwarder runs.
func TestEveryForwarderVarIsReserved(t *testing.T) {
	f := newFixture(t)
	for _, name := range identity.ForwarderVarNames {
		t.Run(name, func(t *testing.T) {
			c := f.load("version: 0\nname: a\ncommand: [python]\ntier: cgroup\ncapture: forwarder\n" +
				"env:\n  pass: [PATH, " + name + "]\n  set: {" + name + ": x}\n")
			rt, ds := f.compile(c)
			n := 0
			for _, d := range ds {
				if d.Code == CodeEnvRuntimeReserved && strings.Contains(d.Message, name) {
					n++
				}
			}
			if n != 2 {
				t.Errorf("%d env-runtime-reserved warnings naming %s, want 2 (pass and set):\n%s", n, name, render(ds))
			}
			if passed, want := slices.Contains(rt.Env, name), name == identity.EnvCodexHome; passed != want {
				t.Errorf("%s left in env.pass: %v, want %v", name, passed, want)
			}
		})
	}
}

// TestModelDirectBypassUnderAPinnedUprobe: E27 warns about a net.allow entry naming a models[] endpoint because
// the forwarder reaches the model on the run's behalf and the entry is a way around it, and its fix says to
// remove the entry. A contract that pins capture: uprobe runs no forwarder wherever the tier runs uprobes: the
// entry is then the agent's one route to its model, the one the probes read, and following that fix refused
// the agent its model. With the tier pinned at cgroup or above there is nothing to warn about; with the tier
// left to the machine the entry is a bypass only on a run that falls back to the forwarder, and the warning says
// that; a contract pinned at landlock always falls back, so it keeps E27's warning as it was.
//
// A machine ceiling can lower a pinned uprobe to the forwarder whatever tier the contract pins: a capture
// ceiling of forwarder, or a tier ceiling of landlock. Load cannot see either, so Compile warns then, with
// E27's own fix; before it did, those runs started the forwarder with the entry allowed and nothing warned.
// want lists the fixes of every model-direct-bypass warning, Load's first, then Compile's.
// agent-contract.md E27: model-direct-bypass under a pinned uprobe.
func TestModelDirectBypassUnderAPinnedUprobe(t *testing.T) {
	f := newFixture(t)
	const (
		remove      = "remove it from net.allow"
		conditional = "keep it for uprobe capture"
	)
	cases := []struct {
		name, tier, capture string
		machineTier         backend.Tier
		machineCapture      string
		want                []string
	}{
		{"forwarder", "", "capture: forwarder\n", "", "", []string{remove}},
		{"auto", "", "", "", "", []string{remove}},
		{"pinned uprobe at tier cgroup", "tier: cgroup\n", "capture: uprobe\n", "", "", nil},
		{"pinned uprobe at tier bpflsm", "tier: bpflsm\n", "capture: uprobe\n", "", "", nil},
		{"pinned uprobe, tier left to the machine", "", "capture: uprobe\n", "", "", []string{conditional}},
		{"pinned uprobe at tier landlock", "tier: landlock\n", "capture: uprobe\n", "", "", []string{remove}},
		{"pinned uprobe at tier cgroup, machine capture ceiling forwarder", "tier: cgroup\n", "capture: uprobe\n", "", "forwarder", []string{remove}},
		{"pinned uprobe at tier cgroup, machine tier ceiling landlock", "tier: cgroup\n", "capture: uprobe\n", backend.TierLandlock, "", []string{remove}},
		{"pinned uprobe, tier left to a landlock machine", "", "capture: uprobe\n", backend.TierLandlock, "", []string{remove}},
		{"pinned uprobe at tier landlock, landlock machine", "tier: landlock\n", "capture: uprobe\n", backend.TierLandlock, "", []string{remove}},
		{"pinned uprobe at tier cgroup, machine capture ceiling uprobe", "tier: cgroup\n", "capture: uprobe\n", "", "uprobe", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(f.project, "agent.yaml")
			f.file(path, "version: 0\nname: a\ncommand: [python]\n"+tc.tier+tc.capture+
				"models:\n  - { provider: anthropic, host: api.anthropic.com, port: 443 }\n"+
				"net:\n  allow: [\"api.anthropic.com:443\"]\n", 0o644)
			c, ds, err := Load(path, f.profiles())
			if err != nil {
				t.Fatalf("load: %v\n%s", err, render(ds))
			}
			m := *f.machine
			m.Tier, m.Capture = tierCeil(tc.machineTier), capCeil(tc.machineCapture)
			_, cds, err := Compile(c, &m, f.opts()...)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, render(cds))
			}
			var got []Diagnostic
			for _, d := range append(ds, cds...) {
				if d.Code == CodeModelDirectBypass {
					got = append(got, d)
				}
			}
			ok := len(got) == len(tc.want)
			for i := 0; ok && i < len(got); i++ {
				ok = strings.Contains(got[i].Fix, tc.want[i])
			}
			if !ok {
				t.Fatalf("got\n%s\nwant model-direct-bypass warnings whose fixes say %q", render(got), tc.want)
			}
		})
	}
}

// A models[] host is matched against net.allow in CanonicalHost's spelling, the one normalization host.go
// names, so a trailing dot, brackets, case or a longer IPv6 spelling still draws E27's warning.
// agent-contract.md E27: model-direct-bypass whatever the models[] host's spelling.
func TestModelDirectBypassWhateverTheHostSpelling(t *testing.T) {
	f := newFixture(t)
	for _, host := range []string{"api.example.com", "API.Example.com", "api.example.com.", `"[::1]"`, `"[0:0::1]"`, `"[::ffff:127.0.0.1]"`} {
		t.Run(host, func(t *testing.T) {
			path := filepath.Join(f.project, "agent.yaml")
			f.file(path, "version: 0\nname: a\ncommand: [python]\ncapture: forwarder\n"+
				"models:\n  - { provider: anthropic, host: "+host+", port: 443 }\n"+
				"net:\n  allow: [\"api.example.com:443\", \"[::1]:443\", \"127.0.0.1:443\"]\n", 0o644)
			_, ds, err := Load(path, f.profiles())
			if err != nil {
				t.Fatalf("load: %v\n%s", err, render(ds))
			}
			n := 0
			for _, d := range ds {
				if d.Code == CodeModelDirectBypass {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("models[].host %s: %d model-direct-bypass warnings, want 1\n%s", host, n, render(ds))
			}
		})
	}
}
