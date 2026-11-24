// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestProvisionRefusesBaselineEnvBeforeCreatingFiles(t *testing.T) {
	rt := childBaselineTable("TEGO_HARNESS_EXTENSION", true)
	provision := harness.Provision{Env: []string{"TEGO_HARNESS_EXTENSION=secret-never-print"}}
	err := CheckProvision(rt, harness.Run{}, provision)
	if !errors.Is(err, agent.ErrBaselineEnvironment) || strings.Contains(err.Error(), "secret-never-print") {
		t.Fatalf("denied harness addition was accepted or printed its value: %v", err)
	}
}

func TestChildSpecBaselineChecksFinalCommand(t *testing.T) {
	rt := childBaselineTable("git push", true)
	rt.Baseline.Entries[0].Key = config.BaselineDenyExec
	r := &runner{rt: rt, cmd: []string{"git", "push", "--dry-run"},
		deps: Deps{Cwd: "/", Environ: []string{}, Enforce: enforce.Observe()}}
	if _, err := r.childSpec(); err == nil || !strings.Contains(err.Error(), "baseline-conflict") {
		t.Fatalf("final command bypassed baseline refusal: %v", err)
	}
}

func childBaselineTable(name string, applied bool) *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{Name: "env-check"}, Tier: backend.TierLandlock,
		Deny: []string{name}, Baseline: &agent.BaselineTable{Applied: applied,
			Entries: []agent.BaselineRule{{ResolvedBaselineEntry: config.ResolvedBaselineEntry{Expanded: name, BaselineEntry: config.BaselineEntry{
				Key: config.BaselineDenyEnv, Value: name,
				Sources: []config.Provenance{{Layer: config.LayerUser, File: "/owner/config.yaml", Line: 7}},
			}}}},
		},
	}
}

func TestChildSpecBaselineChecksFinalEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, denied string
		harness      []string
		vars         map[string]string
	}{
		{"identity after filtering", identity.EnvRunID, nil, nil},
		{"reason when actually provisioned", identity.EnvReason, nil, nil},
		{"harness after filtering", "TEGO_HARNESS_EXTENSION", []string{"TEGO_HARNESS_EXTENSION=secret-never-print"}, nil},
		{"Claude settings when actually provisioned", identity.EnvClaudeSettings, []string{identity.EnvClaudeSettings + "=secret-never-print"}, nil},
		{"Codex home when actually provisioned", identity.EnvCodexHome, nil, map[string]string{identity.EnvCodexHome: "secret-never-print"}},
		{"credential after filtering", "CUSTOM_CREDENTIAL", nil, map[string]string{"CUSTOM_CREDENTIAL": "secret-never-print"}},
		{"routing after filtering", "CUSTOM_BASE_URL", nil, map[string]string{"CUSTOM_BASE_URL": "secret-never-print"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: childBaselineTable(tc.denied, true), cmd: []string{"/bin/true"},
				deps:    Deps{Cwd: "/", Environ: []string{tc.denied + "=inherited-value"}, Enforce: enforce.Observe()},
				harness: harnessState{env: tc.harness}}
			if tc.denied == identity.EnvReason {
				r.reasonFile = "/runtime/secret-never-print"
			}
			if tc.vars != nil {
				r.deps.Capture = []source.Source{&fakeLoopback{vars: tc.vars}}
			}
			spec, err := r.childSpec()
			if !errors.Is(err, agent.ErrBaselineEnvironment) || len(spec.Env) != 0 {
				t.Fatalf("final forbidden name reached child spec: error=%v, env count=%d", err, len(spec.Env))
			}
			if !strings.Contains(err.Error(), tc.denied) || strings.Contains(err.Error(), "secret-never-print") || strings.Contains(err.Error(), "inherited-value") {
				t.Fatalf("error lacks name or leaks value: %v", err)
			}
		})
	}
}

func TestChildSpecBaselineKeepsOrdinaryFilteredEnvironment(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Setenv("SUDO_UID", "1234")
		t.Setenv("SUDO_GID", "1234")
	}
	for _, applied := range []bool{false, true} {
		r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: childBaselineTable("TOKEN", applied), cmd: []string{"/bin/true"},
			deps: Deps{Cwd: "/", Environ: []string{"TOKEN=secret-never-print", "LANG=C"}, Enforce: enforce.Observe()}}
		spec, err := r.childSpec()
		if err != nil {
			t.Fatalf("applied=%t: ordinary filtered environment refused: %v", applied, err)
		}
		if envHas(spec.Env, "TOKEN") || !envHas(spec.Env, "LANG") {
			t.Fatalf("applied=%t: contract filtering or ordinary variable changed", applied)
		}
	}
	r := &runner{id: "r-00000000-000000000000a-aaaaaa", rt: childBaselineTable("TEGO_HARNESS_EXTENSION", false), cmd: []string{"/bin/true"},
		deps:    Deps{Cwd: "/", Environ: []string{}, Enforce: enforce.Observe()},
		harness: harnessState{env: []string{"TEGO_HARNESS_EXTENSION=record-only"}}}
	if _, err := r.childSpec(); err != nil {
		t.Fatalf("not-applied baseline refused record-only environment: %v", err)
	}
}
