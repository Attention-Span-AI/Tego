// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func withBaselineEnv(t *testing.T, f *fixture, names ...string) {
	t.Helper()
	if err := os.Chmod(f.root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.root, "env-baseline.yaml")
	if err := os.WriteFile(path, []byte("baseline: {env: {deny: ["+strings.Join(names, ", ")+"]}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, ds, err := config.LoadSources(config.Sources{User: path}, f.home, os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("load baseline: %v %v", err, ds)
	}
	m.LedgerRoot = f.machine.LedgerRoot
	f.machine = m
}

func TestBaselineEnvConflicts(t *testing.T) {
	const model = "capture: forwarder\nmodels: [{provider: openai, host: 127.0.0.1, port: 9511}]\n"
	const credential = model + "credentials: [{name: local, env: LOCAL_API_KEY, base_url_env: LOCAL_URL, allow: ['127.0.0.1:9511']}]\n"
	for _, tc := range []struct {
		name, denied, body, key string
		env                     []string
	}{
		{"explicit pass", "TOKEN", "env: {pass: [TOKEN]}\n", "env.pass", nil},
		{"explicit set", "TOKEN", "env: {set: {TOKEN: value-not-for-diagnostics}}\n", "env.set", nil},
		{"identity", identity.EnvRunID, "", "runtime identity producer", nil},
		{"parent identity even when empty", identity.EnvParentRun, "", "runtime identity producer", nil},
		{"otel identity", identity.EnvOTELResourceAttributes, "", "runtime identity producer", nil},
		{"postgres identity", identity.EnvPGAppName, "", "runtime identity producer", nil},
		{"forwarder", identity.EnvOpenAIBaseURL, model, "models", nil},
		{"legacy forwarder", identity.EnvOpenAIAPIBase, model, "models", nil},
		{"resolver", "RES_OPTIONS", model, "guarded resolver producer", nil},
		{"credential env", "LOCAL_API_KEY", credential, "credentials", nil},
		{"credential routing", "LOCAL_URL", credential, "credentials", nil},
		{"proxy routing", identity.EnvNoProxyLower, "", "proxy routing producer", []string{"HTTPS_PROXY=proxy-value-not-for-diagnostics"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			withBaselineEnv(t, f, tc.denied)
			c := f.load("version: 0\nname: baseline-env\ncommand: [python]\n" + tc.body)
			rt, ds, err := Compile(c, f.machine, f.opts(WithEnviron(tc.env))...)
			if rt != nil || err == nil {
				t.Fatalf("contradictory environment compiled: table=%t error=%v", rt != nil, err)
			}
			found := false
			for _, d := range ds {
				if d.Code == CodeBaselineConflict && d.IsError() && strings.Contains(d.Message, tc.denied) && strings.Contains(d.Message, tc.key) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no baseline conflict naming both sides: %s", render(ds))
			}
			if text := render(ds); strings.Contains(text, "value-not-for-diagnostics") {
				t.Fatalf("environment value reached diagnostic: %s", text)
			}
		})
	}
}

func TestBaselineEnvOrdinaryInputs(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		denied     []string
		env        []string
	}{
		{"absent section", "", []string{"TOKEN"}, []string{"TOKEN=secret"}},
		{"empty section", "env: {}\n", []string{"TOKEN"}, nil},
		{"empty pass", "env: {pass: []}\n", []string{"TOKEN"}, nil},
		{"other pass", "env: {pass: [PATH]}\n", []string{"TOKEN"}, nil},
		{"duplicate deny", "env: {deny: [TOKEN, TOKEN]}\n", []string{"TOKEN"}, nil},
		{"unused route", "capture: off\n", []string{identity.EnvOpenAIBaseURL, "RES_OPTIONS"}, nil},
		{"unconfigured provider", "capture: forwarder\nmodels: [{provider: anthropic, host: api.anthropic.com, port: 443}]\n", []string{identity.EnvOpenAIBaseURL}, nil},
		{"no harness addition", "harness: none\n", []string{identity.EnvClaudeSettings}, nil},
		{"optional reason channel", "", []string{identity.EnvReason}, nil},
		{"optional Codex SDK configuration", "capture: forwarder\nmodels: [{provider: openai, host: 127.0.0.1, port: 9511}]\n", []string{identity.EnvCodexHome}, nil},
		{"optional harness provisioning", "harness: claude-code\n", []string{identity.EnvClaudeSettings}, nil},
		{"no proxy", "", []string{identity.EnvNoProxyLower}, []string{"LANG=C"}},
		{"bare inherited entry is no proxy variable", "", []string{identity.EnvNoProxyLower}, []string{"HTTPS_PROXY"}},
		{"removed proxy", "env: {deny: [HTTPS_PROXY]}\n", []string{identity.EnvNoProxyLower}, []string{"HTTPS_PROXY=unused"}},
		{"existing uppercase no proxy", "", []string{identity.EnvNoProxyLower}, []string{"HTTPS_PROXY=local", "NO_PROXY=example"}},
		{"denied uppercase no proxy", "", []string{identity.EnvNoProxy}, []string{"HTTPS_PROXY=local", "NO_PROXY=example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			withBaselineEnv(t, f, tc.denied...)
			c := f.load("version: 0\nname: ordinary-env\ncommand: [" + strconv.Quote(filepath.Join(f.bin, "python")) + "]\n" + tc.body)
			_, ds, err := Compile(c, f.machine, f.opts(WithEnviron(tc.env))...)
			if err != nil {
				t.Fatalf("ordinary environment refused: %v\n%s", err, render(ds))
			}
		})
	}
}

func TestBaselineEnvNullPassKeepsExistingSchemaRefusal(t *testing.T) {
	f := newFixture(t)
	withBaselineEnv(t, f, "TOKEN")
	c, ds, err := LoadBytes(filepath.Join(f.project, "null.yaml"), []byte("version: 0\nname: null-env\ncommand: [python]\nenv: {pass: null}\n"), f.profiles())
	if c != nil || err == nil || !strings.Contains(render(ds), "env.pass: has no value") || slices.Contains(codes(ds), CodeBaselineConflict) {
		t.Fatalf("null environment pass changed its existing schema refusal: %v %s", err, render(ds))
	}
}

func TestBaselineEnvRootOptionalProducerNames(t *testing.T) {
	for _, body := range []string{
		"harness: claude-code\n",
		"harness: generic\ncapture: forwarder\nmodels: [{provider: openai, host: 127.0.0.1, port: 9511}]\n",
	} {
		f := newFixture(t)
		withBaselineEnv(t, f, identity.EnvReason, identity.EnvCodexHome, identity.EnvClaudeSettings)
		c := f.load("version: 0\nname: root-optional-env\ncommand: [python]\n" + body)
		if _, ds, err := Compile(c, f.machine, f.opts(WithOwnerUID(0))...); err != nil {
			t.Fatalf("root's absent optional injections caused a refusal: %v\n%s", err, render(ds))
		}
	}
}

func TestValidateBaselineEnv(t *testing.T) {
	rt := &RuleTable{Tier: backend.TierLandlock, Baseline: &BaselineTable{
		Owner: config.BaselineOwner{UID: 1234}, Applied: true,
		Entries: []BaselineRule{{ResolvedBaselineEntry: config.ResolvedBaselineEntry{BaselineEntry: config.BaselineEntry{
			Key: config.BaselineDenyEnv, Value: "TOKEN", Sources: []config.Provenance{{Layer: config.LayerUser, File: "/owner/config.yaml", Line: 12}},
		}}}},
	}}
	for _, env := range [][]string{{"A=1"}, {"TOKENIZER=value"}, {"TOKEN"}, nil} {
		if err := rt.ValidateBaselineEnv(env); err != nil {
			t.Fatalf("nonmatching final environment refused: %v", err)
		}
	}
	for _, env := range [][]string{{"TOKEN=secret-never-print"}, {"TOKEN="}, {"TOKEN=first", "TOKEN=second"}} {
		err := rt.ValidateBaselineEnv(env)
		if !errors.Is(err, ErrBaselineEnvironment) || !strings.Contains(err.Error(), "TOKEN") ||
			!strings.Contains(err.Error(), "/owner/config.yaml:12") || !strings.Contains(err.Error(), "1234") || strings.Contains(err.Error(), "secret-never-print") {
			t.Fatalf("final environment error lacks name/source or leaks value: %v", err)
		}
	}
	rt.Baseline.Applied = false
	if err := rt.ValidateBaselineEnv([]string{"TOKEN=record-only"}); err != nil {
		t.Fatalf("record-only baseline applied: %v", err)
	}
	if err := (*RuleTable)(nil).ValidateBaselineEnv([]string{"TOKEN=value"}); err != nil {
		t.Fatalf("nil table: %v", err)
	}
}

func TestWithRunArgvRetainsAnImmutableCompleteCommand(t *testing.T) {
	argv := []string{"git", "push", "--dry-run"}
	opt := WithRunArgv(argv)
	argv[1] = "status"
	var first, second compileOptions
	opt(&first)
	first.runArgv[1] = "fetch"
	opt(&second)
	if second.runCommand != "git" || strings.Join(second.runArgv, " ") != "git push --dry-run" {
		t.Fatalf("command option lost arguments or retained mutable caller data: %q %q", second.runCommand, second.runArgv)
	}
	WithRunCommand("python")(&second)
	if second.runCommand != "python" || second.runArgv != nil {
		t.Fatalf("legacy image-only option retained another command's arguments: %+v", second)
	}
	WithRunArgv(nil)(&second)
	if second.runCommand != "" || second.runArgv != nil {
		t.Fatalf("empty argv retained another command: %+v", second)
	}
}
