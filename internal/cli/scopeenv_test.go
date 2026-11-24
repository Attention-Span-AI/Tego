// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"
)

// secretLookingEnv is a caller's environment with variables a person keeps tokens in, beside the ones a process needs.
var secretLookingEnv = []string{
	"PATH=/usr/bin", "HOME=/home/x", "LANG=C.UTF-8", "LC_ALL=C", "TERM=xterm",
	"ANTHROPIC_API_KEY=sk-ant-fake-0123456789", "GITHUB_TOKEN=ghp_fake", "AWS_SECRET_ACCESS_KEY=fake",
	"CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-fake", "DEPLOY_PASSWORD=fake", "XDG_RUNTIME_DIR=/hostile",
	"DBUS_SESSION_BUS_ADDRESS=unix:path=/hostile", "SYSTEMD_LOG_LEVEL=debug",
}

// TestScopeManagerEnvHoldsNoSecret: systemd-run is a plain exec, so it is dumpable, and it execs the re-entered launcher
// with the environment it has. It is given a minimal one (what it reads to reach the user's manager), never the caller's:
// the caller's whole environment goes to the re-entered process over the request FIFO, whose reader is undumpable.
func TestScopeManagerEnvHoldsNoSecret(t *testing.T) {
	env := scopeManagerEnv(secretLookingEnv)
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		for _, secret := range []string{"ANTHROPIC_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "DEPLOY_PASSWORD"} {
			if name == secret {
				t.Errorf("the manager's environment holds %s", name)
			}
		}
	}
	for _, want := range []string{"PATH=/usr/bin", "HOME=/home/x", "LANG=C.UTF-8", "LC_ALL=C", "TERM=xterm", "SYSTEMD_LOG_LEVEL=debug"} {
		if !slices.Contains(env, want) {
			t.Errorf("the manager's environment lost %s: %q", want, env)
		}
	}
	if slices.Contains(env, "XDG_RUNTIME_DIR=/hostile") || slices.Contains(env, "DBUS_SESSION_BUS_ADDRESS=unix:path=/hostile") {
		t.Errorf("a caller's runtime directory or bus reached the manager: %q", env)
	}
}

// TestScopeEntryHandsSystemdRunNoSecretButTheRequestCarriesThem: what tryUserScope gives executeUserScope. Its Env (the
// systemd-run process's environment) has none of the caller's secret-bearing variables; its Request.Env, which travels
// over the FIFO, has all of them.
func TestScopeEntryHandsSystemdRunNoSecretButTheRequestCarriesThem(t *testing.T) {
	scopeStands(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-fake-entry-0123456789")
	t.Setenv("GITHUB_TOKEN", "ghp_fake_entry")
	var got scopePlan
	scopeExec = func(_ context.Context, p scopePlan, _ io.Writer) (int, error) { got = p; return 0, nil }
	if _, attempted, err := tryUserScope(t.Context(), scopeInvocation{argv: []string{"tego", "run", "x.yaml"}}, false, io.Discard); !attempted || err != nil {
		t.Fatalf("attempted %v, %v", attempted, err)
	}
	for _, e := range got.Env {
		if strings.HasPrefix(e, "ANTHROPIC_API_KEY=") || strings.HasPrefix(e, "GITHUB_TOKEN=") {
			t.Errorf("systemd-run's environment holds %q", strings.SplitN(e, "=", 2)[0])
		}
	}
	for _, want := range []string{"ANTHROPIC_API_KEY=sk-ant-fake-entry-0123456789", "GITHUB_TOKEN=ghp_fake_entry"} {
		if !slices.Contains(got.Request.Env, want) {
			t.Errorf("the request lost %s", strings.SplitN(want, "=", 2)[0])
		}
	}
}
