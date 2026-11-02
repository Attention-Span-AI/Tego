// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestRunTier: an auto contract, or one pinning the run's tier, compiles at the run's tier; a text pinning another
// tier (a free edit) compiles as tego would, not as if the machine built only the run's tier.
func TestRunTier(t *testing.T) {
	cases := []struct {
		run  string
		pin  agent.TierPin
		want backend.Tier
	}{
		{"landlock", "", backend.TierLandlock},
		{"landlock", "auto", backend.TierLandlock},
		{"landlock", "landlock", backend.TierLandlock},
		{"landlock", "cgroup", ""},
		{"", "", ""},
		{"quantum", "", ""},
	}
	for _, c := range cases {
		if got := runTier(c.run, c.pin); got != c.want {
			t.Errorf("runTier(%q, %q) = %q, want %q", c.run, c.pin, got, c.want)
		}
	}
}

// TestCompileOffline: a host name is not resolved at the check (E18), so a name only DNS could refuse compiles, and an
// error carries the compiler's diagnostics.
func TestCompileOffline(t *testing.T) {
	dir := t.TempDir()
	cc := Context{Contract: filepath.Join(dir, "agent.yaml"), Tier: "landlock", PATH: "/usr/bin:/bin"}
	head := "version: 0\nname: n\ncommand: [\"sh\"]\n"
	if _, err := Compile(context.Background(), config.Builtin(), cc, []byte(head+"exec:\n  allow: [sh]\nnet:\n  allow: [\"no-such-host.invalid:443\"]\n")); err != nil {
		t.Errorf("an unresolvable host: %v", err)
	}
	_, err := Compile(context.Background(), config.Builtin(), cc, []byte(head+"exec:\n  allow: [sh, no-such-program-nextrun]\n"))
	if err == nil || !strings.Contains(err.Error(), "no-such-program-nextrun") {
		t.Errorf("a broken entry: %v", err)
	}
	if _, err := Compile(context.Background(), nil, cc, []byte(head)); err == nil {
		t.Error("compiled with no machine config")
	}
}

// TestCompileDoesNoDNS: a check looks no host up. agent.Offline alone still resolves every host and only makes a
// failure a warning, so each check (a dashboard preview compiles three times) waited on DNS for every host of the
// contract, up to agent.DefaultDNSTimeout a round where DNS does not answer. The system resolver here counts every
// query it would send.
func TestCompileDoesNoDNS(t *testing.T) {
	var queries atomic.Int32
	system := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		queries.Add(1)
		return nil, errors.New("no DNS in this test")
	}}
	t.Cleanup(func() { net.DefaultResolver = system })
	cc := Context{Contract: filepath.Join(t.TempDir(), "agent.yaml"), Tier: "landlock", PATH: "/usr/bin:/bin"}
	text := "version: 0\nname: n\ncommand: [\"sh\"]\nexec:\n  allow: [sh]\nnet:\n" +
		"  allow: [\"api.nextrun-no-dns.test:443\"]\n  ask: [\"ask.nextrun-no-dns.test:443\"]\n"
	if _, err := Compile(context.Background(), config.Builtin(), cc, []byte(text)); err != nil {
		t.Fatalf("a contract naming hosts: %v", err)
	}
	if n := queries.Load(); n != 0 {
		t.Errorf("the check sent %d DNS queries; it resolves no host (the next run does, at its start)", n)
	}
}
