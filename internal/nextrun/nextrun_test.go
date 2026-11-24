// SPDX-License-Identifier: Apache-2.0

package nextrun

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/internal/profilesrc"
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

func TestCompileLoadedKeepsOneProfileSnapshot(t *testing.T) {
	root := t.TempDir()
	profiles := filepath.Join(root, "profiles")
	if err := os.Mkdir(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(profiles, "base.yaml")
	if err := os.WriteFile(profile, []byte("net:\n  limits: {connections: 0}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Home, m.Profiles.Value = root, profiles
	cc := Context{Contract: filepath.Join(root, "agent.yaml"), Cwd: root, Home: root, PATH: "/usr/bin:/bin"}
	text := []byte("version: 0\nname: one-snapshot\nextends: base\ncommand: [sh]\n")
	c, ds, err := agent.LoadBytes(cc.Contract, text, profilesrc.Chain(m))
	if err != nil {
		t.Fatal(DiagError(ds, err))
	}
	if err := os.WriteFile(profile, []byte("net:\n  limits: {connections: 100}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rt, err := CompileLoaded(t.Context(), m, cc, c)
	if err != nil {
		t.Fatal(err)
	}
	if rt.NetLimits.Connections == nil || *rt.NetLimits.Connections != 0 {
		t.Fatal("compiling a loaded snapshot reloaded changed profile bytes")
	}
	rt, err = Compile(t.Context(), m, cc, text)
	if err != nil || rt.NetLimits.Connections == nil || *rt.NetLimits.Connections != 100 {
		t.Fatal("a fresh compile did not read the changed profile")
	}
}
