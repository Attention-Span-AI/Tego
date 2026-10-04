// SPDX-License-Identifier: Apache-2.0

package contracttest

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func TestBuildUsesRealCompilerTreeAndIndependentAskScope(t *testing.T) {
	f := Build(t, `version: 0
name: fixture
command: [fixture]
tier: cgroup
capture: off
fs:
  write: [out]
  deny_read: [sealed/secret]
  ask: [sealed]
net:
  allow: [api.example:443]
`, Tree{"out/": "", "sealed/secret": "private"}, agent.WithResolver(Resolver{"api.example": {netip.MustParseAddr("198.51.100.7")}}))
	if f.Rules.ContractPath != f.Path("contract.yaml") || f.Rules.Hash == [32]byte{} {
		t.Fatalf("not compiled: %+v", f.Rules)
	}
	if data, err := os.ReadFile(f.Path("sealed/secret")); err != nil || string(data) != "private" {
		t.Fatalf("tree: %q %v", data, err)
	}
	if len(f.Rules.FSAsk) != 1 || f.Rules.FSAsk[0].Path != f.Path("sealed") {
		t.Fatalf("compiled separate ask scope: %+v", f.Rules.FSAsk)
	}
	if len(f.Rules.Net) != 1 || f.Rules.Net[0].IPs[0] != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("compiled resolver answer: %+v", f.Rules.Net)
	}
	if f.Home == os.Getenv("HOME") {
		t.Fatal("fixture reused ambient HOME")
	}
}

// The fixture compiles with the machine config a Load gives a contract with no layer files: the built-in's "~/"
// settings expanded against the fixture's home, as config.Load expands them. Handed config.Builtin() itself, Compile
// placed "~/.tego/prices.yaml" in a directory named "~" under the working directory, as an open of that spelling
// would, so fs.write [./] was refused as containing the price table, the profiles and the user registry, and every
// supervisor fixture that writes its root failed to compile.
func TestBuildCompilesWithTheBuiltinMachineAsLoaded(t *testing.T) {
	root := t.TempDir()
	f := BuildAt(t, root, `version: 0
name: fixture
command: [fixture]
capture: off
fs:
  write: [./]
  deny_read: []
`, Tree{"work/": ""}, agent.WithCwd(filepath.Join(root, "work")))
	want := filepath.Join(f.Home, ".tego", "prices.yaml")
	found := false
	for _, p := range f.Rules.OwnState {
		if strings.Contains(p, "/~/") {
			t.Fatalf("own state placed under a directory named ~: %q", p)
		}
		found = found || p == want
	}
	if !found {
		t.Fatalf("own state %q lacks the expanded price table %s", f.Rules.OwnState, want)
	}
}

func TestTreeCannotEscapeOrAliasItsPrivateRoot(t *testing.T) {
	for _, path := range []string{"", ".", "../outside", "/outside", "a/../outside", "a//b"} {
		root := t.TempDir()
		if err := createTree(root, Tree{path: "bad"}); err == nil {
			t.Fatalf("accepted %q", path)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			t.Fatalf("invalid tree had side effects: %v %v", entries, err)
		}
	}
	root := t.TempDir()
	if err := createTree(root, Tree{"bin/tool": "#!/bin/sh\n"}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(root, "bin/tool"))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("private executable: %v %v", st, err)
	}
}

// fatalTB stops a Build where the testing.TB it was given would fail the test, and records why.
type fatalTB struct {
	testing.TB
	failed string
}

func (f *fatalTB) Helper() {}
func (f *fatalTB) Fatal(args ...any) {
	f.failed = fmt.Sprint(args...)
	runtime.Goexit()
}
func (f *fatalTB) Fatalf(format string, args ...any) {
	f.failed = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// buildFails runs BuildAt and returns the failure it stopped with, or "" when it compiled.
func buildFails(t *testing.T, root, yaml string, tree Tree, options ...agent.CompileOption) string {
	t.Helper()
	tb := &fatalTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		BuildAt(tb, root, yaml, tree, options...)
	}()
	<-done
	return tb.failed
}

// TestBuildRefusesAHostExecutable: a fixture's command, exec.allow and MCP entries come from its private tree.
// The observe fixture declared exec.allow [git] over a PATH that began with /usr/bin, so it compiled on a box that
// has git and failed every test that used it as root in the KVM guest, which has none (root-suites R1). Only the
// interpreter the default fixture script names (#!/bin/sh) may be the host's.
func TestBuildRefusesAHostExecutable(t *testing.T) {
	host, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no sh on PATH: %v", err)
	}
	const net = "net: {allow: []}\n"
	for _, tc := range []struct {
		name, yaml string
		hostPATH   bool
	}{
		{"exec.allow found on the host PATH", "command: [fixture]\nexec:\n  allow: [sh]\n", true},
		{"command by host path", "command: [" + host + "]\n", false},
		{"exec.allow by host path", "command: [fixture]\nexec:\n  allow: [" + host + "]\n", false},
	} {
		root := t.TempDir()
		var options []agent.CompileOption
		if tc.hostPATH {
			options = append(options, agent.WithPATH(filepath.Join(root, "bin")+":"+filepath.Dir(host)))
		}
		if failed := buildFails(t, root, "version: 0\nname: fixture\n"+net+tc.yaml, nil, options...); !strings.Contains(failed, "outside the fixture's private tree") {
			t.Errorf("%s: Build = %q, want the host executable refused", tc.name, failed)
		}
	}
	// The same name supplied by the tree compiles, and the default script's #!/bin/sh interpreter is allowed.
	if failed := buildFails(t, t.TempDir(), "version: 0\nname: fixture\n"+net+"command: [fixture]\nexec:\n  allow: [sh, ./bin/fixture]\n",
		Tree{"bin/sh": "#!/bin/sh\nexit 0\n"}); failed != "" {
		t.Errorf("private executables refused: %s", failed)
	}
}

func TestResolverNeverUsesUnknownHostAndHonorsCancellation(t *testing.T) {
	r := Resolver{"known": {netip.MustParseAddr("192.0.2.1")}}
	got, err := r.LookupNetIP(context.Background(), "ip", "known")
	if err != nil {
		t.Fatal(err)
	}
	got[0] = netip.Addr{}
	if !r["known"][0].IsValid() {
		t.Fatal("returned DNS slice aliases fixture")
	}
	if _, err := r.LookupNetIP(context.Background(), "ip", "unconfigured.example"); err == nil {
		t.Fatal("unknown host accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.LookupNetIP(ctx, "ip", "known"); err != context.Canceled {
		t.Fatalf("canceled resolver: %v", err)
	}
}
