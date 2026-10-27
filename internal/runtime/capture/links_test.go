// SPDX-License-Identifier: Apache-2.0

// The link-closure tests run go list, so they stay out of the integration binaries: root-suites.sh runs those in a
// KVM guest with no Go toolchain, where go-shim.sh serves only the prebuilt helpers and fails any other go command.

//go:build !integration

package capture

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const runtimePkg = "github.com/attention-span-ai/tego/internal/runtime"

// engineSubs are the internal/runtime packages (each with its subpackages) no capture source may link, beside the
// facade internal/runtime itself (ADR 0031 (b) step 1): the launcher, the supervisor, every enforcement package,
// the DNS broker, the kernel recorder (it imports the facade), the limits watcher, the open deputy and the
// approval broker. The depguard rules capture-links-no-engine and capture-asks-through-forwarder deny the same
// list as direct imports; this test also catches a link through any intermediate package.
var engineSubs = []string{"launch", "supervisor", "enforce", "dnsbroker", "observe", "limits", "deputy", "ask"}

// engineLink reports whether p is an engine package a capture source must not link.
func engineLink(p string) bool {
	if p == runtimePkg {
		return true
	}
	for _, sub := range engineSubs {
		if p == runtimePkg+"/"+sub || strings.HasPrefix(p, runtimePkg+"/"+sub+"/") {
			return true
		}
	}
	return false
}

// engineAllowed names, per capture package, the engine packages it links by design. The forwarder holds a model
// request for a human approval through the approval broker's Request API (ask_hold.go), so it links
// internal/runtime/ask; ask itself links no other engine package, which this test checks too, since ask's own
// closure is part of the forwarder's.
var engineAllowed = map[string]map[string]bool{
	"github.com/attention-span-ai/tego/internal/runtime/capture/forwarder": {runtimePkg + "/ask": true},
}

// mustCover are the capture sources this test exists for: a go list that stopped finding one of them would let
// the test pass while checking nothing.
var mustCover = []string{
	"github.com/attention-span-ai/tego/internal/runtime/capture",
	"github.com/attention-span-ai/tego/internal/runtime/capture/forwarder",
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe",
}

// TestCaptureLinksNoEngine holds the link closure of every package under internal/runtime/capture, on both
// architectures and with and without the tegobpf tag, free of the engine: before internal/runtime/source the
// capture sources imported the facade for the Source contract, and with it linked launch, the supervisor, every
// backend and the DNS broker.
func TestCaptureLinksNoEngine(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		for _, tags := range []string{"", "tegobpf"} {
			cmd := exec.Command("go", "list", "-tags="+tags,
				"-f", "{{.ImportPath}}{{range .Deps}} {{.}}{{end}}", "./...")
			cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list ./... (GOARCH=%s tags=%q): %v", goarch, tags, err)
			}
			seen := map[string]bool{}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				f := strings.Fields(line)
				if len(f) == 0 {
					continue
				}
				pkg := f[0]
				seen[pkg] = true
				if bad := engineLinks(pkg, f[1:]); len(bad) > 0 {
					t.Errorf("%s links %d engine packages (GOARCH=%s tags=%q): %s",
						pkg, len(bad), goarch, tags, strings.Join(bad, " "))
				}
			}
			for _, p := range mustCover {
				if !seen[p] {
					t.Errorf("go list ./... (GOARCH=%s tags=%q) did not list %s", goarch, tags, p)
				}
			}
		}
	}
}

// engineLinks returns the engine packages among deps that pkg's engineAllowed entry does not name, sorted.
func engineLinks(pkg string, deps []string) []string {
	var bad []string
	for _, p := range deps {
		if engineLink(p) && !engineAllowed[pkg][p] {
			bad = append(bad, p)
		}
	}
	sort.Strings(bad)
	return bad
}

// TestEngineLinkNamesTheEngine pins engineLink's answers, so a typo in engineSubs cannot quietly empty the check.
func TestEngineLinkNamesTheEngine(t *testing.T) {
	for p, want := range map[string]bool{
		runtimePkg:                                         true,
		runtimePkg + "/launch":                             true,
		runtimePkg + "/supervisor":                         true,
		runtimePkg + "/enforce":                            true,
		runtimePkg + "/enforce/api":                        true,
		runtimePkg + "/enforce/cgroup":                     true,
		runtimePkg + "/dnsbroker":                          true,
		runtimePkg + "/observe":                            true,
		runtimePkg + "/limits":                             true,
		runtimePkg + "/deputy":                             true,
		runtimePkg + "/ask":                                true,
		runtimePkg + "/source":                             false,
		runtimePkg + "/derive":                             false,
		runtimePkg + "/cgroup":                             false,
		runtimePkg + "/hoststate":                          false,
		runtimePkg + "/capture/forwarder":                  false,
		runtimePkg + "/launcher":                           false,
		"github.com/attention-span-ai/tego/pkg/spec/agent": false,
	} {
		if got := engineLink(p); got != want {
			t.Errorf("engineLink(%s) = %v, want %v", p, got, want)
		}
	}
}
