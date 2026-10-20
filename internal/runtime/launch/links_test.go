// SPDX-License-Identifier: Apache-2.0

// The link-closure tests run go list, so they stay out of the integration binaries: root-suites.sh runs those in a
// KVM guest with no Go toolchain, where go-shim.sh serves only the prebuilt helpers and fails any other go command.

//go:build !integration

package launch

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// launchLinks are the only packages outside the standard library launch may link (ADR 0031 (a)): the child
// stage and the launcher see a prepared handle through enforce/api's interfaces and never link a backend,
// cilium/ebpf, the engine, a YAML parser or the policy types. A package added here widens the TCB root
// that runs the agent's first instructions, so it is a reviewed change, not a side effect of an import.
var launchLinks = map[string]bool{
	"github.com/attention-span-ai/tego/internal/platform/proc":       true,
	"github.com/attention-span-ai/tego/internal/platform/sys":        true,
	"github.com/attention-span-ai/tego/internal/runtime/deputy":      true,
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api": true,
	"github.com/attention-span-ai/tego/internal/runtime/launch":      true,
	"github.com/attention-span-ai/tego/pkg/spec/identity":            true,
	"golang.org/x/net/bpf":  true,
	"golang.org/x/sys/unix": true,
}

// launchDepsTarget is the package budget for `go list -deps` of launch, the standard library
// included. It is a target, not a gate: a miss prints TARGET-MISS with the number. It is missed (119): ADR 0031's
// 2026-10-19 note on (a) attributes the excess to pkg/spec/identity's crypto/sha256 and regexp, reached directly
// and through internal/platform/proc, and to the ChildSpec frame's encoding/json, and leaves it open for TCB-CHECK.
const launchDepsTarget = 80

// TestLaunchLinksNoBackend holds launch's link closure, on both architectures and with and without the
// tegobpf tag, to launchLinks: no enforcement backend (enforce/{landlock,cgroup,bpflsm,observe}), not
// internal/runtime/enforce itself, no cilium/ebpf, no internal/bpf and no gopkg.in/yaml.v3.
func TestLaunchLinksNoBackend(t *testing.T) {
	for _, goarch := range []string{"amd64", "arm64"} {
		for _, tags := range []string{"", "tegobpf"} {
			cmd := exec.Command("go", "list", "-deps", "-tags="+tags,
				"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".")
			cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps (GOARCH=%s tags=%q): %v", goarch, tags, err)
			}
			var extra []string
			for _, p := range strings.Fields(string(out)) {
				if !launchLinks[p] {
					extra = append(extra, p)
				}
			}
			sort.Strings(extra)
			if len(extra) > 0 {
				t.Errorf("launch links %d packages outside its allowlist (GOARCH=%s tags=%q): %s",
					len(extra), goarch, tags, strings.Join(extra, " "))
			}
		}
	}
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	n := len(strings.Fields(string(out)))
	if n >= launchDepsTarget {
		t.Logf("TARGET-MISS launch links %d packages with the standard library, target < %d (open for TCB-CHECK, "+
			"ADR 0031 note 2026-10-19 on (a))", n, launchDepsTarget)
	} else {
		t.Logf("launch links %d packages with the standard library (target < %d)", n, launchDepsTarget)
	}
}
