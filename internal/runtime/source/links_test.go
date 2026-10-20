// SPDX-License-Identifier: Apache-2.0

// The link-closure tests run go list, so they stay out of the integration binaries: root-suites.sh runs those in a
// KVM guest with no Go toolchain, where go-shim.sh serves only the prebuilt helpers and fails any other go command.

//go:build !integration

package source

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// TestSourceLinksNoInternal holds the leaf's whole link closure, on both architectures and with and without the
// tegobpf tag, free of internal/: depguard source-is-a-leaf sees only this package's own imports, and a pkg/spec
// or pkg/policy package that came to import internal/ would otherwise carry that link into every capture source.
func TestSourceLinksNoInternal(t *testing.T) {
	const self = "github.com/attention-span-ai/tego/internal/runtime/source"
	for _, goarch := range []string{"amd64", "arm64"} {
		for _, tags := range []string{"", "tegobpf"} {
			cmd := exec.Command("go", "list", "-deps", "-tags="+tags, ".")
			cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps (GOARCH=%s tags=%q): %v", goarch, tags, err)
			}
			var bad []string
			found := false
			for _, p := range strings.Fields(string(out)) {
				switch {
				case p == self:
					found = true
				case strings.HasPrefix(p, "github.com/attention-span-ai/tego/internal/"):
					bad = append(bad, p)
				}
			}
			if !found {
				t.Fatalf("go list -deps (GOARCH=%s tags=%q) did not list %s itself", goarch, tags, self)
			}
			sort.Strings(bad)
			if len(bad) > 0 {
				t.Errorf("internal/runtime/source links %d internal packages (GOARCH=%s tags=%q): %s",
					len(bad), goarch, tags, strings.Join(bad, " "))
			}
		}
	}
}
