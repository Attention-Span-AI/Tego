// SPDX-License-Identifier: Apache-2.0

package container

import (
	"os"
	"strings"
	"testing"
)

// TestContainerGuideQuotesTheRefusalTheProductPrints (N123): on Docker's defaults the cgroup mount is read-only and
// `tego run` refuses before it starts the agent. A guest run printed
// "no enforcement tier available on this machine [tier-unavailable] missing for landlock: cgroupv2: cgroup: no
// delegated cgroup v2 subtree for uid ...", not "runtime: cgroup: ...", which the guide had quoted. Each fragment the
// guide quotes must be one the code still holds, and the old quote must stay out.
func TestContainerGuideQuotesTheRefusalTheProductPrints(t *testing.T) {
	guide := readText(t, "../../docs/user/container.md")
	for _, q := range []struct{ quote, file, holds string }{
		{"no enforcement tier available on this machine", "../../pkg/spec/backend/select.go", "no enforcement tier available on this machine"},
		{"[tier-unavailable]", "../../pkg/spec/backend/select.go", `"tier-unavailable"`},
		{"missing for landlock: cgroupv2:", "../../internal/doctor/report.go", "missing for %s: %s"},
		{"no delegated cgroup v2 subtree", "../../internal/runtime/cgroup/errors.go", "no delegated cgroup v2 subtree"},
		{"enable systemd user delegation", "../../internal/runtime/cgroup/detect.go", "enable systemd user delegation"},
		{"tego-entrypoint: no delegated cgroup subtree:", "tego-entrypoint.sh", `say "no delegated cgroup subtree: $why"`},
		{"/sys/fs/cgroup is read-only and could not be remounted read-write", "tego-entrypoint.sh", "is read-only and could not be remounted read-write"},
	} {
		if !strings.Contains(guide, q.quote) {
			t.Errorf("docs/user/container.md no longer quotes %q", q.quote)
		}
		if src := readText(t, q.file); !strings.Contains(src, q.holds) {
			t.Errorf("the guide quotes %q but %s no longer holds %q", q.quote, q.file, q.holds)
		}
	}
	if strings.Contains(guide, "`tego run` refuses with `runtime: cgroup") {
		t.Error("docs/user/container.md says `tego run` refuses with `runtime: cgroup: ...`, which Docker's defaults do not print")
	}
}

// TestInstallContainerSectionVerifiesTheRecord (N123): the install guide's container section ends with a step that
// reads and checks the run's record from a fresh container, with the user and the two volumes it needs.
func TestInstallContainerSectionVerifiesTheRecord(t *testing.T) {
	// The private tree keeps the public install guide as an overlay; the public tree has it at docs/INSTALL.md.
	b, err := os.ReadFile("../../tools/oss/testdata/overlay/docs/INSTALL.md")
	if err != nil {
		b, err = os.ReadFile("../../docs/INSTALL.md")
	}
	if err != nil {
		t.Skipf("no install guide in this tree: %v", err)
	}
	s := string(b)
	i := strings.Index(s, "## Run in a container")
	j := strings.Index(s, "## Build from source")
	if i < 0 || j < i {
		t.Fatal("the install guide has no container section before its build section")
	}
	sec := s[i:j]
	for _, want := range []string{
		"--user 10001:10001", "-v tego-state:/home/tego/.tego", "-v tego-ledger:/var/lib/tego/runs", `tego events "$run" --verify`,
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("the install guide's container section lacks %q", want)
		}
	}
}

func readText(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
