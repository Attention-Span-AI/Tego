// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestNoShippedContractSetsHostSockets (ADR 0070 (7)): no contract or profile under examples/ sets host_sockets, the
// opt-out that restores every unix socket on the host to a run with no net: section. A starting point a user copies
// must not teach the blanket opt-out: a contract that needs one socket (an SSH or gpg agent) names it in a net:
// section's unix: entry instead. The file is read as YAML, so a spelling the loader accepts is caught too.
func TestNoShippedContractSetsHostSockets(t *testing.T) {
	root := filepath.Dir(pkgDir) // examples/
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		var doc any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		n++
		if m, ok := doc.(map[string]any); ok {
			if v, set := m["host_sockets"]; set {
				t.Errorf("examples/%s sets host_sockets: %v; name the one socket the agent needs in a net: section's unix: entry instead (ADR 0070)",
					rel, v)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no YAML under examples/")
	}
}
