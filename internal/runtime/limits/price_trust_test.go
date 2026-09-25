// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// trustedCopy copies testdata/name into a directory of its own that the machine config's trust rule accepts
// (owned by this uid, neither it nor the file group- or other-writable, whatever the umask), and returns its
// path.
func trustedCopy(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestFromMachineTrustRule: the price table a machine config names outside ~/.tego follows the config trust
// rule (limits-check-doctor-cli.md §3), as the layers do: a table others may rewrite is not read, since whoever
// can edit it can price every model at $0 and turn every cost budget off. It is refused like an unreadable
// table, a warning and no prices, never a failed run.
func TestFromMachineTrustRule(t *testing.T) {
	machine := func(path string) *config.Machine {
		m := config.Builtin()
		m.Prices = config.Setting[string]{Value: path}
		return m
	}
	good := trustedCopy(t, "prices.yaml")
	if tab, warn := FromMachine(machine(good)); tab == nil || warn != nil {
		t.Fatalf("a trusted table: %v, %+v", tab, warn)
	}

	fileWritable := trustedCopy(t, "prices.yaml")
	if err := os.Chmod(fileWritable, 0o666); err != nil {
		t.Fatal(err)
	}
	dirWritable := trustedCopy(t, "prices.yaml")
	if err := os.Chmod(filepath.Dir(dirWritable), 0o777); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"a world-writable table": fileWritable, "a table in a world-writable directory": dirWritable} {
		t.Run(name, func(t *testing.T) {
			tab, warn := FromMachine(machine(p))
			if tab != nil {
				t.Fatalf("an untrusted table was loaded: %+v", tab)
			}
			if warn == nil || warn.Why != GapNoPriceTable || !strings.Contains(warn.Message, "writable") {
				t.Fatalf("warning %+v, want a no-price-table warning naming the writable file or directory", warn)
			}
		})
	}
}
