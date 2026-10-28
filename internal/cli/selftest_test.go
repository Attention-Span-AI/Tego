// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestSelftestRefusesAnUntrustedConfigLayer: `tego test` with a $TEGO_CONFIG layer tego run refuses (a world-writable
// file) exits 125 with tego run's [config-untrusted] sentence and its fix, before any check runs, rather than copy
// the layer into its tree and report a pass on settings tego run would never load.
func TestSelftestRefusesAnUntrustedConfigLayer(t *testing.T) {
	dir := t.TempDir()
	layer := filepath.Join(dir, "tego.yaml")
	if err := os.WriteFile(layer, []byte("gc_interval: 1h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(layer, 0o666); err != nil { // the umask narrows WriteFile's mode
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", layer)
	t.Setenv("TMPDIR", tmp)
	code, stdout, stderr := run(t, "test")
	if code != identity.ExitConfig {
		t.Errorf("exit %d, want %d", code, identity.ExitConfig)
	}
	for _, want := range []string{"tego test: machine config untrusted: " + layer, "[" + identity.CodeConfigUntrusted + "]", "chmod g-w,o-w"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if stdout != "" {
		t.Errorf("printed a report: %q", stdout)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("the temporary tree was left behind: %v", left)
	}
}
