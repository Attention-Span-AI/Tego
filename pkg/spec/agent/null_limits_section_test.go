// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNullLimitsSectionIsRefused: a `limits:` section that is null (`limits: ~`, or every key under it commented out)
// parsed as absent, every limit unbounded, one level above the null-limit-key fix; `extends:` with no value parsed as
// no profile the same way.
func TestNullLimitsSectionIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"limits-null":  "version: 0\nname: x\ncommand: [\"true\"]\nlimits:\n#  memory: 2G\n",
		"limits-tilde": "version: 0\nname: x\ncommand: [\"true\"]\nlimits: ~\n",
		"profile-null": "version: 0\nname: x\ncommand: [\"true\"]\nextends:\n",
	} {
		p := filepath.Join(t.TempDir(), name+".yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		c, ds, err := Load(p, testProfiles())
		if err == nil {
			t.Errorf("%s: loaded (limits=%+v), diagnostics %v; want a schema error", name, c.Limits, ds)
		}
	}
}
