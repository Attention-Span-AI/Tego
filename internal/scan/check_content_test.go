// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/scan/result"
)

func TestConfiguredUncertaintyDoesNotDecideProcessCheck(t *testing.T) {
	for _, tc := range []struct{ name, path, content, kind string }{
		{"settings", ".claude.json", `{broken`, "D"},
		{"unit-syntax", ".config/systemd/user/broken.service", "[Service]\nExecStart=codex \"unterminated\n", "E"},
		{"stock-launcher", ".config/systemd/user/ordinary.service", "[Service]\nExecStart=/bin/sh -c /usr/bin/ibus-daemon\n", "E"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := commandOptions(t)
			if err := os.RemoveAll(filepath.Join(o.ProcRoot, "20")); err != nil {
				t.Fatal(err)
			}
			o.Check = true
			writeSettings(t, o.Directory, tc.path, []byte(tc.content))
			s := Collect(t.Context(), o).Snapshot
			failed := false
			for _, source := range s.Sources {
				failed = failed || source.Kind == tc.kind && source.State == "not-read" && source.NotRead == 1
			}
			if !failed || s.Status != "partial" || s.Check != "none-observed" || s.ExitCode() != 0 {
				t.Fatalf("configured uncertainty changed completed process check: %+v", s)
			}
			wire, err := result.Encode(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = result.Decode(wire); err != nil {
				t.Fatal(err)
			}
		})
	}
}
