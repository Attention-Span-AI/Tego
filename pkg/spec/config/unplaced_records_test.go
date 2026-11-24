// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// everyText is each string a load of an unplaced $TEGO_CONFIG value leaves where a caller can print it: the error, the
// diagnostics, the layer sources (file and reason), the digest table's keys and the provenance of a setting.
func everyText(m *Machine, ds []Diagnostic, err error) string {
	var b strings.Builder
	if err != nil {
		b.WriteString(err.Error() + "\n")
		var ue *UntrustedError
		if errors.As(err, &ue) {
			b.WriteString(ue.Error() + " " + ue.Fix() + "\n")
		}
	}
	for _, d := range ds {
		b.WriteString(d.String() + " " + d.Fix + "\n")
	}
	if m != nil {
		for _, s := range m.LayerSources() {
			b.WriteString(s.File + " " + s.Reason + "\n")
		}
		for k := range m.SourceDigests {
			b.WriteString(k + "\n")
		}
		b.WriteString(m.StopGrace.Source.File + "\n")
	}
	return b.String()
}

// TestUnplacedConfigValueReachesNoRecord (G1): the layer's source record, the digest table and every other exported
// field name an unplaced $TEGO_CONFIG value as the variable, for a newline, a "..", a relative value and a /proc one,
// whatever the file is.
func TestUnplacedConfigValueReachesNoRecord(t *testing.T) {
	dir := trustedDir(t)
	odd := filepath.Join(dir, "qzmark\nb")
	for _, d := range []string{filepath.Join(dir, "qzmark-x"), odd} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]struct {
		content string
		mode    os.FileMode
	}{"absent": {}, "untrusted": {"version: 0\n", 0o666}, "malformed": {"stop_grace: [\n", 0o600}, "present": {"stop_grace: 3s\n", 0o600}}
	for name, f := range files {
		file := "qzmark-" + name + ".yaml"
		if f.mode != 0 {
			writeFile(t, dir, file, f.content, f.mode)
			writeFile(t, odd, file, f.content, f.mode)
		}
		for _, value := range []string{dir + "/qzmark-x/../" + file, odd + "/" + file, "qzmark/" + file, "/proc/self/../self/cwd/" + file} {
			for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
				m, ds, err := LoadSources(Sources{EnvFile: value}, "", os.Getuid(), mode)
				if got := everyText(m, ds, err); strings.Contains(got, "qzmark") {
					t.Errorf("%s, value %q, mode %v: the value is printed: %q", name, value, mode, got)
				}
			}
		}
	}
}

// TestUnplacedConfigValueHidesFoldersOnTheWay (G2): a folder on the way to the file that fails the trust check, or an
// error of the identity probe naming one, is a prefix of the value and is described, never printed.
func TestUnplacedConfigValueHidesFoldersOnTheWay(t *testing.T) {
	dir := trustedDir(t)
	odd := filepath.Join(dir, "qzmark\nzz")
	if err := os.Mkdir(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, odd, "c.yaml", "version: 0\n", 0o600)
	if err := os.Chmod(odd, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
		m, ds, err := LoadSources(Sources{EnvFile: odd + "/c.yaml"}, "", os.Getuid(), mode)
		got := everyText(m, ds, err)
		if strings.Contains(got, "qzmark") {
			t.Errorf("mode %v: a folder of the value is printed: %q", mode, got)
		}
		if !strings.Contains(got, folderOnTheWay) {
			t.Errorf("mode %v: the folder is not described: %q", mode, got)
		}
	}
	// A missing target beneath a ".." (the identity probe's error carries the folder it could not look at).
	value := filepath.Join(dir, "qzmark-gone") + "/../c.yaml"
	for _, mode := range []TrustMode{TrustAbort, TrustWarn} {
		m, ds, err := LoadSources(Sources{EnvFile: value}, "", os.Getuid(), mode)
		if got := everyText(m, ds, err); strings.Contains(got, "qzmark") {
			t.Errorf("mode %v: a folder of the value is printed: %q", mode, got)
		}
	}
}
