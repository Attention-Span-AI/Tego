// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func allText(ds []Diagnostic, err error) string {
	var b strings.Builder
	if err != nil {
		b.WriteString(err.Error() + "\n")
	}
	for _, d := range ds {
		b.WriteString(d.Message + " " + d.Fix + "\n")
	}
	return b.String()
}

// TestCompileNeverPrintsAnUnplacedConfigValue (G1): the compile error of an UNKNOWN baseline and the R10 findings about
// the layer file name a $TEGO_CONFIG value that is not a place as the variable, whatever its spelling.
func TestCompileNeverPrintsAnUnplacedConfigValue(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	odd := filepath.Join(dir, "qzmark\nx")
	if err := os.Mkdir(odd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(odd, "c.yaml"), []byte("stop_grace: 3s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "qzmark-y"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "d.yaml"), []byte("stop_grace: 3s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"qzmark/c.yaml", filepath.Join(dir, "qzmark-gone") + "/../c.yaml", odd + "/c.yaml", dir + "/qzmark-y/../d.yaml"} {
		machine, _, err := config.LoadSources(config.Sources{EnvFile: value}, dir, os.Getuid(), config.TrustWarn)
		if err != nil || machine == nil {
			t.Fatalf("%q: %v", value, err)
		}
		f := newFixture(t)
		// The write entry covers the layer file: R10 names it (the machine config) in its refusal.
		contract := f.load("version: 0\nname: layer-cover\ncommand: [python]\nfs:\n  write: [" + quoteYAML(dir) + "]\n")
		_, ds, cerr := Compile(contract, machine, f.opts()...)
		if got := allText(ds, cerr); strings.Contains(got, "qzmark") {
			t.Errorf("value %q: the compile prints it: %s", value, got)
		}
	}
}
