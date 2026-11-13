// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestCompileKeepsOwnerDirectoryProtectionWithAnotherAnchor(t *testing.T) {
	for _, link := range []string{"loop", "root"} {
		t.Run(link, func(t *testing.T) {
			f := newFixture(t)
			own := filepath.Join(f.home, ".tego")
			to := own
			if link == "root" {
				to = "/"
			}
			if err := os.Symlink(to, own); err != nil {
				t.Fatal(err)
			}
			machine := *f.machine
			machine.LedgerRoot = config.Setting[string]{Value: filepath.Join(f.root, "runs")}
			for _, kind := range []string{"write", "ask"} {
				c := f.load(strings.Replace(writeSection("./out"), "write:", kind+":", 1))
				_, ds, err := Compile(c, &machine, f.opts(WithMountInfo(""), WithChainAnchor(filepath.Join(f.root, "anchor", "chain.log")))...)
				if err == nil || !strings.Contains(render(ds), "owner's tego directory") {
					t.Errorf("%s owner directory with alternate anchor admitted %s grant:\n%s", link, kind, render(ds))
				}
			}
		})
	}
}
