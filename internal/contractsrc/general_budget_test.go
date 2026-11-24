// SPDX-License-Identifier: Apache-2.0

package contractsrc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestGeneralGraphBudgetUnknown(t *testing.T) {
	m := config.Builtin()
	m.Home = t.TempDir()
	if err := os.Chmod(m.Home, 0700); err != nil {
		t.Fatal(err)
	}
	m.Profiles.Value = m.Home
	var parents []string
	padding := "#" + strings.Repeat("x", 900<<10) + "\n"
	for i := 0; i < 8; i++ {
		parent := fmt.Sprintf("parent%d", i)
		parents = append(parents, parent)
		var leaves []string
		for j := 0; j < 8; j++ {
			leaf := fmt.Sprintf("leaf%d-%d", i, j)
			leaves = append(leaves, leaf)
			if err := os.WriteFile(filepath.Join(m.Home, leaf+".yaml"), []byte("version: 0\n"+padding), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(m.Home, parent+".yaml"), []byte("version: 0\nextends: ["+strings.Join(leaves, ",")+"]\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	body := "version: 0\nname: shared\ncommand: [true]\nextends: [" + strings.Join(parents, ",") + "]\n"
	g := readGeneral(context.Background(), m, os.Getuid(), SystemPath, func(path string, _ bool, _ int, _ int64) (config.PolicySource, bool, error) {
		return config.PolicySource{Data: []byte(body), Resolved: path}, false, nil
	})
	if g.State != "unknown" || g.Hash != "" || g.Name != "" || len(g.Profiles) != 0 || !strings.Contains(g.Note, "source bytes") {
		t.Fatalf("partial graph shown loaded: %+v", g)
	}
}
