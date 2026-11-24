// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestContractsSourceByteBoundsAreIncomplete(t *testing.T) {
	for _, aggregate := range []bool{false, true} {
		name := "registry batch"
		if aggregate {
			name = "across recorded projects"
		}
		t.Run(name, func(t *testing.T) {
			f, o := fixture(t)
			count := registry.MaxCatalogBytes/agent.MaxContractSize + 1
			other := f.Path("recorded-project")
			for i := 0; i < count; i++ {
				project := f.Root
				if aggregate && i >= count/2 {
					project = other
				}
				entry := fmt.Sprintf("bulk-%02d", i)
				body := strings.Replace(simpleContract, "name: fixture", "name: "+entry, 1)
				// Large valid comments exercise retained source bytes without
				// inventing another contract language or expansion workload.
				body += "#" + strings.Repeat("x", agent.MaxContractSize-len(body)-1)
				write(t, filepath.Join(project, ".tego", "agents", entry+".yaml"), body)
			}
			if aggregate {
				o.Snapshot.Runs = append(o.Snapshot.Runs, run("", other, "", "", "landlock", metadataRunID))
			}
			c := Discover(context.Background(), o)
			bound := false
			for _, d := range c.Issues {
				bound = bound || d.Code == "catalog-byte-bound"
			}
			if len(c.Contracts) != count || !c.Incomplete || !bound || c.ExitCode() != identity.ExitError {
				t.Fatalf("source-byte cut hidden: entries %d, incomplete %t, bound issue %t, exit %d, roots %+v issues %+v", len(c.Contracts), c.Incomplete, bound, c.ExitCode(), c.Roots, c.Issues)
			}
			checked, cut := 0, 0
			for _, e := range c.Contracts {
				switch e.State {
				case "compiles":
					checked++
				case "unreadable":
					cut++
				default:
					t.Errorf("unexpected source state %s: %+v", e.State, e.Diagnostics)
				}
			}
			if checked != count-1 || cut != 1 {
				t.Errorf("expected one explicit source cut: checked %d, cut %d", checked, cut)
			}
		})
	}
}
