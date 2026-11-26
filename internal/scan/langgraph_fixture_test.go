// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestLangGraphExampleRequirementsAreRead holds the requirements file of the LangGraph example's test agent
// (test/workloads/langgraph) to what `tego scan` can read: a requirements.txt with hashes or continuations is refused
// whole, and the file is the one the example's guest row scans to see the project named LangGraph (dep-langgraph).
func TestLangGraphExampleRequirementsAreRead(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "workloads", "langgraph", "requirements.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseRequirements(t.Context(), bytes.NewReader(b))
	if err != nil {
		t.Fatalf("the example's requirements.txt is not read by the scan: %v", err)
	}
	ids := []string{}
	for _, d := range got {
		ids = append(ids, d.ID)
	}
	if len(ids) != 1 || ids[0] != "dep-langgraph" {
		t.Errorf("the scan reads %v from the example's requirements.txt, want [dep-langgraph]", ids)
	}
}
