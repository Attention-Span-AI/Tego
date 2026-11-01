// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRouteDocsSayWhatARouteCarries: a route's backend gets the request's headers, so the docs on routes say a key the
// agent holds itself goes there (ADR 0127 §5), and none promises that a key follows an allow list: that is a key
// layer's rule, a tree may have no layer, and the words would be false where a person decides whom to trust.
func TestRouteDocsSayWhatARouteCarries(t *testing.T) {
	for _, doc := range []string{"docs/user/model-routes.md", "docs/DASHBOARD.md", "docs/adr/0127-model-routes.md"} {
		b, err := os.ReadFile(filepath.Join("..", "..", doc))
		if err != nil {
			t.Skipf("no %s here", doc)
		}
		text := strings.Join(strings.Fields(string(b)), " ") // the docs are wrapped
		if !strings.Contains(text, "a key the agent holds itself goes") {
			t.Errorf("%s does not say a key goes with its request", doc)
		}
		for _, promise := range []string{"Keys follow their allow list", "Credentials follow their allow list", "if its allow list names", "where its allow list names"} {
			if strings.Contains(text, promise) {
				t.Errorf("%s promises %q", doc, promise)
			}
		}
	}
}
