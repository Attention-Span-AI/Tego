// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// publicSpecs is the required inventory of public specifications. These documents define rules in prose and
// tables rather than the R/E/I format of the optional component notes. Missing or empty inputs must fail even
// when docs/p0 is not part of the repository; their links, citations and cited tests are checked below as usual.
var publicSpecs = []string{
	"spec/backend/CAPABILITIES.md",
	"spec/config/v0/README.md",
	"spec/identity/RUN-IDENTITY.md",
	"spec/policy/SEMANTICS.md",
	"spec/reason/REASON-CHANNEL.md",
	"spec/record/v1/README.md",
	"spec/record/v1/CHAIN.md",
}

func checkPublicSpecs(root string) error {
	for _, rel := range publicSpecs {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("required public specification %s: %w", rel, err)
		}
		lines := mdLines(string(b))
		body := false
		for _, line := range lines {
			s := strings.TrimSpace(line)
			if s != "" && !strings.HasPrefix(s, "#") && !strings.HasPrefix(s, "<!--") {
				body = true
			}
		}
		if !body {
			return fmt.Errorf("required public specification %s has no specification text", rel)
		}
	}
	return nil
}
