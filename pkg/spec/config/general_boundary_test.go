// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package config

import (
	"strings"
	"testing"
)

func TestProductionConfigHasNoGeneralSelector(t *testing.T) {
	for _, key := range []string{"general", "managed", "general_contract"} {
		_, ds := parseLayer("config.yaml", []byte(key+": /elsewhere/general.yaml\n"))
		if len(ds) == 0 {
			t.Fatalf("production schema accepts selector %s", key)
		}
		found := false
		for _, d := range ds {
			if d.Severity == SeverityError && strings.Contains(d.Message, key) {
				found = true
			}
		}
		if !found {
			t.Fatalf("selector %s not named in diagnostics: %v", key, ds)
		}
	}
}
