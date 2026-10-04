// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// An exported spelling-check regexp is useful to callers, but replacing or
// decoding into it must not redefine machine or contract validation.
func TestDecimalRegexpDoesNotRedefineValidation(t *testing.T) {
	for _, mutateObject := range []bool{false, true} {
		t.Run(fmt.Sprintf("mutate-object=%t", mutateObject), func(t *testing.T) {
			original, pattern := config.DecimalRE, config.DecimalRE.String()
			t.Cleanup(func() {
				if err := original.UnmarshalText([]byte(pattern)); err != nil {
					t.Fatal(err)
				}
				config.DecimalRE = original
			})
			if mutateObject {
				if err := config.DecimalRE.UnmarshalText([]byte(".*")); err != nil {
					t.Fatal(err)
				}
			} else {
				config.DecimalRE = regexp.MustCompile(".*")
			}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			for _, key := range []string{"cpu", "cost_usd"} {
				data := []byte(fmt.Sprintf("limits: {%s: \"0x1p3\"}\n", key))
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, _, err := config.LoadSources(config.Sources{User: path}, "", os.Geteuid(), config.TrustAbort); !errors.Is(err, config.ErrInvalid) {
					t.Errorf("machine %s accepted hex float after regexp edit: %v", key, err)
				}
			}
			for _, value := range []string{"1_0", "1.5"} {
				data := []byte(fmt.Sprintf("version: 0\nname: agent\ncommand: [true]\nlimits: {cost_usd: %s}\n", value))
				_, _, err := agent.LoadBytes("agent.yaml", data, nil)
				if (err == nil) != (value == "1.5") {
					t.Errorf("contract cost %s after regexp edit: %v", value, err)
				}
			}
			if err := os.WriteFile(path, []byte("limits: {cpu: 1.5, cost_usd: 1.5}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := config.LoadSources(config.Sources{User: path}, "", os.Geteuid(), config.TrustAbort); err != nil {
				t.Errorf("machine decimal values after regexp edit: %v", err)
			}
		})
	}
}
