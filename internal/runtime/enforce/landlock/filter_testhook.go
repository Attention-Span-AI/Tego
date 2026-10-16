// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package landlock

import (
	"os"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestFilterOmit names syscalls, comma-separated by their table names (bpf, add_key, request_key, keyctl, ...), that
// a binary built with -tags tegotesthooks leaves out of the seccomp filter's notify arm and root-tier arm
// (filterTestOmit). A root test sets it to reach the decision plane's `bpf` and `key_permission` hooks from a governed
// run, which the filter's own arms answer first in a product run. A product build does not contain this file; a test
// build ignores it under AT_SECURE, like every TEGO_TEST_ variable.
const EnvTestFilterOmit = "TEGO_TEST_FILTER_OMIT"

func init() {
	// Never under AT_SECURE, where no environment variable may steer the capability-bearing binary
	// (identity-config.md R21).
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	if v := os.Getenv(EnvTestFilterOmit); v != "" {
		filterTestOmit = omitNamed(v)
	}
}

// omitNamed is the seam over a comma-separated list of table names. A name the tables do not have omits nothing.
func omitNamed(list string) func(string) bool {
	names := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names[n] = true
		}
	}
	return func(name string) bool { return names[name] }
}
