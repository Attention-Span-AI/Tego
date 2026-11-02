// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package selftest

import (
	"fmt"
	"os"
	"text/template"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestContract names a contract template that a binary built with -tags tegotesthooks fills, with the data the
// embedded contract.yaml.tmpl gets (writeContract), and runs every check under in its place. The integration test
// hands it the embedded contract with one line changed, so the built binary's `tego test` has a check to report
// `allowed` or `unrecorded` and exits 1: the verdict a product build gives only where this machine's enforcement or
// its record fails. Only the contract tego test hands to `tego run` changes; the engine and `tego run` stay the
// product's, as in the conformance suite's self-test (test/conformance), so no decision is forced open anywhere.
//
// A product build does not contain this file, so its tego test always runs the embedded contract. A test build
// ignores the variable under AT_SECURE, like every TEGO_TEST_ variable (identity-config.md R27). A template that
// cannot be read or filled fails tego test (exit 125), never falls back to the embedded contract.
const EnvTestContract = "TEGO_TEST_SELFTEST_CONTRACT"

func init() {
	p := os.Getenv(EnvTestContract)
	if p == "" {
		return
	}
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	testContract = func() (*template.Template, error) { return readContractTemplate(p) }
}

// readContractTemplate parses the template at p with missingkey=error: a name writeContract's data does not hold
// fails the fill instead of writing "<no value>" into the contract.
func readContractTemplate(p string) (*template.Template, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvTestContract, err)
	}
	tmpl, err := template.New("contract").Option("missingkey=error").Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", EnvTestContract, err)
	}
	return tmpl, nil
}
