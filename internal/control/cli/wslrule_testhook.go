// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"os"

	"github.com/attention-span-ai/tego/internal/platform/peer"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// envTestWSLRule is internal/cli's EnvTestWSLRule (wslrule_testhook.go there): a tego-control built with
// -tags tegotesthooks uses the run-membership rule on WSL when the variable is exactly "on", as the tego test build
// does, so the two binaries of one guest proof judge alike. A product build does not contain this file; a test build
// ignores the variable under AT_SECURE and when AT_SECURE cannot be read.
const envTestWSLRule = "TEGO_TEST_WSL_RULE"

// envTestNestedRule is internal/cli's EnvTestNestedRule: the rule's use outside WSL beyond the first cgroup
// namespace, in a test build only, when the variable is exactly "on".
const envTestNestedRule = "TEGO_TEST_NESTED_RULE"

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	peer.SetWSLRuleForTest(os.Getenv(envTestWSLRule) == "on")
	peer.SetNestedRuleForTest(os.Getenv(envTestNestedRule) == "on")
}
