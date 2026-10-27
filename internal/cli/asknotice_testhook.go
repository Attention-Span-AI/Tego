// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"errors"
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// EnvTestNotifySend names the desktop notifier of a binary built with -tags tegotesthooks: a stand-in the test
// wrote, run without trustedExecutable's ownership check (a test's file is its own, not root's). A test build fails
// closed on it as on its anchor: with the variable unset it has no notifier at all, so a test that drives `tego run`
// over a contract that asks never shows a notice on the developer's own desktop (the session bus its environment
// names). Ignored under AT_SECURE, where no environment variable may choose a program the launcher starts.
const EnvTestNotifySend = "TEGO_TEST_NOTIFY_SEND"

// errTestNotifierUnset is a test build's answer when EnvTestNotifySend is not set.
var errTestNotifierUnset = errors.New("this binary is built with tegotesthooks and " + EnvTestNotifySend +
	" is not set: a test build never runs the desktop's own notifier")

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	stub := os.Getenv(EnvTestNotifySend)
	notifierPath = func(string) (string, error) {
		if stub == "" {
			return "", errTestNotifierUnset
		}
		return stub, nil
	}
}
