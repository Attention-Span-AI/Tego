// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package cli

import (
	"os"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// envTestOwnLogHome is internal/cli's EnvTestOwnLogHome (ownlog_testhook.go there): the home a binary built with
// -tags tegotesthooks keeps its own files under. The dashboard's lock (runlock.HoldDashboard) goes there, and with the
// variable unset a test build holds none, rather than write the developer's own ~/.tego/dashboard. A product build does
// not contain this file; AT_SECURE keeps the product's home.
const envTestOwnLogHome = "TEGO_TEST_OWN_LOG_HOME"

func init() {
	if secure, err := config.DetectSecureExec(); err != nil || secure {
		return
	}
	home := os.Getenv(envTestOwnLogHome)
	dashboardLockHome = func(*config.Machine) string { return home }
}
