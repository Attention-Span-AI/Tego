// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestMain gives every test of this package a makeUndumpable that does nothing: the test binary is one process that
// runs every command in turn (TestProductionGeneralControlDispatch dispatches each one through mainWith), and a
// command that made it undumpable would leave it so for every test after. undumpable_test.go's tests give it their own
// recorder, and the integration test of the real dashboard (internal/control/web/e2e) runs the real hold in a real
// tego-control.
func TestMain(m *testing.M) {
	makeUndumpable = func() error { return nil }
	// No test of this package holds the dashboard's lock in the developer's own ~/.tego unless it names a home itself.
	dashboardLockHome = func(*config.Machine) string { return "" }
	os.Exit(m.Run())
}
