// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// The retention pass runs at a `tego run` start (retainBeforeRun), so a machine with no start for days, or an agent that
// runs for weeks, made none (a documented gap). Where tego already starts a user unit, `tego start` and `tego dashboard`
// (guideDashboard starts tego-dashboard with systemd-run --user) also start a transient user timer, tego-gc, that
// runs `tego gc` once a day (OnCalendar=daily, Persistent=true makes up a day missed while the user manager was off):
// examples/systemd/tego-gc.timer without the hand installation. `tego gc` with no flags is the start's pass, with
// the machine's own retention, so it removes what retention removes and never a run whose lock is held.
//
// Only with gc_interval set: a machine that leaves it at 0 chose to remove nothing unless asked. A timer that is
// already active is left alone, so the person's own copy of examples/systemd/tego-gc.timer (or one made earlier) is
// never replaced; it keeps the program and TEGO_CONFIG it was made with.
const retentionTimerUnit = "tego-gc"

// retentionTimerArgv is the systemd-run call that makes the transient timer: self the program that runs `gc`,
// configFile the TEGO_CONFIG the dashboard unit runs under ("" none). "" self, or a path that systemd would expand
// ($, %), makes none.
func retentionTimerArgv(self, configFile string) []string {
	if self == "" || strings.ContainsAny(self, "$%") {
		return nil
	}
	// self is the running program's path as os.Executable gives it, without selfbin.Named's installation check, on
	// purpose (ADR 0142, amendment 2026-11-18, same-user producers): a transient timer of the person's own service
	// manager runs `gc` as that person with no added authority, as the dashboard's unit does. A unit root or another
	// account runs would be privileged and take the checked path.
	args := []string{"--user", "--unit=" + retentionTimerUnit, "--quiet", "--on-calendar=daily",
		"--timer-property=Persistent=true", "--property=Type=oneshot"}
	if configFile != "" {
		args = append(args, "--setenv="+config.EnvConfigVar+"="+configFile)
	}
	return append(args, self, "gc")
}

// ensureRetentionTimer makes the retention timer once for a machine with gc_interval set. run starts one program
// and returns its output: systemctl is-active tells an existing timer (exit 0), systemd-run makes the new one. It
// reports whether it made one; a failure is in tego's own log and never stops the caller.
func ensureRetentionTimer(ctx context.Context, m *config.Machine, self, configFile string,
	run func(ctx context.Context, argv ...string) ([]byte, error)) bool {
	if m == nil || m.GCInterval.Value <= 0 {
		return false
	}
	args := retentionTimerArgv(self, configFile)
	if args == nil {
		return false
	}
	if _, err := run(ctx, "systemctl", "--user", "is-active", "--quiet", retentionTimerUnit+".timer"); err == nil {
		return false
	}
	if _, err := run(ctx, append([]string{"systemd-run"}, args...)...); err != nil {
		logOwn("retention: the daily timer was not made: " + err.Error())
		return false
	}
	return true
}

// guideRetentionTimer is ensureRetentionTimer for this tego and the configuration the dashboard unit runs under. A
// variable so a test starts no unit.
var guideRetentionTimer = func(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil || !m.BaselineKnown() {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	_, file, _, err := dashboardConfiguration()
	if err != nil {
		return
	}
	ensureRetentionTimer(ctx, m, self, file, func(ctx context.Context, argv ...string) ([]byte, error) {
		var out bytes.Buffer
		c := proc.Command(argv[0], argv[1:]...)
		c.Stdout = &out
		err := runGuideCommand(ctx, c)
		return out.Bytes(), err
	})
}
