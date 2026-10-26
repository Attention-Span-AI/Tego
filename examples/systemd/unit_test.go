// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// serviceKeys reads the [Service] and [Unit] keys of the template, last assignment winning, as systemd reads a
// unit file with no drop-ins; a commented line is not a key.
func serviceKeys(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("tego-agent@.service")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	keys := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("not a key=value line: %q", line)
		}
		keys[k] = v
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return keys
}

// TestUnitTemplateExitStatuses is the unit file's golden: the template must not undo a `tego stop` by restarting
// the agent, must count a stop (its own `systemctl stop`, or tego stop) as success rather than leave the unit
// failed, must not restart a run tego refused to start, and must still restart a crash, a limit and a kill by
// memory or pids. The statuses are tego run's own (pkg/spec/identity), so a renumbering there fails here.
func TestUnitTemplateExitStatuses(t *testing.T) {
	keys := serviceKeys(t)
	want := map[string]string{
		"Type":                     "exec",
		"ExecStart":                "%h/.local/bin/tego run %i",
		"Restart":                  "on-failure",
		"SuccessExitStatus":        strconv.Itoa(identity.ExitStoppedTerm),
		"RestartPreventExitStatus": strconv.Itoa(identity.ExitStoppedTerm) + " " + strconv.Itoa(identity.ExitLauncher),
		"KillMode":                 "mixed",
		"StandardInput":            "null",
	}
	for k, v := range want {
		if keys[k] != v {
			t.Errorf("%s=%q, want %q", k, keys[k], v)
		}
	}
	for _, code := range []int{identity.ExitLimit, identity.ExitStoppedKill, 1, 3} {
		c := strconv.Itoa(code)
		for _, k := range []string{"SuccessExitStatus", "RestartPreventExitStatus"} {
			for _, f := range strings.Fields(keys[k]) {
				if f == c {
					t.Errorf("%s lists %d: a crash, a limit or a kill by memory or pids would not be restarted", k, code)
				}
			}
		}
	}
	// systemctl stop must leave tego the machine's stop_grace and time to write run_end before its SIGKILL.
	d, err := time.ParseDuration(keys["TimeoutStopSec"])
	if err != nil || d <= config.DefaultStopGrace {
		t.Errorf("TimeoutStopSec=%q, want a duration above the default stop_grace %s", keys["TimeoutStopSec"], config.DefaultStopGrace)
	}
}
