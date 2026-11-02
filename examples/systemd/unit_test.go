// SPDX-License-Identifier: Apache-2.0

package systemd

import (
	"bufio"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// unit is a unit file as systemd reads it with no drop-ins: every value assigned to each key of each section, in
// order. A commented line is not a key.
type unit map[string]map[string][]string

// readUnit reads the unit file name in this directory. A line continued with a backslash is refused rather than read
// otherwise than systemd reads it.
func readUnit(t *testing.T, name string) unit {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	u := unit{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			continue
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
			if u[section] == nil {
				u[section] = map[string][]string{}
			}
			continue
		case section == "" || strings.HasSuffix(line, `\`):
			t.Fatalf("%s: %q is outside a section or continues on the next line, which this test does not read", name, line)
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: not a key=value line: %q", name, line)
		}
		k = strings.TrimSpace(k)
		u[section][k] = append(u[section][k], strings.TrimSpace(v))
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return u
}

// value is a setting whose last assignment wins (Type=, TimeoutStopSec=), "" when it has none.
func (u unit) value(section, key string) string {
	vs := u[section][key]
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

// list is a list setting as systemd merges its assignments (SuccessExitStatus=, RestartPreventExitStatus=): each one
// adds its words, and an empty one drops what came before.
func (u unit) list(section, key string) []string {
	var words []string
	for _, v := range u[section][key] {
		if v == "" {
			words = nil
			continue
		}
		words = append(words, strings.Fields(v)...)
	}
	return words
}

// wantOnce fails unless each key is assigned once in the section, to the value given: a second assignment of a list
// key is merged by systemd, not replaced.
func wantOnce(t *testing.T, name string, u unit, section string, want map[string]string) {
	t.Helper()
	for k, v := range want {
		if got := u[section][k]; !slices.Equal(got, []string{v}) {
			t.Errorf("%s: [%s] %s is assigned %q, want %q once", name, section, k, got, v)
		}
	}
}

// TestUnitTemplateExitStatuses is the unit file's golden: the template must not undo a `tego stop` by restarting
// the agent, must count a stop (its own `systemctl stop`, or tego stop) as success rather than leave the unit
// failed, must not restart a run tego refused to start, and must still restart a crash, a limit and a kill by
// memory or pids. The statuses are tego run's own (pkg/spec/identity), so a renumbering there fails here. Each key is
// read as systemd reads it: a second RestartPreventExitStatus= line listing 124 adds to the first, and a limit
// would no longer restart.
func TestUnitTemplateExitStatuses(t *testing.T) {
	const name = "tego-agent@.service"
	u := readUnit(t, name)
	wantOnce(t, name, u, "Service", map[string]string{
		"Type":                     "exec",
		"ExecStart":                "%h/.local/bin/tego run %i",
		"Restart":                  "on-failure",
		"SuccessExitStatus":        strconv.Itoa(identity.ExitStoppedTerm),
		"RestartPreventExitStatus": strconv.Itoa(identity.ExitStoppedTerm) + " " + strconv.Itoa(identity.ExitLauncher),
		"KillMode":                 "mixed",
		"StandardInput":            "null",
	})
	for _, code := range []int{identity.ExitLimit, identity.ExitStoppedKill, 1, 3} {
		for _, k := range []string{"SuccessExitStatus", "RestartPreventExitStatus"} {
			if slices.Contains(u.list("Service", k), strconv.Itoa(code)) {
				t.Errorf("%s lists %d: a crash, a limit or a kill by memory or pids would not be restarted", k, code)
			}
		}
	}
	// systemctl stop must leave tego the machine's stop_grace and time to write run_end before its SIGKILL.
	stop := u.value("Service", "TimeoutStopSec")
	d, err := time.ParseDuration(stop)
	if err != nil || d <= config.DefaultStopGrace {
		t.Errorf("TimeoutStopSec=%q, want a duration above the default stop_grace %s", stop, config.DefaultStopGrace)
	}
}

// TestGCTimerRunsTheRetentionPass: tego-gc.timer starts tego-gc.service once a day and makes up a day missed while the
// user manager was not running (Persistent=true), so a machine where no `tego run` starts for days still gets its
// retention pass. The service runs the agent unit's binary as `gc` with no flags: the machine's retention, and a pass
// that counts as the one a start makes once per gc_interval (with --keep it would be neither). It must read the
// machine config the agents run under, so its TEGO_CONFIG line is the agent unit's.
func TestGCTimerRunsTheRetentionPass(t *testing.T) {
	bin, _, _ := strings.Cut(readUnit(t, "tego-agent@.service").value("Service", "ExecStart"), " ")
	wantOnce(t, "tego-gc.service", readUnit(t, "tego-gc.service"), "Service", map[string]string{
		"Type":      "oneshot",
		"ExecStart": bin + " gc",
	})
	timer := readUnit(t, "tego-gc.timer")
	wantOnce(t, "tego-gc.timer", timer, "Timer", map[string]string{"OnCalendar": "daily", "Persistent": "true"})
	wantOnce(t, "tego-gc.timer", timer, "Install", map[string]string{"WantedBy": "timers.target"})
	if got := timer["Timer"]["Unit"]; got != nil && !slices.Equal(got, []string{"tego-gc.service"}) {
		t.Errorf("tego-gc.timer starts %q, want tego-gc.service", got)
	}
	if a, g := configLine(t, "tego-agent@.service"), configLine(t, "tego-gc.service"); a != g {
		t.Errorf("tego-gc.service's machine config line %q is not the agents' %q: the pass would sweep another ledger "+
			"root by another retention", g, a)
	}
}

// TestPlannedRestartTimer: tego-agent-restart@.timer restarts tego-agent@<name> once a day through `systemctl --user
// try-restart`, which stops the agent's unit as `systemctl --user stop` does and starts it again, and leaves an agent
// that is not running as it is: restart or start would undo a `tego stop --agent` and start a failed unit again. A
// restart missed while the user manager was not running is not made up when it starts (no Persistent=), since the
// agent has just started then. The agent's own unit sets no RuntimeMaxSec=: systemd stops it with SIGTERM at that
// limit, an agent that dies of it ends the run 143, which RestartPreventExitStatus keeps from restarting, and the unit
// is left failed with Result=timeout (systemd 257, these keys), so the agent would stay down.
func TestPlannedRestartTimer(t *testing.T) {
	wantOnce(t, "tego-agent-restart@.service", readUnit(t, "tego-agent-restart@.service"), "Service", map[string]string{
		"Type":      "oneshot",
		"ExecStart": "systemctl --user try-restart tego-agent@%i.service",
	})
	timer := readUnit(t, "tego-agent-restart@.timer")
	wantOnce(t, "tego-agent-restart@.timer", timer, "Install", map[string]string{"WantedBy": "timers.target"})
	if timer.value("Timer", "OnCalendar") == "" {
		t.Error("tego-agent-restart@.timer has no OnCalendar=")
	}
	if p := timer.value("Timer", "Persistent"); systemdTrue(p) {
		t.Errorf("tego-agent-restart@.timer: Persistent=%s restarts an agent that has just started", p)
	}
	if got := timer["Timer"]["Unit"]; got != nil && !slices.Equal(got, []string{"tego-agent-restart@%i.service"}) {
		t.Errorf("tego-agent-restart@.timer starts %q, want tego-agent-restart@%%i.service", got)
	}
	if v := readUnit(t, "tego-agent@.service").value("Service", "RuntimeMaxSec"); v != "" && v != "infinity" {
		t.Errorf("tego-agent@.service: RuntimeMaxSec=%s stops the agent for good, since the run it ends is 143, which "+
			"RestartPreventExitStatus keeps from restarting; a planned restart is tego-agent-restart@.timer's", v)
	}
}

// systemdTrue reports whether systemd reads a boolean setting as true (1, yes, y, true, t or on, in any case).
func systemdTrue(v string) bool {
	switch strings.ToLower(v) {
	case "1", "yes", "y", "true", "t", "on":
		return true
	}
	return false
}

// configLine is the file's one line that sets TEGO_CONFIG, commented or not.
func configLine(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "Environment=TEGO_CONFIG=") {
			found = append(found, strings.TrimSpace(line))
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: %d lines set TEGO_CONFIG, want one: %q", name, len(found), found)
	}
	return found[0]
}
