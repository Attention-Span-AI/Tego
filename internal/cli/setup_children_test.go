// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guideChildRoutes() []guidePTYRoute {
	ordinary := guidePTYRoutes()[0]
	var routes []guidePTYRoute
	for _, stage := range []string{"version", "systemctl", "systemd-help", "systemd-run", "dashboard-poll", "stty", "installer"} {
		steps := append([]guidePTYStep(nil), ordinary.steps...)
		if stage == "version" {
			steps = steps[:1]
		}
		if stage == "installer" {
			steps = []guidePTYStep{ordinary.steps[0], {"Install Claude Code now?", "\r"}}
		}
		if stage == "stty" {
			steps = []guidePTYStep{ordinary.steps[0], {"How do you want to log in to Claude Code?", "\r"}}
		}
		prompt := "[child-" + stage + "-ready]"
		if stage == "stty" {
			prompt = "Paste the token Claude Code printed"
		}
		steps = append(steps, guidePTYStep{prompt, ""})
		routes = append(routes, guidePTYRoute{"child-" + stage, steps})
	}
	return routes
}

func TestGuideChildrenStop(t *testing.T) {
	for _, route := range guideChildRoutes() {
		for _, how := range []string{"key", "signal", "term", "hup"} {
			t.Run(route.name+"/"+how, func(t *testing.T) { t.Parallel(); runGuidePTY(t, route, len(route.steps)-1, how, false) })
		}
	}
}

func prepareGuideChild(t *testing.T, route string) {
	t.Helper()
	stage := strings.TrimPrefix(route, "child-")
	bin := t.TempDir()
	// All commands are local stand-ins. /dev/tty reports readiness even when a
	// version probe captures stdout or a service redirects it to its log.
	ready := "echo $$ > \"$TEGO_TEST_GUIDE_CHILD_PID\"\nprintf '[child-" + stage + "-ready]' > /dev/tty\n"
	sleeper := "trap '' INT TERM HUP\nsleep 300 &\necho $$ $! > \"$TEGO_TEST_GUIDE_CHILD_PID\"\nprintf '[child-" + stage + "-ready]' > /dev/tty\nwait\n"
	write := func(name, text string) string {
		path := filepath.Join(bin, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+text), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	look := guideLookPath
	if stage == "version" || stage == "stty" {
		program := write("claude", map[bool]string{true: sleeper, false: "exit 0\n"}[stage == "version"])
		guideLookPath = func(name string) (string, error) {
			if name == "claude" {
				return program, nil
			}
			if name == "script" {
				return "", os.ErrNotExist
			}
			return look(name)
		}
	}
	if stage == "stty" {
		write("stty", sleeper)
		_ = os.Unsetenv("CLAUDE_CODE_OAUTH_TOKEN")
	}
	if stage == "installer" {
		program := write("installer", sleeper)
		agents := guideAgents
		guideAgents = append([]guideAgent(nil), agents...)
		guideAgents[0].install = "exec " + program
		t.Cleanup(func() { guideAgents = agents })
		guideLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	}
	if strings.HasPrefix(stage, "system") || stage == "dashboard-poll" {
		write("systemctl", map[bool]string{true: sleeper, false: "echo stop >> \"$TEGO_TEST_GUIDE_STOP_CALLS\"\nexit 0\n"}[stage == "systemctl"])
		help := "exit 0\n"
		if stage == "systemd-help" {
			help = sleeper
		}
		command := sleeper
		if stage == "dashboard-poll" {
			command = ready + "exit 0\n"
		}
		write("systemd-run", "if [ \"$1\" = --help ]; then\n"+help+"fi\n"+command)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
}

// Keep the real cancellation functions for the child routes; prompt-only
// routes replace these functions to prove they never start external work.
var realGuideChildLogin = guideSetupToken
var realGuideChildDashboard = guideDashboard
var realGuideChildInstall = guideInstall

func guideChildActions(route string) {
	guideDashboard = realGuideChildDashboard
	guideInstall = realGuideChildInstall
	if route == "child-stty" {
		guideSetupToken = realGuideChildLogin
	}
}
