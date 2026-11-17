// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func guideHandoffRoutes() []guidePTYRoute {
	steps := []guidePTYStep{
		{"Which agent do you want to supervise?", "\r"},
		{"How do you want to log in to Claude Code?", "\r"},
		{"[handoff-ready]", "/SECOND_SECRET\r"},
		{"Paste the token Claude Code printed", "test-token\r"},
		{"Save the login for later sessions?", "\x1b[B\r"},
		{"Which project should Claude Code work in?", ""},
	}
	return []guidePTYRoute{{"handoff-secret", steps}, {"handoff-interrupt", steps}}
}

// Model a sign-in returning with raw/no-echo modes and pending input, using
// the helper's real controlling terminal. The inherited gate makes the bytes
// arrive while the guide's reader is paused, before its restart boundary.
func guideHandoffToken(t *testing.T) (string, error) {
	t.Helper()
	modes, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return "", err
	}
	modes.Lflag &^= unix.ISIG | unix.ICANON | unix.ECHO
	modes.Cc[unix.VMIN], modes.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(0, unix.TCSETS, modes); err != nil {
		return "", err
	}
	fmt.Print("[handoff-ready]")
	gate := os.NewFile(3, "handoff-gate")
	defer func() { _ = gate.Close() }()
	var ack [1]byte
	_, err = io.ReadFull(gate, ack[:])
	return "", err
}

func TestGuideHandoffBoundary(t *testing.T) {
	for _, route := range guideHandoffRoutes() {
		t.Run(route.name, func(t *testing.T) {
			t.Parallel()
			target := len(route.steps) - 1
			if route.name == "handoff-interrupt" {
				target = 2
			}
			runGuidePTY(t, route, target, "key", false)
		})
	}
}
