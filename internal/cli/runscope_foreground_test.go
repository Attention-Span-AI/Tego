// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// Even with pipe stdin, /dev/tty identifies a foreground job. A detached process has no controlling tty.
func TestScopeForegroundCheckIgnoresPipedStdin(t *testing.T) {
	for _, term := range []bool{false, true} {
		name := "detached"
		mode := "foreground-false"
		if term {
			name = "terminal with piped stdin"
			mode = "foreground-true"
		}
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0])
			cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER="+mode)
			cmd.Stdin = strings.NewReader("task")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if term {
				_, slave := scopePTY(t)
				cmd.Stdout, cmd.Stderr = slave, slave
				cmd.SysProcAttr.Setctty = true
				cmd.SysProcAttr.Ctty = 1
			}
			if err := cmd.Run(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
