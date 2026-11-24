// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// Tests re-execute their own image just as the control binary does. This test
// dispatch has no product startup, ledger, config or owner's log side effects.
func init() {
	if len(os.Args) > 1 && os.Args[1] == contracts.HelperCommand {
		if executable, err := os.Executable(); err == nil && len(os.Args) > 2 {
			if fi, err := os.Stat(executable + ".count"); err == nil && fi.IsDir() {
				// The marker says who started it and when: the parent at that moment, the process's start (field 22 of
				// /proc/self/stat, in clock ticks since boot) and the time, for a test that counts them and finds more
				// than it wants (guide_session_test.go).
				note := "ppid=" + strconv.Itoa(os.Getppid()) + " started=" + procStart() + " at=" + time.Now().Format("15:04:05.000000") + "\n"
				if err := os.WriteFile(filepath.Join(executable+".count", os.Args[2]+"-"+strconv.Itoa(os.Getpid())), []byte(note), 0o600); err != nil {
					os.Exit(125)
				}
			}
		}
		os.Exit(contracts.HelperMain(os.Args[2:]))
	}
}

// procStart is this process's start time in clock ticks since boot, "?" where /proc does not say.
func procStart() string {
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "?"
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	if len(f) < 20 {
		return "?"
	}
	return f[19]
}
