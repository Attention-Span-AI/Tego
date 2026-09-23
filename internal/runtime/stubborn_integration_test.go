// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// stubbornAgent writes an agent script that ignores SIGTERM and returns it with the file the script
// creates once its trap is installed. A test of R9's escalation must not send its stop before that
// file exists: until the shell has installed its trap on TERM the SIGTERM the stop delivers ends it, and the run
// is stopped/143 without ever escalating — which is how TestIntegrationStopEscalatesToCgroupKill failed
// as root in the KVM guest once the script was readable there (KVM-11), where the agent starts later
// relative to the test than it does on a busy host.
func stubbornAgent(t *testing.T, f *fixture) (script, trapped string) {
	t.Helper()
	script = filepath.Join(f.dir, "stubborn.sh")
	trapped = filepath.Join(f.out, "trapped")
	body := "#!/bin/sh\ntrap '' TERM\n: > \"$1\"\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	return script, trapped
}

// waitForFile waits until path exists.
func waitForFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s did not appear within %s", path, d)
}
