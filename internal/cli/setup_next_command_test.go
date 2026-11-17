// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestStartNextCommandQuotesProject(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "python3")
	t.Chdir(f.Home)
	app := filepath.Join(f.Home, "app;touch PWNED;#")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runGuide(t, "3\npython3\n2\n"+app+"\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "tego"), []byte("#!/bin/sh\npwd > \"$COMMAND_CWD\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	capture := filepath.Join(f.Home, "cwd")
	t.Setenv("COMMAND_CWD", capture)
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "cd "); i >= 0 && strings.Contains(line, " && tego run ") {
			c := exec.Command("/bin/sh", "-c", line[i:])
			if b, err := c.CombinedOutput(); err != nil {
				t.Fatalf("paste: %v %s", err, b)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(f.Home, "PWNED")); !os.IsNotExist(err) {
		t.Fatal("pasted command executed project name")
	}
	if b, _ := os.ReadFile(capture); strings.TrimSpace(string(b)) != app {
		t.Fatalf("wrong working folder: %s", b)
	}
}
