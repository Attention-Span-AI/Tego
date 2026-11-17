// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDashboardLiteralDollars(t *testing.T) {
	if os.Getenv("DASH_DOLLAR_EXECUTABLE") == "" {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "price$old.test")
		binary, err := os.ReadFile(self)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, binary, 0700); err != nil {
			t.Fatal(err)
		}
		c := exec.Command(path, "-test.run=^TestDashboardLiteralDollars$")
		c.Env = append(os.Environ(), "DASH_DOLLAR_EXECUTABLE=1")
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatalf("literal-dollar executable: %v\n%s", err, b)
		}
		return
	}
	for _, supported := range []bool{false, true} {
		t.Run(fmt.Sprint(supported), func(t *testing.T) {
			t.Setenv("DASH_HELPER_DISABLE_EXPANSION", fmt.Sprint(supported))
			f := onFixture(t, "fresh")
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(dir, "ledger-${USER}-$USER")
			configFile := filepath.Join(dir, "machine-${USER}-$USER.yaml")
			if err := os.WriteFile(configFile, []byte("version: 0\nledger_root: "+root+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TEGO_CONFIG", configFile)
			server := dashboardStandIn(t)
			bin := t.TempDir()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			argsFile := filepath.Join(dir, "args")
			for k, v := range map[string]string{"DASH_TEST_BINARY": self, "DASH_HELPER_ARGS": argsFile, "DASH_HELPER_LINK": server.URL + "/?t=0123abcd", "USER": "expanded"} {
				t.Setenv(k, v)
			}
			for name, text := range map[string]string{"systemctl": "exit 0\n", "systemd-run": "exec \"$DASH_TEST_BINARY\" -test.run=^TestDashboardSystemdHelper$ -- \"$@\"\n"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+text), 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			if got := guideDashboard(f.Home); got == "" {
				t.Fatal("dashboard did not start")
			}
			args, err := os.ReadFile(argsFile)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(strings.Split(string(args), "\n"), self) {
				t.Fatalf("executable path changed: %s", args)
			}
			if !strings.Contains(string(args), "--ledger\n"+root+"\n") || !strings.Contains(string(args), "--setenv=TEGO_CONFIG="+configFile+"\n") {
				t.Fatalf("service expanded literal path: %s", args)
			}
			if supported && !strings.Contains(string(args), "--expand-environment=no\n") {
				t.Fatalf("supported expansion-disable option was not used: %s", args)
			}
		})
	}
}

func TestDashboardSystemdHelper(t *testing.T) {
	path := os.Getenv("DASH_HELPER_ARGS")
	if path == "" {
		return
	}
	args := slices.Clone(os.Args[slices.Index(os.Args, "--")+1:])
	if slices.Contains(args, "--help") {
		if os.Getenv("DASH_HELPER_DISABLE_EXPANSION") == "true" {
			fmt.Println("--expand-environment=BOOL")
		}
		return
	}
	// systemd.service(5), Command lines: the executable is separate from
	// environment-expanded arguments; --setenv is a literal assignment.
	command := slices.Index(args, "serve") - 1
	if command < 0 {
		t.Fatal("service command missing")
	}
	for i := command + 1; i < len(args) && !slices.Contains(args, "--expand-environment=no"); i++ {
		args[i] = strings.ReplaceAll(args[i], "$$", "\x01")
		args[i] = os.ExpandEnv(args[i])
		args[i] = strings.ReplaceAll(args[i], "\x01", "$")
	}
	if err := os.WriteFile(path, []byte(strings.Join(args, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fmt.Println(os.Getenv("DASH_HELPER_LINK"))
}
