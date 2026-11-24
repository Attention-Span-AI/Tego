// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 1 && args[0] == "__path-changed" {
		return pathChanged()
	}
	if len(args) > 0 && args[0] == relayVerb {
		return relayMain(args[1:])
	}
	// Windows delivers Ctrl-C to every attached console process. Let wsl.exe
	// forward it to Linux and return its status, rather than killing its parent.
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	if len(args) > 0 && args[0] == "uninstall" {
		// The relay runs this program's file; stop it so the installer can remove it.
		if rec := readRelayState(); rec != nil {
			stopRelayProcess(*rec)
		}
		return uninstall(args[1:])
	}
	if len(args) == 2 && args[0] == "dashboard" && args[1] == "--stop" {
		return stopDashboard()
	}
	code := linuxCommand(args, interrupts)
	if code != 0 {
		return code
	}
	switch {
	case opensDashboard(args):
		return openDashboard()
	case len(args) == 1 && (args[0] == "start" || args[0] == "setup"):
		// The guide's last step: open the dashboard it started, then the project shell. A browser failure is
		// told in one line and does not keep the person out of their shell.
		_ = openDashboard()
		return linuxCommand([]string{"shell"}, interrupts)
	}
	return code
}

func systemProgram(name string) string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", name)
}

func linuxCommand(args []string, interrupts <-chan os.Signal) int {
	argv, err := wslArguments(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tego:", err)
		return 125
	}
	ready, code, err := startLinuxReady(interrupts)
	if err != nil {
		cause := strings.Join(strings.Fields(err.Error()), " ")
		if len(cause) > 400 {
			cause = cause[:400]
		}
		fmt.Fprint(os.Stderr, startupFailureWords(cause))
	}
	if code != 0 {
		return code
	}
	defer ready.close()
	return child(systemProgram("wsl.exe"), argv)
}

// child is a reviewed start: the Windows launcher never holds a fanotify group
// and links no Linux enforcement code (ADR 0009). Caller arguments are data.
func child(path string, args []string) int {
	cmd := proc.Command(path, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := startWindowsCommand(cmd); err != nil {
		fmt.Fprintln(os.Stderr, "tego: could not start", path+":", err)
		return 125
	}
	if err := cmd.Wait(); err != nil {
		if cmd.ProcessState != nil {
			return cmd.ProcessState.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "tego:", err)
		return 125
	}
	return 0
}

// startWindowsCommand is the reviewed shared start. Every caller is part of
// this Windows-only launcher, which links no fanotify code (ADR 0009).
func startWindowsCommand(cmd *proc.Cmd) error {
	if !filepath.IsAbs(cmd.Path) {
		return errors.New("SystemRoot must name an absolute Windows folder")
	}
	_, err := proc.Start(cmd)
	if err != nil && cmd.Process != nil {
		// Keep the already-open Windows process handle; never reopen by PID.
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	return err
}

func uninstall(args []string) int {
	yes := len(args) == 1 && strings.EqualFold(args[0], "-Yes")
	if len(args) > 1 || len(args) == 1 && !yes {
		fmt.Fprintln(os.Stderr, "usage: tego uninstall [-Yes]")
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tego:", err)
		return 125
	}
	argv := []string{"-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", filepath.Join(filepath.Dir(self), "..", "install.ps1"), "-Uninstall", "-LauncherPid", strconv.Itoa(os.Getpid())}
	if yes {
		argv = append(argv, "-Yes")
	}
	return child(systemProgram(`WindowsPowerShell\v1.0\powershell.exe`), argv)
}
