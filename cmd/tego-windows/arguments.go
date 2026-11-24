// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const linuxEntry = "/usr/local/lib/tego/windows-entry"

func wslBaseArguments() []string {
	return []string{"--distribution", "tego", "--user", "tego", "--exec", linuxEntry}
}

func wslArguments(args []string) ([]string, error) {
	if args == nil {
		args = []string{}
	}
	for _, arg := range args {
		if strings.ContainsRune(arg, 0) {
			return nil, errors.New("an argument contains NUL")
		}
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return append(wslBaseArguments(), base64.StdEncoding.EncodeToString(raw)), nil
}

// startupFailureWords is what the person reads when Tego's Linux did not confirm its user scope in time (a cold start
// after a restart, or a PC short of memory, which the Windows walkthrough of 2026-11-19 met once, the same command
// working a minute later). It says what to do: try the same command again, which is safe because a failed start was
// stopped before anything of Tego's ran (startLinuxReady closes or ends the private client; nothing is armed), and
// when it fails twice, the one command that shows why, run through the entry itself since `tego doctor` starts
// through the same step. cause is the one-line reason startLinuxReady gave.
func startupFailureWords(cause string) string {
	why := "wsl -d tego -u tego --exec " + linuxEntry + " " + base64.StdEncoding.EncodeToString([]byte(`["doctor"]`))
	return "tego: Linux startup did not complete (" + cause + ").\n" +
		"Next: type the same command again. Linux is often still starting right after a restart or when the PC is short of memory, and nothing was changed by this try.\n" +
		"If it fails a second time, this shows why:\n  " + why + "\n"
}
