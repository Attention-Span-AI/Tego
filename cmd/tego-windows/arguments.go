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

// keepAttachedWords is the sentence the launcher says where the person starts work, and where it lets go of the
// hold it keeps itself (the dashboard's connection): Windows stops Tego's Linux a short time after the last
// program attached to it ends, which ends a supervised run still going (docs: Repair and removal, "Keep a Windows
// tego command or Linux shell attached while work runs"). It promises nothing about how long, because that was
// measured in one guest only.
const keepAttachedWords = "Keep a tego command or a Linux shell open while an agent works: Windows can stop Tego's Linux when nothing is attached to it, and that ends any run still going."

// dashboardStoppedWords is what `tego dashboard --stop` says after it ended a relay: the relay was holding Tego's
// Linux up, so this is the moment the hold ends.
func dashboardStoppedWords() string {
	return "Stopped the dashboard's connection to your browser. To open the dashboard again, run: tego dashboard\n" + keepAttachedWords
}
