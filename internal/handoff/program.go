// SPDX-License-Identifier: Apache-2.0

package handoff

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// ProgramLinePrefix starts the line a running dashboard writes into its own log (stderr, beside its link): the SHA-256 of the program bytes
// it runs. A later tego compares that content, never a file's device, inode or time: tego-control runs from a fresh
// sealed memfd on every launch (Exec), so its /proc/self/exe names another inode each time for the same bytes, and
// an identity made of file attributes never matched (D1 of the 2026-11-19 Windows walkthrough).
const ProgramLinePrefix = "tego program sha256:"

// ProgramLine is the log line that records sum, a lowercase-hex SHA-256, newline included.
func ProgramLine(sum string) string { return ProgramLinePrefix + " " + sum + "\n" }

// RecordedProgram is the sum a dashboard log's program line records, false when the log has no well-formed line. The
// first such line is taken: the dashboard writes it itself, right after its link, before anything else it prints.
func RecordedProgram(log []byte) (string, bool) {
	for _, line := range strings.Split(string(log), "\n") {
		if !strings.HasPrefix(line, ProgramLinePrefix) {
			continue
		}
		sum := strings.TrimPrefix(line, ProgramLinePrefix+" ")
		if ProgramLine(sum) != line+"\n" || !validPin(sum) {
			return "", false
		}
		return sum, true
	}
	return "", false
}

// SelfSum is the SHA-256 of the bytes of the program this process runs, read once from /proc/self/exe: the sealed
// memfd tego-control runs from, or the installed file of a process started by its path. Whatever the inode, the
// memfd or the modification time, the same bytes give the same sum.
func SelfSum() (string, error) { return sumOfProgram("/proc/self/exe") }

func sumOfProgram(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() || st.Size() > maxSize {
		return "", fmt.Errorf("%s is not a program file of a size tego-control has", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, st.Size())); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PinnedSum is the SHA-256 of the tego-control this build hands off to, which Open verifies the sealed copy against
// before anything runs: the bytes a dashboard started now would run. False for an unpinned build, which hands off
// nothing and so starts no dashboard to compare with.
func PinnedSum() (string, bool) { return controlSHA256, validPin(controlSHA256) }
