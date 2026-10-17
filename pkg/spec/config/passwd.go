// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// passwdFile is the file the pure-Go lookup reads; a test points it at a fixture.
var passwdFile = "/etc/passwd"

// LookupPasswd is uid's entry in the passwd database, and never one made up from the environment: the entry whose
// home the per-user layer, a "~/" path setting, the chain anchor and the own log are resolved against (R21, E9). An
// error when the database names no entry for uid.
//
// It exists because os/user's LookupId is not that in a pure-Go build (CGO_ENABLED=0, which is how tego is built):
// for the process's own real uid it answers user.Current, and when /etc/passwd lacks that uid and $USER is set,
// Current builds the entry from $USER and $HOME and reports no error (os/user lookup_stubs.go). The per-user layer
// would then be read from $HOME/.tego/config.yaml, and R21's "never $HOME" would hang on whether $USER is set. A
// pure-Go build therefore reads /etc/passwd itself, as os/user's own pure-Go lookup does for
// every other uid; a libc build (cgo) keeps getpwuid_r and NSS, whose Current reports an unknown uid as an error.
func LookupPasswd(uid int) (*user.User, error) {
	if libcPasswd {
		return user.LookupId(strconv.Itoa(uid))
	}
	f, err := os.Open(passwdFile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return findPasswd(f, uid)
}

// PasswdHome is uid's home directory from LookupPasswd; an error when the database names no entry or no home.
func PasswdHome(uid int) (string, error) {
	u, err := LookupPasswd(uid)
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" {
		return "", fmt.Errorf("the passwd database names no home directory for uid %d", uid)
	}
	return u.HomeDir, nil
}

// findPasswd is the entry for uid in a passwd-format file, by the rules of os/user's pure-Go parser (which follows
// glibc's files backend): surrounding blank space and #-comment lines are skipped, a row needs six fields and a
// numeric gid, and a name starting with + or - (an NIS compat row) never matches. A line longer than 1 MiB is an
// error, so the lookup fails closed rather than skipping it.
func findPasswd(r io.Reader, uid int) (*user.User, error) {
	want := strconv.Itoa(uid)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 6 || parts[2] != want || parts[0] == "" || parts[0][0] == '+' || parts[0][0] == '-' {
			continue
		}
		if _, err := strconv.Atoi(parts[3]); err != nil {
			continue
		}
		name, _, _ := strings.Cut(parts[4], ",")
		return &user.User{Username: parts[0], Uid: parts[2], Gid: parts[3], Name: name, HomeDir: parts[5]}, nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", passwdFile, err)
	}
	return nil, user.UnknownUserIdError(uid)
}
