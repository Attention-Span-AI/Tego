// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

// TestFindPasswdFollowsTheFilesBackend is LookupPasswd's parser against the rows os/user's pure-Go parser and glibc's
// files backend accept and skip.
func TestFindPasswdFollowsTheFilesBackend(t *testing.T) {
	file := strings.Join([]string{
		"# a comment naming 4242:x:4242",
		"",
		"+nis:x:4242:4242::/nis:/bin/sh",
		"-nis:x:4242:4242::/nis:/bin/sh",
		"short:x:4242:4242",
		"badgid:x:4242:g::/badgid:/bin/sh",
		"other:x:42420:42420::/other:/bin/sh",
		"  probe:x:4242:4343:Probe User,room 1:/home/probe:/bin/sh  ",
		"late:x:4242:4242::/late:/bin/sh",
	}, "\n")
	u, err := findPasswd(strings.NewReader(file), 4242)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "probe" || u.Uid != "4242" || u.Gid != "4343" || u.Name != "Probe User" || u.HomeDir != "/home/probe" {
		t.Fatalf("entry = %+v, want probe's", u)
	}
	var unknown user.UnknownUserIdError
	if _, err := findPasswd(strings.NewReader(file), 4343); !errors.As(err, &unknown) || int(unknown) != 4343 {
		t.Fatalf("an absent uid answered %v, want UnknownUserIdError(4343)", err)
	}
	if _, err := findPasswd(strings.NewReader(strings.Repeat("x", 2<<20)+"\nprobe:x:4242:4242::/h:/bin/sh\n"), 4242); err == nil {
		t.Fatal("a passwd file with an over-long line was read past it, want an error")
	}
}
