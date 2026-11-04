// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func checkOpenLabel(tid, opener, flags int, read func(string) ([]byte, error), modules func() ([]uint64, error)) error {
	return checkOpenLabelAuthority(tid, opener, flags, read, modules, false)
}

func TestOpenLabelAppArmorNamespaceAssumption(t *testing.T) {
	for _, tc := range []struct {
		name, depth, task, opener  string
		assume, unreadable, wantOK bool
	}{
		{"default refuses", "", "docker-default (enforce)", "docker-default (enforce)", false, true, false},
		{"explicit assertion", "", "docker-default (enforce)", "docker-default (enforce)", true, true, true},
		{"different label", "", "tight (enforce)", "docker-default (enforce)", true, true, false},
		{"different mode", "", "docker-default (complain)", "docker-default (enforce)", true, true, false},
		{"missing label", "", "", "docker-default (enforce)", true, true, false},
		{"known nested namespace", "1\n", "local (enforce)", "local (enforce)", true, false, false},
		{"malformed depth", "0", "docker-default (enforce)", "docker-default (enforce)", true, false, false},
		{"root namespace", "0\n", "docker-default (enforce)", "docker-default (enforce)", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				switch path {
				case "/sys/kernel/security/apparmor/.ns_level":
					if tc.unreadable {
						return nil, os.ErrPermission
					}
					return []byte(tc.depth), nil
				case "/proc/123/attr/apparmor/current":
					return []byte(tc.task), nil
				case "/proc/456/attr/apparmor/current":
					return []byte(tc.opener), nil
				}
				return nil, os.ErrNotExist
			}
			err := checkOpenLabelAuthority(123, 456, unix.O_RDONLY, read, func() ([]uint64, error) { return []uint64{100, 104}, nil }, tc.assume)
			if (err == nil) != tc.wantOK {
				t.Fatalf("got %v, wantOK=%t", err, tc.wantOK)
			}
			if tc.name == "default refuses" && (!strings.Contains(err.Error(), "fs.apparmor_assume_root_namespace: true") || !strings.Contains(err.Error(), "EACCES")) {
				t.Fatalf("refusal omits cause/fix: %v", err)
			}
			if tc.name == "different label" && !errors.Is(err, errOpenLabelDiffers) {
				t.Fatalf("lost known difference: %v", err)
			}
		})
	}
	// The assertion cannot hide an unknown module, missing enumeration, or Smack.
	for _, ids := range [][]uint64{nil, {999}, {100, 102}} {
		err := checkOpenLabelAuthority(123, 456, unix.O_CREAT, func(string) ([]byte, error) { return nil, os.ErrPermission }, func() ([]uint64, error) { return ids, nil }, true)
		if err == nil {
			t.Fatalf("assertion bypassed module facts: %v", ids)
		}
	}
}
