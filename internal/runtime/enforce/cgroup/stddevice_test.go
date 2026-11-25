// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
)

// TestThePlaneKeysAStandardDeviceOnlyOnThatDevice: the rows a plane fill keys are the objects its held descriptors
// name, and a standard-device row (ADR 0158) is keyed only where the descriptor is the character device with the
// row's numbers. A regular file, a directory, another device's descriptor or a missing one stops the fill.
func TestThePlaneKeysAStandardDeviceOnlyOnThatDevice(t *testing.T) {
	f := contracttest.Build(t, "version: 0\nname: std\ncommand: [fixture]\ncapture: off\nfs:\n  write: [out]\n", contracttest.Tree{"out/": ""})
	rows, err := decide.CompilePlane(f.Rules)
	if err != nil {
		t.Fatal(err)
	}
	open := func(p string) int {
		t.Helper()
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Skipf("host has no %s: %v", p, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := func(p string) (int, bool) { return open(p), true }
	if err := checkStandardDevices(f.Rules, rows, real); err != nil {
		t.Fatalf("the host's own devices: %v", err)
	}
	for _, tc := range []struct {
		name string
		held heldFD
		want string
	}{
		{"a regular file at /dev/null", func(p string) (int, bool) {
			if p == "/dev/null" {
				return open(plain), true
			}
			return real(p)
		}, "not the standard character device"},
		{"a directory at /dev/full", func(p string) (int, bool) {
			if p == "/dev/full" {
				return open(filepath.Dir(plain)), true
			}
			return real(p)
		}, "not the standard character device"},
		{"another standard device at /dev/null", func(p string) (int, bool) {
			if p == "/dev/null" {
				return open("/dev/zero"), true
			}
			return real(p)
		}, "not the standard character device"},
		{"the terminal at /dev/urandom", func(p string) (int, bool) {
			if p == "/dev/urandom" {
				return open("/dev/tty"), true
			}
			return real(p)
		}, "not the standard character device"},
		{"no descriptor for /dev/random", func(p string) (int, bool) {
			if p == "/dev/random" {
				return -1, false
			}
			return real(p)
		}, "no descriptor holds it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkStandardDevices(f.Rules, rows, tc.held)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checkStandardDevices = %v, want an error containing %q", err, tc.want)
			}
		})
	}
	// A table with no device row has nothing to check, and a nil table or rows is not an error.
	if err := checkStandardDevices(nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
