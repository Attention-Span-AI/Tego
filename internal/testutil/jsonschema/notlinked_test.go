// SPDX-License-Identifier: Apache-2.0

// This test runs go list, so it stays out of the integration binaries: root-suites.sh runs those in a KVM guest
// with no Go toolchain, where go-shim.sh serves only the prebuilt helpers and fails any other go command.

//go:build !integration

package jsonschema

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// commands returns the name of every directory under cmd/: each is a binary a user may run (cmd/tego, cmd/maze),
// and a command added later is held to the same rule the day it appears.
func commands(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("..", "..", "..", "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) < 2 {
		t.Fatalf("found the commands %v under cmd/, want at least tego and maze", names)
	}
	return names
}

// TestValidatorNotInBinary: the validator module is a test dependency. No package of the link closure of any
// command under cmd/ (tego and maze), on either architecture and with and without the tegobpf tag, comes from
// github.com/santhosh-tekuri/jsonschema (or is this test-support package), so the module needs no entry in
// THIRD_PARTY_NOTICES.txt and scripts/check-licenses.sh, which inventories the linked modules, stays complete.
func TestValidatorNotInBinary(t *testing.T) {
	for _, command := range commands(t) {
		for _, goarch := range []string{"amd64", "arm64"} {
			for _, tags := range []string{"", "tegobpf"} {
				cmd := exec.Command("go", "list", "-deps", "-tags="+tags, "../../../cmd/"+command)
				cmd.Env = append(cmd.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("go list -deps cmd/%s (GOARCH=%s tags=%q): %v", command, goarch, tags, err)
				}
				found := false
				for _, p := range strings.Fields(string(out)) {
					switch {
					case strings.HasSuffix(p, "/cmd/"+command):
						found = true
					case strings.HasPrefix(p, "github.com/santhosh-tekuri/"),
						strings.HasPrefix(p, "github.com/attention-span-ai/tego/internal/testutil/jsonschema"):
						t.Errorf("cmd/%s links %s (GOARCH=%s tags=%q): the validator is test-only", command, p, goarch, tags)
					}
				}
				if !found {
					t.Fatalf("go list -deps cmd/%s (GOARCH=%s tags=%q) did not list the command itself", command, goarch, tags)
				}
			}
		}
	}
}
