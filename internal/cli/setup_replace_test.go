// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"golang.org/x/sys/unix"
)

func TestReplaceAgentPreservesOldOnWriteFailure(t *testing.T) {
	if os.Getenv("TEGO_TEST_REPLACE_FAILURE") == "1" {
		dir := os.Getenv("TEGO_TEST_REPLACE_DIR")
		m := config.Builtin()
		m.Registry.Value = dir
		var limit unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &limit); err != nil {
			t.Fatal(err)
		}
		small := limit
		small.Cur = 64
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &small); err != nil {
			t.Fatal(err)
		}
		_, code := saveOwnRules(m, "helper", filepath.Join(dir, "project"), filepath.Join(dir, "new.yaml"), true, io.Discard)
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limit); err != nil {
			t.Fatal(err)
		}
		if code == identity.ExitOK {
			t.Fatal("injected write limit was ignored")
		}
		return
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "agents"), 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agents", "helper.yaml")
	old := "version: 0\nname: helper\ncommand: [/bin/sh]\n"
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "new.yaml"), []byte(old+strings.Repeat("# new rules\n", 100)), 0600); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := exec.Command(self, "-test.run=^TestReplaceAgentPreservesOldOnWriteFailure$")
	c.Env = append(os.Environ(), "TEGO_TEST_REPLACE_FAILURE=1", "TEGO_TEST_REPLACE_DIR="+dir)
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, b)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != old {
		t.Fatalf("previous rules lost: %q %v", b, err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "agents", ".tego-save-*"))
	if len(matches) > 0 {
		t.Fatalf("partial files left: %v", matches)
	}
}
